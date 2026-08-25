#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "vynkor/error.hpp"
#include "vynkor/mac.hpp"

namespace vynkor {

static constexpr uint16_t FRAME_MAGIC       = 0x5652;
static constexpr size_t   FRAME_HEADER_SIZE = 44;
static constexpr size_t   MAX_PAYLOAD_SIZE  = 1048576; // 1 MiB

// FLAG_MAC_PRESENT is defined in mac.hpp (included above).
static constexpr uint16_t FLAG_COMPRESSED   = 0x0002; // payload is zstd-compressed; CRC32 over compressed bytes
static constexpr uint16_t FLAG_FRAGMENTED   = 0x0004; // payload is one fragment of a larger message; see FRAG_HEADER_SIZE
static constexpr uint16_t FLAG_RAW_BINARY   = 0x0010; // payload is raw bytes (PCM/Opus); skip Protobuf parse
static constexpr size_t   COMPRESS_THRESHOLD = 65536; // payloads >= this size are candidates for compression

// Byte length of the fragment metadata header embedded at the start of a
// FLAG_FRAGMENTED frame's payload. Layout (all big-endian):
//   [fragment_id: u16][sequence: u16][total: u16][stream_id: u32]
// Mirrors wire/src/framing.rs's FRAG_HEADER_SIZE/FragmentHeader.
static constexpr size_t FRAG_HEADER_SIZE = 10;

struct FragmentHeader {
    uint16_t fragment_id = 0;
    uint16_t sequence    = 0;
    uint16_t total       = 0;
    uint32_t stream_id   = 0;
};

// Builds the 10-byte fragment metadata header.
std::vector<uint8_t> pack_frag_header(uint16_t fragment_id, uint16_t sequence,
                                      uint16_t total, uint32_t stream_id);

// Parses a FragmentHeader from the start of a fragment payload. Returns
// std::nullopt if payload is shorter than FRAG_HEADER_SIZE.
std::optional<FragmentHeader> parse_frag_header(const uint8_t* payload, size_t len);

// Wire format (all multi-byte fields big-endian):
//   [0..1]   magic   uint16  = 0x5652
//   [2..3]   flags   uint16  (FLAG_MAC_PRESENT = 0x0001)
//   [4..7]   length  uint32  = payload byte count
//   [8..39]  target  char[32] null-padded plugin_id / "kernel" / "*"
//   [40..43] crc32   uint32  = CRC-32/ISO-HDLC of payload
//   [44..]   payload
//   [44+N..] MAC tag (32 bytes) — present only when FLAG_MAC_PRESENT is set

// CRC-32/ISO-HDLC
uint32_t vynkor_crc32(const uint8_t* data, size_t len);

// Build CRC-only frame (no MAC). Backward-compatible. extra_flags is OR'd
// into the wire flags (e.g. FLAG_FRAGMENTED for fragment frames).
std::vector<uint8_t> pack_frame(const std::string& target,
                                const std::vector<uint8_t>& payload,
                                uint16_t extra_flags = 0);
std::vector<uint8_t> pack_frame(const std::string& target,
                                const std::string& payload,
                                uint16_t extra_flags = 0);

// Build a MAC frame: sets FLAG_MAC_PRESENT (plus any extra_flags) and appends
// a 32-byte HMAC-SHA256 tag.
std::vector<uint8_t> pack_frame_mac(const std::string& target,
                                    const std::vector<uint8_t>& payload,
                                    const std::array<uint8_t, 32>& session_key,
                                    uint16_t extra_flags = 0);

// Build a wire frame with outbound zstd compression and frame MAC, mirroring
// vynkor-wire's write_frame_raw ordering exactly:
//   1. payload >= COMPRESS_THRESHOLD (and neither FLAG_COMPRESSED nor
//      FLAG_RAW_BINARY set) is zstd-compressed at level 3, used only if it
//      actually shrinks the bytes (else the original is sent uncompressed);
//   2. the MAC (when session_key != nullptr) is computed over the *plaintext*
//      header + payload — i.e. BEFORE compression — keyed on the pre-compression
//      header (flags as passed, plaintext length, plaintext crc32);
//   3. the wire header describes the compressed bytes (FLAG_COMPRESSED set,
//      compressed length, crc32 over compressed bytes).
// `flags` must already include FLAG_MAC_PRESENT when session_key is set.
// session_key == nullptr sends CRC-only (no MAC tag appended).
std::vector<uint8_t> pack_frame_raw(const std::string& target,
                                    uint16_t flags,
                                    const std::vector<uint8_t>& payload,
                                    const std::array<uint8_t, 32>* session_key);

// Build a wire frame WITHOUT outbound compression — the WebSocket transport's
// writer (R5-03: the gateway rejects FLAG_COMPRESSED, so a frame is one WS
// binary message of header + payload + optional MAC tag). `flags` must
// already include FLAG_MAC_PRESENT when session_key is set.
std::vector<uint8_t> pack_frame_ws(const std::string& target,
                                   uint16_t flags,
                                   const std::vector<uint8_t>& payload,
                                   const std::array<uint8_t, 32>* session_key);

// Serialize just the 44-byte wire header for target/flags/payload (used by
// the WS writer to compute the MAC over the plaintext header).
std::array<uint8_t, FRAME_HEADER_SIZE> serialize_header_ws(
    const std::string& target, uint16_t flags, const std::vector<uint8_t>& payload);

// Result of read_frame_full.
struct FrameResult {
    std::vector<uint8_t>                    payload;
    uint16_t                                flags = 0;
    bool                                    has_mac = false;
    std::array<uint8_t, 32>                 mac = {};
    // Header the MAC tag was computed over. Equal to the wire header unless the
    // frame arrived with FLAG_COMPRESSED, in which case this is the rebuilt
    // plaintext header (flags with FLAG_COMPRESSED cleared, length/crc32 of the
    // decompressed payload) — mirroring src/ipc/framing.rs:228-241.
    std::array<uint8_t, FRAME_HEADER_SIZE>  raw_header = {};
};

// Default window the rest of a frame (after its first byte arrives) must
// complete within — bounds slow-loris stalls. See read_frame_full_with_timeout.
static constexpr int FRAME_READ_TIMEOUT_MS = 10000;

// Read one frame and return full FrameResult. Payload is always plaintext:
// if the wire frame carries FLAG_COMPRESSED, it is transparently decompressed
// (bounded to MAX_PAYLOAD_SIZE) and `flags`/`raw_header` describe the
// decompressed bytes, matching the kernel's read-side normalization.
// If session_key is non-null and FLAG_MAC_PRESENT is set, verifies the MAC tag;
// throws VynkorInternal on mismatch. If session_key is null, MAC bytes are read
// and stored but not verified.
//
// Blocks indefinitely waiting for the first byte of the next frame (an idle
// connection must not be torn down); once a byte arrives, the remainder of
// the frame must complete within frame_timeout_ms or this throws
// VynkorFrameReadTimeout.
FrameResult read_frame_full_with_timeout(int fd,
                                         const std::array<uint8_t, 32>* session_key,
                                         int frame_timeout_ms);

// Like read_frame_full_with_timeout, but bounds the wait for the first byte
// of the frame too (via poll()), not just mid-frame completion. Used by
// request/response client methods (publish_event, and future streaming/
// session methods) that need a caller-supplied overall deadline.
// Throws VynkorTimeout if the deadline passes before a frame arrives.
FrameResult read_frame_full_with_deadline(int fd,
                                          const std::array<uint8_t, 32>* session_key,
                                          std::chrono::steady_clock::time_point deadline);

inline FrameResult read_frame_full(int fd,
                                   const std::array<uint8_t, 32>* session_key = nullptr) {
    return read_frame_full_with_timeout(fd, session_key, FRAME_READ_TIMEOUT_MS);
}

// Parse one complete wire frame from an in-memory buffer (the WS transport:
// one binary WebSocket message == one wire frame). Same validation and
// FLAG_COMPRESSED normalization as read_frame_full_with_timeout; MAC is
// verified when session_key is non-null (FLAG_MAC_PRESENT required then).
// `consumed` receives the number of bytes taken from the front of the buffer.
FrameResult parse_frame_from_buffer(const uint8_t* data, size_t len,
                                    const std::array<uint8_t, 32>* session_key,
                                    size_t* consumed);

// Backward-compat: returns only payload bytes. Does NOT verify MAC.
std::vector<uint8_t> read_frame(int fd);

} // namespace vynkor
