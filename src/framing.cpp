#include "vynkor/framing.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zstd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "vynkor/error.hpp"

namespace vynkor {

// ---------------------------------------------------------------------------
// CRC-32/ISO-HDLC
// ---------------------------------------------------------------------------
static std::array<uint32_t, 256> build_crc32_table() {
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j)
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        t[i] = c;
    }
    return t;
}

uint32_t vynkor_crc32(const uint8_t* data, size_t len) {
    static const auto table = build_crc32_table();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i)
        crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

// ---------------------------------------------------------------------------
// Fragment header pack/parse (T-18)
// ---------------------------------------------------------------------------
std::vector<uint8_t> pack_frag_header(uint16_t fragment_id, uint16_t sequence,
                                      uint16_t total, uint32_t stream_id) {
    std::vector<uint8_t> out(FRAG_HEADER_SIZE);
    const uint16_t fragment_id_be = htons(fragment_id);
    const uint16_t sequence_be    = htons(sequence);
    const uint16_t total_be       = htons(total);
    const uint32_t stream_id_be   = htonl(stream_id);
    std::memcpy(out.data() + 0, &fragment_id_be, 2);
    std::memcpy(out.data() + 2, &sequence_be, 2);
    std::memcpy(out.data() + 4, &total_be, 2);
    std::memcpy(out.data() + 6, &stream_id_be, 4);
    return out;
}

std::optional<FragmentHeader> parse_frag_header(const uint8_t* payload, size_t len) {
    if (len < FRAG_HEADER_SIZE)
        return std::nullopt;
    FragmentHeader hdr;
    uint16_t fragment_id_be, sequence_be, total_be;
    uint32_t stream_id_be;
    std::memcpy(&fragment_id_be, payload + 0, 2);
    std::memcpy(&sequence_be, payload + 2, 2);
    std::memcpy(&total_be, payload + 4, 2);
    std::memcpy(&stream_id_be, payload + 6, 4);
    hdr.fragment_id = ntohs(fragment_id_be);
    hdr.sequence    = ntohs(sequence_be);
    hdr.total       = ntohs(total_be);
    hdr.stream_id   = ntohl(stream_id_be);
    return hdr;
}

// ---------------------------------------------------------------------------
// pack_frame (CRC-only, backward-compatible)
// ---------------------------------------------------------------------------
std::vector<uint8_t> pack_frame(const std::string& target,
                                const std::vector<uint8_t>& payload,
                                uint16_t extra_flags) {
    if (payload.size() > MAX_PAYLOAD_SIZE)
        throw VynkorPayloadTooLarge(payload.size());

    uint32_t crc = vynkor_crc32(payload.data(), payload.size());

    uint8_t header[FRAME_HEADER_SIZE] = {};
    const uint16_t magic_be = htons(FRAME_MAGIC);
    std::memcpy(header + 0, &magic_be, 2);
    const uint16_t flags_be = htons(extra_flags);
    std::memcpy(header + 2, &flags_be, 2);
    const uint32_t len_be = htonl(static_cast<uint32_t>(payload.size()));
    std::memcpy(header + 4, &len_be, 4);
    const size_t copy_len = std::min(target.size(), size_t{32});
    std::memcpy(header + 8, target.data(), copy_len);
    const uint32_t crc_be = htonl(crc);
    std::memcpy(header + 40, &crc_be, 4);

    std::vector<uint8_t> frame;
    frame.reserve(FRAME_HEADER_SIZE + payload.size());
    frame.insert(frame.end(), header, header + FRAME_HEADER_SIZE);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

std::vector<uint8_t> pack_frame(const std::string& target,
                                const std::string& payload,
                                uint16_t extra_flags) {
    return pack_frame(target, std::vector<uint8_t>(payload.begin(), payload.end()), extra_flags);
}

// ---------------------------------------------------------------------------
// pack_frame_mac — sets FLAG_MAC_PRESENT and appends 32-byte HMAC tag
// ---------------------------------------------------------------------------
std::vector<uint8_t> pack_frame_mac(const std::string& target,
                                    const std::vector<uint8_t>& payload,
                                    const std::array<uint8_t, 32>& session_key,
                                    uint16_t extra_flags) {
    if (payload.size() > MAX_PAYLOAD_SIZE)
        throw VynkorPayloadTooLarge(payload.size());

    uint32_t crc = vynkor_crc32(payload.data(), payload.size());

    uint8_t header[FRAME_HEADER_SIZE] = {};
    const uint16_t magic_be = htons(FRAME_MAGIC);
    std::memcpy(header + 0, &magic_be, 2);
    const uint16_t flags_be = htons(static_cast<uint16_t>(FLAG_MAC_PRESENT | extra_flags));
    std::memcpy(header + 2, &flags_be, 2);
    const uint32_t len_be = htonl(static_cast<uint32_t>(payload.size()));
    std::memcpy(header + 4, &len_be, 4);
    const size_t copy_len = std::min(target.size(), size_t{32});
    std::memcpy(header + 8, target.data(), copy_len);
    const uint32_t crc_be = htonl(crc);
    std::memcpy(header + 40, &crc_be, 4);

    auto tag = compute_tag(session_key,
                           header, FRAME_HEADER_SIZE,
                           payload.data(), payload.size());

    std::vector<uint8_t> frame;
    frame.reserve(FRAME_HEADER_SIZE + payload.size() + MAC_TAG_LEN);
    frame.insert(frame.end(), header, header + FRAME_HEADER_SIZE);
    frame.insert(frame.end(), payload.begin(), payload.end());
    frame.insert(frame.end(), tag.begin(), tag.end());
    return frame;
}

// ---------------------------------------------------------------------------
// Internal I/O helpers
// ---------------------------------------------------------------------------
static void recv_exact(int fd, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        const ssize_t r = ::read(fd, buf + total, n - total);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            throw VynkorIoError("connection closed or recv error");
        total += static_cast<size_t>(r);
    }
}

using Deadline = std::chrono::steady_clock::time_point;

static void recv_exact_deadline(int fd, uint8_t* buf, size_t n, Deadline deadline) {
    size_t total = 0;
    while (total < n) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            throw VynkorFrameReadTimeout();
        const auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();

        struct pollfd pfd {};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, static_cast<int>(remaining_ms));
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            throw VynkorIoError("poll failed during frame read");
        }
        if (pr == 0)
            throw VynkorFrameReadTimeout();

        const ssize_t r = ::read(fd, buf + total, n - total);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            throw VynkorIoError("connection closed or recv error");
        total += static_cast<size_t>(r);
    }
}

// Bounded zstd decompression mirroring src/ipc/framing.rs:234.
static std::vector<uint8_t> zstd_decompress_bounded(const uint8_t* data, size_t len) {
    unsigned long long content_size = ZSTD_getFrameContentSize(data, len);
    if (content_size == ZSTD_CONTENTSIZE_ERROR)
        throw VynkorInternal("decompress frame: invalid zstd frame");
    if (content_size == ZSTD_CONTENTSIZE_UNKNOWN || content_size > MAX_PAYLOAD_SIZE)
        throw VynkorInternal("decompress frame: content size unknown or too large");

    std::vector<uint8_t> out(static_cast<size_t>(content_size));
    size_t result = ZSTD_decompress(out.data(), out.size(), data, len);
    if (ZSTD_isError(result) || result != out.size())
        throw VynkorInternal(std::string("decompress frame: ") + ZSTD_getErrorName(result));
    return out;
}

// Rebuilds the 44-byte header exactly as serialize_header (src/ipc/framing.rs)
// does, for the given flags/target/payload.
static void build_header(uint8_t out[FRAME_HEADER_SIZE], uint16_t flags,
                         const uint8_t target[32], const std::vector<uint8_t>& payload) {
    std::memset(out, 0, FRAME_HEADER_SIZE);
    const uint16_t magic_be = htons(FRAME_MAGIC);
    std::memcpy(out + 0, &magic_be, 2);
    const uint16_t flags_be = htons(flags);
    std::memcpy(out + 2, &flags_be, 2);
    const uint32_t len_be = htonl(static_cast<uint32_t>(payload.size()));
    std::memcpy(out + 4, &len_be, 4);
    std::memcpy(out + 8, target, 32);
    const uint32_t crc_be = htonl(vynkor_crc32(payload.data(), payload.size()));
    std::memcpy(out + 40, &crc_be, 4);
}

static void target_to_bytes(const std::string& target, uint8_t out[32]) {
    std::memset(out, 0, 32);
    const size_t copy_len = std::min(target.size(), size_t{32});
    if (copy_len > 0)
        std::memcpy(out, target.data(), copy_len);
}

static std::vector<uint8_t> zstd_compress_level3(const uint8_t* data, size_t len) {
    std::vector<uint8_t> compressed(ZSTD_compressBound(len));
    size_t csize = ZSTD_compress(compressed.data(), compressed.size(), data, len, 3);
    if (ZSTD_isError(csize))
        throw VynkorInternal(std::string("zstd compress failed: ") + ZSTD_getErrorName(csize));
    compressed.resize(csize);
    return compressed;
}

std::array<uint8_t, FRAME_HEADER_SIZE> serialize_header_ws(
    const std::string& target, uint16_t flags, const std::vector<uint8_t>& payload) {
    std::array<uint8_t, FRAME_HEADER_SIZE> out{};
    uint8_t target_bytes[32];
    target_to_bytes(target, target_bytes);
    build_header(out.data(), flags, target_bytes, payload);
    return out;
}

std::vector<uint8_t> pack_frame_ws(const std::string& target,
                                   uint16_t flags,
                                   const std::vector<uint8_t>& payload,
                                   const std::array<uint8_t, 32>* session_key) {
    if (payload.size() > MAX_PAYLOAD_SIZE)
        throw VynkorPayloadTooLarge(payload.size());

    auto header = serialize_header_ws(target, flags, payload);

    std::vector<uint8_t> frame;
    frame.reserve(FRAME_HEADER_SIZE + payload.size() + (session_key ? MAC_TAG_LEN : 0));
    frame.insert(frame.end(), header.begin(), header.end());
    frame.insert(frame.end(), payload.begin(), payload.end());
    if (session_key != nullptr) {
        auto tag = compute_tag(*session_key, header.data(), FRAME_HEADER_SIZE,
                               payload.data(), payload.size());
        frame.insert(frame.end(), tag.begin(), tag.end());
    }
    return frame;
}

std::vector<uint8_t> pack_frame_raw(const std::string& target,
                                    uint16_t flags,
                                    const std::vector<uint8_t>& payload,
                                    const std::array<uint8_t, 32>* session_key) {
    if (payload.size() > MAX_PAYLOAD_SIZE)
        throw VynkorPayloadTooLarge(payload.size());

    uint8_t target_bytes[32];
    target_to_bytes(target, target_bytes);

    // Plaintext header: MAC (when secured) covers these bytes — computed BEFORE
    // compression, so it must describe the uncompressed payload (flags as
    // passed, plaintext length, plaintext crc32). Mirrors write_frame_raw.
    std::array<uint8_t, FRAME_HEADER_SIZE> plain_header;
    build_header(plain_header.data(), flags, target_bytes, payload);

    std::optional<std::array<uint8_t, 32>> tag;
    if (session_key != nullptr)
        tag = compute_tag(*session_key, plain_header.data(), FRAME_HEADER_SIZE,
                          payload.data(), payload.size());

    // Outbound compression (write_frame_raw semantics): candidates >= threshold,
    // skip raw binary, keep only if it shrinks the bytes.
    const std::vector<uint8_t>* wire_payload = &payload;
    uint16_t wire_flags = flags;
    std::vector<uint8_t> compressed;
    if (payload.size() >= COMPRESS_THRESHOLD &&
        !(flags & FLAG_COMPRESSED) && !(flags & FLAG_RAW_BINARY)) {
        compressed = zstd_compress_level3(payload.data(), payload.size());
        if (compressed.size() < payload.size()) {
            wire_payload = &compressed;
            wire_flags = flags | FLAG_COMPRESSED;
        }
    }

    // Wire header describes the bytes actually on the wire (possibly compressed).
    uint8_t wire_header[FRAME_HEADER_SIZE];
    build_header(wire_header, wire_flags, target_bytes, *wire_payload);

    std::vector<uint8_t> frame;
    frame.reserve(FRAME_HEADER_SIZE + wire_payload->size() + (tag ? MAC_TAG_LEN : 0));
    frame.insert(frame.end(), wire_header, wire_header + FRAME_HEADER_SIZE);
    frame.insert(frame.end(), wire_payload->begin(), wire_payload->end());
    if (tag)
        frame.insert(frame.end(), tag->begin(), tag->end());
    return frame;
}

// ---------------------------------------------------------------------------
// Shared frame parsing — validates magic/length/CRC over the wire bytes,
// normalizes FLAG_COMPRESSED (decompress + rebuild plaintext header), and
// verifies the MAC when session_key is set. Used by both the fd reader and
// parse_frame_from_buffer (WS path).
// ---------------------------------------------------------------------------
static FrameResult parse_frame_bytes(const std::vector<uint8_t>& buf,
                                     const std::array<uint8_t, 32>* session_key,
                                     size_t* consumed) {
    size_t min_len = FRAME_HEADER_SIZE;
    if (buf.size() < min_len)
        throw VynkorIoError("frame shorter than header");

    uint16_t magic;
    std::memcpy(&magic, buf.data() + 0, 2);
    if (ntohs(magic) != FRAME_MAGIC)
        throw VynkorFrameMagicMismatch();

    uint16_t flags;
    std::memcpy(&flags, buf.data() + 2, 2);
    flags = ntohs(flags);

    uint32_t length;
    std::memcpy(&length, buf.data() + 4, 4);
    length = ntohl(length);
    if (length > MAX_PAYLOAD_SIZE)
        throw VynkorPayloadTooLarge(length);

    const bool has_mac = (flags & FLAG_MAC_PRESENT) != 0;
    const size_t total = FRAME_HEADER_SIZE + length + (has_mac ? MAC_TAG_LEN : 0);
    if (buf.size() < total)
        throw VynkorIoError("frame truncated");

    uint32_t expected_crc;
    std::memcpy(&expected_crc, buf.data() + 40, 4);
    expected_crc = ntohl(expected_crc);

    std::vector<uint8_t> payload(buf.begin() + FRAME_HEADER_SIZE,
                                 buf.begin() + FRAME_HEADER_SIZE + length);

    // CRC is over the wire bytes (possibly compressed); verify before decompressing.
    if (vynkor_crc32(payload.data(), payload.size()) != expected_crc)
        throw VynkorFrameCrcMismatch();

    // Normalize the in-memory invariant: payload is always plaintext, and the
    // header used for MAC verification describes the plaintext — mirroring
    // src/ipc/framing.rs:228-241.
    std::array<uint8_t, FRAME_HEADER_SIZE> effective_header;
    std::memcpy(effective_header.data(), buf.data(), FRAME_HEADER_SIZE);
    if (flags & FLAG_COMPRESSED) {
        payload = zstd_decompress_bounded(payload.data(), payload.size());
        flags &= static_cast<uint16_t>(~FLAG_COMPRESSED);
        build_header(effective_header.data(), flags, buf.data() + 8, payload);
    }

    FrameResult result;
    result.flags = flags;
    result.raw_header = effective_header;
    result.payload = std::move(payload);

    if (has_mac) {
        std::memcpy(result.mac.data(),
                    buf.data() + FRAME_HEADER_SIZE + length, MAC_TAG_LEN);
        result.has_mac = true;
        if (session_key != nullptr) {
            if (!verify_tag(*session_key,
                            effective_header.data(), FRAME_HEADER_SIZE,
                            result.payload.data(), result.payload.size(),
                            result.mac.data(), MAC_TAG_LEN))
                throw VynkorInternal("frame MAC verification failed");
        }
    } else if (session_key != nullptr) {
        throw VynkorInternal("frame MAC verification failed");
    }

    if (consumed != nullptr)
        *consumed = total;
    return result;
}

// ---------------------------------------------------------------------------
// read_frame_full_with_deadline — bounds the wait for the first byte too,
// via poll(), then hands off to read_frame_full_with_timeout for the rest.
// ---------------------------------------------------------------------------
FrameResult read_frame_full_with_deadline(int fd, const std::array<uint8_t, 32>* session_key,
                                          Deadline deadline) {
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            throw VynkorTimeout();
        const auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();

        struct pollfd pfd {};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, static_cast<int>(remaining_ms));
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            throw VynkorIoError("poll failed during frame read");
        }
        if (pr == 0)
            throw VynkorTimeout();

        // Data is available; hand off with the remaining budget as the
        // mid-frame bound. Floor at 1ms so a just-signaled-readable fd
        // doesn't spuriously time out on the read it was just cleared for.
        const auto now2 = std::chrono::steady_clock::now();
        auto remaining_ms2 = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now2).count();
        if (remaining_ms2 < 1)
            remaining_ms2 = 1;
        return read_frame_full_with_timeout(fd, session_key, static_cast<int>(remaining_ms2));
    }
}

// ---------------------------------------------------------------------------
// read_frame_full_with_timeout
// ---------------------------------------------------------------------------
FrameResult read_frame_full_with_timeout(int fd, const std::array<uint8_t, 32>* session_key,
                                         int frame_timeout_ms) {
    std::vector<uint8_t> buf(FRAME_HEADER_SIZE);
    // Block indefinitely for the first byte of the next frame — an idle
    // connection between frames must not be torn down. Once a byte arrives,
    // a frame is in progress and the remainder is bounded by frame_timeout_ms.
    recv_exact(fd, buf.data(), 1);
    const Deadline deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(frame_timeout_ms);
    recv_exact_deadline(fd, buf.data() + 1, FRAME_HEADER_SIZE - 1, deadline);

    uint16_t flags;
    std::memcpy(&flags, buf.data() + 2, 2);
    flags = ntohs(flags);

    uint32_t length;
    std::memcpy(&length, buf.data() + 4, 4);
    length = ntohl(length);
    if (length > MAX_PAYLOAD_SIZE)
        throw VynkorPayloadTooLarge(length);

    const size_t rest = length + ((flags & FLAG_MAC_PRESENT) ? MAC_TAG_LEN : 0);
    if (rest > 0) {
        const size_t old_size = buf.size();
        buf.resize(old_size + rest);
        recv_exact_deadline(fd, buf.data() + old_size, rest, deadline);
    }

    return parse_frame_bytes(buf, session_key, nullptr);
}

// ---------------------------------------------------------------------------
// parse_frame_from_buffer (WS path)
// ---------------------------------------------------------------------------
FrameResult parse_frame_from_buffer(const uint8_t* data, size_t len,
                                    const std::array<uint8_t, 32>* session_key,
                                    size_t* consumed) {
    return parse_frame_bytes(std::vector<uint8_t>(data, data + len), session_key, consumed);
}

// ---------------------------------------------------------------------------
// read_frame (backward-compat — no MAC verification)
// ---------------------------------------------------------------------------
std::vector<uint8_t> read_frame(int fd) {
    return read_frame_full(fd, nullptr).payload;
}

} // namespace vynkor
