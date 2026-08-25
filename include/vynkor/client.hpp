#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "vynkor/error.hpp"
#include "vynkor/framing.hpp"
#include "vynkor/mac.hpp"
#include "vynkor/ws.hpp"
#include "vynkor_protocol.pb.h"

namespace vynkor {

// Mirrors the kernel's inbound reassembly bounds (see src/ipc/connection.rs)
// and the rust/python SDKs' client-side reassembly (T-18).
static constexpr size_t MAX_REASSEMBLY_STREAMS = 64;
static constexpr std::chrono::seconds REASSEMBLY_TIMEOUT{30};

// Request timeout when a caller passes timeout_ms == 0 (kernel default, 30 s).
static constexpr std::chrono::milliseconds DEFAULT_REQUEST_TIMEOUT{30000};

class VynkorClient {
public:
    // secret: shared JWT secret for MAC key derivation.
    // Pass empty vector (default) to skip MAC — only valid with allow_no_auth:true kernels.
    explicit VynkorClient(std::string socket_path,
                          std::vector<uint8_t> secret = {});
    // Adopt an already-connected fd directly (tests, or a socket established
    // outside connect()). VynkorClient owns fd and closes it on destruction.
    explicit VynkorClient(int fd, std::vector<uint8_t> secret = {});
    ~VynkorClient();

    // Move-only: owns the connection. The moved-from client no longer closes it.
    VynkorClient(VynkorClient&& other) noexcept;
    VynkorClient& operator=(VynkorClient&& other) noexcept;
    VynkorClient(const VynkorClient&) = delete;
    VynkorClient& operator=(const VynkorClient&) = delete;

    // Static factories returning a connected client (Rust parity: VynkorClient::connect /
    // connect_with_secret / connect_from_env).
    static VynkorClient connect(const std::string& socket_path);
    static VynkorClient connect_with_secret(const std::string& socket_path,
                                            const std::vector<uint8_t>& secret);
    // Uses VYN_SOCKET_PATH (or the per-user default) and VYN_JWT_SECRET
    // (enables frame MACs when set).
    static VynkorClient connect_from_env();

    // Connect to the kernel's WebSocket gateway (D-05): `ws://host:port/ws`
    // or wss://. The client always offers the `vynkor` subprotocol; a
    // non-empty jwt_token is appended as `Sec-WebSocket-Protocol: vynkor,
    // <jwt>` — the gateway's only token channel (never put tokens in the
    // URL; they leak into access logs). Pass the same token to
    // register_full(). An empty `secret` disables frame MACs. Gateway limits
    // apply on this transport (R5-03): outbound frames are never compressed
    // and send_fragmented() is rejected; FLAG_RAW_BINARY passes unchanged.
    static VynkorClient connect_ws(const std::string& url,
                                   const std::string& jwt_token,
                                   const std::vector<uint8_t>& secret = {});

    // Member connect (the ctor(socket_path, secret) + connect() pattern).
    void connect();
    void close();

    // True once a secured registration has derived the per-connection MAC key.
    bool is_secured() const { return session_key_.has_value(); }

    // Underlying UDS file descriptor — used by run_concurrent_loop to poll
    // for readability while owning the client exclusively. Only valid on the
    // UDS transport; throws VynkorInternal over WebSocket.
    int native_handle() const;

    // ── Registration ─────────────────────────────────────────────────
    // Rust's `register` is a reserved C++ keyword, so the tokenless overload
    // keeps the `register_plugin` name. All three return the typed ack (Rust
    // parity — no raw Envelope).

    // Register without a JWT (unsecured kernel only). version "1.0.0".
    PluginRegisterAck register_plugin(const std::string& plugin_id,
                                      const PluginManifest& manifest);
    // Register presenting a JWT. On a secured kernel the ack carries a
    // session_nonce; combined with the shared secret and plugin id it yields
    // the frame-MAC key for all subsequent frames.
    PluginRegisterAck register_with_token(const std::string& plugin_id,
                                          const PluginManifest& manifest,
                                          const std::string& jwt_token);
    // Register with an explicit plugin version string.
    PluginRegisterAck register_full(const std::string& plugin_id,
                                    const std::string& version,
                                    const PluginManifest& manifest,
                                    const std::string& jwt_token);

    // ── Sending ──────────────────────────────────────────────────────
    void send(const std::string& target, const Envelope& env);
    void send_raw(const std::string& target, const std::vector<uint8_t>& payload);
    // Send a raw payload with explicit extra flags ORed into the frame header
    // (e.g. FLAG_RAW_BINARY). MAC and outbound compression are applied
    // automatically by the framing layer (compression on UDS only).
    void send_raw_with_flags(const std::string& target,
                             uint16_t extra_flags,
                             const std::vector<uint8_t>& payload);

    // Split `payload` into FLAG_FRAGMENTED frames of at most `chunk_size` data
    // bytes each and send them on a fresh stream id. The receiving side (kernel
    // or another VynkorClient) reassembles them into one logical frame. Bounds
    // mirror the kernel: total payload <= 1 MiB, <= 65535 fragments.
    // UDS only — the WS gateway rejects fragmented inbound frames (R5-03),
    // so this throws VynkorInternal on a WebSocket transport.
    void send_fragmented(const std::string& target,
                         const std::vector<uint8_t>& payload,
                         size_t chunk_size);

    // ── Receiving ────────────────────────────────────────────────────
    // Receive the next complete frame, transparently reassembling
    // FLAG_FRAGMENTED frames. Mirrors the rust/python SDKs' recv_frame.
    FrameResult recv_frame();
    // Receive and decode the next Envelope. Errors on raw-binary frames.
    Envelope recv();
    // recv() bounded by `timeout`; throws VynkorTimeout if nothing arrives.
    Envelope recv_timeout(std::chrono::milliseconds timeout);

    // ── Events ───────────────────────────────────────────────────────
    void subscribe(const std::vector<std::string>& event_types);
    void unsubscribe(const std::vector<std::string>& event_types);
    // Confirms an Event was received and handled — kernel stops retrying it.
    void ack_event(const std::string& event_id);

    // ── Kernel requests ──────────────────────────────────────────────
    // Publish an event to the kernel event bus. Requires PERMISSION_EVENT_PUBLISH.
    // timeout_ms == 0 uses the kernel default of 30s. The returned EventPublishAck
    // is returned as-is regardless of its status field — callers inspect
    // ack.status() themselves. Throws VynkorInternal on a kernel Error envelope,
    // VynkorTimeout on timeout.
    EventPublishAck publish_event(const std::string& event_type,
                                  const std::vector<uint8_t>& payload_json,
                                  uint32_t timeout_ms = 0);

    // Ask the kernel to perform an action and await its ActionResponse.
    // timeout_ms == 0 uses the kernel default of 30s. Throws VynkorInternal on a
    // kernel Error envelope or ActionStreamAbort for this action_id, VynkorTimeout
    // on timeout.
    ActionResponse send_action(const std::string& action,
                               const std::vector<uint8_t>& params_json,
                               uint32_t timeout_ms = 0);

    // Fire an ActionRequest with streaming=true and return its action_id
    // immediately — no wait. Caller drives send_request_chunk/recv/
    // close_session afterward.
    std::string send_action_streaming(const std::string& action, uint32_t timeout_ms = 0);

    // Fire-and-forget: one chunk of a streaming action's request body.
    void send_request_chunk(const std::string& action_id, uint32_t seq,
                            const std::vector<uint8_t>& chunk, bool is_final);
    // Fire-and-forget: one chunk of a streaming action's response body.
    void send_response_chunk(const std::string& action_id, uint32_t seq,
                             const std::vector<uint8_t>& chunk);
    // Fire-and-forget: tell the peer this action's session is done.
    void close_session(const std::string& action_id, const std::string& reason);

    // Send a KernelCommand and await its ack.
    KernelCommandAck send_command(const std::string& command_id,
                                  const std::string& command,
                                  const std::vector<uint8_t>& params_json);

    // Round-trip a Ping to the kernel; returns measured latency (Rust Duration
    // semantics — a duration, not a raw double).
    std::chrono::duration<double, std::milli> ping();

    // ── Audio ────────────────────────────────────────────────────────
    // Send an AudioStreamChunk (stream negotiation / Opus-over-envelope) to a
    // peer plugin. Requires PERMISSION_AUDIO_STREAM.
    void send_audio_chunk(const std::string& target, const AudioStreamChunk& chunk);
    // Send raw audio bytes (PCM_S16LE or Opus) with FLAG_RAW_BINARY; the router
    // skips Protobuf decode. Raw-binary payloads are never compressed.
    void send_raw_audio(const std::string& target, const std::vector<uint8_t>& data);

private:
    std::string                            socket_path_;
    int                                    fd_ = -1;
    std::unique_ptr<WsConnection>          ws_;
    std::vector<uint8_t>                   secret_;
    std::optional<std::array<uint8_t,32>>  session_key_;

    // In-flight fragment reassembly, keyed by stream_id. Mirrors the rust
    // SDK's ReassemblyBuf / client.rs absorb_fragment (T-18).
    struct ReassemblyBuf {
        std::unordered_map<uint16_t, std::vector<uint8_t>> fragments;
        uint16_t total = 0;
        uint16_t flags = 0;
        std::chrono::steady_clock::time_point first_seen;
        size_t buffered_bytes = 0;

        ReassemblyBuf(uint16_t total_, uint16_t flags_)
            : total(total_), flags(flags_), first_seen(std::chrono::steady_clock::now()) {}

        bool is_complete() const { return fragments.size() == total; }
        std::vector<uint8_t> reassemble() const {
            std::vector<uint8_t> out;
            out.reserve(buffered_bytes);
            for (uint16_t seq = 0; seq < total; ++seq) {
                const auto& chunk = fragments.at(seq);
                out.insert(out.end(), chunk.begin(), chunk.end());
            }
            return out;
        }
    };
    std::unordered_map<uint32_t, ReassemblyBuf> reassembly_;
    uint32_t next_stream_id_ = 1;

    // Buffer one fragment; returns the reassembled frame when the set is
    // complete. Throws on protocol/bound violations (mirrors absorb_fragment
    // in the rust/python SDKs).
    std::optional<FrameResult> absorb_fragment(FrameResult frame);

    // One raw wire frame off the active transport (UDS socket or WS message),
    // MAC-verified against the session key when secured.
    FrameResult read_transport_frame(std::chrono::steady_clock::time_point deadline);
    void write_all(const std::vector<uint8_t>& frame);
    void write_all_ws(const std::vector<uint8_t>& message);

    // Like recv_frame(), but bounds the total wait (including the first byte)
    // by deadline instead of the per-frame idle-forever default.
    FrameResult recv_frame_with_deadline(std::chrono::steady_clock::time_point deadline);

    // Loop recv_frame_with_deadline/parse until is_terminal(env) is true or
    // deadline passes. Shared by publish_event and send_action — each
    // supplies its own match/discard predicate.
    Envelope wait_for_response(std::chrono::steady_clock::time_point deadline,
                               const std::function<bool(const Envelope&)>& is_terminal);
};

} // namespace vynkor
