#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "vynkor/framing.hpp"

namespace vynkor {

// Parsed ws:// or wss:// URL (scheme, host, port defaults 80/443, path with a
// leading slash, at least "/").
struct WsUrl {
    bool        tls  = false;
    std::string host;
    uint16_t    port = 0;
    std::string path = "/";
};

// Throws VynkorInternal on a malformed URL or an unsupported scheme.
WsUrl parse_ws_url(const std::string& url);

// RFC 6455 client-to-server frame: FIN set, `opcode` (0x2 binary, 0x8 close,
// 0xA pong), payload masked with a fresh random key as the spec requires.
std::vector<uint8_t> ws_encode_client_frame(uint8_t opcode,
                                            const uint8_t* payload,
                                            size_t len);

struct WsIncomingFrame {
    bool                 fin    = true;
    uint8_t              opcode = 0;
    std::vector<uint8_t> payload;
};

// Decodes one server frame from the front of `buf`. Returns false when more
// bytes are needed; on success fills `out` and sets *consumed. Server frames
// are never masked (RFC 6455 §5.1); a masked server frame is rejected.
bool ws_try_decode_server_frame(const std::vector<uint8_t>& buf,
                                WsIncomingFrame* out,
                                size_t* consumed);

// Upper bound for one assembled WS application message (a wire frame is at
// most 44-byte header + 1 MiB payload + 32-byte tag; generous slack above).
static constexpr size_t WS_MAX_MESSAGE_SIZE = 4u * 1024u * 1024u;

// Minimal RFC 6455 WebSocket client connection over TCP (ws://) or TLS
// (wss://, OpenSSL). One Vynkor wire frame travels per binary WS message.
class WsConnection {
public:
    // Performs the opening handshake. `protocol` goes into the
    // Sec-WebSocket-Protocol header (the kernel gateway's handshake marker,
    // e.g. "vynkor" or "vynkor, <jwt>"); the 101 response's Upgrade and
    // Sec-WebSocket-Accept fields are validated. Throws VynkorIoError /
    // VynkorInternal on any handshake failure.
    static std::unique_ptr<WsConnection> connect(const WsUrl& url,
                                                 const std::string& protocol);
    ~WsConnection();

    WsConnection(const WsConnection&)            = delete;
    WsConnection& operator=(const WsConnection&) = delete;

    void send_binary(const uint8_t* data, size_t len);

    // Next application message assembled from binary (+continuation) frames.
    // Text frames are skipped, ping is auto-ponged; a Close frame or transport
    // failure throws VynkorIoError("websocket connection closed"/io message).
    std::vector<uint8_t> receive_binary();
    // Like receive_binary, but bounds the wait for underlying bytes by
    // `deadline` (throws VynkorTimeout when it passes first).
    std::vector<uint8_t> receive_binary_deadline(
        std::chrono::steady_clock::time_point deadline);

    // Best-effort close handshake + socket teardown (never throws).
    void close();

private:
    WsConnection() = default;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace vynkor
