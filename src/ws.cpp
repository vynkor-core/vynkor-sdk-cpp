#include "vynkor/ws.hpp"

#include <endian.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <limits>
#include <sstream>

#include "vynkor/error.hpp"

namespace vynkor {

namespace {

constexpr uint8_t OP_CONT      = 0x0;
constexpr uint8_t OP_TEXT      = 0x1;
constexpr uint8_t OP_BINARY    = 0x2;
constexpr uint8_t OP_CLOSE     = 0x8;
constexpr uint8_t OP_PING      = 0x9;
constexpr uint8_t OP_PONG      = 0xA;

const char kWsGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

std::string base64_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.resize(4 * ((len + 2) / 3) + 1);
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                  data, static_cast<int>(len));
    out.resize(static_cast<size_t>(n));
    return out;
}

std::string sha1_base64(const std::string& input) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_Digest(input.data(), input.size(), digest, &digest_len, EVP_sha1(), nullptr) != 1)
        throw VynkorInternal("EVP_Digest(SHA-1) failed");
    return base64_encode(digest, digest_len);
}

[[noreturn]] void throw_ws_io(const std::string& what) {
    unsigned long code = ERR_peek_last_error();
    if (code != 0) {
        const char* msg = ERR_reason_error_string(code);
        if (msg != nullptr)
            throw VynkorIoError(what + ": " + msg);
    }
    throw VynkorIoError(what);
}

bool iequal(const std::string& a, const std::string& b) {
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

} // namespace

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------
WsUrl parse_ws_url(const std::string& url) {
    WsUrl out;

    const std::string ws_scheme = "ws://";
    const std::string wss_scheme = "wss://";
    std::string rest;
    if (url.rfind(ws_scheme, 0) == 0) {
        out.tls = false;
        rest = url.substr(ws_scheme.size());
    } else if (url.rfind(wss_scheme, 0) == 0) {
        out.tls = true;
        rest = url.substr(wss_scheme.size());
    } else {
        throw VynkorInternal("invalid ws url: scheme must be ws:// or wss://");
    }

    const auto slash = rest.find('/');
    const std::string authority =
        slash == std::string::npos ? rest : rest.substr(0, slash);
    out.path = slash == std::string::npos ? "/" : rest.substr(slash);

    std::string hostport = authority;
    if (!hostport.empty() && hostport.front() == '[') {
        // [ipv6-literal]:port
        const auto close_bracket = hostport.find(']');
        if (close_bracket == std::string::npos)
            throw VynkorInternal("invalid ws url: unterminated IPv6 literal");
        out.host = hostport.substr(1, close_bracket - 1);
        if (close_bracket + 1 < hostport.size()) {
            if (hostport[close_bracket + 1] != ':')
                throw VynkorInternal("invalid ws url: bad text after IPv6 literal");
            out.port = static_cast<uint16_t>(std::stoi(hostport.substr(close_bracket + 2)));
        }
    } else {
        const auto colon = hostport.rfind(':');
        if (colon != std::string::npos && colon != 0) {
            out.port = static_cast<uint16_t>(std::stoi(hostport.substr(colon + 1)));
            hostport.resize(colon);
        }
        out.host = hostport;
    }

    if (out.host.empty())
        throw VynkorInternal("invalid ws url: missing host");
    if (out.port == 0)
        out.port = out.tls ? 443 : 80;
    if (out.path.empty())
        out.path = "/";
    return out;
}

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------
std::vector<uint8_t> ws_encode_client_frame(uint8_t opcode,
                                            const uint8_t* payload,
                                            size_t len) {
    std::vector<uint8_t> frame;
    frame.reserve(2 + 4 + len);
    frame.push_back(static_cast<uint8_t>(0x80 | opcode));

    std::array<uint8_t, 4> mask{};
    if (RAND_bytes(mask.data(), 4) != 1)
        throw VynkorInternal("RAND_bytes failed");

    if (len < 126) {
        frame.push_back(static_cast<uint8_t>(0x80 | len));
    } else if (len <= 0xFFFF) {
        frame.push_back(static_cast<uint8_t>(0x80 | 126));
        const uint16_t be = htons(static_cast<uint16_t>(len));
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&be),
                     reinterpret_cast<const uint8_t*>(&be) + 2);
    } else {
        frame.push_back(static_cast<uint8_t>(0x80 | 127));
        const uint64_t be = htobe64(static_cast<uint64_t>(len));
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&be),
                     reinterpret_cast<const uint8_t*>(&be) + 8);
    }
    frame.insert(frame.end(), mask.begin(), mask.end());
    for (size_t i = 0; i < len; ++i)
        frame.push_back(payload[i] ^ mask[i % 4]);
    return frame;
}

bool ws_try_decode_server_frame(const std::vector<uint8_t>& buf,
                                WsIncomingFrame* out,
                                size_t* consumed) {
    if (buf.size() < 2)
        return false;
    const bool fin  = (buf[0] & 0x80) != 0;
    const uint8_t opcode = buf[0] & 0x0F;
    const bool masked = (buf[1] & 0x80) != 0;
    uint64_t len = buf[1] & 0x7F;
    size_t offset = 2;

    if (masked)
        throw VynkorInternal("websocket: server sent a masked frame");

    if (len == 126) {
        if (buf.size() < offset + 2)
            return false;
        uint16_t be;
        std::memcpy(&be, buf.data() + offset, 2);
        len = ntohs(be);
        offset += 2;
    } else if (len == 127) {
        if (buf.size() < offset + 8)
            return false;
        uint64_t be;
        std::memcpy(&be, buf.data() + offset, 8);
        len = be64toh(be);
        offset += 8;
    }

    if (len > WS_MAX_MESSAGE_SIZE)
        throw VynkorPayloadTooLarge(static_cast<size_t>(len));
    if (buf.size() < offset + len)
        return false;

    out->fin = fin;
    out->opcode = opcode;
    out->payload.assign(buf.begin() + static_cast<long>(offset),
                        buf.begin() + static_cast<long>(offset + len));
    *consumed = offset + static_cast<size_t>(len);
    return true;
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------
struct WsConnection::Impl {
    int fd = -1;
    SSL_CTX* ssl_ctx = nullptr;
    SSL* ssl = nullptr;
    std::vector<uint8_t> read_buf;

    bool tls_active() const { return ssl != nullptr; }

    void stream_write_all(const uint8_t* data, size_t len) {
        size_t total = 0;
        while (total < len) {
            ssize_t n;
            if (tls_active()) {
                const int r = SSL_write(ssl, data + total,
                                        static_cast<int>(len - total));
                if (r <= 0) {
                    const int err = SSL_get_error(ssl, r);
                    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                        wait_writable();
                        continue;
                    }
                    throw_ws_io("websocket send failed");
                }
                n = r;
            } else {
                n = ::write(fd, data + total, len - total);
                if (n < 0 && errno == EINTR)
                    continue;
                if (n <= 0)
                    throw VynkorIoError("websocket send failed: write()");
            }
            total += static_cast<size_t>(n);
        }
    }

    // Reads more bytes into the underlying buffer; blocks until at least one
    // byte arrives or `deadline` passes (throws VynkorTimeout).
    void stream_fill(std::chrono::steady_clock::time_point deadline) {
        uint8_t chunk[4096];
        ssize_t n;
        while (true) {
            if (tls_active()) {
                if (SSL_pending(ssl) == 0)
                    poll_readable(deadline);
                const int r = SSL_read(ssl, chunk, sizeof(chunk));
                if (r > 0) {
                    n = r;
                    break;
                }
                const int err = SSL_get_error(ssl, r);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue; // polled again on the next iteration
                if (err == SSL_ERROR_ZERO_RETURN)
                    throw VynkorIoError("websocket connection closed");
                throw_ws_io("websocket read failed");
            } else {
                poll_readable(deadline);
                n = ::read(fd, chunk, sizeof(chunk));
                if (n < 0 && errno == EINTR)
                    continue;
                break;
            }
        }
        if (n <= 0)
            throw VynkorIoError("websocket connection closed");
        read_buf.insert(read_buf.end(), chunk, chunk + n);
    }

    void poll_readable(std::chrono::steady_clock::time_point deadline) {
        while (true) {
            const auto now = std::chrono::steady_clock::now();
            int remaining_ms;
            if (deadline == std::chrono::steady_clock::time_point::max()) {
                remaining_ms = -1; // block indefinitely
            } else {
                if (now >= deadline)
                    throw VynkorTimeout();
                remaining_ms = static_cast<int>(std::min<long>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count(),
                    std::numeric_limits<int>::max()));
            }

            struct pollfd pfd {};
            pfd.fd = fd;
            pfd.events = POLLIN;
            const int pr = ::poll(&pfd, 1, remaining_ms);
            if (pr < 0) {
                if (errno == EINTR)
                    continue;
                throw VynkorIoError("websocket poll failed");
            }
            if (pr == 0 && remaining_ms >= 0)
                throw VynkorTimeout();
            return;
        }
    }

    void wait_writable() {
        struct pollfd pfd {};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        ::poll(&pfd, 1, 5000);
    }

    void teardown() noexcept {
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (ssl_ctx != nullptr) {
            SSL_CTX_free(ssl_ctx);
            ssl_ctx = nullptr;
        }
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }
};

std::unique_ptr<WsConnection> WsConnection::connect(const WsUrl& url,
                                                    const std::string& protocol) {
    std::unique_ptr<WsConnection> conn(new WsConnection());
    conn->impl_ = std::make_unique<Impl>();
    Impl& impl = *conn->impl_;

    // ── TCP connect ─────────────────────────────────────────────────────
    std::string port_str = std::to_string(url.port);
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* result = nullptr;
    const int gai = ::getaddrinfo(url.host.c_str(), port_str.c_str(), &hints, &result);
    if (gai != 0)
        throw VynkorIoError("websocket connect: getaddrinfo failed for " + url.host);

    int last_errno = 0;
    for (struct addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
        impl.fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (impl.fd < 0) {
            last_errno = errno;
            continue;
        }
        if (::connect(impl.fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            last_errno = 0;
            break;
        }
        last_errno = errno;
        ::close(impl.fd);
        impl.fd = -1;
    }
    ::freeaddrinfo(result);
    if (impl.fd < 0)
        throw VynkorIoError("websocket connect failed: " + url.host + ":" + port_str +
                            (last_errno != 0 ? " (" + std::string(strerror(last_errno)) + ")" : ""));

    // ── TLS handshake ───────────────────────────────────────────────────
    if (url.tls) {
        impl.ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (impl.ssl_ctx == nullptr)
            throw_ws_io("SSL_CTX_new failed");
        SSL_CTX_set_verify(impl.ssl_ctx, SSL_VERIFY_PEER, nullptr);
        if (SSL_CTX_set_default_verify_paths(impl.ssl_ctx) != 1)
            throw_ws_io("SSL_CTX_set_default_verify_paths failed");
        impl.ssl = SSL_new(impl.ssl_ctx);
        if (impl.ssl == nullptr)
            throw_ws_io("SSL_new failed");
        SSL_set_fd(impl.ssl, impl.fd);
        SSL_set_tlsext_host_name(impl.ssl, url.host.c_str());
        if (SSL_connect(impl.ssl) != 1)
            throw_ws_io("TLS handshake failed with " + url.host);
    }

    // ── Opening handshake (RFC 6455 §4.1) ───────────────────────────────
    std::array<unsigned char, 16> nonce{};
    if (RAND_bytes(nonce.data(), 16) != 1)
        throw VynkorInternal("RAND_bytes failed");
    const std::string key = base64_encode(nonce.data(), nonce.size());

    std::string request;
    request.reserve(256 + protocol.size());
    request += "GET " + url.path + " HTTP/1.1\r\n";
    request += "Host: " + url.host + ":" + port_str + "\r\n";
    request += "Upgrade: websocket\r\n";
    request += "Connection: Upgrade\r\n";
    request += "Sec-WebSocket-Key: " + key + "\r\n";
    request += "Sec-WebSocket-Version: 13\r\n";
    if (!protocol.empty())
        request += "Sec-WebSocket-Protocol: " + protocol + "\r\n";
    request += "\r\n";
    impl.stream_write_all(reinterpret_cast<const uint8_t*>(request.data()), request.size());

    // Read the response head.
    constexpr size_t kMaxHead = 16384;
    static const std::string marker = "\r\n\r\n";
    const auto find_head_end = [&] {
        const auto it = std::search(impl.read_buf.begin(), impl.read_buf.end(),
                                    marker.begin(), marker.end());
        return it == impl.read_buf.end()
                   ? std::string::npos
                   : static_cast<size_t>(it - impl.read_buf.begin());
    };
    size_t head_end = find_head_end();
    while (head_end == std::string::npos) {
        if (impl.read_buf.size() > kMaxHead)
            throw VynkorInternal("websocket handshake response too large");
        impl.stream_fill(std::chrono::steady_clock::now() + std::chrono::seconds(30));
        head_end = find_head_end();
    }

    const std::string head(impl.read_buf.begin(),
                           impl.read_buf.begin() + static_cast<long>(head_end));
    impl.read_buf.erase(impl.read_buf.begin(),
                        impl.read_buf.begin() + static_cast<long>(head_end + marker.size()));

    std::istringstream lines(head);
    std::string status_line;
    std::getline(lines, status_line);
    if (status_line.find(" 101 ") == std::string::npos &&
        status_line.rfind("HTTP/1.1 101", 0) != 0)
        throw VynkorInternal("websocket handshake rejected: " + status_line);

    const std::string expected_accept = sha1_base64(key + kWsGuid);
    bool saw_upgrade = false;
    bool accept_ok = false;
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        const auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        const auto trim = [](std::string& s) {
            const auto first = s.find_first_not_of(" \t");
            const auto last = s.find_last_not_of(" \t");
            s = first == std::string::npos ? "" : s.substr(first, last - first + 1);
        };
        trim(name);
        trim(value);
        if (iequal(name, "upgrade") && iequal(value, "websocket"))
            saw_upgrade = true;
        if (iequal(name, "sec-websocket-accept") && value == expected_accept)
            accept_ok = true;
    }
    if (!saw_upgrade)
        throw VynkorInternal("websocket handshake: missing Upgrade header");
    if (!accept_ok)
        throw VynkorInternal("websocket handshake: Sec-WebSocket-Accept mismatch");

    return conn;
}

WsConnection::~WsConnection() {
    if (impl_)
        impl_->teardown();
}

void WsConnection::send_binary(const uint8_t* data, size_t len) {
    std::vector<uint8_t> frame = ws_encode_client_frame(OP_BINARY, data, len);
    impl_->stream_write_all(frame.data(), frame.size());
}

std::vector<uint8_t> WsConnection::receive_binary() {
    return receive_binary_deadline(std::chrono::steady_clock::time_point::max());
}

std::vector<uint8_t> WsConnection::receive_binary_deadline(
    std::chrono::steady_clock::time_point deadline) {
    Impl& impl = *impl_;
    std::vector<uint8_t> message;
    bool in_message = false;

    while (true) {
        WsIncomingFrame frame;
        size_t consumed = 0;
        while (!ws_try_decode_server_frame(impl.read_buf, &frame, &consumed)) {
            if (impl.read_buf.size() > WS_MAX_MESSAGE_SIZE)
                throw VynkorPayloadTooLarge(WS_MAX_MESSAGE_SIZE + 1);
            impl.stream_fill(deadline);
        }
        impl.read_buf.erase(impl.read_buf.begin(),
                            impl.read_buf.begin() + static_cast<long>(consumed));

        switch (frame.opcode) {
        case OP_BINARY:
            if (in_message)
                throw VynkorInternal("websocket: unexpected binary fragment start");
            in_message = !frame.fin;
            message = std::move(frame.payload);
            if (!in_message)
                return message;
            break;
        case OP_CONT:
            if (!in_message)
                throw VynkorInternal("websocket: continuation without a started message");
            message.insert(message.end(), frame.payload.begin(), frame.payload.end());
            if (message.size() > WS_MAX_MESSAGE_SIZE)
                throw VynkorPayloadTooLarge(message.size());
            if (frame.fin) {
                in_message = false;
                return message;
            }
            break;
        case OP_TEXT:
            // The gateway never sends text as traffic — skip it.
            break;
        case OP_PING: {
            std::vector<uint8_t> pong =
                ws_encode_client_frame(OP_PONG, frame.payload.data(), frame.payload.size());
            impl.stream_write_all(pong.data(), pong.size());
            break;
        }
        case OP_PONG:
            break;
        case OP_CLOSE:
            try {
                std::vector<uint8_t> close_reply =
                    ws_encode_client_frame(OP_CLOSE, frame.payload.data(),
                                           std::min<size_t>(frame.payload.size(), 125));
                impl.stream_write_all(close_reply.data(), close_reply.size());
            } catch (...) {
            }
            throw VynkorIoError("websocket connection closed");
        default:
            throw VynkorInternal("websocket: unknown opcode " + std::to_string(frame.opcode));
        }
    }
}

void WsConnection::close() {
    if (!impl_)
        return;
    try {
        std::vector<uint8_t> close_frame = ws_encode_client_frame(OP_CLOSE, nullptr, 0);
        impl_->stream_write_all(close_frame.data(), close_frame.size());
    } catch (...) {
    }
    impl_->teardown();
}

} // namespace vynkor
