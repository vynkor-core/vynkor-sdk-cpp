#include "vynkor/client.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstring>

#include "vynkor/env.hpp"

namespace vynkor {

namespace {
// Module-level counter, mirroring the rust SDK's free-function
// next_request_id("act") (not per-connection state).
std::atomic<uint64_t> g_action_seq{0};

std::string next_action_id() {
    const uint64_t seq = g_action_seq.fetch_add(1, std::memory_order_relaxed);
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return "act-" + std::to_string(now_ms) + "-" + std::to_string(seq);
}

uint64_t unix_millis() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}
} // namespace

VynkorClient::VynkorClient(std::string socket_path, std::vector<uint8_t> secret)
    : socket_path_(std::move(socket_path))
    , secret_(std::move(secret)) {}

VynkorClient::VynkorClient(int fd, std::vector<uint8_t> secret)
    : fd_(fd)
    , secret_(std::move(secret)) {}

VynkorClient::~VynkorClient() { close(); }

VynkorClient::VynkorClient(VynkorClient&& other) noexcept
    : socket_path_(std::move(other.socket_path_))
    , fd_(other.fd_)
    , ws_(std::move(other.ws_))
    , secret_(std::move(other.secret_))
    , session_key_(std::move(other.session_key_))
    , reassembly_(std::move(other.reassembly_))
    , next_stream_id_(other.next_stream_id_) {
    other.fd_ = -1;
}

VynkorClient& VynkorClient::operator=(VynkorClient&& other) noexcept {
    if (this != &other) {
        close();
        socket_path_ = std::move(other.socket_path_);
        fd_ = other.fd_;
        ws_ = std::move(other.ws_);
        secret_ = std::move(other.secret_);
        session_key_ = std::move(other.session_key_);
        reassembly_ = std::move(other.reassembly_);
        next_stream_id_ = other.next_stream_id_;
        other.fd_ = -1;
    }
    return *this;
}

VynkorClient VynkorClient::connect(const std::string& socket_path) {
    VynkorClient client(socket_path);
    client.connect();
    return client;
}

VynkorClient VynkorClient::connect_with_secret(const std::string& socket_path,
                                               const std::vector<uint8_t>& secret) {
    VynkorClient client(socket_path, secret);
    client.connect();
    return client;
}

VynkorClient VynkorClient::connect_from_env() {
    const std::string socket_path = default_socket_path();
    const std::vector<uint8_t> secret = resolve_jwt_secret({});
    if (!secret.empty())
        return connect_with_secret(socket_path, secret);
    return connect(socket_path);
}

VynkorClient VynkorClient::connect_ws(const std::string& url,
                                      const std::string& jwt_token,
                                      const std::vector<uint8_t>& secret) {
    const WsUrl parsed = parse_ws_url(url);
    // The `vynkor` subprotocol is the gateway's handshake marker; the JWT
    // rides along in the same header (never in the URL — access logs).
    const std::string protocol =
        jwt_token.empty() ? "vynkor" : "vynkor, " + jwt_token;
    VynkorClient client(std::string{}, secret);
    client.ws_ = WsConnection::connect(parsed, protocol);
    return client;
}

void VynkorClient::connect() {
    close();
    fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_ < 0)
        throw VynkorIoError("socket() failed");

    if (socket_path_.size() >= sizeof(sockaddr_un{}.sun_path)) {
        ::close(fd_);
        fd_ = -1;
        throw VynkorIoError("socket path too long: " + socket_path_);
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd_);
        fd_ = -1;
        throw VynkorIoError("connect() failed: " + socket_path_);
    }
}

void VynkorClient::close() {
    if (ws_) {
        ws_->close();
        ws_.reset();
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

int VynkorClient::native_handle() const {
    if (ws_ != nullptr)
        throw VynkorInternal("native_handle is only valid on the UDS transport");
    return fd_;
}

PluginRegisterAck VynkorClient::register_plugin(const std::string& plugin_id,
                                                const PluginManifest& manifest) {
    return register_with_token(plugin_id, manifest, "");
}

PluginRegisterAck VynkorClient::register_with_token(const std::string& plugin_id,
                                                    const PluginManifest& manifest,
                                                    const std::string& jwt_token) {
    return register_full(plugin_id, "1.0.0", manifest, jwt_token);
}

PluginRegisterAck VynkorClient::register_full(const std::string& plugin_id,
                                              const std::string& version,
                                              const PluginManifest& manifest,
                                              const std::string& jwt_token) {
    Envelope env;
    auto* reg = env.mutable_plugin_register();
    reg->set_plugin_id(plugin_id);
    reg->set_version(version);
    reg->set_jwt_token(jwt_token);
    *reg->mutable_manifest() = manifest;

    // Registration frame is always CRC-only; session_key not yet derived.
    send("kernel", env);
    Envelope ack = recv();

    if (ack.has_plugin_register_ack()) {
        if (!secret_.empty()) {
            const auto& nonce_str = ack.plugin_register_ack().session_nonce();
            if (!nonce_str.empty()) {
                std::vector<uint8_t> nonce(nonce_str.begin(), nonce_str.end());
                session_key_ = derive_session_key(secret_, nonce, plugin_id);
            }
        }
        return ack.plugin_register_ack();
    }
    if (ack.has_error()) {
        throw VynkorInternal("registration rejected: " + ack.error().message() +
                             " (" + ack.error().details() + ")");
    }
    throw VynkorInternal("expected PluginRegisterAck");
}

void VynkorClient::send(const std::string& target, const Envelope& env) {
    std::string bytes;
    env.SerializeToString(&bytes);
    send_raw(target, std::vector<uint8_t>(bytes.begin(), bytes.end()));
}

void VynkorClient::send_raw(const std::string& target, const std::vector<uint8_t>& payload) {
    send_raw_with_flags(target, 0, payload);
}

void VynkorClient::send_raw_with_flags(const std::string& target,
                                       uint16_t extra_flags,
                                       const std::vector<uint8_t>& payload) {
    const uint16_t base_flags = session_key_.has_value() ? FLAG_MAC_PRESENT : 0;
    const std::array<uint8_t, 32>* key_ptr =
        session_key_.has_value() ? &session_key_.value() : nullptr;
    const uint16_t flags = static_cast<uint16_t>(base_flags | extra_flags);

    if (ws_ != nullptr) {
        // R5-03: the gateway rejects FLAG_COMPRESSED inbound and does not
        // normalize before MAC verification — never auto-compress; a frame
        // is one WS binary message.
        if (payload.size() > MAX_PAYLOAD_SIZE)
            throw VynkorPayloadTooLarge(payload.size());
        write_all_ws(pack_frame_ws(target, flags, payload, key_ptr));
        return;
    }
    write_all(pack_frame_raw(target, flags, payload, key_ptr));
}

void VynkorClient::write_all_ws(const std::vector<uint8_t>& message) {
    ws_->send_binary(message.data(), message.size());
}

void VynkorClient::send_fragmented(const std::string& target,
                                   const std::vector<uint8_t>& payload,
                                   size_t chunk_size) {
    if (ws_ != nullptr)
        throw VynkorInternal("fragmented frames are not supported over WebSocket (R5-03)");
    if (payload.size() > MAX_PAYLOAD_SIZE)
        throw VynkorPayloadTooLarge(payload.size());
    if (chunk_size == 0 || chunk_size + FRAG_HEADER_SIZE > MAX_PAYLOAD_SIZE)
        throw VynkorInternal("invalid fragment chunk_size: " + std::to_string(chunk_size));

    size_t total = payload.empty() ? 1 : (payload.size() + chunk_size - 1) / chunk_size;
    if (total > 0xFFFF)
        throw VynkorInternal("payload needs " + std::to_string(total) + " fragments; max is 65535");

    const uint32_t stream_id = next_stream_id_;
    next_stream_id_ = next_stream_id_ + 1;
    if (next_stream_id_ == 0)
        next_stream_id_ = 1;
    const uint16_t fragment_id = static_cast<uint16_t>(stream_id & 0xFFFF);

    for (size_t seq = 0; seq < total; ++seq) {
        const size_t start = seq * chunk_size;
        const size_t len = std::min(chunk_size, payload.size() - start);

        std::vector<uint8_t> frag_payload =
            pack_frag_header(fragment_id, static_cast<uint16_t>(seq),
                             static_cast<uint16_t>(total), stream_id);
        frag_payload.insert(frag_payload.end(),
                            payload.begin() + start, payload.begin() + start + len);

        send_raw_with_flags(target, FLAG_FRAGMENTED, frag_payload);
    }
}

std::optional<FrameResult> VynkorClient::absorb_fragment(FrameResult frame) {
    // Prune stale sets first so an abandoned stream cannot pin memory.
    const auto now = std::chrono::steady_clock::now();
    for (auto it = reassembly_.begin(); it != reassembly_.end();) {
        if (now - it->second.first_seen >= REASSEMBLY_TIMEOUT)
            it = reassembly_.erase(it);
        else
            ++it;
    }

    auto hdr = parse_frag_header(frame.payload.data(), frame.payload.size());
    if (!hdr)
        throw VynkorInternal("fragment header too short");
    if (hdr->total == 0 || hdr->sequence >= hdr->total)
        throw VynkorInternal("invalid fragment header: seq " + std::to_string(hdr->sequence) +
                             " / total " + std::to_string(hdr->total));

    auto it = reassembly_.find(hdr->stream_id);
    if (it != reassembly_.end()) {
        if (it->second.total != hdr->total) {
            reassembly_.erase(it);
            throw VynkorInternal("fragment total mismatch within stream");
        }
    } else if (reassembly_.size() >= MAX_REASSEMBLY_STREAMS) {
        throw VynkorInternal("too many concurrent fragment streams");
    }

    auto emplaced = reassembly_.try_emplace(
        hdr->stream_id, hdr->total,
        static_cast<uint16_t>(frame.flags & ~(FLAG_FRAGMENTED | FLAG_MAC_PRESENT)));
    ReassemblyBuf& buf = emplaced.first->second;

    std::vector<uint8_t> chunk(frame.payload.begin() + FRAG_HEADER_SIZE, frame.payload.end());
    // A re-sent sequence replaces its old bytes; subtracting first keeps the
    // arithmetic underflow-free, matching the rust/python SDKs' accounting.
    size_t replaced_len = 0;
    auto fit = buf.fragments.find(hdr->sequence);
    if (fit != buf.fragments.end())
        replaced_len = fit->second.size();
    const size_t new_total = buf.buffered_bytes - replaced_len + chunk.size();
    if (new_total > MAX_PAYLOAD_SIZE) {
        reassembly_.erase(hdr->stream_id);
        throw VynkorPayloadTooLarge(MAX_PAYLOAD_SIZE + 1);
    }
    buf.buffered_bytes = new_total;
    buf.fragments[hdr->sequence] = std::move(chunk);

    if (buf.is_complete()) {
        FrameResult result;
        result.flags = buf.flags;
        result.payload = buf.reassemble();
        reassembly_.erase(hdr->stream_id);
        return result;
    }
    return std::nullopt;
}

FrameResult VynkorClient::read_transport_frame(std::chrono::steady_clock::time_point deadline) {
    const std::array<uint8_t,32>* key_ptr =
        session_key_.has_value() ? &session_key_.value() : nullptr;
    if (ws_ != nullptr) {
        std::vector<uint8_t> message = ws_->receive_binary_deadline(deadline);
        return parse_frame_from_buffer(message.data(), message.size(), key_ptr, nullptr);
    }
    if (deadline == std::chrono::steady_clock::time_point::max())
        return read_frame_full(fd_, key_ptr); // idle-forever default
    return read_frame_full_with_deadline(fd_, key_ptr, deadline);
}

FrameResult VynkorClient::recv_frame() {
    while (true) {
        auto frame = read_transport_frame(std::chrono::steady_clock::time_point::max());
        if (frame.flags & FLAG_FRAGMENTED) {
            auto complete = absorb_fragment(std::move(frame));
            if (!complete)
                continue;
            return std::move(*complete);
        }
        return frame;
    }
}

FrameResult VynkorClient::recv_frame_with_deadline(std::chrono::steady_clock::time_point deadline) {
    while (true) {
        auto frame = read_transport_frame(deadline);
        if (frame.flags & FLAG_FRAGMENTED) {
            auto complete = absorb_fragment(std::move(frame));
            if (!complete)
                continue;
            return std::move(*complete);
        }
        return frame;
    }
}

Envelope VynkorClient::recv() {
    auto result = recv_frame();
    if (result.flags & FLAG_RAW_BINARY)
        throw VynkorInternal("received raw-binary frame; use recv_frame() for audio");
    Envelope env;
    if (!env.ParseFromArray(result.payload.data(),
                            static_cast<int>(result.payload.size())))
        throw VynkorProtoError("protobuf parse failed");
    return env;
}

Envelope VynkorClient::recv_timeout(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    auto result = recv_frame_with_deadline(deadline);
    if (result.flags & FLAG_RAW_BINARY)
        throw VynkorInternal("received raw-binary frame; use recv_frame() for audio");
    Envelope env;
    if (!env.ParseFromArray(result.payload.data(),
                            static_cast<int>(result.payload.size())))
        throw VynkorProtoError("protobuf parse failed");
    return env;
}

void VynkorClient::subscribe(const std::vector<std::string>& event_types) {
    Envelope env;
    auto* sub = env.mutable_subscribe();
    for (const auto& t : event_types)
        sub->add_event_types(t);
    send("kernel", env);
}

void VynkorClient::unsubscribe(const std::vector<std::string>& event_types) {
    Envelope env;
    auto* un = env.mutable_unsubscribe();
    for (const auto& t : event_types)
        un->add_event_types(t);
    send("kernel", env);
}

void VynkorClient::ack_event(const std::string& event_id) {
    Envelope env;
    env.mutable_event_ack()->set_event_id(event_id);
    send("kernel", env);
}

Envelope VynkorClient::wait_for_response(std::chrono::steady_clock::time_point deadline,
                                         const std::function<bool(const Envelope&)>& is_terminal) {
    while (true) {
        auto frame = recv_frame_with_deadline(deadline);
        Envelope resp;
        if (!resp.ParseFromArray(frame.payload.data(), static_cast<int>(frame.payload.size())))
            throw VynkorProtoError("protobuf parse failed");
        if (is_terminal(resp))
            return resp;
        // unrelated traffic while waiting — discard, keep waiting
    }
}

EventPublishAck VynkorClient::publish_event(const std::string& event_type,
                                            const std::vector<uint8_t>& payload_json,
                                            uint32_t timeout_ms) {
    Envelope env;
    auto* pub = env.mutable_event_publish();
    pub->set_event_type(event_type);
    pub->set_payload_json(payload_json.data(), payload_json.size());
    send("kernel", env);

    const auto timeout = timeout_ms == 0 ? DEFAULT_REQUEST_TIMEOUT
                                         : std::chrono::milliseconds(timeout_ms);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    Envelope resp = wait_for_response(deadline, [](const Envelope& e) {
        return e.has_event_publish_ack() || e.has_error();
    });
    if (resp.has_error())
        throw VynkorInternal("kernel error: " + resp.error().message() +
                             " (" + resp.error().details() + ")");
    return resp.event_publish_ack();
}

ActionResponse VynkorClient::send_action(const std::string& action,
                                         const std::vector<uint8_t>& params_json,
                                         uint32_t timeout_ms) {
    const std::string action_id = next_action_id();
    Envelope env;
    auto* req = env.mutable_action_request();
    req->set_action_id(action_id);
    req->set_action(action);
    req->set_params_json(params_json.data(), params_json.size());
    req->set_timeout_ms(timeout_ms);
    req->set_streaming(false);
    send("kernel", env);

    const auto timeout = timeout_ms == 0 ? DEFAULT_REQUEST_TIMEOUT
                                         : std::chrono::milliseconds(timeout_ms);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    Envelope resp = wait_for_response(deadline, [&](const Envelope& e) {
        return (e.has_action_response() && e.action_response().action_id() == action_id) ||
               (e.has_action_stream_abort() && e.action_stream_abort().action_id() == action_id) ||
               e.has_error();
    });
    if (resp.has_error())
        throw VynkorInternal("kernel error: " + resp.error().message() +
                             " (" + resp.error().details() + ")");
    if (resp.has_action_stream_abort())
        throw VynkorInternal("stream aborted: " + resp.action_stream_abort().reason());
    return resp.action_response();
}

std::string VynkorClient::send_action_streaming(const std::string& action, uint32_t timeout_ms) {
    const std::string action_id = next_action_id();
    Envelope env;
    auto* req = env.mutable_action_request();
    req->set_action_id(action_id);
    req->set_action(action);
    req->set_timeout_ms(timeout_ms);
    req->set_streaming(true);
    send("kernel", env);
    return action_id;
}

void VynkorClient::send_request_chunk(const std::string& action_id, uint32_t seq,
                                      const std::vector<uint8_t>& chunk, bool is_final) {
    Envelope env;
    auto* c = env.mutable_action_request_chunk();
    c->set_action_id(action_id);
    c->set_seq(seq);
    c->set_chunk(chunk.data(), chunk.size());
    c->set_final(is_final);
    send("kernel", env);
}

void VynkorClient::send_response_chunk(const std::string& action_id, uint32_t seq,
                                       const std::vector<uint8_t>& chunk) {
    Envelope env;
    auto* c = env.mutable_action_response_chunk();
    c->set_action_id(action_id);
    c->set_seq(seq);
    c->set_chunk(chunk.data(), chunk.size());
    send("kernel", env);
}

void VynkorClient::close_session(const std::string& action_id, const std::string& reason) {
    Envelope env;
    auto* sc = env.mutable_session_close();
    sc->set_action_id(action_id);
    sc->set_reason(reason);
    send("kernel", env);
}

KernelCommandAck VynkorClient::send_command(const std::string& command_id,
                                            const std::string& command,
                                            const std::vector<uint8_t>& params_json) {
    Envelope env;
    auto* kc = env.mutable_kernel_command();
    kc->set_command_id(command_id);
    kc->set_command(command);
    kc->set_params_json(params_json.data(), params_json.size());
    send("kernel", env);

    Envelope resp = recv();
    if (!resp.has_kernel_command_ack())
        throw VynkorInternal("expected KernelCommandAck");
    return resp.kernel_command_ack();
}

std::chrono::duration<double, std::milli> VynkorClient::ping() {
    Envelope env;
    env.mutable_ping()->set_timestamp(unix_millis());

    const auto t0 = std::chrono::steady_clock::now();
    send("kernel", env);
    Envelope resp = recv();
    if (!resp.has_pong())
        throw VynkorInternal("expected Pong");
    return std::chrono::steady_clock::now() - t0;
}

void VynkorClient::send_audio_chunk(const std::string& target, const AudioStreamChunk& chunk) {
    Envelope env;
    *env.mutable_audio_stream_chunk() = chunk;
    send(target, env);
}

void VynkorClient::send_raw_audio(const std::string& target, const std::vector<uint8_t>& data) {
    send_raw_with_flags(target, FLAG_RAW_BINARY, data);
}

void VynkorClient::write_all(const std::vector<uint8_t>& frame) {
    const uint8_t* ptr = frame.data();
    size_t remaining   = frame.size();
    while (remaining > 0) {
        ssize_t written = ::write(fd_, ptr, remaining);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            throw VynkorIoError("write() failed");
        ptr       += written;
        remaining -= static_cast<size_t>(written);
    }
}

} // namespace vynkor
