#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include "vynkor/client.hpp"
#include "vynkor/env.hpp"

namespace vynkor {

// A Vynkor plugin, mirroring the Rust SDK's `Plugin` trait 1:1. Implement
// id(), manifest(), and on_message(); everything else has a sensible default.
//
// Lifecycle driven by run()/run_with()/serve():
//   1. connect to the kernel socket (VYN_SOCKET_PATH or the per-user default);
//   2. register, presenting VYN_JWT_TOKEN when set;
//   3. call on_init(client);
//   4. receive loop: Ping is answered automatically; PluginShutdown exits the
//      loop; Events go to on_event() and are auto-acked on normal return;
//      everything else goes to on_message(), whose returned envelope (if any)
//      is auto-sent to "kernel";
//   5. call on_shutdown().
class Plugin {
public:
    virtual ~Plugin() = default;

    // Unique plugin id, e.g. "weather". The id now comes from this override,
    // not from the constructor (Rust parity).
    virtual const std::string& id() const = 0;

    // Semver version reported at registration.
    virtual std::string version() const { return "1.0.0"; }

    // Declared capabilities: permissions, provided actions, event
    // subscriptions, IPC targets. Default is empty (mirrors the Rust SDK's
    // Plugin::manifest) — override to unlock IPC send / action-provider
    // routing, both of which the kernel default-denies on an empty manifest.
    virtual PluginManifest manifest() const { return PluginManifest{}; }

    // Called once after successful registration, before the receive loop.
    // Use the client to subscribe, negotiate audio streams, etc.
    virtual void on_init(VynkorClient& client) { (void)client; }

    // Called for every inbound envelope not handled by the SDK (Ping/Pong,
    // PluginShutdown and Event have dedicated handling). Return an envelope to
    // have it auto-sent to "kernel"; return std::nullopt to send nothing.
    // Throwing signals a fatal condition and ends the receive loop (the
    // exception is re-thrown out of serve() after on_shutdown() runs).
    virtual std::optional<Envelope> on_message(const Envelope& env) = 0;

    // Called for each delivered Event. A normal return makes the SDK send an
    // EventAck (kernel stops retrying) and auto-sends a returned envelope, if
    // any. Throwing skips the ack so the kernel retries (mirrors the Rust SDK).
    virtual std::optional<Envelope> on_event(const Event& event) {
        (void)event;
        return std::nullopt;
    }

    // Called once when the receive loop ends (kernel shutdown request,
    // disconnect, or handler error).
    virtual void on_shutdown() {}

    // Connect, register, and serve until shutdown. Socket path comes from
    // VYN_SOCKET_PATH, falling back to the same per-user resolution as the
    // kernel (XDG_RUNTIME_DIR → /run/user/{uid} → ~/.local/state/vyn/run). Never the
    // world-writable shared /tmp (BUG-006).
    void run() { run_with(default_socket_path()); }

    // run() against an explicit socket path. JWT credentials are still read
    // from VYN_JWT_TOKEN / VYN_JWT_SECRET when present.
    void run_with(const std::string& socket_path) {
        const std::string token = resolve_jwt_token("");
        const std::vector<uint8_t> secret = resolve_jwt_secret({});
        VynkorClient client(socket_path, secret);
        client.connect();
        serve(client, token);
    }

    // Connect to the kernel's WebSocket gateway (D-05) and serve until
    // shutdown — the WS mirror of run_with() for remote devices. JWT
    // credentials come from the same env vars as the UDS path; the token is
    // presented both in the Sec-WebSocket-Protocol handshake header and in
    // the registration envelope.
    void run_ws(const std::string& url) {
        const std::string token = resolve_jwt_token("");
        const std::vector<uint8_t> secret = resolve_jwt_secret({});
        VynkorClient client = VynkorClient::connect_ws(url, token, secret);
        serve(client, token);
    }

    // Register on an existing client and run the receive loop. Building block
    // for run(); also useful in tests.
    void serve(VynkorClient& client, const std::string& jwt_token) {
        client_ = &client;

        PluginRegisterAck ack = client.register_full(id(), version(), manifest(), jwt_token);
        if (!ack.accepted()) {
            client_ = nullptr;
            throw VynkorPermissionDenied("registration rejected: " + ack.reject_reason());
        }

        try {
            on_init(client);
        } catch (...) {
            on_shutdown();
            client_ = nullptr;
            throw;
        }

        // A handler error ends the receive loop (fatal condition), captured so
        // it propagates out of serve() after on_shutdown() runs instead of being
        // swallowed by the break — mirrors the Rust SDK (T-07).
        std::exception_ptr handler_err;
        while (true) {
            Envelope env;
            try {
                env = client.recv();
            } catch (...) {
                break; // disconnect / EOF
            }

            if (env.has_plugin_shutdown())
                break;

            if (env.has_ping()) {
                Envelope pong;
                pong.mutable_pong()->set_original_timestamp(env.ping().timestamp());
                pong.mutable_pong()->set_server_timestamp(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count());
                client.send("kernel", pong);
                continue;
            }

            if (env.has_event()) {
                const std::string event_id = env.event().event_id();
                // On handler error no ack is sent — the kernel will retry.
                try {
                    auto reply = on_event(env.event());
                    client.ack_event(event_id);
                    if (reply)
                        client.send("kernel", *reply);
                } catch (...) {
                }
                continue;
            }

            try {
                auto reply = on_message(env);
                if (reply)
                    client.send("kernel", *reply);
            } catch (...) {
                handler_err = std::current_exception();
                break;
            }
        }

        on_shutdown();
        client_ = nullptr;
        if (handler_err)
            std::rethrow_exception(handler_err);
    }

protected:
    // Non-owning view of the client being served. Set by serve() before
    // on_init and cleared after on_shutdown; valid inside on_init / on_message /
    // on_event / on_shutdown for plugins that need to send additional traffic
    // (e.g. multi-message streaming responses).
    VynkorClient* client_ = nullptr;
};

} // namespace vynkor
