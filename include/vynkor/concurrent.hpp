#pragma once

#include <optional>
#include <string>
#include <vector>

#include "vynkor/client.hpp"
#include "vynkor_protocol.pb.h"

namespace vynkor {

// Outcome of one action execution — the C++ shape of Rust's
// Result<Vec<u8>, String> in response_envelope.
struct ActionResult {
    bool                 ok        = false;
    std::vector<uint8_t> data_json;
    std::string          error;

    static ActionResult Ok(std::vector<uint8_t> data) {
        ActionResult r;
        r.ok = true;
        r.data_json = std::move(data);
        return r;
    }
    static ActionResult Err(std::string message) {
        ActionResult r;
        r.error = std::move(message);
        return r;
    }
};

// Build the response envelope for a completed (or failed) action.
Envelope response_envelope(const std::string& action_id, const ActionResult& result);

// Handler for a plugin driven by the concurrent message loop.
//
// Unlike Plugin, on_action runs on its own thread per inbound request while
// the loop keeps receiving, so replies may go back out of order (the kernel
// matches on action_id). Implementations must be safe to call concurrently
// from multiple threads and share interior state behind a mutex.
//
// Registration metadata (id/version/manifest) lives on the handler so
// serve_concurrent can perform registration itself.
class ConcurrentHandler {
public:
    virtual ~ConcurrentHandler() = default;

    // Unique plugin id, e.g. "database".
    virtual const std::string& id() const = 0;

    // Semver version reported at registration.
    virtual std::string version() const { return "1.0.0"; }

    // Declared capabilities: permissions, actions, event subscriptions.
    virtual PluginManifest manifest() const { return PluginManifest{}; }

    // Called once after successful registration, before the receive loop.
    virtual void on_init(VynkorClient& client) { (void)client; }

    // Pre-spawn gate, run in the loop before a handler thread is spawned for
    // `req`. Throw (e.g. VynkorInternal) to reject the request immediately
    // with an ACTION_ERROR reply carrying the exception message — no handler
    // thread is spawned. Keep this cheap; it runs on the loop's critical path.
    // The default accepts everything.
    virtual void accept(const ActionRequest& req) { (void)req; }

    // Handle one inbound ActionRequest on a dedicated thread. Return the
    // reply envelope(s) to send back to the kernel — usually exactly one
    // ActionResponse (use response_envelope), but more are allowed as
    // best-effort traffic (e.g. an event publish sent after the response).
    // Throwing here becomes an ACTION_ERROR reply for this request's
    // action_id ("handler panicked: ..."), so no reply is ever dropped.
    virtual std::vector<Envelope> on_action(const ActionRequest& req) = 0;

    // Called for each delivered Event. Normal return makes the loop send an
    // EventAck so the kernel stops retrying; a returned envelope is sent as
    // additional traffic. Throwing skips the ack (kernel retries).
    virtual std::optional<Envelope> on_event(const Event& event) {
        (void)event;
        return std::nullopt;
    }

    // Called for any inbound envelope the loop does not handle itself (Ping,
    // PluginShutdown, ActionRequest and Event are consumed by the loop).
    // Return an envelope to send, or nullopt. A throw is swallowed and the
    // message dropped (mirrors the rust loop's `if let Ok(Some(reply))`).
    virtual std::optional<Envelope> on_message(const Envelope& env) {
        (void)env;
        return std::nullopt;
    }

    // Called by serve_concurrent after the loop ends (kernel shutdown request
    // or disconnect) and all outstanding handler threads have been joined.
    // run_concurrent_loop alone does not invoke it.
    virtual void on_shutdown() {}
};

// Register `handler` with the kernel, run on_init, then drive the concurrent
// message loop until shutdown. Wraps run_concurrent_loop with registration;
// jwt_token is presented at registration (empty string on unsecured kernels).
// A rejected registration throws VynkorPermissionDenied. An exception out of
// on_init runs on_shutdown and propagates.
void serve_concurrent(VynkorClient& client,
                      const std::string& jwt_token,
                      ConcurrentHandler& handler);

// Drive the concurrent message loop to completion (disconnect/EOF or an
// explicit PluginShutdown). `client` is owned exclusively by this call — the
// loop polls its fd between inbound frames and completed responses pushed by
// handler threads; handler threads never touch the client, so no lock is held
// around it. Blocks until the loop ends and all handler threads finish.
void run_concurrent_loop(VynkorClient& client, ConcurrentHandler& handler);

} // namespace vynkor
