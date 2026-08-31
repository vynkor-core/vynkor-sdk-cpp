# vynkor-sdk-cpp

[![CI](https://github.com/vynkor-core/vynkor-sdk-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/vynkor-core/vynkor-sdk-cpp/actions/workflows/ci.yml)


C++ SDK for writing [vynkor](https://github.com/vynkor-core/vynkor) plugins.

A Vynkor plugin is a separate OS process supervised by the vynkor kernel. It
talks to the kernel over a Unix domain socket using the Vynkor wire protocol:
framed messages carrying Protobuf envelopes, with optional zstd compression,
HMAC-SHA256 frame authentication, and fragmentation.

The public API mirrors the [Rust reference SDK](https://crates.io/crates/vynkor-sdk)
one-for-one — `VynkorClient` matches `vynkor_sdk::VynkorClient`, and `Plugin`
matches the `vynkor_sdk::Plugin` trait (full parity; the `Plugin` callback model
is a breaking change from `0.1.0`).

## Protocol source

`proto/vynkor_protocol.proto` is vendored from
[`vynkor-wire`](https://crates.io/crates/vynkor-wire)'s `proto/` (wire
protocol **v1.6** as of the latest sync). It's copied by hand, not
path-referenced — re-sync it when the protocol changes upstream.

## Requirements

- CMake ≥ 3.20, C++17
- Protobuf, OpenSSL, Abseil, libzstd (pkg-config), GTest (for tests)

## Build

```bash
cmake -B build -S .
cmake --build build
ctest --test-dir build
```

## Quick start

```cpp
#include "vynkor/plugin.hpp"

class EchoPlugin : public vynkor::Plugin {
public:
    const std::string& id() const override { return id_; }

    vynkor::PluginManifest manifest() const override {
        vynkor::PluginManifest m;
        m.add_actions("echo");
        return m;
    }

    std::optional<vynkor::Envelope> on_message(const vynkor::Envelope& env) override {
        if (!env.has_action_request()) return std::nullopt;
        const auto& req = env.action_request();
        vynkor::Envelope out;
        auto* resp = out.mutable_action_response();
        resp->set_action_id(req.action_id());
        resp->set_status(vynkor::ActionStatus::ACTION_OK);
        resp->set_data_json(req.params_json());
        return out; // auto-sent to "kernel" by the SDK
    }

private:
    std::string id_ = "echo-plugin";
};

int main() {
    EchoPlugin plugin;
    plugin.run();
}
```

`Plugin::run` connects, registers, and serves until the kernel asks the plugin
to shut down. The SDK answers `Ping` automatically, acknowledges delivered
events after `on_event` returns normally, and exits the loop on
`PluginShutdown`.

### The `Plugin` model (Rust `Plugin` trait parity)

| Member | Default | Notes |
|--------|---------|-------|
| `virtual const std::string& id() const = 0` | — | **required**; the plugin id now comes from this override, not the constructor. |
| `virtual std::string version() const` | `"1.0.0"` | reported at registration. |
| `virtual PluginManifest manifest() const` | empty | permissions / actions / events / ipc_targets. |
| `virtual void on_init(VynkorClient&)` | no-op | called once after registration; the client is passed in. |
| `virtual std::optional<Envelope> on_message(const Envelope&) = 0` | — | **required**; return an envelope to auto-send it to `"kernel"`, `std::nullopt` to send nothing. Throwing is a fatal error (re-thrown after `on_shutdown`). |
| `virtual std::optional<Envelope> on_event(const Event&)` | `std::nullopt` | normal return auto-acks the event; throwing skips the ack (kernel retries). |
| `virtual void on_shutdown()` | no-op | runs when the loop ends. |

`run()` / `run_with(socket_path)` / `serve(client, jwt_token)` mirror Rust's
`Plugin::run` / `run_with` / `serve`. `serve` registers via
`register_full(id(), version(), manifest(), jwt_token)` and rejects a
non-accepted registration with `vynkorPermissionDenied`. The `client_` member
is a non-owning pointer to the served client, valid inside the callback methods
for plugins that send extra traffic (e.g. multi-message streaming replies).

## Environment

| Variable             | Meaning                                                        |
|----------------------|-----------------------------------------------------------------|
| `VYN_SOCKET_PATH` | Kernel UDS path. Default: `XDG_RUNTIME_DIR` → `/run/user/<uid>` → `~/.local/state/vyn/run` (never shared `/tmp`; the `~/.local/state/vyn/run` fallback is created with mode `0700`). |
| `VYN_JWT_TOKEN`   | JWT presented at registration (required on secured kernels).   |
| `VYN_JWT_SECRET`  | Shared secret; enables per-frame HMAC-SHA256 tags after registration. |

## Errors

`vynkorError` (in `vynkor/error.hpp`) is a typed exception hierarchy mirroring
Rust's `WireError` enum variant-for-variant. Every subclass derives from
`std::runtime_error`, so existing `catch (const std::runtime_error&)` and
`catch (...)` sites keep working while new code can discriminate:

| Exception | Rust variant |
|-----------|--------------|
| `vynkorIoError` | `WireError::Io` |
| `vynkorProtoError` | `WireError::Proto` |
| `vynkorFrameMagicMismatch` | `WireError::FrameMagicMismatch` |
| `vynkorFrameCrcMismatch` | `WireError::FrameCrcMismatch` |
| `vynkorFrameReadTimeout` | `WireError::FrameReadTimeout` |
| `vynkorPayloadTooLarge` | `WireError::PayloadTooLarge` |
| `vynkorTimeout` | `WireError::Timeout` |
| `vynkorPermissionDenied` | `WireError::PermissionDenied` |
| `vynkorInternal` | `WireError::Internal` |

## Client API

For lower-level control, use `VynkorClient` directly:

```cpp
#include "vynkor/client.hpp"

auto client = vynkor::VynkorClient::connect_with_secret(socket_path, secret);
auto ack = client.register_with_token("weather", manifest, jwt_token);
// Rust's `register` is a reserved C++ keyword; the tokenless overload is
// `register_plugin(plugin_id, manifest)` (version "1.0.0", no token).

client.subscribe({"alarm.fired"});
client.unsubscribe({"alarm.fired"});
auto pub_ack = client.publish_event("weather.updated",
                                     std::vector<uint8_t>{'{', '}'}, 5000);
auto latency = client.ping(); // std::chrono::duration<double, std::milli>

auto resp = client.send_action("get_weather", std::vector<uint8_t>{'{', '}'}, 5000);
auto cmd_ack = client.send_command("cmd-1", "health_check", {});

std::string action_id = client.send_action_streaming("transcribe", 30000);
client.send_request_chunk(action_id, 0, std::vector<uint8_t>{'h', 'i'}, true);
client.send_response_chunk(action_id, 0, std::vector<uint8_t>{'o', 'k'});
client.close_session(action_id, "done");

// raw / audio sends
client.send_raw("kernel", std::vector<uint8_t>{...});
client.send_audio_chunk("peer-plugin", chunk);
client.send_raw_audio("peer-plugin", std::vector<uint8_t>{...});
```

### Connecting

- `VynkorClient(socket_path, secret)` + member `connect()` — the primary ctor pattern.
- `VynkorClient::connect(socket_path)` / `connect_with_secret(socket_path, secret)` / `connect_from_env()` — static factories returning a connected client (Rust parity).
- `VynkorClient::connect_ws(url, jwt_token, secret = {})` — the kernel's WebSocket gateway (`ws://host:port/ws`, or `wss://`), for remote devices (D-05).
- `VynkorClient(fd, secret)` — adopt an already-connected fd (tests).
- `is_secured()` — true once a secured registration has derived the frame-MAC key.

### WebSocket transport (D-05)

`connect_ws` performs the RFC 6455 opening handshake with the gateway's
`Sec-WebSocket-Protocol: vynkor[, <jwt>]` marker (the token's only channel —
never put it in the URL). Registration and frame-MAC enablement mirror UDS
exactly; the differences are dictated by the gateway (R5-03): outbound frames
are never zstd-compressed and never fragmented (`send_fragmented` throws on
this transport), while `FLAG_RAW_BINARY` passes unchanged. One wire frame
travels per binary WebSocket message; control frames (ping/pong/text) are
handled transparently. On a dropped connection reconnect by calling
`connect_ws` again and re-registering — the session key is re-derived from
the fresh nonce in the new ack.

`Plugin::run_ws(url)` is the WS mirror of `run_with`: same
`VYN_JWT_TOKEN`/`VYN_JWT_SECRET` env credentials, token presented both in the
handshake header and in the registration envelope:

```cpp
EchoPlugin plugin;
plugin.run_ws("ws://kernel-host:8080/ws");
```

### Registration

`register_plugin(plugin_id, manifest)`, `register_with_token(plugin_id, manifest, jwt_token)`,
and `register_full(plugin_id, version, manifest, jwt_token)` all return the
typed `PluginRegisterAck` (no raw `Envelope`). On a secured kernel the ack's
`session_nonce` is combined with the shared secret and plugin id to derive the
per-frame MAC key automatically.

`publish_event` requires `PERMISSION_EVENT_PUBLISH`; `timeout_ms == 0` uses
the kernel's 30s default. It returns the kernel's `EventPublishAck` as-is —
inspect `ack.status()` yourself (`EVENT_PUBLISH_OK`/`ERROR`/`PERMISSION_DENY`)
— and only throws `vynkorInternal` on a kernel `Error` envelope or
`vynkorTimeout` on timeout. Requests and responses are matched on a single
connection; drive request/response traffic from one thread.

`send_action` follows the same `timeout_ms == 0` → 30s-default convention
and returns the kernel's `ActionResponse` as-is (inspect `.status()`
yourself). It throws `VynkorInternal` on a kernel `Error` envelope, on an
`ActionStreamAbort` for this `action_id`, or `VynkorTimeout` on timeout.
`send_action_streaming` fires an `ActionRequest{streaming: true}` and
returns its generated `action_id` immediately, without waiting for any
response — drive `recv()`/chunks yourself afterward. `send_request_chunk`,
`send_response_chunk`, and `close_session` are fire-and-forget sends (no
response awaited); `close_session` has no `final` flag — the response side
of a stream is terminated by an ordinary `ActionResponse`.

## Concurrent loop (`vynkor/concurrent.hpp`) — hot-path plugins

The default `Plugin::serve` loop is fully sequential: `recv()` →
`on_message()` → reply → next `recv()`. Correct for low-volume plugins
(`ai`, `tts`, `stt`), wrong for storage-class plugins where a slow request
would block every other caller. The concurrent loop mirrors the Rust SDK's
`ConcurrentHandler`:

- the loop owns the client exclusively; handler threads never touch it, so a
  replying handler can never deadlock against the parked `recv()`;
- each inbound `ActionRequest` is dispatched to its own thread — requests run
  concurrently and replies may go back out of order (the kernel matches on
  `action_id`);
- `accept(req)` is a pre-spawn gate — throw to reject immediately with an
  `ACTION_ERROR` carrying your message, without spawning anything;
- an exception inside `on_action` becomes an `ACTION_ERROR`
  ("handler panicked: ...") instead of a silently dropped reply.

```cpp
#include "vynkor/concurrent.hpp"

class DatabaseHandler : public vynkor::ConcurrentHandler {
public:
    const std::string& id() const override { return id_; }

    std::vector<vynkor::Envelope> on_action(const vynkor::ActionRequest& req) override {
        // slow query here — other requests keep flowing meanwhile
        return {vynkor::response_envelope(
            req.action_id(), vynkor::ActionResult::Ok(run_query(req.params_json())))};
    }

private:
    std::string id_ = "database";
};

int main() {
    auto client = vynkor::VynkorClient::connect_from_env();
    DatabaseHandler handler;
    vynkor::serve_concurrent(client, /*jwt_token=*/"", handler);
}
```

## Confirmation gate (`vynkor/confirmation_gate.hpp`, D-09)

Plugin-level permission separation for high-risk actions: one risky `op`
splits into `request_<op>` (any caller; params stored as pending) and
`confirm_<op>` (only allowlisted callers; executes the params stored at
request time — the confirming caller cannot swap in different arguments).
The kernel stays dumb; the gate keys on the kernel-stamped
`caller_plugin_id`, which cannot be spoofed.

```cpp
#include "vynkor/confirmation_gate.hpp"

// Provider side: build once, merge manifest entries, route in on_action /
// ConcurrentHandler::on_action.
vynkor::ConfirmationGate gate("transfer", "Move money between accounts",
                              R"({"type":"object"})",
                              vynkor::ACTION_RISK_CRITICAL, {"device.*"});
auto [actions, specs] = gate.manifest_entries();  // merge into PluginManifest

std::vector<vynkor::Envelope> replies = gate.route(
    req, [](const std::vector<uint8_t>& stored_params) { return execute(stored_params); });

// Caller side:
std::string pending_id = vynkor::send_confirmation_request(client, "transfer", params_json);
vynkor::ActionResponse resp = vynkor::send_confirmation(client, "transfer", pending_id);
```

Pending requests expire after `with_pending_ttl()` (default 5 minutes), so a
hostile caller cannot accumulate unbounded pending entries.

## Consuming via CMake

```cmake
find_package(vynkor-sdk REQUIRED)
target_link_libraries(my_plugin PRIVATE vynkor::sdk)
```

A `conanfile.py` is present in this directory, but the package is **not
published anywhere yet** — protocol vendoring and the wire-crate split are
still moving. For now, consume via:

- Git submodule + `add_subdirectory`, or
- local Conan use: `conan create .` against a private/local remote
  (Artifactory, self-hosted) — see `conanfile.py`.

### Packaging plan

1. **Now:** no public package. Recipe lives in-tree, iterate freely —
   version bumps cost nothing since there's no external review.
2. **Once stable** (proto + ABI settle, wire-crate split lands): publish
   to a real Conan remote for external consumers.
3. **Later, optionally:** submit the recipe to [ConanCenter
   Index](https://github.com/conan-io/conan-center-index). Each version
   there requires a fresh PR through their CI + human review, so it only
   pays off once the API stops churning.

## License

MIT
