# veyron-sdk (C++)

C++ SDK for writing [Veyron](https://github.com/veyron-core/vynkor) plugins.

A Veyron plugin is a separate OS process supervised by the Veyron kernel. It
talks to the kernel over a Unix domain socket using the Veyron wire protocol:
framed messages carrying Protobuf envelopes, with optional zstd compression,
HMAC-SHA256 frame authentication, and fragmentation.

The public API mirrors the [Rust reference SDK](https://crates.io/crates/veyron-sdk)
one-for-one — `VeyronClient` matches `veyron_sdk::VeyronClient`, and `Plugin`
matches the `veyron_sdk::Plugin` trait (full parity; the `Plugin` callback model
is a breaking change from `0.1.0`).

## Protocol source

`proto/vynkor_protocol.proto` is vendored from
[`veyron-wire`](https://crates.io/crates/veyron-wire)'s `proto/` (wire
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
| `virtual void on_init(VeyronClient&)` | no-op | called once after registration; the client is passed in. |
| `virtual std::optional<Envelope> on_message(const Envelope&) = 0` | — | **required**; return an envelope to auto-send it to `"kernel"`, `std::nullopt` to send nothing. Throwing is a fatal error (re-thrown after `on_shutdown`). |
| `virtual std::optional<Envelope> on_event(const Event&)` | `std::nullopt` | normal return auto-acks the event; throwing skips the ack (kernel retries). |
| `virtual void on_shutdown()` | no-op | runs when the loop ends. |

`run()` / `run_with(socket_path)` / `serve(client, jwt_token)` mirror Rust's
`Plugin::run` / `run_with` / `serve`. `serve` registers via
`register_full(id(), version(), manifest(), jwt_token)` and rejects a
non-accepted registration with `VeyronPermissionDenied`. The `client_` member
is a non-owning pointer to the served client, valid inside the callback methods
for plugins that send extra traffic (e.g. multi-message streaming replies).

## Environment

| Variable             | Meaning                                                        |
|----------------------|-----------------------------------------------------------------|
| `VYN_SOCKET_PATH` | Kernel UDS path. Default: `XDG_RUNTIME_DIR` → `/run/user/<uid>` → `~/.local/state/vyn/run` (never shared `/tmp`; the `~/.local/state/vyn/run` fallback is created with mode `0700`). |
| `VYN_JWT_TOKEN`   | JWT presented at registration (required on secured kernels).   |
| `VYN_JWT_SECRET`  | Shared secret; enables per-frame HMAC-SHA256 tags after registration. |

## Errors

`VeyronError` (in `vynkor/error.hpp`) is a typed exception hierarchy mirroring
Rust's `WireError` enum variant-for-variant. Every subclass derives from
`std::runtime_error`, so existing `catch (const std::runtime_error&)` and
`catch (...)` sites keep working while new code can discriminate:

| Exception | Rust variant |
|-----------|--------------|
| `VeyronIoError` | `WireError::Io` |
| `VeyronProtoError` | `WireError::Proto` |
| `VeyronFrameMagicMismatch` | `WireError::FrameMagicMismatch` |
| `VeyronFrameCrcMismatch` | `WireError::FrameCrcMismatch` |
| `VeyronFrameReadTimeout` | `WireError::FrameReadTimeout` |
| `VeyronPayloadTooLarge` | `WireError::PayloadTooLarge` |
| `VeyronTimeout` | `WireError::Timeout` |
| `VeyronPermissionDenied` | `WireError::PermissionDenied` |
| `VeyronInternal` | `WireError::Internal` |

## Client API

For lower-level control, use `VeyronClient` directly:

```cpp
#include "vynkor/client.hpp"

auto client = vynkor::VeyronClient::connect_with_secret(socket_path, secret);
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

- `VeyronClient(socket_path, secret)` + member `connect()` — the primary ctor pattern.
- `VeyronClient::connect(socket_path)` / `connect_with_secret(socket_path, secret)` / `connect_from_env()` — static factories returning a connected client (Rust parity).
- `VeyronClient(fd, secret)` — adopt an already-connected fd (tests).
- `is_secured()` — true once a secured registration has derived the frame-MAC key.

### Registration

`register_plugin(plugin_id, manifest)`, `register_with_token(plugin_id, manifest, jwt_token)`,
and `register_full(plugin_id, version, manifest, jwt_token)` all return the
typed `PluginRegisterAck` (no raw `Envelope`). On a secured kernel the ack's
`session_nonce` is combined with the shared secret and plugin id to derive the
per-frame MAC key automatically.

`publish_event` requires `PERMISSION_EVENT_PUBLISH`; `timeout_ms == 0` uses
the kernel's 30s default. It returns the kernel's `EventPublishAck` as-is —
inspect `ack.status()` yourself (`EVENT_PUBLISH_OK`/`ERROR`/`PERMISSION_DENY`)
— and only throws `VeyronInternal` on a kernel `Error` envelope or
`VeyronTimeout` on timeout. Requests and responses are matched on a single
connection; drive request/response traffic from one thread.

`send_action` follows the same `timeout_ms == 0` → 30s-default convention
and returns the kernel's `ActionResponse` as-is (inspect `.status()`
yourself). It throws `VeyronInternal` on a kernel `Error` envelope, on an
`ActionStreamAbort` for this `action_id`, or `VeyronTimeout` on timeout.
`send_action_streaming` fires an `ActionRequest{streaming: true}` and
returns its generated `action_id` immediately, without waiting for any
response — drive `recv()`/chunks yourself afterward. `send_request_chunk`,
`send_response_chunk`, and `close_session` are fire-and-forget sends (no
response awaited); `close_session` has no `final` flag — the response side
of a stream is terminated by an ordinary `ActionResponse`.

## Consuming via CMake

```cmake
find_package(veyron-sdk REQUIRED)
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
