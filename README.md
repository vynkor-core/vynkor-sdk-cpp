# veyron-sdk (C++)

C++ SDK for writing [Veyron](https://github.com/veyron-core/veyron) plugins.

A Veyron plugin is a separate OS process supervised by the Veyron kernel. It
talks to the kernel over a Unix domain socket using the Veyron wire protocol:
framed messages carrying Protobuf envelopes, with optional zstd compression,
HMAC-SHA256 frame authentication, and fragmentation.

## Protocol source

`proto/veyron_protocol.proto` is vendored from
[`veyron-wire`](https://crates.io/crates/veyron-wire)'s `proto/` (wire
protocol **v1.4** as of the latest sync). It's copied by hand, not
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
#include "veyron/plugin.hpp"

class EchoPlugin : public veyron::Plugin {
public:
    EchoPlugin() : veyron::Plugin("echo-plugin") {}

    void on_message(const veyron::Envelope& env) override {
        if (!env.has_action_request()) return;
        // handle env.action_request(), reply via client()
    }
};

int main() {
    EchoPlugin plugin;
    plugin.run();
}
```

`Plugin::run` connects, registers, and serves until the kernel asks the
plugin to shut down. The SDK answers `Ping` automatically and exits the loop
on `PluginShutdown`. See `examples/echo_plugin.cpp` for a fuller example.

## Environment

| Variable             | Meaning                                                        |
|----------------------|-----------------------------------------------------------------|
| `VEYRON_SOCKET_PATH` | Kernel UDS path. Default: `XDG_RUNTIME_DIR` → `/run/user/<uid>` → `~/.veyron/run` (never shared `/tmp`). |
| `VEYRON_JWT_TOKEN`   | JWT presented at registration (required on secured kernels).   |
| `VEYRON_JWT_SECRET`  | Shared secret; enables per-frame HMAC-SHA256 tags after registration. |

## Client API

For lower-level control, use `VeyronClient` directly:

```cpp
VeyronClient client(socket_path, secret);
client.connect();
auto ack = client.register_plugin("weather", manifest, jwt_token);

client.subscribe({"alarm.fired"});
auto pub_ack = client.publish_event("weather.updated",
                                     std::vector<uint8_t>{'{', '}'}, 5000);
double latency = client.ping();

auto resp = client.send_action("get_weather", std::vector<uint8_t>{'{', '}'}, 5000);

std::string action_id = client.send_action_streaming("transcribe", 30000);
client.send_request_chunk(action_id, 0, std::vector<uint8_t>{'h', 'i'}, true);
client.send_response_chunk(action_id, 0, std::vector<uint8_t>{'o', 'k'});
client.close_session(action_id, "done");
```

`publish_event` requires `PERMISSION_EVENT_PUBLISH`; `timeout_ms == 0` uses
the kernel's 30s default. It returns the kernel's `EventPublishAck` as-is —
inspect `ack.status()` yourself (`EVENT_PUBLISH_OK`/`ERROR`/`PERMISSION_DENY`)
— and only throws `std::runtime_error` on a kernel `Error` envelope or on
timeout. Requests and responses are matched on a single connection; drive
request/response traffic from one thread.

`send_action` follows the same `timeout_ms == 0` → 30s-default convention
and returns the kernel's `ActionResponse` as-is (inspect `.status()`
yourself). It throws `std::runtime_error` on a kernel `Error` envelope, on
an `ActionStreamAbort` for this `action_id`, or on timeout.
`send_action_streaming` fires an `ActionRequest{streaming: true}` and
returns its generated `action_id` immediately, without waiting for any
response — drive `recv()`/chunks yourself afterward. `send_request_chunk`,
`send_response_chunk`, and `close_session` are fire-and-forget sends (no
response awaited); `close_session` has no `final` flag — the response side
of a stream is terminated by an ordinary `ActionResponse`.

## Consuming via CMake

```cmake
find_package(veyron-sdk REQUIRED)
target_link_libraries(my_plugin PRIVATE veyron::sdk)
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
