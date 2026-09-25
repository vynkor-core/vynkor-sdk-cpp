#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vynkor {

// Per-user socket location, mirroring the kernel's default_socket_path()
// (src/utils/config.rs) and the Python SDK's _default_socket_path():
// XDG_RUNTIME_DIR -> /run/user/<uid> -> ~/.local/state/vyn/run. Never the
// world-writable shared /tmp (BUG-006).
std::string default_socket_path();

// Resolves the JWT token to present at registration: explicit_token if
// non-empty, else VYN_JWT_TOKEN, else "".
std::string resolve_jwt_token(const std::string& explicit_token);

// Resolves the shared secret for frame MACs: explicit_secret if non-empty,
// else the bytes of VYN_JWT_SECRET, else empty (no MAC). Host-side plugins
// only — a paired remote device uses resolve_ws_credentials() instead.
std::vector<uint8_t> resolve_jwt_secret(const std::vector<uint8_t>& explicit_secret);

// MAC credentials for Plugin::run_ws (CD-02 / E-01). Same names and policy
// as the Rust SDK's resolve_ws_credentials.
struct WsCredentials {
    enum class Kind {
        Device,  // paired device: register with device_id, MAC off secret
        Shared,  // legacy: host master jwt_secret
        None,    // unsecured kernel (allow_no_auth)
    };
    Kind kind = Kind::None;
    std::string device_id;
    std::vector<uint8_t> secret;
};

// Pure policy over VYN_DEVICE_ID / VYN_DEVICE_SECRET / VYN_JWT_SECRET
// values ("" = unset). Strict: a half-set device pair, or a master secret
// next to a device pair, throws VynkorInternal instead of silently falling
// back — the kernel would otherwise reject later with an opaque
// "token plugin_id mismatch".
WsCredentials resolve_ws_credentials(const std::string& device_id,
                                     const std::string& device_secret,
                                     const std::string& jwt_secret);

// resolve_ws_credentials() over the process environment.
WsCredentials resolve_ws_credentials_from_env();

} // namespace vynkor
