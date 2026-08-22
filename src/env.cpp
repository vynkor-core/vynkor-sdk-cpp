#include "vynkor/env.hpp"

#include <cstdlib>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace vynkor {

namespace {
bool is_directory(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

// Creates ~/.local/state/vyn/run with mode 0700 (mirrors vynkor-wire's
// default_private_dir). Returns true on success or if it already exists.
bool ensure_private_dir(const std::string& dir) {
    if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST)
        return false;
    // chmod regardless — a pre-existing dir may predate the 0700 guarantee.
    return ::chmod(dir.c_str(), 0700) == 0;
}
} // namespace

std::string default_socket_path() {
    if (const char* explicit_path = std::getenv("VYN_SOCKET_PATH"); explicit_path && *explicit_path) {
        return std::string(explicit_path);
    }
    if (const char* xdg = std::getenv("XDG_RUNTIME_DIR"); xdg && *xdg) {
        return std::string(xdg) + "/vyn.sock";
    }
    std::string run_user = "/run/user/" + std::to_string(getuid());
    if (is_directory(run_user)) {
        return run_user + "/vyn.sock";
    }
    const char* home = std::getenv("HOME");
    if (home && *home) {
        const std::string dir = std::string(home) + "/.local/state/vyn/run";
        if (ensure_private_dir(dir))
            return dir + "/vyn.sock";
    }
    return "";
}

std::string resolve_jwt_token(const std::string& explicit_token) {
    if (!explicit_token.empty()) {
        return explicit_token;
    }
    if (const char* tok = std::getenv("VYN_JWT_TOKEN"); tok && *tok) {
        return std::string(tok);
    }
    return "";
}

std::vector<uint8_t> resolve_jwt_secret(const std::vector<uint8_t>& explicit_secret) {
    if (!explicit_secret.empty()) {
        return explicit_secret;
    }
    if (const char* secret = std::getenv("VYN_JWT_SECRET"); secret && *secret) {
        return std::vector<uint8_t>(secret, secret + std::string(secret).size());
    }
    return {};
}

} // namespace vynkor
