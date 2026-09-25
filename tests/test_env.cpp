#include <gtest/gtest.h>
#include <cstdlib>
#include "vynkor/env.hpp"
#include "vynkor/error.hpp"

using namespace vynkor;

namespace {
void unset_all() {
    unsetenv("XDG_RUNTIME_DIR");
    unsetenv("VYN_JWT_TOKEN");
    unsetenv("VYN_JWT_SECRET");
    unsetenv("VYN_DEVICE_ID");
    unsetenv("VYN_DEVICE_SECRET");
}
} // namespace

TEST(DefaultSocketPath, UsesXdgRuntimeDirWhenSet) {
    unset_all();
    setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);
    EXPECT_EQ(default_socket_path(), "/run/user/1000/vyn.sock");
    unset_all();
}

TEST(DefaultSocketPath, NeverFallsBackToSharedTmp) {
    unset_all();
    std::string path = default_socket_path();
    EXPECT_EQ(path.find("/tmp/vyn.sock"), std::string::npos);
    unset_all();
}

TEST(ResolveJwtToken, ExplicitTokenWins) {
    unset_all();
    setenv("VYN_JWT_TOKEN", "env-token", 1);
    EXPECT_EQ(resolve_jwt_token("explicit"), "explicit");
    unset_all();
}

TEST(ResolveJwtToken, FallsBackToEnv) {
    unset_all();
    setenv("VYN_JWT_TOKEN", "env-token", 1);
    EXPECT_EQ(resolve_jwt_token(""), "env-token");
    unset_all();
}

TEST(ResolveJwtToken, EmptyWithoutEnv) {
    unset_all();
    EXPECT_EQ(resolve_jwt_token(""), "");
}

TEST(ResolveJwtSecret, ExplicitSecretWins) {
    unset_all();
    setenv("VYN_JWT_SECRET", "env-secret", 1);
    std::vector<uint8_t> explicit_secret = {'x', 'y'};
    EXPECT_EQ(resolve_jwt_secret(explicit_secret), explicit_secret);
    unset_all();
}

TEST(ResolveJwtSecret, FallsBackToEnv) {
    unset_all();
    setenv("VYN_JWT_SECRET", "shh", 1);
    std::vector<uint8_t> expected = {'s', 'h', 'h'};
    EXPECT_EQ(resolve_jwt_secret({}), expected);
    unset_all();
}

TEST(ResolveJwtSecret, EmptyWithoutEnv) {
    unset_all();
    EXPECT_TRUE(resolve_jwt_secret({}).empty());
}

// ── resolve_ws_credentials (CD-02 / E-01) — same policy as the Rust SDK ──

TEST(ResolveWsCredentials, DevicePairSelectsDevice) {
    auto c = resolve_ws_credentials("phone-1", "dev-secret", "");
    EXPECT_EQ(c.kind, WsCredentials::Kind::Device);
    EXPECT_EQ(c.device_id, "phone-1");
    EXPECT_EQ(c.secret, (std::vector<uint8_t>{'d','e','v','-','s','e','c','r','e','t'}));
}

TEST(ResolveWsCredentials, MasterSecretAloneIsShared) {
    auto c = resolve_ws_credentials("", "", "master");
    EXPECT_EQ(c.kind, WsCredentials::Kind::Shared);
    EXPECT_TRUE(c.device_id.empty());
    EXPECT_EQ(c.secret, (std::vector<uint8_t>{'m','a','s','t','e','r'}));
}

TEST(ResolveWsCredentials, NothingSetIsUnsecured) {
    auto c = resolve_ws_credentials("", "", "");
    EXPECT_EQ(c.kind, WsCredentials::Kind::None);
    EXPECT_TRUE(c.secret.empty());
}

TEST(ResolveWsCredentials, MasterSecretNextToDevicePairRejected) {
    try {
        resolve_ws_credentials("phone-1", "dev-secret", "master");
        FAIL() << "expected VynkorInternal";
    } catch (const VynkorInternal& e) {
        EXPECT_NE(std::string(e.what()).find("VYN_JWT_SECRET"), std::string::npos);
    }
}

TEST(ResolveWsCredentials, HalfDevicePairRejectedEvenWithMasterFallback) {
    EXPECT_THROW(resolve_ws_credentials("phone-1", "", ""), VynkorInternal);
    EXPECT_THROW(resolve_ws_credentials("", "dev-secret", ""), VynkorInternal);
    // no silent downgrade to the shared path
    EXPECT_THROW(resolve_ws_credentials("phone-1", "", "master"), VynkorInternal);
    EXPECT_THROW(resolve_ws_credentials("", "dev-secret", "master"), VynkorInternal);
}

TEST(ResolveWsCredentials, FromEnvReadsDeviceVars) {
    unset_all();
    setenv("VYN_DEVICE_ID", "phone-1", 1);
    setenv("VYN_DEVICE_SECRET", "dev-secret", 1);
    EXPECT_EQ(resolve_ws_credentials_from_env().kind, WsCredentials::Kind::Device);
    setenv("VYN_JWT_SECRET", "master", 1);
    EXPECT_THROW(resolve_ws_credentials_from_env(), VynkorInternal);
    unset_all();
}
