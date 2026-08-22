#include <gtest/gtest.h>
#include <cstdlib>
#include "vynkor/env.hpp"

using namespace vynkor;

namespace {
void unset_all() {
    unsetenv("XDG_RUNTIME_DIR");
    unsetenv("VYN_JWT_TOKEN");
    unsetenv("VYN_JWT_SECRET");
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
