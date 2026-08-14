#include <gtest/gtest.h>
#include <cstdlib>
#include "veyron/plugin.hpp"

using namespace veyron;

namespace {
class NoopPlugin : public Plugin {
public:
    const std::string& id() const override { return id_; }
    std::optional<Envelope> on_message(const Envelope&) override { return std::nullopt; }

    std::string id_ = "test-plugin";
};
} // namespace

TEST(PluginDefaults, VersionDefaultsTo100) {
    NoopPlugin plugin;
    EXPECT_EQ(plugin.version(), "1.0.0");
}

TEST(PluginDefaults, ManifestDefaultsToEmpty) {
    NoopPlugin plugin;
    PluginManifest m = plugin.manifest();
    EXPECT_EQ(m.permissions_size(), 0);
    EXPECT_EQ(m.actions_size(), 0);
    EXPECT_EQ(m.events_size(), 0);
    EXPECT_EQ(m.ipc_targets_size(), 0);
}

TEST(PluginDefaults, IdComesFromOverride) {
    NoopPlugin plugin;
    EXPECT_EQ(plugin.id(), "test-plugin");
}

TEST(PluginDefaults, NeverDefaultsSocketToSharedTmp) {
    unsetenv("XDG_RUNTIME_DIR");
    EXPECT_NE(default_socket_path(), "/tmp/veyron.sock");
}
