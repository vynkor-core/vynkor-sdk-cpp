#include <gtest/gtest.h>
#include <sys/un.h>

#include <sys/socket.h>
#include <unistd.h>

#include "vynkor/client.hpp"
#include "vynkor/framing.hpp"
#include "vynkor/mac.hpp"

using namespace vynkor;

TEST(VynkorClientConnect, RejectsOverlongSocketPath) {
    std::string too_long(sizeof(sockaddr_un{}.sun_path), 'x');
    VynkorClient client(too_long);
    EXPECT_THROW(client.connect(), VynkorIoError);
}

TEST(VynkorClientConnect, AcceptsPathAtMaxLength) {
    // sizeof(sun_path) - 1 chars, plus nul terminator, fits exactly.
    std::string max_len(sizeof(sockaddr_un{}.sun_path) - 1, 'x');
    VynkorClient client(max_len);
    // No listener at this path — connect() itself fails, but not with the
    // "socket path too long" message, proving the length check passed.
    try {
        client.connect();
        FAIL() << "expected connect() to throw (no listener at synthetic path)";
    } catch (const VynkorIoError& e) {
        EXPECT_EQ(std::string(e.what()).find("too long"), std::string::npos);
    }
}

// ── CD-02 / E-01: device-scoped registration ─────────────────────────

namespace {
// Queue a register ack on the kernel side before the client registers; the
// socket buffers it, so the test stays single-threaded.
void queue_ack(int kernel_fd, const std::string& target, const std::vector<uint8_t>& nonce) {
    Envelope env;
    auto* ack = env.mutable_plugin_register_ack();
    ack->set_accepted(true);
    ack->set_session_nonce(std::string(nonce.begin(), nonce.end()));
    std::string serialized;
    ASSERT_TRUE(env.SerializeToString(&serialized));
    auto frame = pack_frame(target, serialized);
    ASSERT_EQ(::write(kernel_fd, frame.data(), frame.size()),
              static_cast<ssize_t>(frame.size()));
}

PluginRegister read_register(int kernel_fd) {
    auto frame = read_frame_full(kernel_fd, nullptr);
    Envelope env;
    EXPECT_TRUE(env.ParseFromArray(frame.payload.data(),
                                   static_cast<int>(frame.payload.size())));
    EXPECT_TRUE(env.has_plugin_register());
    return env.plugin_register();
}
} // namespace

TEST(VynkorClientDevice, RegistrationSendsDeviceIdAndMacsWithDeviceSecret) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    const std::vector<uint8_t> device_secret = {'p','e','r','-','d','e','v','i','c','e'};
    const std::vector<uint8_t> nonce(16, 0x42);

    VynkorClient client(fds[0], device_secret);
    client.set_device_id("phone-1");
    queue_ack(fds[1], "phone-1", nonce);

    auto ack = client.register_full("phone-1", "1.0.0", PluginManifest{}, "jwt");
    EXPECT_TRUE(ack.accepted());
    EXPECT_TRUE(client.is_secured());
    EXPECT_EQ(read_register(fds[1]).device_id(), "phone-1");

    // next frame must verify under the key derived from the device secret
    client.subscribe({"*"});
    auto key = derive_session_key(device_secret, nonce, "phone-1");
    EXPECT_NO_THROW(read_frame_full(fds[1], &key));
    ::close(fds[1]);
}

TEST(VynkorClientDevice, LocalRegistrationLeavesDeviceIdEmpty) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    VynkorClient client(fds[0]);
    queue_ack(fds[1], "local-plugin", {});

    client.register_full("local-plugin", "1.0.0", PluginManifest{}, "");
    EXPECT_TRUE(read_register(fds[1]).device_id().empty());
    ::close(fds[1]);
}
