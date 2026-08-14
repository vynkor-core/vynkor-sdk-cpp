// AUDIT H-02 regression: the Plugin base-class run loop must answer the
// kernel watchdog's Ping with a Pong, or supervised C++ plugins get
// SIGKILLed ~40 s after registration. A fake kernel over a real UDS drives
// the full run() loop: register -> ack -> Ping -> expect Pong -> shutdown.
#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "veyron/framing.hpp"
#include "veyron/plugin.hpp"
#include "veyron_protocol.pb.h"

using namespace veyron;

namespace {

class RecordingPlugin : public Plugin {
public:
    const std::string& id() const override { return id_; }
    std::vector<Envelope> seen;
    std::vector<Event> events_seen;
    std::optional<Envelope> on_message(const Envelope& env) override {
        seen.push_back(env);
        return std::nullopt;
    }
    std::optional<Envelope> on_event(const Event& event) override {
        events_seen.push_back(event);
        return std::nullopt;
    }

private:
    std::string id_ = "test-plugin";
};

void write_all(int fd, const std::vector<uint8_t>& bytes) {
    size_t off = 0;
    while (off < bytes.size()) {
        ssize_t n = ::write(fd, bytes.data() + off, bytes.size() - off);
        ASSERT_GT(n, 0) << "fake kernel write failed";
        off += static_cast<size_t>(n);
    }
}

void send_envelope(int fd, const Envelope& env) {
    std::string bytes;
    ASSERT_TRUE(env.SerializeToString(&bytes));
    write_all(fd, pack_frame("test-plugin", bytes));
}

Envelope recv_envelope(int fd) {
    FrameResult fr = read_frame_full(fd);
    Envelope env;
    EXPECT_TRUE(env.ParseFromArray(fr.payload.data(),
                                   static_cast<int>(fr.payload.size())));
    return env;
}

} // namespace

TEST(PluginRunLoop, AnswersWatchdogPingWithPong) {
    std::string sock_path =
        "/tmp/veyron-test-ping-" + std::to_string(::getpid()) + ".sock";
    ::unlink(sock_path.c_str());

    int listen_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_GE(listen_fd, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    ASSERT_EQ(::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(listen_fd, 1), 0);

    Envelope captured_pong;
    bool got_pong = false;

    std::thread fake_kernel([&] {
        int fd = ::accept(listen_fd, nullptr, nullptr);
        ASSERT_GE(fd, 0);

        // 1. Registration in, ack out.
        Envelope reg = recv_envelope(fd);
        EXPECT_TRUE(reg.has_plugin_register());
        Envelope ack;
        ack.mutable_plugin_register_ack()->set_accepted(true);
        send_envelope(fd, ack);

        // 2. Watchdog Ping out, Pong expected back.
        Envelope ping;
        ping.mutable_ping()->set_timestamp(424242);
        send_envelope(fd, ping);

        Envelope reply = recv_envelope(fd);
        got_pong = reply.has_pong();
        captured_pong = reply;

        // 3. Shutdown ends the run loop.
        Envelope shutdown;
        shutdown.mutable_plugin_shutdown();
        send_envelope(fd, shutdown);
        ::close(fd);
    });

    RecordingPlugin plugin;
    plugin.run_with(sock_path);
    fake_kernel.join();
    ::close(listen_fd);
    ::unlink(sock_path.c_str());

    ASSERT_TRUE(got_pong) << "run loop must reply to Ping with Pong";
    EXPECT_EQ(captured_pong.pong().original_timestamp(), 424242u);
    EXPECT_GT(captured_pong.pong().server_timestamp(), 0u);
    EXPECT_TRUE(plugin.seen.empty())
        << "Ping must be handled by the base class, not passed to on_message";
}

// T-06: Event delivery must reach on_event and get auto-acked, or the kernel
// retries it until max_retries then drops it — every event to a stock C++
// plugin was silently lost before this fix.
TEST(PluginRunLoop, DispatchesEventToOnEventAndSendsAck) {
    std::string sock_path =
        "/tmp/veyron-test-event-" + std::to_string(::getpid()) + ".sock";
    ::unlink(sock_path.c_str());

    int listen_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_GE(listen_fd, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    ASSERT_EQ(::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(listen_fd, 1), 0);

    bool got_ack = false;
    std::string acked_event_id;

    std::thread fake_kernel([&] {
        int fd = ::accept(listen_fd, nullptr, nullptr);
        ASSERT_GE(fd, 0);

        Envelope reg = recv_envelope(fd);
        EXPECT_TRUE(reg.has_plugin_register());
        Envelope ack;
        ack.mutable_plugin_register_ack()->set_accepted(true);
        send_envelope(fd, ack);

        Envelope event_env;
        event_env.mutable_event()->set_event_id("evt-99");
        send_envelope(fd, event_env);

        Envelope reply = recv_envelope(fd);
        got_ack = reply.has_event_ack();
        acked_event_id = reply.event_ack().event_id();

        Envelope shutdown;
        shutdown.mutable_plugin_shutdown();
        send_envelope(fd, shutdown);
        ::close(fd);
    });

    RecordingPlugin plugin;
    plugin.run_with(sock_path);
    fake_kernel.join();
    ::close(listen_fd);
    ::unlink(sock_path.c_str());

    ASSERT_TRUE(got_ack) << "run loop must send EventAck after on_event";
    EXPECT_EQ(acked_event_id, "evt-99");
    ASSERT_EQ(plugin.events_seen.size(), 1u);
    EXPECT_EQ(plugin.events_seen[0].event_id(), "evt-99");
    EXPECT_TRUE(plugin.seen.empty())
        << "Event must be handled by the base class, not passed to on_message";
}
