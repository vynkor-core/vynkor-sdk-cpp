// P7-01: VeyronClient::publish_event — mirrors sdk/rust/src/client.rs's
// publish_event tests (OK/PERMISSION_DENY ack passthrough, kernel error
// raises, deadline timeout raises, unrelated traffic discarded).

#include <gtest/gtest.h>
#include <sys/socket.h>

#include <chrono>
#include <thread>

#include "veyron/client.hpp"
#include "veyron/framing.hpp"
#include "veyron_protocol.pb.h"

using namespace veyron;

namespace {

std::pair<int, int> make_socketpair() {
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        throw std::runtime_error("socketpair() failed");
    return {fds[0], fds[1]};
}

Envelope recv_kernel_side(int fd) {
    auto frame = read_frame_full(fd);
    Envelope env;
    env.ParseFromArray(frame.payload.data(), static_cast<int>(frame.payload.size()));
    return env;
}

void send_kernel_side(int fd, const Envelope& env) {
    std::string bytes;
    env.SerializeToString(&bytes);
    auto frame = pack_frame("plugin", bytes);
    ::write(fd, frame.data(), frame.size());
}

} // namespace

TEST(PublishEvent, OkAckReturned) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        Envelope req = recv_kernel_side(b);
        ASSERT_TRUE(req.has_event_publish());
        EXPECT_EQ(req.event_publish().event_type(), "my.event");

        Envelope resp;
        auto* ack = resp.mutable_event_publish_ack();
        ack->set_event_id("evt-1");
        ack->set_status(EVENT_PUBLISH_OK);
        send_kernel_side(b, resp);
    });

    std::vector<uint8_t> payload{'{', '}'};
    EventPublishAck ack = client.publish_event("my.event", payload, 1000);
    kernel.join();

    EXPECT_EQ(ack.event_id(), "evt-1");
    EXPECT_EQ(ack.status(), EVENT_PUBLISH_OK);
}

TEST(PublishEvent, PermissionDenyAckReturnedNotRaised) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        recv_kernel_side(b);
        Envelope resp;
        auto* ack = resp.mutable_event_publish_ack();
        ack->set_event_id("evt-2");
        ack->set_status(EVENT_PUBLISH_PERMISSION_DENY);
        send_kernel_side(b, resp);
    });

    std::vector<uint8_t> payload{'{', '}'};
    EventPublishAck ack = client.publish_event("my.event", payload, 1000);
    kernel.join();

    EXPECT_EQ(ack.status(), EVENT_PUBLISH_PERMISSION_DENY);
}

TEST(PublishEvent, KernelErrorEnvelopeRaises) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        recv_kernel_side(b);
        Envelope resp;
        auto* err = resp.mutable_error();
        err->set_message("boom");
        err->set_details("detail");
        send_kernel_side(b, resp);
    });

    std::vector<uint8_t> payload{'{', '}'};
    EXPECT_THROW(client.publish_event("my.event", payload, 1000), VeyronInternal);
    kernel.join();
}

TEST(PublishEvent, TimesOutWhenNoResponse) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        recv_kernel_side(b);
        // Never respond; keep fd open until test finishes.
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    });

    std::vector<uint8_t> payload{'{', '}'};
    const auto start = std::chrono::steady_clock::now();
    EXPECT_THROW(client.publish_event("my.event", payload, 150), VeyronTimeout);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, std::chrono::seconds(2));

    kernel.join();
    ::close(b);
}

TEST(PublishEvent, UnrelatedEnvelopeDiscardedThenAckReturned) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        recv_kernel_side(b);

        // Unrelated traffic first — must be discarded, not mistaken for the ack.
        Envelope ping_env;
        ping_env.mutable_ping()->set_timestamp(1);
        send_kernel_side(b, ping_env);

        Envelope resp;
        auto* ack = resp.mutable_event_publish_ack();
        ack->set_event_id("evt-3");
        ack->set_status(EVENT_PUBLISH_OK);
        send_kernel_side(b, resp);
    });

    std::vector<uint8_t> payload{'{', '}'};
    EventPublishAck ack = client.publish_event("my.event", payload, 1000);
    kernel.join();

    EXPECT_EQ(ack.event_id(), "evt-3");
}
