// P7-02: VeyronClient::send_action/send_action_streaming/send_request_chunk/
// send_response_chunk/close_session — mirrors sdk/rust/src/client.rs's
// send_action tests plus streaming-specific additions.

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

TEST(SendAction, OkResponseReturned) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        Envelope req = recv_kernel_side(b);
        ASSERT_TRUE(req.has_action_request());
        EXPECT_EQ(req.action_request().action(), "get_weather");
        EXPECT_FALSE(req.action_request().streaming());

        Envelope resp;
        auto* ar = resp.mutable_action_response();
        ar->set_action_id(req.action_request().action_id());
        ar->set_status(ACTION_OK);
        ar->set_data_json("{}");
        send_kernel_side(b, resp);
    });

    std::vector<uint8_t> params{'{', '}'};
    ActionResponse resp = client.send_action("get_weather", params, 1000);
    kernel.join();

    EXPECT_EQ(resp.status(), ACTION_OK);
    EXPECT_EQ(resp.data_json(), "{}");
}

TEST(SendAction, StreamAbortForActionIdRaises) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        Envelope req = recv_kernel_side(b);
        Envelope resp;
        auto* abort = resp.mutable_action_stream_abort();
        abort->set_action_id(req.action_request().action_id());
        abort->set_reason("plugin crashed");
        send_kernel_side(b, resp);
    });

    std::vector<uint8_t> params{'{', '}'};
    EXPECT_THROW(client.send_action("get_weather", params, 1000), VeyronInternal);
    kernel.join();
}

TEST(SendAction, KernelErrorEnvelopeRaises) {
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

    std::vector<uint8_t> params{'{', '}'};
    EXPECT_THROW(client.send_action("get_weather", params, 1000), VeyronInternal);
    kernel.join();
}

TEST(SendAction, TimesOutWhenNoResponse) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        recv_kernel_side(b);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    });

    std::vector<uint8_t> params{'{', '}'};
    const auto start = std::chrono::steady_clock::now();
    EXPECT_THROW(client.send_action("get_weather", params, 150), VeyronTimeout);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, std::chrono::seconds(2));

    kernel.join();
    ::close(b);
}

TEST(SendAction, UnrelatedEnvelopeDiscardedThenResponseReturned) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        Envelope req = recv_kernel_side(b);

        Envelope ping_env;
        ping_env.mutable_ping()->set_timestamp(1);
        send_kernel_side(b, ping_env);

        Envelope resp;
        auto* ar = resp.mutable_action_response();
        ar->set_action_id(req.action_request().action_id());
        ar->set_status(ACTION_OK);
        send_kernel_side(b, resp);
    });

    std::vector<uint8_t> params{'{', '}'};
    ActionResponse resp = client.send_action("get_weather", params, 1000);
    kernel.join();

    EXPECT_EQ(resp.status(), ACTION_OK);
}

TEST(SendActionStreaming, ReturnsActionIdImmediatelyWithoutBlocking) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        Envelope req = recv_kernel_side(b);
        ASSERT_TRUE(req.has_action_request());
        EXPECT_TRUE(req.action_request().streaming());
        EXPECT_TRUE(req.action_request().params_json().empty());
        // Deliberately never respond — send_action_streaming must not block.
    });

    std::string action_id = client.send_action_streaming("transcribe", 1000);
    EXPECT_FALSE(action_id.empty());
    kernel.join();
    ::close(b);
}

TEST(SendActionStreaming, RequestAndResponseChunksSerializeExpectedFields) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        Envelope req_chunk = recv_kernel_side(b);
        ASSERT_TRUE(req_chunk.has_action_request_chunk());
        EXPECT_EQ(req_chunk.action_request_chunk().action_id(), "act-1");
        EXPECT_EQ(req_chunk.action_request_chunk().seq(), 3u);
        EXPECT_EQ(req_chunk.action_request_chunk().chunk(), "hello");
        EXPECT_TRUE(req_chunk.action_request_chunk().final());

        Envelope resp_chunk = recv_kernel_side(b);
        ASSERT_TRUE(resp_chunk.has_action_response_chunk());
        EXPECT_EQ(resp_chunk.action_response_chunk().action_id(), "act-1");
        EXPECT_EQ(resp_chunk.action_response_chunk().seq(), 7u);
        EXPECT_EQ(resp_chunk.action_response_chunk().chunk(), "world");
    });

    std::vector<uint8_t> req_bytes{'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> resp_bytes{'w', 'o', 'r', 'l', 'd'};
    client.send_request_chunk("act-1", 3, req_bytes, true);
    client.send_response_chunk("act-1", 7, resp_bytes);
    kernel.join();
}

TEST(CloseSession, SerializesActionIdAndReason) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    std::thread kernel([&] {
        Envelope env = recv_kernel_side(b);
        ASSERT_TRUE(env.has_session_close());
        EXPECT_EQ(env.session_close().action_id(), "act-2");
        EXPECT_EQ(env.session_close().reason(), "done");
    });

    client.close_session("act-2", "done");
    kernel.join();
}
