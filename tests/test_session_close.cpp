// P7-03: VeyronClient::recv() distinguishes SessionClose from
// ActionStreamAbort — mirrors sdk/rust/tests/protocol.rs's
// recv_distinguishes_session_close_from_stream_abort.

#include <gtest/gtest.h>
#include <sys/socket.h>

#include "vynkor/client.hpp"
#include "vynkor/framing.hpp"
#include "vynkor_protocol.pb.h"

using namespace vynkor;

namespace {

std::pair<int, int> make_socketpair() {
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        throw std::runtime_error("socketpair() failed");
    return {fds[0], fds[1]};
}

void send_kernel_side(int fd, const Envelope& env) {
    std::string bytes;
    env.SerializeToString(&bytes);
    auto frame = pack_frame("plugin", bytes);
    ::write(fd, frame.data(), frame.size());
}

} // namespace

TEST(SessionClose, RecvReturnsSessionClose) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    Envelope close_env;
    auto* close = close_env.mutable_session_close();
    close->set_action_id("act-1");
    close->set_reason("client closed");
    send_kernel_side(b, close_env);

    Envelope received = client.recv();
    ASSERT_TRUE(received.has_session_close());
    EXPECT_EQ(received.session_close().action_id(), "act-1");
    EXPECT_EQ(received.session_close().reason(), "client closed");
}

TEST(SessionClose, RecvDistinguishesFromActionStreamAbort) {
    auto [a, b] = make_socketpair();
    VeyronClient client(a);

    Envelope close_env;
    auto* close = close_env.mutable_session_close();
    close->set_action_id("act-1");
    close->set_reason("client closed");
    send_kernel_side(b, close_env);

    Envelope received_close = client.recv();
    ASSERT_TRUE(received_close.has_session_close());

    Envelope abort_env;
    auto* abort = abort_env.mutable_action_stream_abort();
    abort->set_action_id("act-1");
    abort->set_reason("idle timeout");
    send_kernel_side(b, abort_env);

    Envelope received_abort = client.recv();
    ASSERT_TRUE(received_abort.has_action_stream_abort());
    EXPECT_EQ(received_abort.action_stream_abort().action_id(), "act-1");
    EXPECT_EQ(received_abort.action_stream_abort().reason(), "idle timeout");
    EXPECT_FALSE(received_abort.has_session_close());
}
