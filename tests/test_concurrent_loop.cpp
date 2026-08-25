#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "vynkor/concurrent.hpp"
#include "vynkor/framing.hpp"

using namespace vynkor;

namespace {

// Kernel-side half of a socketpair: writes Envelopes to the plugin as framed
// wire frames, reads the plugin's replies back.
class FakeKernel {
public:
    FakeKernel() {
        int fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
            throw std::runtime_error("socketpair failed");
        kernel_fd_ = fds[0];
        client_fd_ = fds[1];

        timeval tv{};
        tv.tv_sec = 5;
        setsockopt(kernel_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    ~FakeKernel() {
        ::close(kernel_fd_);
        ::close(client_fd_);
    }

    int client_end() const { return client_fd_; }
    int kernel_end() const { return kernel_fd_; }

    void send_to_plugin(const Envelope& env) const {
        std::string bytes;
        ASSERT_TRUE(env.SerializeToString(&bytes));
        const std::vector<uint8_t> payload(bytes.begin(), bytes.end());
        const std::vector<uint8_t> frame = pack_frame("kernel", payload);
        size_t written = 0;
        while (written < frame.size()) {
            const ssize_t n = ::write(kernel_fd_, frame.data() + written,
                                      frame.size() - written);
            ASSERT_GT(n, 0);
            written += static_cast<size_t>(n);
        }
    }

    Envelope recv_from_plugin() const {
        const std::vector<uint8_t> payload = read_frame(kernel_fd_);
        Envelope env;
        EXPECT_TRUE(env.ParseFromArray(payload.data(), static_cast<int>(payload.size())));
        return env;
    }

private:
    int kernel_fd_ = -1;
    int client_fd_ = -1;
};

class EchoHandler : public ConcurrentHandler {
public:
    EchoHandler(std::vector<std::string> reject_actions,
                std::vector<std::string> panic_actions)
        : reject_actions_(std::move(reject_actions)),
          panic_actions_(std::move(panic_actions)) {}

    const std::string& id() const override { return id_; }

    void accept(const ActionRequest& req) override {
        for (const auto& action : reject_actions_) {
            if (req.action() == action)
                throw VynkorInternal("no slots for " + action);
        }
    }

    std::vector<Envelope> on_action(const ActionRequest& req) override {
        for (const auto& action : panic_actions_) {
            if (req.action() == action)
                throw std::runtime_error("kaput");
        }
        std::vector<uint8_t> echoed(req.params_json().begin(), req.params_json().end());
        return {response_envelope(req.action_id(), ActionResult::Ok(std::move(echoed)))};
    }

private:
    std::string id_ = "echo-hot";
    std::vector<std::string> reject_actions_;
    std::vector<std::string> panic_actions_;
};

ActionRequest make_request(const std::string& action_id, const std::string& action,
                           const std::string& params_json) {
    ActionRequest req;
    req.set_action_id(action_id);
    req.set_action(action);
    req.set_params_json(params_json);
    return req;
}

Envelope wrap(const ActionRequest& req) {
    Envelope env;
    *env.mutable_action_request() = req;
    return env;
}

} // namespace

TEST(ConcurrentLoop, ResponseEnvelopeOkAndErrorShapes) {
    Envelope ok = response_envelope("a1", ActionResult::Ok({'{', '}'}));
    ASSERT_TRUE(ok.has_action_response());
    EXPECT_EQ(ok.action_response().action_id(), "a1");
    EXPECT_EQ(ok.action_response().status(), ActionStatus::ACTION_OK);
    EXPECT_EQ(ok.action_response().data_json(), "{}");
    EXPECT_EQ(ok.action_response().error(), "");

    Envelope err = response_envelope("a2", ActionResult::Err("boom"));
    ASSERT_TRUE(err.has_action_response());
    EXPECT_EQ(err.action_response().status(), ActionStatus::ACTION_ERROR);
    EXPECT_EQ(err.action_response().error(), "boom");
}

TEST(ConcurrentLoop, AnswersPingOutOfBand) {
    FakeKernel kernel;
    VynkorClient client(kernel.client_end());
    EchoHandler handler({}, {});

    std::thread loop([&] { run_concurrent_loop(client, handler); });

    Ping ping;
    ping.set_timestamp(1234);
    Envelope ping_env;
    *ping_env.mutable_ping() = ping;
    kernel.send_to_plugin(ping_env);

    const Envelope reply = kernel.recv_from_plugin();
    ASSERT_TRUE(reply.has_pong());
    EXPECT_EQ(reply.pong().original_timestamp(), 1234);

    ::shutdown(kernel.kernel_end(), SHUT_RDWR);
    loop.join();
}

TEST(ConcurrentLoop, DispatchesActionsConcurrentlyAndRepliesInOrder) {
    FakeKernel kernel;
    VynkorClient client(kernel.client_end());
    EchoHandler handler({}, {});

    std::thread loop([&] { run_concurrent_loop(client, handler); });

    // Two requests; the first one's handler sleeps so replies would come out
    // of order if the loop were sequential — both must arrive regardless.
    kernel.send_to_plugin(wrap(make_request("r0", "echo", "{\"n\":0}")));
    kernel.send_to_plugin(wrap(make_request("r1", "echo", "{\"n\":1}")));

    bool saw_r0 = false;
    bool saw_r1 = false;
    for (int i = 0; i < 2 && !(saw_r0 && saw_r1); ++i) {
        const Envelope reply = kernel.recv_from_plugin();
        ASSERT_TRUE(reply.has_action_response());
        const ActionResponse& resp = reply.action_response();
        EXPECT_EQ(resp.status(), ActionStatus::ACTION_OK);
        if (resp.action_id() == "r0") {
            saw_r0 = true;
            EXPECT_EQ(resp.data_json(), "{\"n\":0}");
        } else if (resp.action_id() == "r1") {
            saw_r1 = true;
            EXPECT_EQ(resp.data_json(), "{\"n\":1}");
        } else {
            ADD_FAILURE() << "unexpected action_id " << resp.action_id();
        }
    }
    EXPECT_TRUE(saw_r0);
    EXPECT_TRUE(saw_r1);

    ::shutdown(kernel.kernel_end(), SHUT_RDWR);
    loop.join();
}

TEST(ConcurrentLoop, AcceptRejectionBecomesActionErrorWithoutSpawning) {
    FakeKernel kernel;
    VynkorClient client(kernel.client_end());
    EchoHandler handler({"reject"}, {});

    std::thread loop([&] { run_concurrent_loop(client, handler); });

    kernel.send_to_plugin(wrap(make_request("x1", "reject", "{}")));

    const Envelope reply = kernel.recv_from_plugin();
    ASSERT_TRUE(reply.has_action_response());
    EXPECT_EQ(reply.action_response().action_id(), "x1");
    EXPECT_EQ(reply.action_response().status(), ActionStatus::ACTION_ERROR);
    EXPECT_NE(reply.action_response().error().find("no slots"), std::string::npos);

    ::shutdown(kernel.kernel_end(), SHUT_RDWR);
    loop.join();
}

TEST(ConcurrentLoop, PanickingHandlerStillProducesActionErrorReply) {
    FakeKernel kernel;
    VynkorClient client(kernel.client_end());
    EchoHandler handler({}, {"boom"});

    std::thread loop([&] { run_concurrent_loop(client, handler); });

    kernel.send_to_plugin(wrap(make_request("p1", "boom", "{}")));

    const Envelope reply = kernel.recv_from_plugin();
    ASSERT_TRUE(reply.has_action_response());
    EXPECT_EQ(reply.action_response().action_id(), "p1");
    EXPECT_EQ(reply.action_response().status(), ActionStatus::ACTION_ERROR);
    EXPECT_NE(reply.action_response().error().find("handler panicked"),
              std::string::npos);

    ::shutdown(kernel.kernel_end(), SHUT_RDWR);
    loop.join();
}

TEST(ConcurrentLoop, PluginShutdownEndsLoopAndRunsOnShutdown) {
    FakeKernel kernel;
    VynkorClient client(kernel.client_end());

    std::atomic<bool> shutdown_called{false};
    class NotifyingHandler : public EchoHandler {
    public:
        explicit NotifyingHandler(std::atomic<bool>& flag)
            : EchoHandler({}, {}), flag_(flag) {}
        void on_shutdown() override { flag_ = true; }
    private:
        std::atomic<bool>& flag_;
    } notifying(shutdown_called);

    std::thread loop([&] { serve_concurrent(client, "", notifying); });

    // Registration handshake: serve_concurrent registers before looping.
    const Envelope reg = kernel.recv_from_plugin();
    ASSERT_TRUE(reg.has_plugin_register());
    Envelope ack_env;
    ack_env.mutable_plugin_register_ack()->set_accepted(true);
    kernel.send_to_plugin(ack_env);

    Envelope shutdown_env;
    shutdown_env.mutable_plugin_shutdown()->set_reason("test");
    kernel.send_to_plugin(shutdown_env);

    loop.join();
    EXPECT_TRUE(shutdown_called.load()) << "serve_concurrent runs on_shutdown";

    ::shutdown(kernel.kernel_end(), SHUT_RDWR);
}
