#include "vynkor/concurrent.hpp"

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <deque>
#include <exception>
#include <mutex>
#include <thread>
#include <utility>

namespace vynkor {

namespace {

uint64_t unix_millis() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

Envelope make_pong(const Ping& ping) {
    Envelope pong;
    pong.mutable_pong()->set_original_timestamp(ping.timestamp());
    pong.mutable_pong()->set_server_timestamp(unix_millis());
    return pong;
}

// Completed response envelopes flow from handler threads back to the single
// loop thread through this queue. Handlers never touch the client — pushing
// only needs the queue's short-lived mutex, so a finishing handler can never
// deadlock against the loop parked inside client.recv().
class ResponseChannel {
public:
    explicit ResponseChannel(int wake_fd) : wake_fd_(wake_fd) {}

    void push(Envelope env) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            queue_.push_back(std::move(env));
        }
        const char signal = 0;
        ssize_t ignored = ::write(wake_fd_, &signal, 1);
        (void)ignored;
    }

    std::optional<Envelope> try_pop() {
        std::lock_guard<std::mutex> lock(mu_);
        if (queue_.empty())
            return std::nullopt;
        Envelope env = std::move(queue_.front());
        queue_.pop_front();
        return env;
    }

private:
    std::mutex mu_;
    std::deque<Envelope> queue_;
    int wake_fd_;
};

void send_best_effort(VynkorClient& client, const std::string& target,
                      const Envelope& env) {
    try {
        client.send(target, env);
    } catch (...) {
        // Mirrors the rust loop's `let _ = client.send(...)` — a failed
        // best-effort reply must not kill the loop.
    }
}

void drain_wake_pipe(int fd) {
    char buf[64];
    while (true) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n > 0)
            continue;
        if (n < 0 && errno == EINTR)
            continue;
        break;
    }
}

} // namespace

Envelope response_envelope(const std::string& action_id, const ActionResult& result) {
    Envelope env;
    auto* resp = env.mutable_action_response();
    resp->set_action_id(action_id);
    if (result.ok) {
        resp->set_status(ActionStatus::ACTION_OK);
        resp->set_data_json(result.data_json.data(), result.data_json.size());
    } else {
        resp->set_status(ActionStatus::ACTION_ERROR);
        resp->set_error(result.error);
    }
    return env;
}

void run_concurrent_loop(VynkorClient& client, ConcurrentHandler& handler) {
    int wake_fds[2];
    if (::pipe2(wake_fds, O_CLOEXEC | O_NONBLOCK) != 0)
        throw VynkorIoError("pipe2 failed for concurrent loop wake channel");
    const int wake_read_fd = wake_fds[0];

    ResponseChannel channel(wake_fds[1]);
    std::vector<std::thread> workers;

    auto spawn_handler = [&](const ActionRequest& req) {
        try {
            handler.accept(req);
        } catch (const std::exception& e) {
            channel.push(response_envelope(req.action_id(), ActionResult::Err(e.what())));
            return;
        } catch (...) {
            channel.push(response_envelope(req.action_id(), ActionResult::Err("rejected")));
            return;
        }
        workers.emplace_back([&channel, &handler, req] {
            std::vector<Envelope> envelopes;
            try {
                envelopes = handler.on_action(req);
            } catch (const std::exception& e) {
                envelopes.push_back(response_envelope(
                    req.action_id(),
                    ActionResult::Err(std::string("handler panicked: ") + e.what())));
            } catch (...) {
                envelopes.push_back(response_envelope(
                    req.action_id(), ActionResult::Err("handler panicked")));
            }
            for (auto& envelope : envelopes)
                channel.push(std::move(envelope));
        });
    };

    bool running = true;
    while (running) {
        struct pollfd fds[2] = {};
        fds[0].fd = client.native_handle();
        fds[0].events = POLLIN;
        fds[1].fd = wake_read_fd;
        fds[1].events = POLLIN;

        const int pr = ::poll(fds, 2, -1);
        if (pr < 0 && errno != EINTR)
            break;

        if ((fds[1].revents & POLLIN) != 0) {
            drain_wake_pipe(wake_read_fd);
            while (auto envelope = channel.try_pop())
                send_best_effort(client, "kernel", *envelope);
        }

        if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) == 0)
            continue;

        Envelope env;
        try {
            env = client.recv();
        } catch (...) {
            break; // disconnect / EOF
        }

        if (env.has_ping()) {
            send_best_effort(client, "kernel", make_pong(env.ping()));
            continue;
        }
        if (env.has_plugin_shutdown()) {
            running = false;
            continue;
        }
        if (env.has_action_request()) {
            spawn_handler(env.action_request());
            continue;
        }
        if (env.has_event()) {
            const std::string event_id = env.event().event_id();
            // On handler error no ack is sent — the kernel will retry.
            try {
                auto reply = handler.on_event(env.event());
                client.ack_event(event_id);
                if (reply)
                    send_best_effort(client, "kernel", *reply);
            } catch (...) {
            }
            continue;
        }

        // A throw out of on_message is swallowed and the message dropped
        // (mirrors the rust loop's `if let Ok(Some(reply))`).
        try {
            auto reply = handler.on_message(env);
            if (reply)
                send_best_effort(client, "kernel", *reply);
        } catch (...) {
        }
    }

    for (auto& worker : workers)
        worker.join();
    ::close(wake_read_fd);
    ::close(wake_fds[1]);
}

void serve_concurrent(VynkorClient& client,
                      const std::string& jwt_token,
                      ConcurrentHandler& handler) {
    PluginRegisterAck ack =
        client.register_full(handler.id(), handler.version(), handler.manifest(), jwt_token);
    if (!ack.accepted())
        throw VynkorPermissionDenied("registration rejected: " + ack.reject_reason());

    try {
        handler.on_init(client);
    } catch (...) {
        handler.on_shutdown();
        throw;
    }

    run_concurrent_loop(client, handler);
    handler.on_shutdown();
}

} // namespace vynkor
