// Lightweight demo plugin for the Veyron C++ SDK.
//
// Shows: lifecycle hooks, event subscription, action handling (plain,
// streaming, and publish-from-plugin), and SessionClose dispatch.
//
// Run (with a kernel listening on the default socket):
//     VYN_JWT_TOKEN=<token> ./echo_plugin

#include <iostream>
#include <map>
#include <string>

#include "vynkor/plugin.hpp"

using namespace vynkor;

namespace {

class EchoPlugin : public Plugin {
public:
    const std::string& id() const override { return id_; }

    void on_init(VeyronClient& client) override {
        std::cout << "[" << id_ << "] registered, subscribing to events\n";
        client.subscribe({"system.low_memory"});
    }

    // Declares the actions this plugin provides so the kernel's action
    // broker (find_action_provider) routes ActionRequests here, and the
    // publish permission stream_echo/publish_test need.
    PluginManifest manifest() const override {
        PluginManifest m;
        m.add_permissions("PERMISSION_EVENT_PUBLISH");
        m.add_actions("echo");
        m.add_actions("stream_echo");
        m.add_actions("publish_test");
        return m;
    }

    std::optional<Envelope> on_message(const Envelope& env) override {
        if (env.has_action_request()) {
            return handle_action(env.action_request());
        }
        if (env.has_action_request_chunk()) {
            return handle_request_chunk(env.action_request_chunk());
        }
        if (env.has_session_close()) {
            // Proves the subprocess correctly discriminates SessionClose
            // from ActionStreamAbort over the real wire (P7-03 unit tests
            // already cover the discrimination logic itself).
            std::cout << "session_closed:" << env.session_close().reason() << "\n";
            std::cout.flush();
            return std::nullopt;
        }
        std::cout << "[" << id_ << "] unhandled message (case "
                  << env.payload_case() << ")\n";
        return std::nullopt;
    }

    std::optional<Envelope> on_event(const Event& evt) override {
        std::cout << "[" << id_ << "] event " << evt.event_type()
                  << ": " << evt.payload_json() << "\n";
        return std::nullopt;
    }

    void on_shutdown() override {
        std::cout << "[" << id_ << "] shutting down\n";
    }

private:
    std::optional<Envelope> handle_action(const ActionRequest& req) {
        if (req.action() == "stream_echo" && req.streaming()) {
            // Accept the session immediately, before any chunks arrive.
            // The kernel only honors SessionClose once the provider has
            // sent an accepting ActionResponse{OK} for this streaming
            // action (PendingAction::session_accepted) — see
            // src/plugins/registry.rs resolve_action_response.
            stream_action_id_ = req.action_id();
            stream_chunks_.clear();
            Envelope accept;
            auto* resp = accept.mutable_action_response();
            resp->set_action_id(req.action_id());
            resp->set_status(ActionStatus::ACTION_OK);
            return accept;
        }
        if (req.action() == "publish_test") {
            return handle_publish_test(req);
        }
        Envelope out;
        auto* resp = out.mutable_action_response();
        resp->set_action_id(req.action_id());
        if (req.action() == "echo") {
            resp->set_status(ActionStatus::ACTION_OK);
            resp->set_data_json(req.params_json());
        } else {
            resp->set_status(ActionStatus::ACTION_NOT_FOUND);
            resp->set_error("unknown action: " + req.action());
        }
        return out;
    }

    // Accumulates chunks by seq until `final`, then replies with 2
    // ActionResponseChunks (request bytes split roughly in half) followed
    // by a terminal ActionResponse. In-memory, one streaming action at a
    // time — sufficient for a round-trip test, not a general pattern.
    std::optional<Envelope> handle_request_chunk(const ActionRequestChunk& chunk) {
        if (chunk.action_id() != stream_action_id_) {
            return std::nullopt;
        }
        stream_chunks_[chunk.seq()] = chunk.chunk();
        if (!chunk.final()) {
            return std::nullopt;
        }

        std::string full;
        for (const auto& [seq, data] : stream_chunks_) {
            full += data;
        }
        size_t mid = full.size() / 2;
        std::string first_half = full.substr(0, mid);
        std::string second_half = full.substr(mid);

        Envelope c0;
        auto* rc0 = c0.mutable_action_response_chunk();
        rc0->set_action_id(stream_action_id_);
        rc0->set_seq(0);
        rc0->set_chunk(first_half);
        client_->send("kernel", c0);

        Envelope c1;
        auto* rc1 = c1.mutable_action_response_chunk();
        rc1->set_action_id(stream_action_id_);
        rc1->set_seq(1);
        rc1->set_chunk(second_half);
        client_->send("kernel", c1);

        Envelope out;
        auto* resp = out.mutable_action_response();
        resp->set_action_id(stream_action_id_);
        resp->set_status(ActionStatus::ACTION_OK);
        resp->set_data_json(full);

        stream_chunks_.clear();
        stream_action_id_.clear();
        return out;
    }

    std::optional<Envelope> handle_publish_test(const ActionRequest& req) {
        Envelope out;
        auto* resp = out.mutable_action_response();
        resp->set_action_id(req.action_id());
        try {
            std::vector<uint8_t> payload(req.params_json().begin(), req.params_json().end());
            EventPublishAck ack = client_->publish_event("test_publish", payload, 0);
            if (ack.status() == EventPublishStatus::EVENT_PUBLISH_OK) {
                resp->set_status(ActionStatus::ACTION_OK);
            } else {
                resp->set_status(ActionStatus::ACTION_ERROR);
                resp->set_error(ack.error());
            }
        } catch (const std::exception& e) {
            resp->set_status(ActionStatus::ACTION_ERROR);
            resp->set_error(e.what());
        }
        return out;
    }

    std::string id_ = "echo-plugin";
    std::string stream_action_id_;
    std::map<uint32_t, std::string> stream_chunks_;
};

} // namespace

int main() {
    EchoPlugin plugin;
    plugin.run();
    return 0;
}
