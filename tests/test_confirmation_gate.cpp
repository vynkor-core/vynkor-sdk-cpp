#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "vynkor/confirmation_gate.hpp"

using namespace vynkor;

namespace {

ConfirmationGate make_gate(std::vector<std::string> confirm_callers) {
    return ConfirmationGate("transfer", "Move money", "{\"type\":\"object\"}",
                            ActionRisk::ACTION_RISK_CRITICAL,
                            std::move(confirm_callers));
}

ActionRequest make_request(const std::string& action, const std::string& action_id,
                           const std::string& caller, const std::string& params_json) {
    ActionRequest req;
    req.set_action_id(action_id);
    req.set_action(action);
    req.set_params_json(params_json);
    req.set_caller_plugin_id(caller);
    return req;
}

ActionResponse run(const ConfirmationGate& gate, const ActionRequest& req) {
    const std::vector<Envelope> envelopes = gate.route(
        req, [](const std::vector<uint8_t>& params) { return ActionResult::Ok(params); });
    EXPECT_EQ(envelopes.size(), 1u);
    EXPECT_TRUE(envelopes[0].has_action_response());
    return envelopes[0].action_response();
}

// Pulls the pending_id value out of a request_<op> reply's data_json.
std::string extract_pending_id(const ActionResponse& resp) {
    const std::string data(resp.data_json().begin(), resp.data_json().end());
    const std::string key = "\"pending_id\":\"";
    const auto start = data.find(key);
    EXPECT_NE(start, std::string::npos) << data;
    const auto end = data.find('"', start + key.size());
    EXPECT_NE(end, std::string::npos) << data;
    return data.substr(start + key.size(), end - start - key.size());
}

} // namespace

TEST(ConfirmationGate, RequestStoresPendingAndReturnsPendingId) {
    const ConfirmationGate gate = make_gate({"device.phone"});
    const ActionResponse resp = run(gate, make_request(
        "request_transfer", "a1", "ai", "{\"amount\": 100, \"to\": \"bob\"}"));

    EXPECT_EQ(resp.status(), ActionStatus::ACTION_OK);
    const std::string pending_id = extract_pending_id(resp);
    EXPECT_EQ(pending_id.rfind("pending-", 0), 0);

    const std::string data(resp.data_json().begin(), resp.data_json().end());
    EXPECT_NE(data.find("\"action\":\"request_transfer\""), std::string::npos);
    EXPECT_NE(data.find("\"ttl_secs\":300"), std::string::npos);
    EXPECT_EQ(gate.pending_count(), 1u);
}

TEST(ConfirmationGate, AnyCallerCanRequestEvenOneNotAllowedToConfirm) {
    const ConfirmationGate gate = make_gate({"device.phone"});
    const ActionResponse resp = run(gate, make_request(
        "request_transfer", "a1", "some_other_plugin", "{\"amount\": 1}"));
    EXPECT_EQ(resp.status(), ActionStatus::ACTION_OK);
}

TEST(ConfirmationGate, ApprovedCallerConfirmsAndExecutesStoredParams) {
    const ConfirmationGate gate = make_gate({"device.phone"});
    const std::string pending_id =
        extract_pending_id(run(gate, make_request(
            "request_transfer", "a1", "ai", "{\"amount\": 42, \"to\": \"bob\"}")));

    // The executor must receive the *stored* params, not anything the
    // confirming caller supplies.
    const ActionResponse resp = run(gate, make_request(
        "confirm_transfer", "a2", "device.phone",
        "{\"pending_id\": \"" + pending_id + "\", \"amount\": 9999}"));

    EXPECT_EQ(resp.status(), ActionStatus::ACTION_OK);
    const std::string executed(resp.data_json().begin(), resp.data_json().end());
    EXPECT_EQ(executed, "{\"amount\": 42, \"to\": \"bob\"}")
        << "executor ran with the request-time params";
    EXPECT_EQ(gate.pending_count(), 0u) << "confirmed pending is consumed";
}

TEST(ConfirmationGate, UnapprovedCallerIsDeniedEvenForARealPendingId) {
    const ConfirmationGate gate = make_gate({"device.phone"});
    const std::string pending_id =
        extract_pending_id(run(gate, make_request(
            "request_transfer", "a1", "ai", "{\"amount\": 1}")));

    const ActionResponse resp = run(gate, make_request(
        "confirm_transfer", "a2", "ai", "{\"pending_id\": \"" + pending_id + "\"}"));

    EXPECT_EQ(resp.status(), ActionStatus::ACTION_ERROR);
    EXPECT_NE(resp.error().find("permission denied"), std::string::npos);
    EXPECT_NE(resp.error().find("ai"), std::string::npos)
        << "error should name the denied caller: " << resp.error();
    EXPECT_EQ(resp.error().find(pending_id), std::string::npos)
        << "denied callers must not learn pending ids: " << resp.error();
    EXPECT_EQ(gate.pending_count(), 1u) << "the real caller can still confirm";
}

TEST(ConfirmationGate, PrefixGlobMatchesAllSubDevices) {
    const ConfirmationGate gate = make_gate({"device.*"});
    const std::string pending_id =
        extract_pending_id(run(gate, make_request(
            "request_transfer", "a1", "device.phone", "{\"amount\": 1}")));

    // Any device.* mirror may confirm.
    const ActionResponse ok = run(gate, make_request(
        "confirm_transfer", "a2", "device.geo",
        "{\"pending_id\": \"" + pending_id + "\"}"));
    EXPECT_EQ(ok.status(), ActionStatus::ACTION_OK);

    // A non-device caller still cannot.
    const ActionResponse denied = run(gate, make_request(
        "confirm_transfer", "a3", "ai",
        "{\"pending_id\": \"" + extract_pending_id(run(gate, make_request(
            "request_transfer", "a4", "ai", "{}"))) + "\"}"));
    EXPECT_EQ(denied.status(), ActionStatus::ACTION_ERROR);
}

TEST(ConfirmationGate, UnknownOrMissingPendingIdErrors) {
    const ConfirmationGate gate = make_gate({"device.phone"});

    const ActionResponse unknown = run(gate, make_request(
        "confirm_transfer", "a1", "device.phone",
        "{\"pending_id\": \"pending-does-not-exist\"}"));
    EXPECT_EQ(unknown.status(), ActionStatus::ACTION_ERROR);
    EXPECT_NE(unknown.error().find("no pending transfer request"), std::string::npos);

    const ActionResponse malformed = run(gate, make_request(
        "confirm_transfer", "a2", "device.phone", "{}"));
    EXPECT_EQ(malformed.status(), ActionStatus::ACTION_ERROR);
    EXPECT_NE(malformed.error().find("pending_id"), std::string::npos);
}

TEST(ConfirmationGate, ExpiredPendingIsSweptAndCannotBeConfirmed) {
    ConfirmationGate gate = make_gate({"device.phone"});
    gate.with_pending_ttl(std::chrono::milliseconds(10));

    const std::string pending_id =
        extract_pending_id(run(gate, make_request(
            "request_transfer", "a1", "ai", "{\"amount\": 1}")));
    ASSERT_EQ(gate.pending_count(), 1u);

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    // The next route call sweeps the expired entry before looking up.
    const ActionResponse resp = run(gate, make_request(
        "confirm_transfer", "a2", "device.phone",
        "{\"pending_id\": \"" + pending_id + "\"}"));
    EXPECT_EQ(resp.status(), ActionStatus::ACTION_ERROR);
    EXPECT_NE(resp.error().find("no pending transfer request"), std::string::npos);
    EXPECT_EQ(gate.pending_count(), 0u) << "expired entry swept";
}

TEST(ConfirmationGate, UnknownActionsGetActionNotFound) {
    const ConfirmationGate gate = make_gate({"device.phone"});

    const ActionResponse other = run(gate, make_request("do_something_else", "a1", "ai", "{}"));
    EXPECT_EQ(other.status(), ActionStatus::ACTION_NOT_FOUND);

    // Cross-op requests are not routed by this gate either.
    const ActionResponse cross_op = run(gate, make_request("request_other_op", "a2", "ai", "{}"));
    EXPECT_EQ(cross_op.status(), ActionStatus::ACTION_NOT_FOUND);
}

TEST(ConfirmationGate, ManifestEntriesCarryConfirmationMetadata) {
    const ConfirmationGate gate = make_gate({"device.phone"});
    const auto [actions, specs] = gate.manifest_entries();

    ASSERT_EQ(actions.size(), 2u);
    EXPECT_EQ(actions[0], "request_transfer");
    EXPECT_EQ(actions[1], "confirm_transfer");

    ASSERT_EQ(specs.size(), 2u);
    EXPECT_EQ(specs[0].name(), "request_transfer");
    EXPECT_TRUE(specs[0].requires_confirmation());
    EXPECT_EQ(specs[0].risk(), ActionRisk::ACTION_RISK_CRITICAL);
    EXPECT_EQ(specs[0].params_schema(), "{\"type\":\"object\"}");

    EXPECT_EQ(specs[1].name(), "confirm_transfer");
    EXPECT_FALSE(specs[1].requires_confirmation());
    EXPECT_NE(specs[1].params_schema().find("pending_id"), std::string::npos);
}

TEST(ConfirmationGate, InvalidOperationsAreRejectedAtConstruction) {
    EXPECT_THROW(make_gate({}) /* empty allowlist */, std::invalid_argument);
    EXPECT_THROW(ConfirmationGate("", "d", "{}", ActionRisk::ACTION_RISK_LOW, {"x"}),
                 std::invalid_argument);
    EXPECT_THROW(ConfirmationGate("bad op", "d", "{}", ActionRisk::ACTION_RISK_LOW, {"x"}),
                 std::invalid_argument);
    EXPECT_THROW(ConfirmationGate("request_x", "d", "{}", ActionRisk::ACTION_RISK_LOW, {"x"}),
                 std::invalid_argument)
        << "request_ prefix would collide with the gate's own naming";
    EXPECT_THROW(ConfirmationGate("ok-op", "", "{}", ActionRisk::ACTION_RISK_LOW, {"x"}),
                 std::invalid_argument);
    EXPECT_NO_THROW(ConfirmationGate("ok-op", "d", "{}", ActionRisk::ACTION_RISK_LOW, {"x"}));
}

TEST(ConfirmationGate, ConfirmAllowlistMatchesExactAndGlob) {
    const ConfirmationGate exact = make_gate({"device.phone", "host-ui"});
    EXPECT_TRUE(exact.may_confirm("device.phone"));
    EXPECT_TRUE(exact.may_confirm("host-ui"));
    EXPECT_FALSE(exact.may_confirm("device.geo"));
    EXPECT_FALSE(exact.may_confirm("ai"));

    const ConfirmationGate glob = make_gate({"device.*"});
    EXPECT_TRUE(glob.may_confirm("device.phone"));
    EXPECT_TRUE(glob.may_confirm("device.geo"));
    EXPECT_FALSE(glob.may_confirm("devices.phone"))
        << "the glob keeps the dot";
    EXPECT_FALSE(glob.may_confirm("ai"));
}
