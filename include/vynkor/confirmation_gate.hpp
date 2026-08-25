#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "vynkor/client.hpp"
#include "vynkor/concurrent.hpp"
#include "vynkor_protocol.pb.h"

namespace vynkor {

// Default lifetime of an unconfirmed pending request (5 minutes).
static constexpr std::chrono::milliseconds DEFAULT_PENDING_TTL{300000};

// A stored request_<op> awaiting confirmation.
struct PendingAction {
    std::string          action;
    std::vector<uint8_t> params;
    std::string          caller_plugin_id;
    std::chrono::steady_clock::time_point created_at;
};

// Plugin-side confirmation gate for one high-risk operation (D-09): splits
// `op` into `request_<op>` (any caller; stores params as pending) and
// `confirm_<op>` (only allowlisted callers; executes the *stored* params).
//
// The kernel stays dumb on purpose — the gate lives entirely inside the
// plugin, keyed on the kernel-stamped ActionRequest::caller_plugin_id, which
// the kernel overwrites from the real registered sender on every forwarded
// request, so the check cannot be spoofed by the caller.
//
// Share one instance across concurrent handler threads: the only interior
// state is the pending map behind a mutex never held across user callbacks.
class ConfirmationGate {
public:
    // Create a gate named `request_<op>` / `confirm_<op>`. Throws
    // std::invalid_argument when op is empty / has characters outside
    // [A-Za-z0-9_-] / starts with request_ or confirm_ (would collide with
    // the gate's own action names), when description is empty, or when
    // confirm_callers is empty.
    ConfirmationGate(std::string op, std::string description,
                     std::string params_schema, ActionRisk risk,
                     std::vector<std::string> confirm_callers);

    // Override how long an unconfirmed pending request survives.
    ConfirmationGate& with_pending_ttl(std::chrono::milliseconds ttl);

    const std::string& op() const { return op_; }

    // Merge into PluginManifest: the two action names for actions[] plus the
    // two ActionSpecs served to the AI (D-08) — request_<op> marked
    // requires_confirmation, confirm_<op> carrying its pending_id schema.
    std::pair<std::vector<std::string>, std::vector<ActionSpec>>
    manifest_entries() const;

    // Route one inbound ActionRequest through the gate:
    //   - request_<op> from any caller → stores params, replies
    //     {"pending_id": ..., "action": ..., "ttl_secs": ...}
    //   - confirm_<op> with {"pending_id": ...} from an allowlisted caller →
    //     hands the stored params to `executor` and replies with its result;
    //     any other caller → permission-denied ACTION_ERROR (checked before
    //     the pending lookup, so denied callers learn nothing about which
    //     pending ids exist); unknown/expired pending_id → ACTION_ERROR
    //   - anything else → ACTION_NOT_FOUND ("unknown action")
    // Returns the response envelopes for the concurrent loop; a sequential
    // Plugin::on_message implementation takes the single element.
    std::vector<Envelope> route(
        const ActionRequest& req,
        const std::function<ActionResult(const std::vector<uint8_t>&)>& executor) const;

    // Whether caller_plugin_id is on the confirm allowlist: exact ids, or a
    // `prefix.*` glob matching any caller whose id starts with `prefix.`
    // (`device.*` matches `device.phone` but not `devices.phone`).
    bool may_confirm(const std::string& caller_plugin_id) const;

    // Snapshot of the pending map size, for inspection/tests.
    size_t pending_count() const;

private:
    std::string store_request(const ActionRequest& req) const;
    std::optional<PendingAction> take_pending(const std::string& pending_id) const;
    void sweep_expired_locked() const;

    static std::vector<Envelope> not_found(const std::string& action_id);

    std::string            op_;
    std::string            description_;
    std::string            params_schema_;
    ActionRisk             risk_;
    std::vector<std::string> confirm_callers_;
    std::chrono::milliseconds pending_ttl_{DEFAULT_PENDING_TTL};

    mutable std::mutex mu_;
    mutable std::map<std::string, PendingAction> pending_;
};

// Caller-side one-liner for the requesting side (e.g. the AI): invoke a
// plugin's `request_<op>` with params_json and return the assigned
// pending_id. Throws VynkorInternal unless the plugin replies ActionOk with
// a pending_id.
std::string send_confirmation_request(VynkorClient& client,
                                      const std::string& op,
                                      const std::vector<uint8_t>& params_json);

// Caller-side one-liner for the confirming side (e.g. the user's device):
// invoke the plugin's `confirm_<op>` with pending_id; returns its
// ActionResponse as-is (a caller not on the confirm allowlist gets an
// ACTION_ERROR response).
ActionResponse send_confirmation(VynkorClient& client,
                                 const std::string& op,
                                 const std::string& pending_id);

} // namespace vynkor
