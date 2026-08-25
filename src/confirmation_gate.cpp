#include "vynkor/confirmation_gate.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <stdexcept>

namespace vynkor {

namespace {

uint64_t unix_millis() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

uint64_t next_seq() {
    static std::atomic<uint64_t> seq{0};
    return seq.fetch_add(1, std::memory_order_relaxed);
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (const char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20)
                out += "\\u" + [&] {
                    char buf[5];
                    std::snprintf(buf, sizeof(buf), "%04x", c);
                    return std::string(buf);
                }();
            else
                out += c;
        }
    }
    return out;
}

// Extracts the string value of `key` from a JSON object without pulling in a
// JSON library — the gate only ever reads {"pending_id": "..."} shapes.
std::optional<std::string> json_find_string(const std::string& json,
                                            const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = 0;
    while (true) {
        pos = json.find(needle, pos);
        if (pos == std::string::npos)
            return std::nullopt;

        // Require the match to be a real key: preceded by start/{/, and
        // followed by optional ws, ':', optional ws, then a string.
        const bool key_start_ok = pos == 0 || json[pos - 1] == '{' || json[pos - 1] == ',';
        pos += needle.size();
        if (!key_start_ok)
            continue;

        size_t cursor = pos;
        while (cursor < json.size() && (json[cursor] == ' ' || json[cursor] == '\t'))
            ++cursor;
        if (cursor >= json.size() || json[cursor] != ':')
            continue;
        ++cursor;
        while (cursor < json.size() && (json[cursor] == ' ' || json[cursor] == '\t'))
            ++cursor;
        if (cursor >= json.size() || json[cursor] != '"')
            continue;
        ++cursor;

        std::string value;
        while (cursor < json.size()) {
            const char c = json[cursor];
            if (c == '"')
                return value;
            if (c != '\\') {
                value += c;
                ++cursor;
                continue;
            }
            if (++cursor >= json.size())
                return std::nullopt;
            switch (json[cursor]) {
            case '"':  value += '"';  break;
            case '\\': value += '\\'; break;
            case '/':  value += '/';  break;
            case 'b':  value += '\b'; break;
            case 'f':  value += '\f'; break;
            case 'n':  value += '\n'; break;
            case 'r':  value += '\r'; break;
            case 't':  value += '\t'; break;
            case 'u': {
                if (cursor + 4 >= json.size())
                    return std::nullopt;
                const unsigned cp =
                    static_cast<unsigned>(std::stoul(json.substr(cursor + 1, 4), nullptr, 16));
                cursor += 4;
                if (cp < 0x80) {
                    value += static_cast<char>(cp);
                } else if (cp < 0x800) {
                    value += static_cast<char>(0xC0 | (cp >> 6));
                    value += static_cast<char>(0x80 | (cp & 0x3F));
                } else {
                    value += static_cast<char>(0xE0 | (cp >> 12));
                    value += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                    value += static_cast<char>(0x80 | (cp & 0x3F));
                }
                break;
            }
            default: return std::nullopt;
            }
            ++cursor;
        }
        return std::nullopt;
    }
}

std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace

// ---------------------------------------------------------------------------
// ConfirmationGate
// ---------------------------------------------------------------------------
ConfirmationGate::ConfirmationGate(std::string op, std::string description,
                                   std::string params_schema, ActionRisk risk,
                                   std::vector<std::string> confirm_callers)
    : op_(std::move(op))
    , description_(std::move(description))
    , params_schema_(std::move(params_schema))
    , risk_(risk)
    , confirm_callers_(std::move(confirm_callers)) {
    const auto invalid = [](const std::string& why) {
        throw std::invalid_argument("ConfirmationGate: " + why);
    };
    if (op_.empty())
        invalid("operation name must not be empty");
    if (!std::all_of(op_.begin(), op_.end(), [](char c) {
            // C locale: isalnum matches [0-9A-Za-z] only.
            return std::isalnum(static_cast<unsigned char>(c)) != 0 ||
                   c == '-' || c == '_';
        }))
        invalid("operation name may only contain ASCII alphanumerics, '-' and '_'");
    if (op_.rfind("request_", 0) == 0 || op_.rfind("confirm_", 0) == 0)
        invalid("operation name must not start with request_/confirm_ "
                "(would collide with the gate's own action names)");
    if (description_.empty())
        invalid("description must not be empty");
    if (confirm_callers_.empty())
        invalid("confirm_callers must name at least one caller allowed to confirm");
}

ConfirmationGate& ConfirmationGate::with_pending_ttl(std::chrono::milliseconds ttl) {
    pending_ttl_ = ttl;
    return *this;
}

std::pair<std::vector<std::string>, std::vector<ActionSpec>>
ConfirmationGate::manifest_entries() const {
    const std::string request = "request_" + op_;
    const std::string confirm = "confirm_" + op_;

    ActionSpec request_spec;
    request_spec.set_name(request);
    request_spec.set_description(
        description_ +
        " — requests execution; the operation only runs after an approved caller confirms"
        " (requires_confirmation).");
    request_spec.set_params_schema(params_schema_);
    request_spec.set_risk(risk_);
    request_spec.set_requires_confirmation(true);

    ActionSpec confirm_spec;
    confirm_spec.set_name(confirm);
    confirm_spec.set_description(
        description_ +
        " — executes a previously requested operation; only approved callers may invoke.");
    confirm_spec.set_params_schema(
        "{\"type\":\"object\",\"properties\":{\"pending_id\":{\"type\":\"string\"}},"
        "\"required\":[\"pending_id\"]}");
    confirm_spec.set_risk(risk_);
    confirm_spec.set_requires_confirmation(false);

    return {{request, confirm}, {request_spec, confirm_spec}};
}

bool ConfirmationGate::may_confirm(const std::string& caller_plugin_id) const {
    return std::any_of(confirm_callers_.begin(), confirm_callers_.end(),
                       [&](const std::string& allowed) {
                           const std::string glob = ".*";
                           if (allowed.size() > glob.size() &&
                               allowed.compare(allowed.size() - 2, 2, glob) == 0) {
                               const std::string prefix = allowed.substr(0, allowed.size() - 2);
                               return caller_plugin_id.rfind(prefix, 0) == 0 &&
                                      caller_plugin_id.size() > prefix.size() &&
                                      caller_plugin_id[prefix.size()] == '.';
                           }
                           return caller_plugin_id == allowed;
                       });
}

size_t ConfirmationGate::pending_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return pending_.size();
}

void ConfirmationGate::sweep_expired_locked() const {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (now - it->second.created_at >= pending_ttl_)
            it = pending_.erase(it);
        else
            ++it;
    }
}

std::string ConfirmationGate::store_request(const ActionRequest& req) const {
    std::lock_guard<std::mutex> lock(mu_);
    sweep_expired_locked();
    const std::string id = "pending-" + std::to_string(unix_millis()) + "-" +
                           std::to_string(next_seq());
    PendingAction pending;
    pending.action = req.action();
    pending.params.assign(req.params_json().begin(), req.params_json().end());
    pending.caller_plugin_id = req.caller_plugin_id();
    pending.created_at = std::chrono::steady_clock::now();
    pending_.emplace(id, std::move(pending));
    return id;
}

std::optional<PendingAction> ConfirmationGate::take_pending(
    const std::string& pending_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    sweep_expired_locked();
    const auto it = pending_.find(pending_id);
    if (it == pending_.end())
        return std::nullopt;
    PendingAction pending = std::move(it->second);
    pending_.erase(it);
    return pending;
}

std::vector<Envelope> ConfirmationGate::not_found(const std::string& action_id) {
    Envelope env;
    auto* resp = env.mutable_action_response();
    resp->set_action_id(action_id);
    resp->set_status(ActionStatus::ACTION_NOT_FOUND);
    resp->set_error("unknown action");
    return {env};
}

std::vector<Envelope> ConfirmationGate::route(
    const ActionRequest& req,
    const std::function<ActionResult(const std::vector<uint8_t>&)>& executor) const {
    const std::string& action = req.action();

    if (action.rfind("request_", 0) == 0) {
        if (action.substr(8) != op_)
            return not_found(req.action_id());

        const std::string pending_id = store_request(req);
        const std::string data =
            "{\"pending_id\":\"" + json_escape(pending_id) +
            "\",\"action\":\"" + json_escape(action) +
            "\",\"ttl_secs\":" +
            std::to_string(std::chrono::duration_cast<std::chrono::seconds>(pending_ttl_).count()) +
            "}";
        return {response_envelope(req.action_id(), ActionResult::Ok(to_bytes(data)))};
    }

    if (action.rfind("confirm_", 0) == 0) {
        if (action.substr(8) != op_)
            return not_found(req.action_id());

        // Deny before looking up the pending id so denied callers learn
        // nothing about which pending ids exist.
        if (!may_confirm(req.caller_plugin_id())) {
            std::string allowlist;
            for (size_t i = 0; i < confirm_callers_.size(); ++i) {
                if (i != 0)
                    allowlist += ", ";
                allowlist += confirm_callers_[i];
            }
            return {response_envelope(
                req.action_id(),
                ActionResult::Err("permission denied: caller " + req.caller_plugin_id() +
                                  " may not confirm " + op_ +
                                  " (approved callers: " + allowlist + ")"))};
        }

        const std::optional<std::string> pending_id =
            json_find_string(req.params_json(), "pending_id");
        if (!pending_id) {
            return {response_envelope(
                req.action_id(),
                ActionResult::Err("invalid confirm params: confirm params must include a"
                                  " string pending_id"))};
        }
        const std::optional<PendingAction> pending = take_pending(*pending_id);
        if (!pending) {
            return {response_envelope(
                req.action_id(),
                ActionResult::Err("no pending " + op_ + " request with id " + *pending_id))};
        }

        // Execute with the *stored* params, never the confirm-time ones —
        // the confirming caller cannot swap in different arguments.
        const ActionResult result = executor(pending->params);
        return {response_envelope(req.action_id(), result)};
    }

    return not_found(req.action_id());
}

// ---------------------------------------------------------------------------
// Caller-side helpers
// ---------------------------------------------------------------------------
std::string send_confirmation_request(VynkorClient& client,
                                      const std::string& op,
                                      const std::vector<uint8_t>& params_json) {
    const ActionResponse resp = client.send_action("request_" + op, params_json, 0);
    if (resp.status() != ActionStatus::ACTION_OK)
        throw VynkorInternal("request_" + op + " failed: " + resp.error());

    const std::string data(resp.data_json().begin(), resp.data_json().end());
    const std::optional<std::string> pending_id = json_find_string(data, "pending_id");
    if (!pending_id)
        throw VynkorInternal("pending response missing pending_id");
    return *pending_id;
}

ActionResponse send_confirmation(VynkorClient& client,
                                 const std::string& op,
                                 const std::string& pending_id) {
    const std::string params = "{\"pending_id\":\"" + json_escape(pending_id) + "\"}";
    return client.send_action("confirm_" + op, to_bytes(params), 0);
}

} // namespace vynkor
