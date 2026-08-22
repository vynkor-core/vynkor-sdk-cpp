#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vynkor {

static constexpr uint16_t FLAG_MAC_PRESENT = 0x0001;
static constexpr size_t   MAC_TAG_LEN      = 32;

// HKDF-SHA256(ikm=secret, salt=nonce, info="vynkor-frame-mac-v1|{plugin_id}") → 32-byte key.
// Mirrors Rust auth::frame_mac::derive_session_key.
std::array<uint8_t, 32> derive_session_key(
    const std::vector<uint8_t>& secret,
    const std::vector<uint8_t>& nonce,
    const std::string& plugin_id);

// HMAC-SHA256(key, header || payload) → 32-byte tag.
std::array<uint8_t, 32> compute_tag(
    const std::array<uint8_t, 32>& key,
    const uint8_t* header, size_t header_len,
    const uint8_t* payload, size_t payload_len);

// Constant-time verification: returns true iff the tag is valid.
bool verify_tag(
    const std::array<uint8_t, 32>& key,
    const uint8_t* header, size_t header_len,
    const uint8_t* payload, size_t payload_len,
    const uint8_t* tag, size_t tag_len);

} // namespace vynkor
