#include "vynkor/mac.hpp"

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <cstring>

#include "vynkor/error.hpp"

namespace vynkor {

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869) using OpenSSL HMAC
// ---------------------------------------------------------------------------

static std::array<uint8_t, 32> hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len)
{
    std::array<uint8_t, 32> out{};
    unsigned int out_len = 32;
    if (!HMAC(EVP_sha256(), key, static_cast<int>(key_len),
              data, data_len, out.data(), &out_len))
        throw VynkorInternal("mac: HMAC failed");
    return out;
}

static std::array<uint8_t, 32> hkdf_extract(
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& ikm)
{
    return hmac_sha256(salt.data(), salt.size(), ikm.data(), ikm.size());
}

static std::array<uint8_t, 32> hkdf_expand(
    const std::array<uint8_t, 32>& prk,
    const std::vector<uint8_t>& info,
    size_t length)
{
    // Single round: T(1) = HMAC(PRK, "" || info || 0x01)
    // We only ever need 32 bytes so one round suffices.
    if (length > 32)
        throw VynkorInternal("mac: hkdf_expand length > 32 unsupported");

    std::vector<uint8_t> input;
    input.insert(input.end(), info.begin(), info.end());
    input.push_back(0x01);
    auto t1 = hmac_sha256(prk.data(), 32, input.data(), input.size());

    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), t1.data(), length);
    return out;
}

std::array<uint8_t, 32> derive_session_key(
    const std::vector<uint8_t>& secret,
    const std::vector<uint8_t>& nonce,
    const std::string& plugin_id)
{
    auto prk = hkdf_extract(nonce, secret);

    std::vector<uint8_t> info;
    const char prefix[] = "vynkor-frame-mac-v1|";
    info.insert(info.end(), prefix, prefix + sizeof(prefix) - 1);
    info.insert(info.end(), plugin_id.begin(), plugin_id.end());

    return hkdf_expand(prk, info, 32);
}

// ---------------------------------------------------------------------------
// Frame MAC
// ---------------------------------------------------------------------------

std::array<uint8_t, 32> compute_tag(
    const std::array<uint8_t, 32>& key,
    const uint8_t* header, size_t header_len,
    const uint8_t* payload, size_t payload_len)
{
    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx)
        throw VynkorInternal("mac: HMAC_CTX_new failed");

    std::array<uint8_t, 32> out{};
    unsigned int out_len = 32;

    if (!HMAC_Init_ex(ctx, key.data(), 32, EVP_sha256(), nullptr) ||
        !HMAC_Update(ctx, header, header_len) ||
        !HMAC_Update(ctx, payload, payload_len) ||
        !HMAC_Final(ctx, out.data(), &out_len))
    {
        HMAC_CTX_free(ctx);
        throw VynkorInternal("mac: HMAC computation failed");
    }

    HMAC_CTX_free(ctx);
    return out;
}

bool verify_tag(
    const std::array<uint8_t, 32>& key,
    const uint8_t* header, size_t header_len,
    const uint8_t* payload, size_t payload_len,
    const uint8_t* tag, size_t tag_len)
{
    if (tag_len != 32)
        return false;
    auto expected = compute_tag(key, header, header_len, payload, payload_len);
    return CRYPTO_memcmp(expected.data(), tag, 32) == 0;
}

} // namespace vynkor
