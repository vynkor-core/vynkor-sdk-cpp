#include <gtest/gtest.h>
#include "vynkor/mac.hpp"

using namespace vynkor;

TEST(DeriveSessionKey, Deterministic) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce  = {'n','o','n','c','e','-','0','1','2','3','4','5','6','7','8','9'};
    auto k1 = derive_session_key(secret, nonce, "plugin-a");
    auto k2 = derive_session_key(secret, nonce, "plugin-a");
    EXPECT_EQ(k1, k2);
}

TEST(DeriveSessionKey, InputSensitive) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce  = {'n','o','n','c','e','-','0','1','2','3','4','5','6','7','8','9'};
    auto base = derive_session_key(secret, nonce, "plugin-a");

    std::vector<uint8_t> other_secret = {'o','t','h','e','r','!'};
    EXPECT_NE(base, derive_session_key(other_secret, nonce, "plugin-a"));

    std::vector<uint8_t> other_nonce = {'x','x','x','x','x','x','x','x','x','x','x','x','x','x','x','x'};
    EXPECT_NE(base, derive_session_key(secret, other_nonce, "plugin-a"));

    EXPECT_NE(base, derive_session_key(secret, nonce, "plugin-b"));
}

TEST(DeriveSessionKey, Matches32Bytes) {
    std::vector<uint8_t> secret = {'s'};
    std::vector<uint8_t> nonce(16, 0xAB);
    auto key = derive_session_key(secret, nonce, "p");
    EXPECT_EQ(key.size(), size_t(32));
}

TEST(ComputeVerifyTag, RoundTrip) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce(16, 0x01);
    auto key = derive_session_key(secret, nonce, "p");

    uint8_t header[44] = {};
    for (int i = 0; i < 44; ++i) header[i] = static_cast<uint8_t>(i);
    const uint8_t payload[] = {'h','e','l','l','o'};

    auto tag = compute_tag(key, header, 44, payload, 5);
    EXPECT_TRUE(verify_tag(key, header, 44, payload, 5, tag.data(), 32));
}

TEST(ComputeVerifyTag, TamperedPayloadRejected) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce(16, 0x01);
    auto key = derive_session_key(secret, nonce, "p");

    uint8_t header[44] = {};
    const uint8_t payload[]  = {'h','e','l','l','o'};
    const uint8_t bad_pl[]   = {'h','e','l','l','x'};

    auto tag = compute_tag(key, header, 44, payload, 5);
    EXPECT_FALSE(verify_tag(key, header, 44, bad_pl, 5, tag.data(), 32));
}

TEST(ComputeVerifyTag, TamperedHeaderRejected) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce(16, 0x01);
    auto key = derive_session_key(secret, nonce, "p");

    uint8_t header[44] = {};
    uint8_t bad_hdr[44] = {};
    bad_hdr[0] = 0xFF;
    const uint8_t payload[] = {'h','e','l','l','o'};

    auto tag = compute_tag(key, header, 44, payload, 5);
    EXPECT_FALSE(verify_tag(key, bad_hdr, 44, payload, 5, tag.data(), 32));
}

TEST(ComputeVerifyTag, WrongKeyRejected) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce_a(16, 0x01);
    std::vector<uint8_t> nonce_b(16, 0x02);
    auto key_a = derive_session_key(secret, nonce_a, "p");
    auto key_b = derive_session_key(secret, nonce_b, "p");

    uint8_t header[44] = {};
    const uint8_t payload[] = {'h','e','l','l','o'};
    auto tag = compute_tag(key_a, header, 44, payload, 5);
    EXPECT_FALSE(verify_tag(key_b, header, 44, payload, 5, tag.data(), 32));
}

// ---------------------------------------------------------------------------
// Framing MAC tests (Task 4)
// ---------------------------------------------------------------------------
#include "vynkor/framing.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>

static std::pair<int,int> make_pipe() {
    int fds[2];
    if (::pipe(fds) != 0) throw std::runtime_error("pipe failed");
    return {fds[0], fds[1]};
}

TEST(FramingMac, PackFrameMacSetsFlag) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce(16, 0x01);
    auto key = vynkor::derive_session_key(secret, nonce, "tgt");

    std::vector<uint8_t> payload = {'h','e','l','l','o'};
    auto frame = vynkor::pack_frame_mac("tgt", payload, key);

    ASSERT_EQ(frame.size(), size_t(44 + 5 + 32));

    uint16_t flags;
    std::memcpy(&flags, frame.data() + 2, 2);
    flags = ntohs(flags);
    EXPECT_TRUE(flags & vynkor::FLAG_MAC_PRESENT);
}

TEST(FramingMac, ReadFrameFullVerifiesValidMac) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce(16, 0x01);
    auto key = vynkor::derive_session_key(secret, nonce, "tgt");

    std::vector<uint8_t> payload = {'h','e','l','l','o'};
    auto frame = vynkor::pack_frame_mac("tgt", payload, key);

    auto [read_fd, write_fd] = make_pipe();
    ::write(write_fd, frame.data(), frame.size());
    ::close(write_fd);

    auto result = vynkor::read_frame_full(read_fd, &key);
    ::close(read_fd);

    EXPECT_EQ(result.payload, payload);
    EXPECT_TRUE(result.has_mac);
}

TEST(FramingMac, ReadFrameFullRejectsTamperedTag) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce(16, 0x01);
    auto key = vynkor::derive_session_key(secret, nonce, "tgt");

    std::vector<uint8_t> payload = {'h','i'};
    auto frame = vynkor::pack_frame_mac("tgt", payload, key);
    frame.back() ^= 0xFF;

    auto [read_fd, write_fd] = make_pipe();
    ::write(write_fd, frame.data(), frame.size());
    ::close(write_fd);

    EXPECT_THROW(vynkor::read_frame_full(read_fd, &key), vynkor::VeyronInternal);
    ::close(read_fd);
}

TEST(FramingMac, ReadFrameFullNoKeySkipsVerification) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce(16, 0x01);
    auto key = vynkor::derive_session_key(secret, nonce, "tgt");

    std::vector<uint8_t> payload = {'n','o','k','e','y'};
    auto frame = vynkor::pack_frame_mac("tgt", payload, key);

    auto [read_fd, write_fd] = make_pipe();
    ::write(write_fd, frame.data(), frame.size());
    ::close(write_fd);

    auto result = vynkor::read_frame_full(read_fd, nullptr);
    ::close(read_fd);

    EXPECT_EQ(result.payload, payload);
    EXPECT_TRUE(result.has_mac);
}

// ---------------------------------------------------------------------------
// Client MAC test (Task 5)
// ---------------------------------------------------------------------------
#include "vynkor/client.hpp"

TEST(VeyronClientMac, DeriveSessionKeyAfterMockAck) {
    std::vector<uint8_t> secret = {'j','w','t','s','e','c'};
    std::vector<uint8_t> nonce(16, 0xBE);

    Envelope ack_env;
    auto* ack = ack_env.mutable_plugin_register_ack();
    ack->set_accepted(true);
    ack->set_session_nonce(std::string(nonce.begin(), nonce.end()));
    std::string serialized;
    ack_env.SerializeToString(&serialized);

    auto frame = vynkor::pack_frame("plugin-test", serialized);

    auto [read_fd, write_fd] = make_pipe();
    ::write(write_fd, frame.data(), frame.size());
    ::close(write_fd);

    auto expected_key = vynkor::derive_session_key(secret, nonce, "plugin-test");

    auto result = vynkor::read_frame_full(read_fd, nullptr);
    ::close(read_fd);

    Envelope parsed;
    ASSERT_TRUE(parsed.ParseFromArray(result.payload.data(),
                                     static_cast<int>(result.payload.size())));
    ASSERT_TRUE(parsed.has_plugin_register_ack());
    const auto& parsed_ack = parsed.plugin_register_ack();
    ASSERT_TRUE(parsed_ack.accepted());

    auto raw_nonce = parsed_ack.session_nonce();
    std::vector<uint8_t> parsed_nonce(raw_nonce.begin(), raw_nonce.end());
    auto derived = vynkor::derive_session_key(secret, parsed_nonce, "plugin-test");
    EXPECT_EQ(derived, expected_key);
}

// ---------------------------------------------------------------------------
// Compressed frame tests (R5-01) — kernel zstd-compresses payloads >= 64 KiB;
// read_frame_full must decompress and verify MAC against the plaintext.
// ---------------------------------------------------------------------------
#include <zstd.h>

// Builds a wire frame the way the kernel does for large payloads: zstd-compress,
// set FLAG_COMPRESSED, CRC over the compressed bytes, MAC (if any) over the
// *plaintext* header+payload — mirroring src/ipc/framing.rs write_frame_raw.
static std::vector<uint8_t> pack_compressed_frame(const std::string& target,
                                                  const std::vector<uint8_t>& plain,
                                                  const std::array<uint8_t, 32>* session_key) {
    std::vector<uint8_t> compressed(ZSTD_compressBound(plain.size()));
    size_t csize = ZSTD_compress(compressed.data(), compressed.size(),
                                 plain.data(), plain.size(), 3);
    if (ZSTD_isError(csize)) throw std::runtime_error("zstd compress failed");
    compressed.resize(csize);

    uint16_t flags = vynkor::FLAG_COMPRESSED;
    if (session_key != nullptr) flags |= vynkor::FLAG_MAC_PRESENT;

    uint8_t target_bytes[32] = {};
    std::memcpy(target_bytes, target.data(), std::min(target.size(), size_t{32}));

    uint8_t wire_header[44] = {};
    uint16_t magic_be = htons(vynkor::FRAME_MAGIC);
    std::memcpy(wire_header + 0, &magic_be, 2);
    uint16_t flags_be = htons(flags);
    std::memcpy(wire_header + 2, &flags_be, 2);
    uint32_t len_be = htonl(static_cast<uint32_t>(compressed.size()));
    std::memcpy(wire_header + 4, &len_be, 4);
    std::memcpy(wire_header + 8, target_bytes, 32);
    uint32_t wire_crc_be = htonl(vynkor::vynkor_crc32(compressed.data(), compressed.size()));
    std::memcpy(wire_header + 40, &wire_crc_be, 4);

    std::vector<uint8_t> frame(wire_header, wire_header + 44);
    frame.insert(frame.end(), compressed.begin(), compressed.end());

    if (session_key != nullptr) {
        uint16_t plain_flags = flags & static_cast<uint16_t>(~vynkor::FLAG_COMPRESSED);
        uint8_t plain_header[44] = {};
        std::memcpy(plain_header + 0, &magic_be, 2);
        uint16_t plain_flags_be = htons(plain_flags);
        std::memcpy(plain_header + 2, &plain_flags_be, 2);
        uint32_t plain_len_be = htonl(static_cast<uint32_t>(plain.size()));
        std::memcpy(plain_header + 4, &plain_len_be, 4);
        std::memcpy(plain_header + 8, target_bytes, 32);
        uint32_t plain_crc_be = htonl(vynkor::vynkor_crc32(plain.data(), plain.size()));
        std::memcpy(plain_header + 40, &plain_crc_be, 4);

        auto tag = vynkor::compute_tag(*session_key, plain_header, 44, plain.data(), plain.size());
        frame.insert(frame.end(), tag.begin(), tag.end());
    }

    return frame;
}

TEST(FramingCompressed, DecompressesLargePayload) {
    std::vector<uint8_t> plain(100'000);
    for (size_t i = 0; i < plain.size(); ++i) plain[i] = static_cast<uint8_t>(i);

    auto frame = pack_compressed_frame("kernel", plain, nullptr);

    auto [read_fd, write_fd] = make_pipe();
    ::write(write_fd, frame.data(), frame.size());
    ::close(write_fd);

    auto result = vynkor::read_frame_full(read_fd, nullptr);
    ::close(read_fd);

    EXPECT_EQ(result.payload, plain);
    EXPECT_FALSE(result.flags & vynkor::FLAG_COMPRESSED);
}

TEST(FramingCompressed, DecompressesAndVerifiesMac) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce(16, 0x03);
    auto key = vynkor::derive_session_key(secret, nonce, "tgt");

    std::vector<uint8_t> plain(100'000, 0x7A);
    auto frame = pack_compressed_frame("tgt", plain, &key);

    auto [read_fd, write_fd] = make_pipe();
    ::write(write_fd, frame.data(), frame.size());
    ::close(write_fd);

    auto result = vynkor::read_frame_full(read_fd, &key);
    ::close(read_fd);

    EXPECT_EQ(result.payload, plain);
    EXPECT_TRUE(result.has_mac);
}

TEST(FramingCompressed, RejectsBadMacOnCompressedFrame) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce(16, 0x04);
    auto key = vynkor::derive_session_key(secret, nonce, "tgt");
    auto wrong_key = vynkor::derive_session_key(secret, nonce, "other");

    std::vector<uint8_t> plain(100'000, 0x5B);
    auto frame = pack_compressed_frame("tgt", plain, &key);

    auto [read_fd, write_fd] = make_pipe();
    ::write(write_fd, frame.data(), frame.size());
    ::close(write_fd);

    EXPECT_THROW(vynkor::read_frame_full(read_fd, &wrong_key), vynkor::VeyronInternal);
    ::close(read_fd);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
