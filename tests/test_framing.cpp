// Adversarial-input tests for read_frame_full/pack_frame_mac (T-13).
// Complements test_mac.cpp's FramingMac/FramingCompressed suites, which cover
// the happy paths and MAC tamper cases. This file targets malformed headers
// and truncated/oversized wire input that a hostile or buggy peer could send.
#include <gtest/gtest.h>
#include "vynkor/framing.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>

using namespace vynkor;

static std::pair<int,int> make_pipe() {
    int fds[2];
    if (::pipe(fds) != 0) throw std::runtime_error("pipe failed");
    return {fds[0], fds[1]};
}

static void write_all(int fd, const std::vector<uint8_t>& data) {
    ::write(fd, data.data(), data.size());
}

TEST(FramingMalformed, RejectsBadMagic) {
    std::vector<uint8_t> payload = {'h','i'};
    auto frame = pack_frame("tgt", payload);
    frame[0] ^= 0xFF; // corrupt magic byte

    auto [read_fd, write_fd] = make_pipe();
    write_all(write_fd, frame);
    ::close(write_fd);

    EXPECT_THROW(read_frame_full(read_fd, nullptr), VeyronFrameMagicMismatch);
    ::close(read_fd);
}

TEST(FramingMalformed, RejectsOversizedLengthField) {
    // Header claims a payload larger than MAX_PAYLOAD_SIZE; must be rejected
    // before attempting to read (or allocate) that many bytes.
    uint8_t header[FRAME_HEADER_SIZE] = {};
    uint16_t magic_be = htons(FRAME_MAGIC);
    std::memcpy(header + 0, &magic_be, 2);
    uint32_t huge_len_be = htonl(static_cast<uint32_t>(MAX_PAYLOAD_SIZE) + 1);
    std::memcpy(header + 4, &huge_len_be, 4);

    auto [read_fd, write_fd] = make_pipe();
    write_all(write_fd, std::vector<uint8_t>(header, header + FRAME_HEADER_SIZE));
    ::close(write_fd);

    EXPECT_THROW(read_frame_full(read_fd, nullptr), VeyronPayloadTooLarge);
    ::close(read_fd);
}

TEST(FramingMalformed, RejectsCrcMismatch) {
    std::vector<uint8_t> payload = {'h','e','l','l','o'};
    auto frame = pack_frame("tgt", payload);
    frame.back() ^= 0xFF; // corrupt last payload byte, CRC now stale

    auto [read_fd, write_fd] = make_pipe();
    write_all(write_fd, frame);
    ::close(write_fd);

    EXPECT_THROW(read_frame_full(read_fd, nullptr), VeyronFrameCrcMismatch);
    ::close(read_fd);
}

TEST(FramingMalformed, RejectsTruncatedHeader) {
    // Fewer than FRAME_HEADER_SIZE bytes available before EOF.
    std::vector<uint8_t> partial_header(FRAME_HEADER_SIZE - 1, 0);

    auto [read_fd, write_fd] = make_pipe();
    write_all(write_fd, partial_header);
    ::close(write_fd);

    EXPECT_THROW(read_frame_full(read_fd, nullptr), VeyronIoError);
    ::close(read_fd);
}

TEST(FramingMalformed, RejectsTruncatedPayload) {
    // Header declares a payload length, but the connection closes early.
    std::vector<uint8_t> payload = {'h','e','l','l','o','w','o','r','l','d'};
    auto frame = pack_frame("tgt", payload);
    frame.resize(frame.size() - 3); // drop the last few payload bytes

    auto [read_fd, write_fd] = make_pipe();
    write_all(write_fd, frame);
    ::close(write_fd);

    EXPECT_THROW(read_frame_full(read_fd, nullptr), VeyronIoError);
    ::close(read_fd);
}

TEST(FramingMalformed, RejectsTruncatedMacTag) {
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce(16, 0x02);
    auto key = derive_session_key(secret, nonce, "tgt");

    std::vector<uint8_t> payload = {'h','i'};
    auto frame = pack_frame_mac("tgt", payload, key);
    frame.resize(frame.size() - 5); // truncate the MAC tag itself

    auto [read_fd, write_fd] = make_pipe();
    write_all(write_fd, frame);
    ::close(write_fd);

    EXPECT_THROW(read_frame_full(read_fd, &key), VeyronIoError);
    ::close(read_fd);
}

TEST(FramingMalformed, RejectsGarbageCompressedPayload) {
    // FLAG_COMPRESSED set but payload isn't a valid zstd frame.
    std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02};

    uint8_t header[FRAME_HEADER_SIZE] = {};
    uint16_t magic_be = htons(FRAME_MAGIC);
    std::memcpy(header + 0, &magic_be, 2);
    uint16_t flags_be = htons(FLAG_COMPRESSED);
    std::memcpy(header + 2, &flags_be, 2);
    uint32_t len_be = htonl(static_cast<uint32_t>(garbage.size()));
    std::memcpy(header + 4, &len_be, 4);
    uint32_t crc_be = htonl(vynkor_crc32(garbage.data(), garbage.size()));
    std::memcpy(header + 40, &crc_be, 4);

    std::vector<uint8_t> frame(header, header + FRAME_HEADER_SIZE);
    frame.insert(frame.end(), garbage.begin(), garbage.end());

    auto [read_fd, write_fd] = make_pipe();
    write_all(write_fd, frame);
    ::close(write_fd);

    EXPECT_THROW(read_frame_full(read_fd, nullptr), VeyronInternal);
    ::close(read_fd);
}

TEST(FramingMalformed, RejectsMissingMacOnSecuredConnection) {
    // Frame has no FLAG_MAC_PRESENT, but caller supplies a session key
    // (secured connection) — must be rejected, not silently accepted.
    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    std::vector<uint8_t> nonce(16, 0x05);
    auto key = derive_session_key(secret, nonce, "tgt");

    std::vector<uint8_t> payload = {'n','o','m','a','c'};
    auto frame = pack_frame("tgt", payload); // no MAC

    auto [read_fd, write_fd] = make_pipe();
    write_all(write_fd, frame);
    ::close(write_fd);

    EXPECT_THROW(read_frame_full(read_fd, &key), VeyronInternal);
    ::close(read_fd);
}

TEST(FramingMalformed, AcceptsEmptyPayload) {
    // Zero-length payload is valid, not malformed — guards against an
    // off-by-one that could reject it during the hardening above.
    std::vector<uint8_t> payload;
    auto frame = pack_frame("tgt", payload);

    auto [read_fd, write_fd] = make_pipe();
    write_all(write_fd, frame);
    ::close(write_fd);

    auto result = read_frame_full(read_fd, nullptr);
    ::close(read_fd);

    EXPECT_TRUE(result.payload.empty());
}
