#include <gtest/gtest.h>

#include <netinet/in.h>

#include <cstring>
#include <string>
#include <vector>

#include "vynkor/framing.hpp"
#include "vynkor/mac.hpp"
#include "vynkor/ws.hpp"

using namespace vynkor;

TEST(WsUrlParse, ParsesHostPortPath) {
    const WsUrl url = parse_ws_url("ws://localhost:9000/ws");
    EXPECT_FALSE(url.tls);
    EXPECT_EQ(url.host, "localhost");
    EXPECT_EQ(url.port, 9000);
    EXPECT_EQ(url.path, "/ws");
}

TEST(WsUrlParse, DefaultsPortsAndPath) {
    const WsUrl plain = parse_ws_url("ws://example.com");
    EXPECT_FALSE(plain.tls);
    EXPECT_EQ(plain.port, 80);
    EXPECT_EQ(plain.path, "/");

    const WsUrl tls = parse_ws_url("wss://example.com/gateway");
    EXPECT_TRUE(tls.tls);
    EXPECT_EQ(tls.port, 443);
    EXPECT_EQ(tls.path, "/gateway");
}

TEST(WsUrlParse, RejectsNonWsSchemes) {
    EXPECT_THROW(parse_ws_url("http://example.com"), VynkorInternal);
    EXPECT_THROW(parse_ws_url("example.com/ws"), VynkorInternal);
}

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------
namespace {

std::vector<uint8_t> unmask(const std::vector<uint8_t>& frame, size_t mask_offset,
                            size_t payload_offset) {
    std::array<uint8_t, 4> mask;
    std::memcpy(mask.data(), frame.data() + mask_offset, 4);
    std::vector<uint8_t> out(frame.begin() + static_cast<long>(payload_offset), frame.end());
    for (size_t i = 0; i < out.size(); ++i)
        out[i] ^= mask[i % 4];
    return out;
}

} // namespace

TEST(WsCodec, ClientFrameIsMaskedBinary) {
    const std::vector<uint8_t> payload = {'h', 'i'};
    const std::vector<uint8_t> frame = ws_encode_client_frame(0x2, payload.data(), payload.size());

    ASSERT_GE(frame.size(), 2u + 4u);
    EXPECT_EQ(frame[0], 0x82);          // FIN | binary
    EXPECT_EQ(frame[1] & 0x80, 0x80);   // MASK bit required for client frames
    EXPECT_EQ(frame[1] & 0x7F, 2);      // small length inline

    const std::vector<uint8_t> decoded = unmask(frame, 2, 6);
    EXPECT_EQ(decoded, payload);
}

TEST(WsCodec, ClientFrame16BitLength) {
    std::vector<uint8_t> payload(300, 0xAB);
    const std::vector<uint8_t> frame = ws_encode_client_frame(0x2, payload.data(), payload.size());

    EXPECT_EQ(frame[1] & 0x7F, 126);
    uint16_t be;
    std::memcpy(&be, frame.data() + 2, 2);
    EXPECT_EQ(ntohs(be), 300);

    const std::vector<uint8_t> decoded = unmask(frame, 4, 8);
    EXPECT_EQ(decoded, payload);
}

TEST(WsCodec, DecodeServerBinaryFrame) {
    const std::vector<uint8_t> frame = {static_cast<uint8_t>(0x82), 0x03, 'a', 'b', 'c'};
    WsIncomingFrame out;
    size_t consumed = 0;
    ASSERT_TRUE(ws_try_decode_server_frame(frame, &out, &consumed));
    EXPECT_TRUE(out.fin);
    EXPECT_EQ(out.opcode, 0x2);
    EXPECT_EQ(out.payload, std::vector<uint8_t>({'a', 'b', 'c'}));
    EXPECT_EQ(consumed, frame.size());
}

TEST(WsCodec, DecodeNeedsMoreBytesWhenIncomplete) {
    const std::vector<uint8_t> partial = {static_cast<uint8_t>(0x82), 0x03, 'a'};
    WsIncomingFrame out;
    size_t consumed = 0;
    EXPECT_FALSE(ws_try_decode_server_frame(partial, &out, &consumed));

    const std::vector<uint8_t> header_only = {static_cast<uint8_t>(0x82)};
    EXPECT_FALSE(ws_try_decode_server_frame(header_only, &out, &consumed));
}

TEST(WsCodec, Decodes16BitServerLength) {
    std::vector<uint8_t> frame = {static_cast<uint8_t>(0x82), 126, 0x01, 0x00};
    frame.insert(frame.end(), 256, 'z');
    WsIncomingFrame out;
    size_t consumed = 0;
    ASSERT_TRUE(ws_try_decode_server_frame(frame, &out, &consumed));
    EXPECT_EQ(out.payload.size(), 256u);
    EXPECT_EQ(consumed, frame.size());
}

TEST(WsCodec, RejectsMaskedServerFrame) {
    const std::vector<uint8_t> frame = {static_cast<uint8_t>(0x82), 0x80};
    WsIncomingFrame out;
    size_t consumed = 0;
    EXPECT_THROW(ws_try_decode_server_frame(frame, &out, &consumed), VynkorInternal);
}

// ---------------------------------------------------------------------------
// Wire-frame round trip over the buffer parser (WS path)
// ---------------------------------------------------------------------------
TEST(WsWireFrame, RoundTripWithoutMac) {
    const std::string target = "kernel";
    const std::vector<uint8_t> payload = {'{', '}'};

    const std::vector<uint8_t> frame = pack_frame_ws(target, FLAG_RAW_BINARY, payload, nullptr);
    size_t consumed = 0;
    const FrameResult result =
        parse_frame_from_buffer(frame.data(), frame.size(), nullptr, &consumed);

    EXPECT_EQ(consumed, frame.size());
    EXPECT_EQ(result.flags, FLAG_RAW_BINARY);
    EXPECT_FALSE(result.has_mac);
    EXPECT_EQ(result.payload, payload);
}

TEST(WsWireFrame, RoundTripWithMacVerification) {
    const std::string target = "peer";
    const std::vector<uint8_t> payload = {'x', 'y', 'z'};
    const std::vector<uint8_t> secret = {'s', 'e', 'c', 'r', 'e', 't'};
    const std::vector<uint8_t> nonce = {'n', 'o', 'n', 'c', 'e'};

    const auto key = derive_session_key(secret, nonce, "plugin-a");
    const std::vector<uint8_t> frame = pack_frame_ws(target, FLAG_MAC_PRESENT, payload, &key);

    const FrameResult ok = parse_frame_from_buffer(frame.data(), frame.size(), &key, nullptr);
    EXPECT_TRUE(ok.has_mac);
    EXPECT_EQ(ok.payload, payload);

    const auto wrong_key = derive_session_key(secret, nonce, "plugin-b");
    EXPECT_THROW((parse_frame_from_buffer(frame.data(), frame.size(), &wrong_key, nullptr)),
                 VynkorInternal);
}

TEST(WsWireFrame, MacRequiredWhenKeyProvided) {
    const std::vector<uint8_t> payload = {'a'};
    const std::vector<uint8_t> frame = pack_frame_ws("kernel", 0, payload, nullptr);
    const std::array<uint8_t, 32> key{};
    EXPECT_THROW((parse_frame_from_buffer(frame.data(), frame.size(), &key, nullptr)),
                 VynkorInternal);
}
