// C++ SDK fragmentation support (T-18) — mirrors sdk/rust/tests/protocol.rs's
// fragmentation_roundtrip_via_client_recv / fragment_wire_format_matches_framing_doc /
// send_fragmented_rejects_oversized_payload.

#include <gtest/gtest.h>
#include <sys/socket.h>

#include <stdexcept>
#include <thread>
#include <vector>

#include "vynkor/client.hpp"
#include "vynkor/framing.hpp"
#include "vynkor_protocol.pb.h"

using namespace vynkor;

namespace {

std::pair<int, int> make_socketpair() {
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        throw std::runtime_error("socketpair() failed");
    return {fds[0], fds[1]};
}

} // namespace

TEST(Fragmentation, RoundtripViaClientRecv) {
    auto [a, b] = make_socketpair();
    VeyronClient sender(a);
    VeyronClient receiver(b);

    Envelope env;
    env.mutable_event()->set_event_id("evt-frag");
    env.mutable_event()->set_event_type("test.event");
    std::string inner;
    env.SerializeToString(&inner);
    std::vector<uint8_t> payload(inner.begin(), inner.end());

    std::thread sender_thread([&] { sender.send_fragmented("peer", payload, 7); });

    Envelope received = receiver.recv();
    sender_thread.join();

    ASSERT_TRUE(received.has_event());
    EXPECT_EQ(received.event().event_id(), "evt-frag");
}

TEST(Fragmentation, WireFormatMatchesFramingDoc) {
    auto [a, b] = make_socketpair();
    VeyronClient sender(a);

    std::vector<uint8_t> payload(25, 9); // 3 fragments of 10 + header each
    std::thread sender_thread([&] { sender.send_fragmented("peer", payload, 10); });

    for (uint16_t expected_seq = 0; expected_seq < 3; ++expected_seq) {
        auto frame = read_frame_full(b);
        ASSERT_NE(frame.flags & FLAG_FRAGMENTED, 0);
        auto hdr = parse_frag_header(frame.payload.data(), frame.payload.size());
        ASSERT_TRUE(hdr.has_value());
        EXPECT_EQ(hdr->sequence, expected_seq);
        EXPECT_EQ(hdr->total, 3);
        const size_t chunk_len = frame.payload.size() - FRAG_HEADER_SIZE;
        EXPECT_EQ(chunk_len, expected_seq < 2 ? 10u : 5u);
    }
    sender_thread.join();
}

TEST(Fragmentation, SendFragmentedRejectsOversizedPayload) {
    auto [a, b] = make_socketpair();
    VeyronClient sender(a);
    ::close(b);

    std::vector<uint8_t> payload(MAX_PAYLOAD_SIZE + 1, 0);
    EXPECT_THROW(sender.send_fragmented("peer", payload, 65536), VeyronPayloadTooLarge);
}

TEST(Fragmentation, RejectsFragmentTotalMismatchWithinStream) {
    auto [a, b] = make_socketpair();
    VeyronClient receiver(b);

    // First fragment of a 2-fragment stream...
    auto frag1 = pack_frag_header(1, 0, 2, 42);
    frag1.push_back('x');
    auto frame1 = pack_frame("peer", frag1, FLAG_FRAGMENTED);
    ASSERT_EQ(::write(a, frame1.data(), frame1.size()), static_cast<ssize_t>(frame1.size()));

    // ...followed by a fragment claiming a different total for the same stream id.
    auto frag2 = pack_frag_header(1, 1, 3, 42);
    frag2.push_back('y');
    auto frame2 = pack_frame("peer", frag2, FLAG_FRAGMENTED);
    ASSERT_EQ(::write(a, frame2.data(), frame2.size()), static_cast<ssize_t>(frame2.size()));

    EXPECT_THROW(receiver.recv(), VeyronInternal);
}

TEST(Fragmentation, TooManyConcurrentStreamsRejected) {
    auto [a, b] = make_socketpair();
    VeyronClient receiver(b);

    // Open MAX_REASSEMBLY_STREAMS distinct incomplete streams, then a fresh one.
    for (uint32_t stream_id = 1; stream_id <= MAX_REASSEMBLY_STREAMS; ++stream_id) {
        auto frag = pack_frag_header(1, 0, 2, stream_id);
        frag.push_back('z');
        auto frame = pack_frame("peer", frag, FLAG_FRAGMENTED);
        ASSERT_EQ(::write(a, frame.data(), frame.size()), static_cast<ssize_t>(frame.size()));
    }
    auto overflow_frag = pack_frag_header(1, 0, 2, MAX_REASSEMBLY_STREAMS + 1);
    overflow_frag.push_back('z');
    auto overflow_frame = pack_frame("peer", overflow_frag, FLAG_FRAGMENTED);
    ASSERT_EQ(::write(a, overflow_frame.data(), overflow_frame.size()),
             static_cast<ssize_t>(overflow_frame.size()));

    EXPECT_THROW(receiver.recv(), VeyronInternal);
}
