// T-15: read_frame_full must not block forever on a slow-loris peer that
// sends a partial frame and then stops. Uses a short custom deadline (the
// production 10s default would make this test itself slow-loris the suite).
#include <gtest/gtest.h>
#include "veyron/framing.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <thread>
#include <unistd.h>

using namespace veyron;

static std::pair<int,int> make_pipe() {
    int fds[2];
    if (::pipe(fds) != 0) throw std::runtime_error("pipe failed");
    return {fds[0], fds[1]};
}

TEST(FramingTimeout, IdleConnectionBetweenFramesDoesNotTimeOut) {
    // No bytes sent yet — read_frame_full must block waiting for the first
    // byte, not immediately time out. Verified by racing a delayed writer
    // against the call: if the read returned early with a timeout error,
    // this would fail as soon as it throws before the sleep finishes.
    auto pipe_fds = make_pipe();
    const int read_fd = pipe_fds.first;
    const int write_fd = pipe_fds.second;

    std::vector<uint8_t> payload = {'h', 'i'};
    auto frame = pack_frame("tgt", payload);

    std::thread writer([write_fd, frame]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        ::write(write_fd, frame.data(), frame.size());
        ::close(write_fd);
    });

    auto result = read_frame_full(read_fd, nullptr);
    writer.join();
    ::close(read_fd);

    EXPECT_EQ(result.payload, payload);
}

TEST(FramingTimeout, StalledMidFrameEventuallyDisconnectsRatherThanHanging) {
    // Send only the header (declaring a payload that never arrives) and
    // never close the write end. The peer must give up rather than block
    // the caller forever. Uses a short 200ms timeout via
    // read_frame_full_with_timeout so this test doesn't itself take 10s —
    // the codepath exercised is identical to the production default.
    auto pipe_fds = make_pipe();
    const int read_fd = pipe_fds.first;
    const int write_fd = pipe_fds.second;

    std::vector<uint8_t> payload(1024, 'x');
    auto frame = pack_frame("tgt", payload);
    // Write only the 44-byte header; withhold the payload entirely.
    ::write(write_fd, frame.data(), FRAME_HEADER_SIZE);

    const auto start = std::chrono::steady_clock::now();
    EXPECT_THROW(read_frame_full_with_timeout(read_fd, nullptr, 200), VeyronFrameReadTimeout);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, std::chrono::seconds(2));
    EXPECT_GE(elapsed, std::chrono::milliseconds(150));

    ::close(write_fd);
    ::close(read_fd);
}
