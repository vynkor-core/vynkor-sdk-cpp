#include <gtest/gtest.h>
#include <sys/un.h>

#include "vynkor/client.hpp"

using namespace vynkor;

TEST(VeyronClientConnect, RejectsOverlongSocketPath) {
    std::string too_long(sizeof(sockaddr_un{}.sun_path), 'x');
    VeyronClient client(too_long);
    EXPECT_THROW(client.connect(), VeyronIoError);
}

TEST(VeyronClientConnect, AcceptsPathAtMaxLength) {
    // sizeof(sun_path) - 1 chars, plus nul terminator, fits exactly.
    std::string max_len(sizeof(sockaddr_un{}.sun_path) - 1, 'x');
    VeyronClient client(max_len);
    // No listener at this path — connect() itself fails, but not with the
    // "socket path too long" message, proving the length check passed.
    try {
        client.connect();
        FAIL() << "expected connect() to throw (no listener at synthetic path)";
    } catch (const VeyronIoError& e) {
        EXPECT_EQ(std::string(e.what()).find("too long"), std::string::npos);
    }
}
