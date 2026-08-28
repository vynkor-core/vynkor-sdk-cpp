// libFuzzer harness for vynkor::read_frame / read_frame_full (T-14).
//
// Build: cmake -DCMAKE_CXX_COMPILER=clang++ -DVYNKOR_BUILD_FUZZERS=ON ..
//        make fuzz_framing
// Run:   ./fuzz_framing -max_len=1100000   # a bit over MAX_PAYLOAD_SIZE
//
// Bytes are written to a memfd (not a pipe) so an oversized input can never
// deadlock the harness on a full pipe buffer before the parser gets to
// reject it via the length-field check.
#include "vynkor/framing.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

#include <sys/mman.h>
#include <unistd.h>

static int make_memfd_with(const uint8_t* data, size_t size) {
    int fd = memfd_create("vynkor-fuzz-frame", 0);
    if (fd < 0) throw std::runtime_error("memfd_create failed");
    if (size > 0) {
        ssize_t written = ::write(fd, data, size);
        (void)written; // short writes just feed the parser less input
    }
    ::lseek(fd, 0, SEEK_SET);
    return fd;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Path 1: no session key (backward-compat / unauthenticated read).
    {
        int fd = make_memfd_with(data, size);
        try {
            (void)vynkor::read_frame(fd);
        } catch (const std::exception&) {
            // Rejecting malformed input is the expected, correct behavior.
        }
        ::close(fd);
    }

    // Path 2: MAC-verifying read, same bytes against a fixed key — exercises
    // FLAG_MAC_PRESENT / FLAG_COMPRESSED handling and verify_tag.
    {
        int fd = make_memfd_with(data, size);
        static const std::array<uint8_t, 32> key = [] {
            std::array<uint8_t, 32> k{};
            for (size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(i);
            return k;
        }();
        try {
            (void)vynkor::read_frame_full(fd, &key);
        } catch (const std::exception&) {
        }
        ::close(fd);
    }

    return 0;
}
