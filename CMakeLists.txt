cmake_minimum_required(VERSION 3.20)
project(vynkor_sdk
    VERSION 0.0.1
    DESCRIPTION "C++ SDK for writing Vynkor plugins"
    HOMEPAGE_URL "https://github.com/vynkor-core/vynkor"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(Protobuf REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(absl REQUIRED)

# zstd: prefer the upstream/Conan CMake config (exports zstd::libzstd_shared
# or zstd::libzstd_static depending on how it was built); Debian/Ubuntu's
# libzstd-dev ships headers and libs but no CMake config, so fall back to
# pkg-config for those.
find_package(zstd QUIET CONFIG)
if(TARGET zstd::libzstd_shared)
    set(ZSTD_TARGET zstd::libzstd_shared)
elseif(TARGET zstd::libzstd_static)
    set(ZSTD_TARGET zstd::libzstd_static)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ZSTD_PC REQUIRED IMPORTED_TARGET libzstd)
    set(ZSTD_TARGET PkgConfig::ZSTD_PC)
endif()

# Generate C++ bindings from the vendored proto (sourced from vynkor-wire's
# wire/proto/vynkor_protocol.proto — re-copy by hand when the protocol changes)
set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/proto/vynkor_protocol.proto)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILE})

add_library(vynkor_sdk_cpp STATIC
    src/client.cpp
    src/framing.cpp
    src/mac.cpp
    src/env.cpp
    src/ws.cpp
    src/concurrent.cpp
    src/confirmation_gate.cpp
    include/vynkor/client.hpp
    include/vynkor/error.hpp
    include/vynkor/framing.hpp
    include/vynkor/mac.hpp
    include/vynkor/plugin.hpp
    include/vynkor/env.hpp
    include/vynkor/ws.hpp
    include/vynkor/concurrent.hpp
    include/vynkor/confirmation_gate.hpp
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)

add_library(vynkor::sdk ALIAS vynkor_sdk_cpp)

target_include_directories(vynkor_sdk_cpp
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/proto>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(vynkor_sdk_cpp
    PUBLIC
    protobuf::libprotobuf
    absl::base
    absl::strings
    OpenSSL::Crypto
    OpenSSL::SSL
    ${ZSTD_TARGET}
    Threads::Threads
)

# protobuf-generated pb.cc references CHECK_OP internals only when built
# against abseil-backed protobuf (v22+); older system protobuf (e.g. Ubuntu
# 24.04's 3.21) neither needs nor ships that target — link it when present
if(TARGET absl::log_internal_check_op)
    target_link_libraries(vynkor_sdk_cpp PUBLIC absl::log_internal_check_op)
endif()

# ── Tests ──────────────────────────────────────────────────────────────────
include(CTest)
find_package(GTest REQUIRED)

add_executable(vynkor_sdk_tests tests/test_mac.cpp tests/test_env.cpp tests/test_plugin.cpp tests/test_plugin_ping.cpp tests/test_framing.cpp tests/test_framing_timeout.cpp tests/test_client.cpp tests/test_fragmentation.cpp tests/test_publish_event.cpp tests/test_send_action.cpp tests/test_session_close.cpp tests/test_ws.cpp tests/test_concurrent_loop.cpp tests/test_confirmation_gate.cpp)
target_link_libraries(vynkor_sdk_tests
    PRIVATE
    vynkor_sdk_cpp
    GTest::GTest
)
add_test(NAME vynkor_sdk_tests COMMAND vynkor_sdk_tests)

# ── Fuzzing (T-14) ─────────────────────────────────────────────────────────
# libFuzzer requires Clang; off by default so a normal GCC/Clang build (and
# the vynkor_sdk_tests target above) is unaffected.
option(VYNKOR_BUILD_FUZZERS "Build libFuzzer harnesses (requires Clang)" OFF)
if(VYNKOR_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "VYNKOR_BUILD_FUZZERS requires Clang: reconfigure with -DCMAKE_CXX_COMPILER=clang++")
    endif()
    add_executable(fuzz_framing fuzz/fuzz_framing.cpp src/framing.cpp src/mac.cpp)
    target_include_directories(fuzz_framing PRIVATE include)
    target_compile_options(fuzz_framing PRIVATE -fsanitize=fuzzer,address,undefined -g -O1)
    target_link_options(fuzz_framing PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(fuzz_framing PRIVATE OpenSSL::Crypto ${ZSTD_TARGET})
endif()

# ── Examples ───────────────────────────────────────────────────────────────
add_executable(echo_plugin examples/echo_plugin.cpp)
target_link_libraries(echo_plugin PRIVATE vynkor_sdk_cpp)

# ── Install ────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(
    TARGETS vynkor_sdk_cpp
    EXPORT vynkor-sdk-targets
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

install(
    EXPORT vynkor-sdk-targets
    FILE vynkor-sdk-config.cmake
    NAMESPACE vynkor::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vynkor-sdk
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/vynkor-sdk-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/vynkor-sdk-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vynkor-sdk
)
