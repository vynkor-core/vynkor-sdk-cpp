cmake_minimum_required(VERSION 3.20)
project(veyron_sdk
    VERSION 0.1.0
    DESCRIPTION "C++ SDK for writing Veyron plugins"
    HOMEPAGE_URL "https://github.com/veyron-core/veyron"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(Protobuf REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(absl REQUIRED)
find_package(zstd REQUIRED)

# zstd's CMake config (both upstream and Conan) exports either
# zstd::libzstd_shared or zstd::libzstd_static depending on how it was built.
if(TARGET zstd::libzstd_shared)
    set(ZSTD_TARGET zstd::libzstd_shared)
else()
    set(ZSTD_TARGET zstd::libzstd_static)
endif()

# Generate C++ bindings from the vendored proto (sourced from veyron-wire's
# wire/proto/veyron_protocol.proto — re-copy by hand when the protocol changes)
set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/proto/veyron_protocol.proto)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILE})

add_library(veyron_sdk_cpp STATIC
    src/client.cpp
    src/framing.cpp
    src/mac.cpp
    src/env.cpp
    include/veyron/client.hpp
    include/veyron/framing.hpp
    include/veyron/mac.hpp
    include/veyron/plugin.hpp
    include/veyron/env.hpp
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)

add_library(veyron::sdk ALIAS veyron_sdk_cpp)

target_include_directories(veyron_sdk_cpp
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/proto>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(veyron_sdk_cpp
    PUBLIC
    protobuf::libprotobuf
    absl::base
    absl::strings
    OpenSSL::Crypto
    ${ZSTD_TARGET}
    Threads::Threads
)

# ── Tests ──────────────────────────────────────────────────────────────────
include(CTest)
find_package(GTest REQUIRED)

add_executable(veyron_sdk_tests tests/test_mac.cpp tests/test_env.cpp tests/test_plugin.cpp tests/test_plugin_ping.cpp tests/test_framing.cpp tests/test_framing_timeout.cpp tests/test_client.cpp tests/test_fragmentation.cpp tests/test_publish_event.cpp tests/test_send_action.cpp tests/test_session_close.cpp)
target_link_libraries(veyron_sdk_tests
    PRIVATE
    veyron_sdk_cpp
    GTest::GTest
)
add_test(NAME veyron_sdk_tests COMMAND veyron_sdk_tests)

# ── Fuzzing (T-14) ─────────────────────────────────────────────────────────
# libFuzzer requires Clang; off by default so a normal GCC/Clang build (and
# the veyron_sdk_tests target above) is unaffected.
option(VEYRON_BUILD_FUZZERS "Build libFuzzer harnesses (requires Clang)" OFF)
if(VEYRON_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "VEYRON_BUILD_FUZZERS requires Clang: reconfigure with -DCMAKE_CXX_COMPILER=clang++")
    endif()
    add_executable(fuzz_framing fuzz/fuzz_framing.cpp src/framing.cpp src/mac.cpp)
    target_include_directories(fuzz_framing PRIVATE include)
    target_compile_options(fuzz_framing PRIVATE -fsanitize=fuzzer,address,undefined -g -O1)
    target_link_options(fuzz_framing PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(fuzz_framing PRIVATE OpenSSL::Crypto ${ZSTD_TARGET})
endif()

# ── Examples ───────────────────────────────────────────────────────────────
add_executable(echo_plugin examples/echo_plugin.cpp)
target_link_libraries(echo_plugin PRIVATE veyron_sdk_cpp)

# ── Install ────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(
    TARGETS veyron_sdk_cpp
    EXPORT veyron-sdk-targets
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

install(
    EXPORT veyron-sdk-targets
    FILE veyron-sdk-config.cmake
    NAMESPACE veyron::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/veyron-sdk
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/veyron-sdk-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/veyron-sdk-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/veyron-sdk
)
