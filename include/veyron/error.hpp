#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>

namespace veyron {

// Typed exception hierarchy mirroring the Rust SDK's `WireError` enum
// (veyron-wire/src/error.rs) variant-for-variant. Every subclass derives from
// std::runtime_error so existing `catch (const std::runtime_error&)` and
// `catch (...)` sites keep working while new code can discriminate on the
// exact failure mode.
class VeyronError : public std::runtime_error {
public:
    explicit VeyronError(const std::string& message) : std::runtime_error(message) {}
};

// WireError::Io — socket/stream read/write/connect failures.
class VeyronIoError : public VeyronError {
public:
    explicit VeyronIoError(const std::string& message) : VeyronError("io error: " + message) {}
};

// WireError::Proto — protobuf encode/decode failures.
class VeyronProtoError : public VeyronError {
public:
    explicit VeyronProtoError(const std::string& message)
        : VeyronError("proto decode error: " + message) {}
};

// WireError::FrameMagicMismatch — wire frame magic != 0x5652.
class VeyronFrameMagicMismatch : public VeyronError {
public:
    VeyronFrameMagicMismatch() : VeyronError("frame magic mismatch") {}
};

// WireError::FrameCrcMismatch — wire payload CRC32 mismatch.
class VeyronFrameCrcMismatch : public VeyronError {
public:
    VeyronFrameCrcMismatch() : VeyronError("frame crc mismatch") {}
};

// WireError::FrameReadTimeout — the rest of a frame failed to arrive within
// the read window (slow-loris stall).
class VeyronFrameReadTimeout : public VeyronError {
public:
    VeyronFrameReadTimeout() : VeyronError("timed out reading frame body") {}
};

// WireError::PayloadTooLarge — payload exceeds MAX_PAYLOAD_SIZE (1 MiB).
class VeyronPayloadTooLarge : public VeyronError {
public:
    explicit VeyronPayloadTooLarge(size_t size)
        : VeyronError("payload too large: " + std::to_string(size) + " bytes") {}
};

// WireError::Timeout — a request/response wait expired before any matching
// reply arrived (distinct from a mid-frame read stall).
class VeyronTimeout : public VeyronError {
public:
    VeyronTimeout() : VeyronError("operation timed out") {}
};

// WireError::PermissionDenied — registration rejected / action not permitted.
class VeyronPermissionDenied : public VeyronError {
public:
    explicit VeyronPermissionDenied(const std::string& message)
        : VeyronError("permission denied: " + message) {}
};

// WireError::Internal — protocol violations and other SDK-side failures.
class VeyronInternal : public VeyronError {
public:
    explicit VeyronInternal(const std::string& message)
        : VeyronError("internal error: " + message) {}
};

} // namespace veyron
