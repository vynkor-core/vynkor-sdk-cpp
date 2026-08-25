#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>

namespace vynkor {

// Typed exception hierarchy mirroring the Rust SDK's `WireError` enum
// (vynkor-wire/src/error.rs) variant-for-variant. Every subclass derives from
// std::runtime_error so existing `catch (const std::runtime_error&)` and
// `catch (...)` sites keep working while new code can discriminate on the
// exact failure mode.
class VynkorError : public std::runtime_error {
public:
    explicit VynkorError(const std::string& message) : std::runtime_error(message) {}
};

// WireError::Io — socket/stream read/write/connect failures.
class VynkorIoError : public VynkorError {
public:
    explicit VynkorIoError(const std::string& message) : VynkorError("io error: " + message) {}
};

// WireError::Proto — protobuf encode/decode failures.
class VynkorProtoError : public VynkorError {
public:
    explicit VynkorProtoError(const std::string& message)
        : VynkorError("proto decode error: " + message) {}
};

// WireError::FrameMagicMismatch — wire frame magic != 0x5652.
class VynkorFrameMagicMismatch : public VynkorError {
public:
    VynkorFrameMagicMismatch() : VynkorError("frame magic mismatch") {}
};

// WireError::FrameCrcMismatch — wire payload CRC32 mismatch.
class VynkorFrameCrcMismatch : public VynkorError {
public:
    VynkorFrameCrcMismatch() : VynkorError("frame crc mismatch") {}
};

// WireError::FrameReadTimeout — the rest of a frame failed to arrive within
// the read window (slow-loris stall).
class VynkorFrameReadTimeout : public VynkorError {
public:
    VynkorFrameReadTimeout() : VynkorError("timed out reading frame body") {}
};

// WireError::PayloadTooLarge — payload exceeds MAX_PAYLOAD_SIZE (1 MiB).
class VynkorPayloadTooLarge : public VynkorError {
public:
    explicit VynkorPayloadTooLarge(size_t size)
        : VynkorError("payload too large: " + std::to_string(size) + " bytes") {}
};

// WireError::Timeout — a request/response wait expired before any matching
// reply arrived (distinct from a mid-frame read stall).
class VynkorTimeout : public VynkorError {
public:
    VynkorTimeout() : VynkorError("operation timed out") {}
};

// WireError::PermissionDenied — registration rejected / action not permitted.
class VynkorPermissionDenied : public VynkorError {
public:
    explicit VynkorPermissionDenied(const std::string& message)
        : VynkorError("permission denied: " + message) {}
};

// WireError::Internal — protocol violations and other SDK-side failures.
class VynkorInternal : public VynkorError {
public:
    explicit VynkorInternal(const std::string& message)
        : VynkorError("internal error: " + message) {}
};

} // namespace vynkor
