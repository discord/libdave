#pragma once

#include <array>
#include <cassert>
#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <dave/dave_interfaces.h>
#include <dave/logger.h>

// Malformed encoder output is recovered from, so fuzzing must be able to reach past it
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define DEBUG_ASSERT_MALFORMED(message)
#else
#define DEBUG_ASSERT_MALFORMED(message) assert(false && message)
#endif

#define REPORT_MALFORMED(message)           \
    do {                                    \
        DISCORD_LOG(LS_WARNING) << message; \
        DEBUG_ASSERT_MALFORMED(message);    \
    } while (0)

namespace discord {
namespace dave {

using UnencryptedFrameHeaderSize = uint16_t;
using TruncatedSyncNonce = uint32_t;
using MagicMarker = uint16_t;
using SupplementalBytesSize = uint8_t;

constexpr std::array<uint8_t, sizeof(MagicMarker)> kMarkerBytes = {0xFA, 0xFA};

// Layout constants
constexpr size_t kAesGcm128KeyBytes = 16;
constexpr size_t kAesGcm128NonceBytes = 12;
constexpr size_t kAesGcm128TruncatedSyncNonceBytes = 4;
constexpr size_t kAesGcm128TruncatedSyncNonceOffset =
  kAesGcm128NonceBytes - kAesGcm128TruncatedSyncNonceBytes;
constexpr size_t kAesGcm128TruncatedTagBytes = 8;
constexpr size_t kRatchetGenerationBytes = 1;
constexpr size_t kRatchetGenerationShiftBits =
  8 * (kAesGcm128TruncatedSyncNonceBytes - kRatchetGenerationBytes);
constexpr size_t kSupplementalBytes =
  kAesGcm128TruncatedTagBytes + sizeof(SupplementalBytesSize) + sizeof(MagicMarker);
constexpr size_t kTransformPaddingBytes = 64;

// Timing constants
constexpr auto kCryptorExpiry = std::chrono::seconds(10);

// Behavior constants
constexpr auto kMaxGenerationGap = 250;
constexpr auto kMaxMissingNonces = 1000;
constexpr auto kGenerationWrap = 1 << (8 * kRatchetGenerationBytes);
constexpr auto kMaxFramesPerSecond = 50 + 2 * 60; // 50 audio frames + 2 * 60fps video streams

// The truncated nonce occupies the trailing bytes of the full nonce in little-endian order
inline std::array<uint8_t, kAesGcm128NonceBytes> ExpandTruncatedNonce(
  TruncatedSyncNonce truncatedNonce) noexcept
{
    auto nonce = std::array<uint8_t, kAesGcm128NonceBytes>();
    for (size_t i = 0; i < kAesGcm128TruncatedSyncNonceBytes; ++i) {
        nonce[kAesGcm128TruncatedSyncNonceOffset + i] =
          static_cast<uint8_t>(truncatedNonce >> (8 * i));
    }
    return nonce;
}

// Utility routine for variant return types
template <class T, class V>
inline std::optional<T> GetOptional(V&& variant)
{
    if (auto map = std::get_if<T>(&variant)) {
        if constexpr (std::is_rvalue_reference_v<decltype(variant)>) {
            return std::move(*map);
        }
        else {
            return *map;
        }
    }
    else {
        return std::nullopt;
    }
}

} // namespace dave
} // namespace discord
