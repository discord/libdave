#pragma once

#include <array>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include <dave/dave_interfaces.h>
#include <dave/version.h>

#include "codec_utils.h"
#include "common.h"
#include "cryptor.h"
#include "cryptor_manager.h"
#include "frame_processors.h"
#include "utils/clock.h"

namespace discord {
namespace dave {

class IKeyRatchet;

class Decryptor final : public IDecryptor {
public:
    using Duration = std::chrono::seconds;

    virtual ~Decryptor() noexcept = default;

    virtual void TransitionToKeyRatchet(
      std::unique_ptr<IKeyRatchet> keyRatchet,
      Duration transitionExpiry = kDefaultTransitionDuration) override;
    virtual void TransitionToPassthroughMode(
      bool passthroughMode,
      Duration transitionExpiry = kDefaultTransitionDuration) override;

    virtual ResultCode Decrypt(MediaType mediaType,
                               ArrayView<const uint8_t> encryptedFrame,
                               ArrayView<uint8_t> frame,
                               size_t* bytesWritten) override;

    virtual size_t GetMaxPlaintextByteSize(MediaType mediaType, size_t encryptedFrameSize) override;
    virtual DecryptorStats GetStats(MediaType mediaType) const override
    {
        return stats_[mediaType];
    }

private:
    using TimePoint = IClock::TimePoint;

    Decryptor::ResultCode DecryptImpl(CryptorManager& cryptor,
                                      MediaType mediaType,
                                      InboundFrameProcessor& encryptedFrame);

    void UpdateCryptorManagerExpiry(Duration expiry);
    void CleanupExpiredCryptorManagers();

    std::unique_ptr<InboundFrameProcessor> GetOrCreateFrameProcessor();
    void ReturnFrameProcessor(std::unique_ptr<InboundFrameProcessor> frameProcessor);

    Clock clock_;
    std::deque<CryptorManager> cryptorManagers_;

    std::mutex frameProcessorsMutex_;
    std::vector<std::unique_ptr<InboundFrameProcessor>> frameProcessors_;

    TimePoint allowPassThroughUntil_{TimePoint::min()};

    TimePoint lastStatsTime_{TimePoint::min()};
    std::array<DecryptorStats, 2> stats_;
};

} // namespace dave
} // namespace discord
