#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include <dave/dave_interfaces.h>
#include <dave/version.h>

#include "codec_utils.h"
#include "common.h"
#include "cryptor.h"
#include "frame_processors.h"

namespace discord {
namespace dave {

class Encryptor final : public IEncryptor {
public:
    virtual ~Encryptor() noexcept = default;

    virtual void SetKeyRatchet(std::unique_ptr<IKeyRatchet> keyRatchet) override;
    virtual void SetPassthroughMode(bool passthroughMode) override;

    virtual bool HasKeyRatchet() const override { return keyRatchet_ != nullptr; }
    virtual bool IsPassthroughMode() const override { return passthroughMode_; }

    virtual void AssignSsrcToCodec(uint32_t ssrc, Codec codecType) override;
    virtual Codec CodecForSsrc(uint32_t ssrc) override;

    virtual ResultCode Encrypt(MediaType mediaType,
                               uint32_t ssrc,
                               ArrayView<const uint8_t> frame,
                               ArrayView<uint8_t> encryptedFrame,
                               size_t* bytesWritten) override;

    virtual size_t GetMaxCiphertextByteSize(MediaType mediaType, size_t frameSize) override;
    virtual EncryptorStats GetStats(MediaType mediaType) const override
    {
        return stats_[mediaType];
    }

    using ProtocolVersionChangedCallback = std::function<void()>;
    virtual void SetProtocolVersionChangedCallback(ProtocolVersionChangedCallback callback) override
    {
        protocolVersionChangedCallback_ = std::move(callback);
    }
    virtual ProtocolVersion GetProtocolVersion() const override { return currentProtocolVersion_; }

private:
    std::unique_ptr<OutboundFrameProcessor> GetOrCreateFrameProcessor();
    void ReturnFrameProcessor(std::unique_ptr<OutboundFrameProcessor> frameProcessor);

    using CryptorAndNonce = std::pair<std::shared_ptr<ICryptor>, TruncatedSyncNonce>;
    CryptorAndNonce GetNextCryptorAndNonce();

    void UpdateCurrentProtocolVersion(ProtocolVersion version);

    std::atomic_bool passthroughMode_{false};

    std::mutex keyGenMutex_;
    std::unique_ptr<IKeyRatchet> keyRatchet_;
    std::shared_ptr<ICryptor> cryptor_;
    KeyGeneration currentKeyGeneration_{0};
    TruncatedSyncNonce truncatedNonce_{0};

    std::mutex frameProcessorsMutex_;
    std::vector<std::unique_ptr<OutboundFrameProcessor>> frameProcessors_;

    using SsrcCodecPair = std::pair<uint32_t, Codec>;
    std::vector<SsrcCodecPair> ssrcCodecPairs_;

    using TimePoint = std::chrono::time_point<std::chrono::steady_clock>;
    TimePoint lastStatsTime_{TimePoint::min()};
    std::array<EncryptorStats, 2> stats_;

    ProtocolVersionChangedCallback protocolVersionChangedCallback_;
    ProtocolVersion currentProtocolVersion_{MaxSupportedProtocolVersion()};
};

} // namespace dave
} // namespace discord
