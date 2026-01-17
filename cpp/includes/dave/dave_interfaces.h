#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <map>
#include <variant>
#include <chrono>
#include <vector>

#include <dave/array_view.h>
#include <dave/dave.h>
#include <dave/version.h>

namespace mlspp {
namespace bytes_ns {
struct bytes;
}; // namespace bytes_ns

struct SignaturePrivateKey;
} // namespace mlspp


namespace discord {
namespace dave {

using EncryptorStats = DAVEEncryptorStats;
using DecryptorStats = DAVEDecryptorStats;
using KeyGeneration = uint32_t;
using EncryptionKey = ::mlspp::bytes_ns::bytes;

class MlsKeyRatchet;

enum MediaType : uint8_t { Audio, Video };
enum Codec : uint8_t { Unknown, Opus, VP8, VP9, H264, H265, AV1 };
enum LoggingSeverity {
    LS_VERBOSE,
    LS_INFO,
    LS_WARNING,
    LS_ERROR,
    LS_NONE,
};

// Returned in std::variant when a message is hard-rejected and should trigger a reset
struct failed_t {};

// Returned in std::variant when a message is soft-rejected and should not trigger a reset
struct ignored_t {};

// Map of ID-key pairs.
// In ProcessCommit, this lists IDs whose keys have been added, changed, or removed;
// an empty value value means a key was removed.
using RosterMap = std::map<uint64_t, std::vector<uint8_t>>;

// Return type for functions producing RosterMap or hard or soft failures
using RosterVariant = std::variant<failed_t, ignored_t, RosterMap>;

constexpr auto kDefaultTransitionDuration = std::chrono::seconds(10);

class IKeyRatchet {
public:
    virtual ~IKeyRatchet() noexcept = default;
    virtual EncryptionKey GetKey(KeyGeneration generation) noexcept = 0;
    virtual void DeleteKey(KeyGeneration generation) noexcept = 0;
};

namespace mls {

#if defined(__ANDROID__)
typedef JNIEnv* KeyPairContextType;
#else
typedef const char* KeyPairContextType;
#endif

class ISession {
public:
    virtual ~ISession() noexcept = default;

    virtual void Init(ProtocolVersion version,
                      uint64_t groupId,
                      std::string const& selfUserId,
                      std::shared_ptr<::mlspp::SignaturePrivateKey>& transientKey) noexcept = 0;
    virtual void Reset() noexcept = 0;

    virtual void SetProtocolVersion(ProtocolVersion version) noexcept = 0;
    virtual ProtocolVersion GetProtocolVersion() const noexcept = 0;

    virtual std::vector<uint8_t> GetLastEpochAuthenticator() const noexcept = 0;

    virtual void SetExternalSender(std::vector<uint8_t> const& externalSenderPackage) noexcept = 0;

    virtual std::optional<std::vector<uint8_t>> ProcessProposals(
      std::vector<uint8_t> proposals,
      std::set<std::string> const& recognizedUserIDs) noexcept = 0;

    virtual RosterVariant ProcessCommit(std::vector<uint8_t> commit) noexcept = 0;

    virtual std::optional<RosterMap> ProcessWelcome(
      std::vector<uint8_t> welcome,
      std::set<std::string> const& recognizedUserIDs) noexcept = 0;

    virtual std::vector<uint8_t> GetMarshalledKeyPackage() noexcept = 0;

    virtual std::unique_ptr<IKeyRatchet> GetKeyRatchet(
      std::string const& userId) const noexcept = 0;

    using PairwiseFingerprintCallback = std::function<void(std::vector<uint8_t> const&)>;
    virtual void GetPairwiseFingerprint(uint16_t version,
                                        std::string const& userId,
                                        PairwiseFingerprintCallback callback) const noexcept = 0;
};

using MLSFailureCallback = std::function<void(std::string const&, std::string const&)>;
std::unique_ptr<ISession> CreateSession(KeyPairContextType context,
                                                    std::string authSessionId,
                                                    MLSFailureCallback callback) noexcept;

} // namespace mls

class IEncryptor {
public:
    enum ResultCode {
        Success,
        EncryptionFailure,
        MissingKeyRatchet,
        MissingCryptor,
        TooManyAttempts,
    };

    virtual ~IEncryptor() = default;

    virtual void SetKeyRatchet(std::unique_ptr<IKeyRatchet> keyRatchet) = 0;
    virtual void SetPassthroughMode(bool passthroughMode) = 0;

    virtual bool HasKeyRatchet() const = 0;
    virtual bool IsPassthroughMode() const = 0;

    virtual void AssignSsrcToCodec(uint32_t ssrc, Codec codecType) = 0;
    virtual Codec CodecForSsrc(uint32_t ssrc) = 0;

    virtual ResultCode Encrypt(MediaType mediaType,
                               uint32_t ssrc,
                               ArrayView<const uint8_t> frame,
                               ArrayView<uint8_t> encryptedFrame,
                               size_t* bytesWritten) = 0;

    virtual size_t GetMaxCiphertextByteSize(MediaType mediaType, size_t frameSize) = 0;
    virtual EncryptorStats GetStats(MediaType mediaType) const = 0;

    using ProtocolVersionChangedCallback = std::function<void()>;
    virtual void SetProtocolVersionChangedCallback(ProtocolVersionChangedCallback callback) = 0;

    virtual ProtocolVersion GetProtocolVersion() const = 0;
};

std::unique_ptr<IEncryptor> CreateEncryptor();

class IDecryptor {
public:
    using Duration = std::chrono::seconds;
    enum ResultCode {
        Success,
        DecryptionFailure,
        MissingKeyRatchet,
        InvalidNonce,
        MissingCryptor,
    };

    virtual ~IDecryptor() = default;

    virtual void TransitionToKeyRatchet(std::unique_ptr<IKeyRatchet> keyRatchet,
                                        Duration transitionExpiry = kDefaultTransitionDuration) = 0;
    virtual void TransitionToPassthroughMode(
      bool passthroughMode,
      Duration transitionExpiry = kDefaultTransitionDuration) = 0;

    virtual ResultCode Decrypt(MediaType mediaType,
                               ArrayView<const uint8_t> encryptedFrame,
                               ArrayView<uint8_t> frame,
                               size_t* bytesWritten) = 0;

    virtual size_t GetMaxPlaintextByteSize(MediaType mediaType, size_t encryptedFrameSize) = 0;
    virtual DecryptorStats GetStats(MediaType mediaType) const = 0;
};

std::unique_ptr<IDecryptor> CreateDecryptor();

static_assert(DAVE_CODEC_UNKNOWN == static_cast<int>(Codec::Unknown));
static_assert(DAVE_CODEC_OPUS == static_cast<int>(Codec::Opus));
static_assert(DAVE_CODEC_VP8 == static_cast<int>(Codec::VP8));
static_assert(DAVE_CODEC_VP9 == static_cast<int>(Codec::VP9));
static_assert(DAVE_CODEC_H264 == static_cast<int>(Codec::H264));
static_assert(DAVE_CODEC_H265 == static_cast<int>(Codec::H265));
static_assert(DAVE_CODEC_AV1 == static_cast<int>(Codec::AV1));
static_assert(DAVE_MEDIA_TYPE_AUDIO == static_cast<int>(MediaType::Audio));
static_assert(DAVE_MEDIA_TYPE_VIDEO == static_cast<int>(MediaType::Video));
static_assert(DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS == static_cast<int>(IEncryptor::Success));
static_assert(DAVE_ENCRYPTOR_RESULT_CODE_ENCRYPTION_FAILURE ==
              static_cast<int>(IEncryptor::EncryptionFailure));
static_assert(DAVE_ENCRYPTOR_RESULT_CODE_MISSING_KEY_RATCHET ==
              static_cast<int>(IEncryptor::MissingKeyRatchet));
static_assert(DAVE_ENCRYPTOR_RESULT_CODE_MISSING_CRYPTOR ==
              static_cast<int>(IEncryptor::MissingCryptor));
static_assert(DAVE_ENCRYPTOR_RESULT_CODE_TOO_MANY_ATTEMPTS ==
              static_cast<int>(IEncryptor::TooManyAttempts));
static_assert(DAVE_DECRYPTOR_RESULT_CODE_SUCCESS == static_cast<int>(IDecryptor::Success));
static_assert(DAVE_DECRYPTOR_RESULT_CODE_DECRYPTION_FAILURE ==
              static_cast<int>(IDecryptor::DecryptionFailure));
static_assert(DAVE_DECRYPTOR_RESULT_CODE_MISSING_KEY_RATCHET ==
              static_cast<int>(IDecryptor::MissingKeyRatchet));
static_assert(DAVE_DECRYPTOR_RESULT_CODE_INVALID_NONCE ==
              static_cast<int>(IDecryptor::InvalidNonce));
static_assert(DAVE_DECRYPTOR_RESULT_CODE_MISSING_CRYPTOR ==
              static_cast<int>(IDecryptor::MissingCryptor));
static_assert(DAVE_LOGGING_SEVERITY_VERBOSE == static_cast<int>(LoggingSeverity::LS_VERBOSE));
static_assert(DAVE_LOGGING_SEVERITY_INFO == static_cast<int>(LoggingSeverity::LS_INFO));
static_assert(DAVE_LOGGING_SEVERITY_WARNING == static_cast<int>(LoggingSeverity::LS_WARNING));
static_assert(DAVE_LOGGING_SEVERITY_ERROR == static_cast<int>(LoggingSeverity::LS_ERROR));
static_assert(DAVE_LOGGING_SEVERITY_NONE == static_cast<int>(LoggingSeverity::LS_NONE));

} // namespace dave
} // namespace discord
