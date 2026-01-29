#include <dave/dave_interfaces.h>

#include <atomic>
#include <cstdint>
#include <cstring>

#include <mls/messages.h>

#include <dave/logger.h>
#include <dave/version.h>

#include "mls_key_ratchet.h"

#define ARG_CHECK(arg)                                \
    if (arg == nullptr) {                             \
        fprintf(stderr, "ERROR: %s is null\n", #arg); \
        assert(false);                                \
        return;                                       \
    }

#define ARG_CHECK_RET(arg, ret)                       \
    if (arg == nullptr) {                             \
        fprintf(stderr, "ERROR: %s is null\n", #arg); \
        assert(false);                                \
        return ret;                                   \
    }

std::unique_ptr<discord::dave::MlsKeyRatchet> CopyKeyRatchet(DAVEKeyRatchetHandle keyRatchet)
{
    auto mlsKeyRatchet = reinterpret_cast<discord::dave::MlsKeyRatchet*>(keyRatchet);
    if (!mlsKeyRatchet) {
        return nullptr;
    }

    auto hashRatchet = mlsKeyRatchet->GetHashRatchet();
    auto cipherSuite = hashRatchet.suite;
    auto baseSecret = hashRatchet.next_secret;

    return std::make_unique<discord::dave::MlsKeyRatchet>(cipherSuite, std::move(baseSecret));
}

void CopyVectorToOutputBuffer(std::vector<uint8_t> const& vector, uint8_t** data, size_t* length)
{
    if (data == nullptr || length == nullptr) {
        return;
    }

    if (vector.empty()) {
        *data = nullptr;
        *length = 0;
        return;
    }

    *data = reinterpret_cast<uint8_t*>(malloc(vector.size()));
    memcpy(*data, vector.data(), vector.size());
    *length = vector.size();
}

void GetRosterMemberIds(const discord::dave::RosterMap& rosterMap,
                        uint64_t** rosterIds,
                        size_t* rosterIdsLength)
{
    *rosterIdsLength = rosterMap.size();
    *rosterIds = reinterpret_cast<uint64_t*>(malloc(*rosterIdsLength * sizeof(uint64_t)));
    size_t i = 0;
    for (const auto& [key, value] : rosterMap) {
        (*rosterIds)[i++] = key;
    }
}

void GetRosterMemberSignature(const discord::dave::RosterMap& rosterMap,
                              uint64_t rosterId,
                              uint8_t** signature,
                              size_t* signatureLength)
{
    CopyVectorToOutputBuffer(rosterMap.at(rosterId), signature, signatureLength);
}

uint16_t daveMaxSupportedProtocolVersion(void)
{
    return discord::dave::MaxSupportedProtocolVersion();
}

void daveFree(void* ptr)
{
    free(ptr);
}

DAVESessionHandle daveSessionCreate(void* context,
                                    const char* authSessionId,
                                    DAVEMLSFailureCallback callback,
                                    void* userData)
{
    discord::dave::mls::MLSFailureCallback mlsFailureCallback;
    if (callback != nullptr) {
        mlsFailureCallback = [callback, userData](std::string source, std::string reason) {
            callback(source.c_str(), reason.c_str(), userData);
        };
    };

    auto contextType = static_cast<discord::dave::mls::KeyPairContextType>(context);
    auto authSessionIdStr = authSessionId ? std::string(authSessionId) : std::string();
    auto session =
      discord::dave::mls::CreateSession(contextType, authSessionIdStr, mlsFailureCallback);
    return reinterpret_cast<DAVESessionHandle>(session.release());
}

void daveSessionDestroy(DAVESessionHandle sessionHandle)
{
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    delete session;
}

void daveSessionInit(DAVESessionHandle sessionHandle,
                     uint16_t version,
                     uint64_t groupId,
                     const char* selfUserId)
{
    ARG_CHECK(sessionHandle);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    auto selfUserIdStr = selfUserId ? std::string(selfUserId) : std::string();
    std::shared_ptr<::mlspp::SignaturePrivateKey> transientKey;
    session->Init(version, groupId, selfUserIdStr, transientKey);
}

void daveSessionReset(DAVESessionHandle sessionHandle)
{
    ARG_CHECK(sessionHandle);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    session->Reset();
}

void daveSessionSetProtocolVersion(DAVESessionHandle sessionHandle, uint16_t version)
{
    ARG_CHECK(sessionHandle);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    session->SetProtocolVersion(version);
}

uint16_t daveSessionGetProtocolVersion(DAVESessionHandle sessionHandle)
{
    ARG_CHECK_RET(sessionHandle, 0);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    return session->GetProtocolVersion();
}

void daveSessionGetLastEpochAuthenticator(DAVESessionHandle sessionHandle,
                                          uint8_t** authenticator,
                                          size_t* length)
{
    ARG_CHECK(sessionHandle);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    auto lastEpochAuthenticator = session->GetLastEpochAuthenticator();
    CopyVectorToOutputBuffer(lastEpochAuthenticator, authenticator, length);
}

void daveSessionSetExternalSender(DAVESessionHandle sessionHandle,
                                  const uint8_t* externalSender,
                                  size_t length)
{
    ARG_CHECK(sessionHandle);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    auto externalSenderVec = std::vector<uint8_t>(externalSender, externalSender + length);
    session->SetExternalSender(externalSenderVec);
}

void daveSessionProcessProposals(DAVESessionHandle sessionHandle,
                                 const uint8_t* proposals,
                                 size_t length,
                                 const char** recognizedUserIds,
                                 size_t recognizedUserIdsLength,
                                 uint8_t** commitWelcomeBytes,
                                 size_t* commitWelcomeBytesLength)
{
    ARG_CHECK(sessionHandle);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    auto proposalsVec = std::vector<uint8_t>(proposals, proposals + length);
    auto recognizedUserIdsSet =
      std::set<std::string>(recognizedUserIds, recognizedUserIds + recognizedUserIdsLength);
    auto result =
      session->ProcessProposals(std::move(proposalsVec), std::move(recognizedUserIdsSet));

    if (result) {
        CopyVectorToOutputBuffer(*result, commitWelcomeBytes, commitWelcomeBytesLength);
    }
}

DAVECommitResultHandle daveSessionProcessCommit(DAVESessionHandle sessionHandle,
                                                const uint8_t* commit,
                                                size_t length)
{
    ARG_CHECK_RET(sessionHandle, nullptr);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    auto commitVec = std::vector<uint8_t>(commit, commit + length);

    auto rosterVariant = session->ProcessCommit(std::move(commitVec));

    auto rosterVariantPtr = new discord::dave::RosterVariant(std::move(rosterVariant));
    return reinterpret_cast<DAVECommitResultHandle>(rosterVariantPtr);
}

DAVEWelcomeResultHandle daveSessionProcessWelcome(DAVESessionHandle sessionHandle,
                                                  const uint8_t* welcome,
                                                  size_t length,
                                                  const char** recognizedUserIds,
                                                  size_t recognizedUserIdsLength)
{
    ARG_CHECK_RET(sessionHandle, nullptr);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    auto welcomeVec = std::vector<uint8_t>(welcome, welcome + length);
    auto recognizedUserIdsSet =
      std::set<std::string>(recognizedUserIds, recognizedUserIds + recognizedUserIdsLength);

    auto result = session->ProcessWelcome(std::move(welcomeVec), std::move(recognizedUserIdsSet));
    if (!result) {
        return nullptr;
    }

    auto rosterMapPtr = new discord::dave::RosterMap(std::move(*result));
    return reinterpret_cast<DAVEWelcomeResultHandle>(rosterMapPtr);
}

void daveSessionGetMarshalledKeyPackage(DAVESessionHandle sessionHandle,
                                        uint8_t** keyPackage,
                                        size_t* length)
{
    ARG_CHECK(sessionHandle);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    auto keyPackageVec = session->GetMarshalledKeyPackage();
    CopyVectorToOutputBuffer(keyPackageVec, keyPackage, length);
}

DAVEKeyRatchetHandle daveSessionGetKeyRatchet(DAVESessionHandle sessionHandle, const char* userId)
{
    ARG_CHECK_RET(sessionHandle, nullptr);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    auto userIdStr = userId ? std::string(userId) : std::string();
    auto keyRatchetPtr = session->GetKeyRatchet(userIdStr);
    return reinterpret_cast<DAVEKeyRatchetHandle>(keyRatchetPtr.release());
}

void daveSessionGetPairwiseFingerprint(DAVESessionHandle sessionHandle,
                                       uint16_t version,
                                       const char* userId,
                                       DAVEPairwiseFingerprintCallback callback,
                                       void* userData)
{
    ARG_CHECK(sessionHandle);
    auto session = reinterpret_cast<discord::dave::mls::ISession*>(sessionHandle);
    auto userIdStr = userId ? std::string(userId) : std::string();
    session->GetPairwiseFingerprint(
      version, userIdStr, [callback, userData](std::vector<uint8_t> const& fingerprint) {
          callback(fingerprint.data(), fingerprint.size(), userData);
      });
}

void daveKeyRatchetDestroy(DAVEKeyRatchetHandle keyRatchet)
{
    delete reinterpret_cast<discord::dave::MlsKeyRatchet*>(keyRatchet);
}

bool daveCommitResultIsFailed(DAVECommitResultHandle commitResultHandle)
{
    ARG_CHECK_RET(commitResultHandle, false);
    auto commitResult = reinterpret_cast<discord::dave::RosterVariant*>(commitResultHandle);
    return std::holds_alternative<discord::dave::failed_t>(*commitResult);
}

bool daveCommitResultIsIgnored(DAVECommitResultHandle commitResultHandle)
{
    ARG_CHECK_RET(commitResultHandle, false);
    auto commitResult = reinterpret_cast<discord::dave::RosterVariant*>(commitResultHandle);
    return std::holds_alternative<discord::dave::ignored_t>(*commitResult);
}

void daveCommitResultGetRosterMemberIds(DAVECommitResultHandle commitResultHandle,
                                        uint64_t** rosterIds,
                                        size_t* rosterIdsLength)
{
    ARG_CHECK(commitResultHandle);
    auto commitResult = reinterpret_cast<discord::dave::RosterVariant*>(commitResultHandle);
    if (!std::holds_alternative<discord::dave::RosterMap>(*commitResult)) {
        *rosterIds = nullptr;
        *rosterIdsLength = 0;
        return;
    }
    GetRosterMemberIds(
      std::get<discord::dave::RosterMap>(*commitResult), rosterIds, rosterIdsLength);
}

void daveCommitResultGetRosterMemberSignature(DAVECommitResultHandle commitResultHandle,
                                              uint64_t rosterId,
                                              uint8_t** signature,
                                              size_t* signatureLength)
{
    ARG_CHECK(commitResultHandle);
    auto commitResult = reinterpret_cast<discord::dave::RosterVariant*>(commitResultHandle);
    if (!std::holds_alternative<discord::dave::RosterMap>(*commitResult)) {
        *signature = nullptr;
        *signatureLength = 0;
        return;
    }
    GetRosterMemberSignature(
      std::get<discord::dave::RosterMap>(*commitResult), rosterId, signature, signatureLength);
}

void daveCommitResultDestroy(DAVECommitResultHandle commitResultHandle)
{
    auto commitResult = reinterpret_cast<discord::dave::RosterVariant*>(commitResultHandle);
    delete commitResult;
}

void daveWelcomeResultGetRosterMemberIds(DAVEWelcomeResultHandle welcomeResultHandle,
                                         uint64_t** rosterIds,
                                         size_t* rosterIdsLength)
{
    ARG_CHECK(welcomeResultHandle);
    auto welcomeResult = reinterpret_cast<discord::dave::RosterMap*>(welcomeResultHandle);
    GetRosterMemberIds(*welcomeResult, rosterIds, rosterIdsLength);
}

void daveWelcomeResultGetRosterMemberSignature(DAVEWelcomeResultHandle welcomeResultHandle,
                                               uint64_t rosterId,
                                               uint8_t** signature,
                                               size_t* signatureLength)
{
    ARG_CHECK(welcomeResultHandle);
    auto welcomeResult = reinterpret_cast<discord::dave::RosterMap*>(welcomeResultHandle);
    GetRosterMemberSignature(*welcomeResult, rosterId, signature, signatureLength);
}

void daveWelcomeResultDestroy(DAVEWelcomeResultHandle welcomeResultHandle)
{
    auto welcomeResult = reinterpret_cast<discord::dave::RosterMap*>(welcomeResultHandle);
    delete welcomeResult;
}

DAVEEncryptorHandle daveEncryptorCreate()
{
    auto encryptor = discord::dave::CreateEncryptor();
    return reinterpret_cast<DAVEEncryptorHandle>(encryptor.release());
}

void daveEncryptorDestroy(DAVEEncryptorHandle encryptorHandle)
{
    auto encryptor = reinterpret_cast<discord::dave::IEncryptor*>(encryptorHandle);
    delete encryptor;
}

void daveEncryptorSetKeyRatchet(DAVEEncryptorHandle encryptorHandle,
                                DAVEKeyRatchetHandle keyRatchet)
{
    ARG_CHECK(encryptorHandle);
    auto encryptor = reinterpret_cast<discord::dave::IEncryptor*>(encryptorHandle);
    auto keyRatchetCopy = CopyKeyRatchet(keyRatchet);
    encryptor->SetKeyRatchet(std::move(keyRatchetCopy));
}

void daveEncryptorSetPassthroughMode(DAVEEncryptorHandle encryptorHandle, bool passthroughMode)
{
    ARG_CHECK(encryptorHandle);
    auto encryptor = reinterpret_cast<discord::dave::IEncryptor*>(encryptorHandle);
    encryptor->SetPassthroughMode(passthroughMode);
}

void daveEncryptorAssignSsrcToCodec(DAVEEncryptorHandle encryptorHandle,
                                    uint32_t ssrc,
                                    DAVECodec codecType)
{
    ARG_CHECK(encryptorHandle);
    auto encryptor = reinterpret_cast<discord::dave::IEncryptor*>(encryptorHandle);
    encryptor->AssignSsrcToCodec(ssrc, static_cast<discord::dave::Codec>(codecType));
}

uint16_t daveEncryptorGetProtocolVersion(DAVEEncryptorHandle encryptorHandle)
{
    ARG_CHECK_RET(encryptorHandle, 0);
    auto encryptor = reinterpret_cast<discord::dave::IEncryptor*>(encryptorHandle);
    return encryptor->GetProtocolVersion();
}

size_t daveEncryptorGetMaxCiphertextByteSize(DAVEEncryptorHandle encryptorHandle,
                                             DAVEMediaType mediaType,
                                             size_t frameSize)
{
    ARG_CHECK_RET(encryptorHandle, 0);
    auto encryptor = reinterpret_cast<discord::dave::IEncryptor*>(encryptorHandle);
    return encryptor->GetMaxCiphertextByteSize(static_cast<discord::dave::MediaType>(mediaType),
                                               frameSize);
}

bool daveEncryptorHasKeyRatchet(DAVEEncryptorHandle encryptorHandle)
{
    ARG_CHECK_RET(encryptorHandle, false);
    auto encryptor = reinterpret_cast<discord::dave::IEncryptor*>(encryptorHandle);
    return encryptor->HasKeyRatchet();
}

bool daveEncryptorIsPassthroughMode(DAVEEncryptorHandle encryptorHandle)
{
    ARG_CHECK_RET(encryptorHandle, false);
    auto encryptor = reinterpret_cast<discord::dave::IEncryptor*>(encryptorHandle);
    return encryptor->IsPassthroughMode();
}

DAVEEncryptorResultCode daveEncryptorEncrypt(DAVEEncryptorHandle encryptorHandle,
                                             DAVEMediaType mediaType,
                                             uint32_t ssrc,
                                             const uint8_t* frame,
                                             size_t frameLength,
                                             uint8_t* encryptedFrame,
                                             size_t encryptedFrameCapacity,
                                             size_t* bytesWritten)
{
    ARG_CHECK_RET(encryptorHandle, DAVE_ENCRYPTOR_RESULT_CODE_ENCRYPTION_FAILURE);
    auto encryptor = reinterpret_cast<discord::dave::IEncryptor*>(encryptorHandle);
    auto frameView = discord::dave::MakeArrayView(frame, frameLength);
    auto encryptedFrameView = discord::dave::MakeArrayView(encryptedFrame, encryptedFrameCapacity);
    auto result = encryptor->Encrypt(static_cast<discord::dave::MediaType>(mediaType),
                                     ssrc,
                                     frameView,
                                     encryptedFrameView,
                                     bytesWritten);
    return static_cast<DAVEEncryptorResultCode>(result);
}

void daveEncryptorSetProtocolVersionChangedCallback(
  DAVEEncryptorHandle encryptorHandle,
  DAVEEncryptorProtocolVersionChangedCallback callback,
  void* userData)
{
    ARG_CHECK(encryptorHandle);
    auto encryptor = reinterpret_cast<discord::dave::IEncryptor*>(encryptorHandle);
    encryptor->SetProtocolVersionChangedCallback([callback, userData]() { callback(userData); });
}

void daveEncryptorGetStats(DAVEEncryptorHandle encryptorHandle,
                           DAVEMediaType mediaType,
                           DAVEEncryptorStats* stats)
{
    ARG_CHECK(encryptorHandle);
    auto encryptor = reinterpret_cast<discord::dave::IEncryptor*>(encryptorHandle);
    *stats = encryptor->GetStats(static_cast<discord::dave::MediaType>(mediaType));
}

DAVEDecryptorHandle daveDecryptorCreate()
{
    auto decryptor = discord::dave::CreateDecryptor();
    return reinterpret_cast<DAVEDecryptorHandle>(decryptor.release());
}

void daveDecryptorDestroy(DAVEDecryptorHandle decryptorHandle)
{
    auto decryptor = reinterpret_cast<discord::dave::IDecryptor*>(decryptorHandle);
    delete decryptor;
}

void daveDecryptorTransitionToKeyRatchet(DAVEDecryptorHandle decryptorHandle,
                                         DAVEKeyRatchetHandle keyRatchet)
{
    ARG_CHECK(decryptorHandle);
    auto decryptor = reinterpret_cast<discord::dave::IDecryptor*>(decryptorHandle);
    auto keyRatchetCopy = CopyKeyRatchet(keyRatchet);
    decryptor->TransitionToKeyRatchet(std::move(keyRatchetCopy));
}

void daveDecryptorTransitionToPassthroughMode(DAVEDecryptorHandle decryptorHandle,
                                              bool passthroughMode)
{
    ARG_CHECK(decryptorHandle);
    auto decryptor = reinterpret_cast<discord::dave::IDecryptor*>(decryptorHandle);
    decryptor->TransitionToPassthroughMode(passthroughMode);
}

DAVEDecryptorResultCode daveDecryptorDecrypt(DAVEDecryptorHandle decryptorHandle,
                                             DAVEMediaType mediaType,
                                             const uint8_t* encryptedFrame,
                                             size_t encryptedFrameLength,
                                             uint8_t* frame,
                                             size_t frameCapacity,
                                             size_t* bytesWritten)
{
    ARG_CHECK_RET(decryptorHandle, DAVE_DECRYPTOR_RESULT_CODE_DECRYPTION_FAILURE);
    auto decryptor = reinterpret_cast<discord::dave::IDecryptor*>(decryptorHandle);
    auto encryptedFrameView = discord::dave::MakeArrayView(encryptedFrame, encryptedFrameLength);
    auto frameView = discord::dave::MakeArrayView(frame, frameCapacity);
    auto result = decryptor->Decrypt(static_cast<discord::dave::MediaType>(mediaType),
                                     encryptedFrameView,
                                     frameView,
                                     bytesWritten);
    return static_cast<DAVEDecryptorResultCode>(result);
}

size_t daveDecryptorGetMaxPlaintextByteSize(DAVEDecryptorHandle decryptorHandle,
                                            DAVEMediaType mediaType,
                                            size_t encryptedFrameSize)
{
    ARG_CHECK_RET(decryptorHandle, 0);
    auto decryptor = reinterpret_cast<discord::dave::IDecryptor*>(decryptorHandle);
    return decryptor->GetMaxPlaintextByteSize(static_cast<discord::dave::MediaType>(mediaType),
                                              encryptedFrameSize);
}

void daveDecryptorGetStats(DAVEDecryptorHandle decryptorHandle,
                           DAVEMediaType mediaType,
                           DAVEDecryptorStats* stats)
{
    ARG_CHECK(decryptorHandle);
    auto decryptor = reinterpret_cast<discord::dave::IDecryptor*>(decryptorHandle);
    *stats = decryptor->GetStats(static_cast<discord::dave::MediaType>(mediaType));
}

static std::atomic<DAVELogSinkCallback> gLogSinkCallback{nullptr};

void LogSinkCallback(discord::dave::LoggingSeverity severity,
                     const char* file,
                     int line,
                     const std::string& message)
{
    auto callback = gLogSinkCallback.load();
    if (callback) {
        callback(static_cast<DAVELoggingSeverity>(severity), file, line, message.c_str());
    }
}

void daveSetLogSinkCallback(DAVELogSinkCallback callback)
{
    gLogSinkCallback.store(callback);
    discord::dave::SetLogSink(callback ? LogSinkCallback : nullptr);
}
