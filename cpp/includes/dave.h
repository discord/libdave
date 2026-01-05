#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#if (defined(_WIN32) || defined(_WIN64))
#define DAVE_EXPORT __declspec(dllexport)
#else
#define DAVE_EXPORT __attribute__((visibility("default")))
#endif

#define DECLARE_OPAQUE_HANDLE(x) typedef struct x##_s* x

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_OPAQUE_HANDLE(DAVESessionHandle);
DECLARE_OPAQUE_HANDLE(DAVECommitResultHandle);
DECLARE_OPAQUE_HANDLE(DAVEWelcomeResultHandle);
DECLARE_OPAQUE_HANDLE(DAVEKeyRatchetHandle);
DECLARE_OPAQUE_HANDLE(DAVESignaturePrivateKeyHandle);
DECLARE_OPAQUE_HANDLE(DAVEEncryptorHandle);
DECLARE_OPAQUE_HANDLE(DAVEDecryptorHandle);

typedef enum {
    DAVE_CODEC_UNKNOWN = 0,
    DAVE_CODEC_OPUS = 1,
    DAVE_CODEC_VP8 = 2,
    DAVE_CODEC_VP9 = 3,
    DAVE_CODEC_H264 = 4,
    DAVE_CODEC_H265 = 5,
    DAVE_CODEC_AV1 = 6
} DAVECodec;

typedef enum { DAVE_MEDIA_TYPE_AUDIO = 0, DAVE_MEDIA_TYPE_VIDEO = 1 } DAVEMediaType;

typedef enum {
    DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS = 0,
    DAVE_ENCRYPTOR_RESULT_CODE_ENCRYPTION_FAILURE = 1,
} DAVEEncryptorResultCode;


typedef enum {
    DAVE_DECRYPTOR_RESULT_CODE_SUCCESS = 0,
    DAVE_DECRYPTOR_RESULT_CODE_DECRYPTION_FAILURE = 1,
    DAVE_DECRYPTOR_RESULT_CODE_MISSING_KEY_RATCHET = 2,
    DAVE_DECRYPTOR_RESULT_CODE_INVALID_NONCE = 3,
    DAVE_DECRYPTOR_RESULT_CODE_MISSING_CRYPTOR = 4,
} DAVEDecryptorResultCode;

typedef enum {
    DAVE_LOGGING_SEVERITY_VERBOSE = 0,
    DAVE_LOGGING_SEVERITY_INFO = 1,
    DAVE_LOGGING_SEVERITY_WARNING = 2,
    DAVE_LOGGING_SEVERITY_ERROR = 3,
    DAVE_LOGGING_SEVERITY_NONE = 4,
} DAVELoggingSeverity;

typedef void (*DAVEMLSFailureCallback)(const char* source, const char* reason, void* userData);
typedef void (*DAVEPairwiseFingerprintCallback)(const uint8_t* fingerprint, size_t length, void* userData);
typedef void (*DAVEEncryptorProtocolVersionChangedCallback)(void* userData);
typedef void (*DAVELogSinkCallback)(DAVELoggingSeverity severity,
                                    const char* file,
                                    int line,
                                    const char* message);

typedef struct DAVEEncryptorStats {
    uint64_t passthroughCount;
    uint64_t encryptSuccessCount;
    uint64_t encryptFailureCount;
    uint64_t encryptDuration;
    uint64_t encryptAttempts;
    uint64_t encryptMaxAttempts;
    uint64_t encryptMissingKeyCount;
} DAVEEncryptorStats;

typedef struct DAVEDecryptorStats {
    uint64_t passthroughCount;
    uint64_t decryptSuccessCount;
    uint64_t decryptFailureCount;
    uint64_t decryptDuration;
    uint64_t decryptAttempts;
    uint64_t decryptMissingKeyCount;
    uint64_t decryptInvalidNonceCount;
} DAVEDecryptorStats;

DAVE_EXPORT uint16_t daveMaxSupportedProtocolVersion(void);

DAVE_EXPORT DAVESessionHandle daveSessionCreate(void* context,
                                                const char* authSessionId,
                                                DAVEMLSFailureCallback callback,
                                                void* userData);
DAVE_EXPORT void daveSessionDestroy(DAVESessionHandle session);
DAVE_EXPORT void daveSessionInit(DAVESessionHandle session,
                                 uint16_t version,
                                 uint64_t groupId,
                                 const char* selfUserId);
DAVE_EXPORT void daveSessionReset(DAVESessionHandle session);
DAVE_EXPORT void daveSessionSetProtocolVersion(DAVESessionHandle session, uint16_t version);
DAVE_EXPORT uint16_t daveSessionGetProtocolVersion(DAVESessionHandle session);
DAVE_EXPORT void daveSessionGetLastEpochAuthenticator(DAVESessionHandle session,
                                                      uint8_t** authenticator,
                                                      size_t* length);
DAVE_EXPORT void daveSessionSetExternalSender(DAVESessionHandle session,
                                              const uint8_t* externalSender,
                                              size_t length);
DAVE_EXPORT void daveSessionProcessProposals(DAVESessionHandle session,
                                             const uint8_t* proposals,
                                             size_t length,
                                             const char** recognizedUserIds,
                                             size_t recognizedUserIdsLength,
                                             uint8_t** commitWelcomeBytes,
                                             size_t* commitWelcomeBytesLength);
DAVE_EXPORT DAVECommitResultHandle daveSessionProcessCommit(DAVESessionHandle session,
                                          const uint8_t* commit,
                                          size_t length);
DAVE_EXPORT DAVEWelcomeResultHandle daveSessionProcessWelcome(DAVESessionHandle session,
                                           const uint8_t* welcome,
                                           size_t length,
                                           const char** recognizedUserIds,
                                           size_t recognizedUserIdsLength);
DAVE_EXPORT void daveSessionGetMarshalledKeyPackage(DAVESessionHandle session,
                                                    uint8_t** keyPackage,
                                                    size_t* length);
DAVE_EXPORT DAVEKeyRatchetHandle daveSessionGetKeyRatchet(DAVESessionHandle session,
                                                          const char* userId);
DAVE_EXPORT void daveSessionGetPairwiseFingerprint(DAVESessionHandle session,
                                                   uint16_t version,
                                                   const char* userId,
                                                   DAVEPairwiseFingerprintCallback callback,
                                                   void* userData);


DAVE_EXPORT void daveKeyRatchetDestroy(DAVEKeyRatchetHandle keyRatchet);


DAVE_EXPORT void daveKeyRatchetDestroy(DAVEKeyRatchetHandle keyRatchet);

DAVE_EXPORT bool daveCommitResultIsFailed(DAVECommitResultHandle commitResultHandle);
DAVE_EXPORT bool daveCommitResultIsIgnored(DAVECommitResultHandle commitResultHandle);
DAVE_EXPORT void daveCommitResultGetRosterMemberIds(DAVECommitResultHandle commitResultHandle, uint64_t** rosterIds, size_t* rosterIdsLength);
DAVE_EXPORT void daveCommitResultGetRosterMemberSignature(DAVECommitResultHandle commitResultHandle, uint64_t rosterId, uint8_t** signature, size_t* signatureLength);
DAVE_EXPORT void daveCommitResultDestroy(DAVECommitResultHandle commitResultHandle);

DAVE_EXPORT void daveWelcomeResultGetRosterMemberIds(DAVEWelcomeResultHandle welcomeResultHandle, uint64_t** rosterIds, size_t* rosterIdsLength);
DAVE_EXPORT void daveWelcomeResultGetRosterMemberSignature(DAVEWelcomeResultHandle welcomeResultHandle, uint64_t rosterId, uint8_t** signature, size_t* signatureLength);
DAVE_EXPORT void daveWelcomeResultDestroy(DAVEWelcomeResultHandle welcomeResultHandle);

DAVE_EXPORT DAVEEncryptorHandle daveEncryptorCreate(void);
DAVE_EXPORT void daveEncryptorDestroy(DAVEEncryptorHandle encryptor);
DAVE_EXPORT void daveEncryptorSetKeyRatchet(DAVEEncryptorHandle encryptor,
                                            DAVEKeyRatchetHandle keyRatchet);
DAVE_EXPORT void daveEncryptorSetPassthroughMode(DAVEEncryptorHandle encryptor,
                                                 bool passthroughMode);
DAVE_EXPORT void daveEncryptorAssignSsrcToCodec(DAVEEncryptorHandle encryptor,
                                                uint32_t ssrc,
                                                DAVECodec codecType);
DAVE_EXPORT uint16_t daveEncryptorGetProtocolVersion(DAVEEncryptorHandle encryptor);
DAVE_EXPORT size_t daveEncryptorGetMaxCiphertextByteSize(DAVEEncryptorHandle encryptor,
                                                         DAVEMediaType mediaType,
                                                         size_t frameSize);
DAVE_EXPORT DAVEEncryptorResultCode daveEncryptorEncrypt(DAVEEncryptorHandle encryptor,
                                                DAVEMediaType mediaType,
                                                uint32_t ssrc,
                                                const uint8_t* frame,
                                                size_t frameLength,
                                                uint8_t* encryptedFrame,
                                                size_t encryptedFrameCapacity,
                                                size_t* bytesWritten);
DAVE_EXPORT void daveEncryptorSetProtocolVersionChangedCallback(
  DAVEEncryptorHandle encryptor,
  DAVEEncryptorProtocolVersionChangedCallback callback,
  void* userData);
DAVE_EXPORT void daveEncryptorGetStats(DAVEEncryptorHandle encryptor,
                                       DAVEMediaType mediaType,
                                       DAVEEncryptorStats* stats);




DAVE_EXPORT DAVEDecryptorHandle daveDecryptorCreate(void);
DAVE_EXPORT void daveDecryptorDestroy(DAVEDecryptorHandle decryptor);
DAVE_EXPORT void daveDecryptorTransitionToKeyRatchet(DAVEDecryptorHandle decryptor,
                                                     DAVEKeyRatchetHandle keyRatchet);
DAVE_EXPORT void daveDecryptorTransitionToPassthroughMode(DAVEDecryptorHandle decryptor,
                                                          bool passthroughMode);
DAVE_EXPORT DAVEDecryptorResultCode daveDecryptorDecrypt(DAVEDecryptorHandle decryptor,
                                                         DAVEMediaType mediaType,
                                                         const uint8_t* encryptedFrame,
                                                         size_t encryptedFrameLength,
                                                         uint8_t* frame,
                                                         size_t frameCapacity,
                                                         size_t* bytesWritten);
DAVE_EXPORT size_t daveDecryptorGetMaxPlaintextByteSize(DAVEDecryptorHandle decryptor,
                                                        DAVEMediaType mediaType,
                                                        size_t encryptedFrameSize);
DAVE_EXPORT void daveDecryptorGetStats(DAVEDecryptorHandle decryptor,
                                       DAVEMediaType mediaType,
                                       DAVEDecryptorStats* stats);

DAVE_EXPORT void daveSetLogSinkCallback(DAVELogSinkCallback callback);

#ifdef __cplusplus
}
#endif
