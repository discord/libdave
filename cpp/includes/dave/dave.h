/**
 * @file dave.h
 * @brief DAVE (Discord Audio/Video Encryption) C API
 *
 * This header provides the C API for end-to-end encryption of audio and video
 * streams using the DAVE protocol.
 *
 * All handles are opaque pointers that must be created and destroyed using
 * the corresponding API functions. Memory management rules:
 * - Handles from *Create functions must be freed with their *Destroy counterpart
 * - Output handles should be destroyed by the caller using the corresponding *Destroy function
 * - Functions do not take ownership of the input data unless otherwise specified
 * - Output byte arrays should be freed by the caller using free() unless otherwise specified
 */

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

/** @brief DAVE session handle for managing group encryption state */
DECLARE_OPAQUE_HANDLE(DAVESessionHandle);
/** @brief Result handle from processing an MLS commit message */
DECLARE_OPAQUE_HANDLE(DAVECommitResultHandle);
/** @brief Result handle from processing an MLS welcome message */
DECLARE_OPAQUE_HANDLE(DAVEWelcomeResultHandle);
/** @brief Key ratchet handle for deriving encryption keys */
DECLARE_OPAQUE_HANDLE(DAVEKeyRatchetHandle);
/** @brief Media frame encryptor handle */
DECLARE_OPAQUE_HANDLE(DAVEEncryptorHandle);
/** @brief Media frame decryptor handle */
DECLARE_OPAQUE_HANDLE(DAVEDecryptorHandle);

/**
 * @brief Supported media codecs for encryption
 */
typedef enum {
    DAVE_CODEC_UNKNOWN = 0, /**< Unknown or unspecified codec */
    DAVE_CODEC_OPUS = 1,    /**< Opus audio codec */
    DAVE_CODEC_VP8 = 2,     /**< VP8 video codec */
    DAVE_CODEC_VP9 = 3,     /**< VP9 video codec */
    DAVE_CODEC_H264 = 4,    /**< H.264/AVC video codec */
    DAVE_CODEC_H265 = 5,    /**< H.265/HEVC video codec */
    DAVE_CODEC_AV1 = 6      /**< AV1 video codec */
} DAVECodec;

/**
 * @brief Media stream type classification
 */
typedef enum {
    DAVE_MEDIA_TYPE_AUDIO = 0, /**< Audio stream */
    DAVE_MEDIA_TYPE_VIDEO = 1  /**< Video stream */
} DAVEMediaType;

/**
 * @brief Result codes returned by encryption operations
 */
typedef enum {
    DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS = 0,            /**< Encryption succeeded */
    DAVE_ENCRYPTOR_RESULT_CODE_ENCRYPTION_FAILURE = 1, /**< Encryption failed */
    DAVE_ENCRYPTOR_RESULT_CODE_MISSING_KEY_RATCHET = 2,/**< No key ratchet available */
    DAVE_ENCRYPTOR_RESULT_CODE_MISSING_CRYPTOR = 3,    /**< Missing cryptographic context */
    DAVE_ENCRYPTOR_RESULT_CODE_TOO_MANY_ATTEMPTS = 4,  /**< Too many attempts to encrypt the frame failed */
} DAVEEncryptorResultCode;

/**
 * @brief Result codes returned by decryption operations
 */
typedef enum {
    DAVE_DECRYPTOR_RESULT_CODE_SUCCESS = 0,            /**< Decryption succeeded */
    DAVE_DECRYPTOR_RESULT_CODE_DECRYPTION_FAILURE = 1, /**< Decryption failed */
    DAVE_DECRYPTOR_RESULT_CODE_MISSING_KEY_RATCHET = 2,/**< No key ratchet available */
    DAVE_DECRYPTOR_RESULT_CODE_INVALID_NONCE = 3,      /**< Invalid nonce in encrypted frame */
    DAVE_DECRYPTOR_RESULT_CODE_MISSING_CRYPTOR = 4     /**< Missing cryptographic context */
} DAVEDecryptorResultCode;

/**
 * @brief Log message severity levels
 */
typedef enum {
    DAVE_LOGGING_SEVERITY_VERBOSE = 0, /**< Verbose debug information */
    DAVE_LOGGING_SEVERITY_INFO = 1,    /**< Informational messages */
    DAVE_LOGGING_SEVERITY_WARNING = 2, /**< Warning messages */
    DAVE_LOGGING_SEVERITY_ERROR = 3,   /**< Error messages */
    DAVE_LOGGING_SEVERITY_NONE = 4     /**< Messages to be ignored */
} DAVELoggingSeverity;

/**
 * @brief Callback invoked when an MLS protocol failure occurs
 * @param source The source/component where the failure occurred
 * @param reason Human-readable failure reason
 * @param userData User-provided context pointer
 */
typedef void (*DAVEMLSFailureCallback)(const char* source, const char* reason, void* userData);

/**
 * @brief Callback invoked with the computed pairwise fingerprint for identity verification
 * @param fingerprint Pointer to fingerprint bytes (freed by the library after the callback returns)
 * @param length Length of fingerprint in bytes
 * @param userData User-provided context pointer
 */
typedef void (*DAVEPairwiseFingerprintCallback)(const uint8_t* fingerprint, size_t length, void* userData);

/**
 * @brief Callback invoked when the encryptor's protocol version changes
 * @param userData User-provided context pointer
 */
typedef void (*DAVEEncryptorProtocolVersionChangedCallback)(void* userData);

/**
 * @brief Custom log sink callback for receiving library log messages
 * @param severity Log severity level
 * @param file Source file name where log originated (freed by the library after the callback returns)
 * @param line Line number in source file
 * @param message Log message text (freed by the library after the callback returns)
 */
typedef void (*DAVELogSinkCallback)(DAVELoggingSeverity severity,
                                    const char* file,
                                    int line,
                                    const char* message);

/**
 * @brief Statistics for encryption operations
 */
typedef struct DAVEEncryptorStats {
    uint64_t passthroughCount;      /**< Frames passed through without encryption */
    uint64_t encryptSuccessCount;   /**< Successful encryption count */
    uint64_t encryptFailureCount;   /**< Failed encryption count */
    uint64_t encryptDuration;       /**< Total encryption duration */
    uint64_t encryptAttempts;       /**< Total encryption attempts */
    uint64_t encryptMaxAttempts;    /**< Maximum retry attempts for a single frame */
    uint64_t encryptMissingKeyCount;/**< Encryptions skipped due to missing key */
} DAVEEncryptorStats;

/**
 * @brief Statistics for decryption operations
 */
typedef struct DAVEDecryptorStats {
    uint64_t passthroughCount;        /**< Frames passed through without decryption */
    uint64_t decryptSuccessCount;     /**< Successful decryption count */
    uint64_t decryptFailureCount;     /**< Failed decryption count */
    uint64_t decryptDuration;         /**< Total decryption duration */
    uint64_t decryptAttempts;         /**< Total decryption attempts */
    uint64_t decryptMissingKeyCount;  /**< Decryptions failed due to missing key */
    uint64_t decryptInvalidNonceCount;/**< Decryptions failed due to invalid nonce */
} DAVEDecryptorStats;


/*******************************************************************************
 * Version
 ******************************************************************************/

/**
 * @brief Returns the maximum protocol version supported by this library
 * @return Maximum supported protocol version number
 */
DAVE_EXPORT uint16_t daveMaxSupportedProtocolVersion(void);

/*******************************************************************************
 * Session Management
 ******************************************************************************/

/**
 * @brief Creates a new DAVE session
 * @param context Currently unused platform-specific context pointer (can be NULL)
 * @param authSessionId String used to manage persistent key lifetimes (can be NULL)
 * @param callback Callback invoked on MLS failures
 * @param userData User data pointer passed to the callback
 * @return New session handle, or NULL on failure. Must be destroyed with daveSessionDestroy()
 */
DAVE_EXPORT DAVESessionHandle daveSessionCreate(void* context,
                                                const char* authSessionId,
                                                DAVEMLSFailureCallback callback,
                                                void* userData);

/**
 * @brief Destroys a session and frees associated resources
 * @param session Session handle to destroy
 */
DAVE_EXPORT void daveSessionDestroy(DAVESessionHandle session);

/**
 * @brief Initializes a session with protocol version and group information
 * @param session Session handle
 * @param version Protocol version to use
 * @param groupId Group identifier common to all users in the group
 * @param selfUserId User ID of the local user
 */
DAVE_EXPORT void daveSessionInit(DAVESessionHandle session,
                                 uint16_t version,
                                 uint64_t groupId,
                                 const char* selfUserId);

/**
 * @brief Resets the session state
 * @param session Session handle
 */
DAVE_EXPORT void daveSessionReset(DAVESessionHandle session);

/**
 * @brief Sets the protocol version for the session
 * @param session Session handle
 * @param version Protocol version to set
 */
DAVE_EXPORT void daveSessionSetProtocolVersion(DAVESessionHandle session, uint16_t version);

/**
 * @brief Gets the current protocol version of the session
 * @param session Session handle
 * @return Current protocol version
 */
DAVE_EXPORT uint16_t daveSessionGetProtocolVersion(DAVESessionHandle session);

/**
 * @brief Retrieves the authenticator from the last MLS epoch
 * @param session Session handle
 * @param[out] authenticator Output pointer to authenticator bytes (caller must free)
 * @param[out] length Output pointer to authenticator length
 */
DAVE_EXPORT void daveSessionGetLastEpochAuthenticator(DAVESessionHandle session,
                                                      uint8_t** authenticator,
                                                      size_t* length);

/**
 * @brief Sets the external sender credentials for the session
 * @param session Session handle
 * @param externalSender External sender credential bytes
 * @param length Length of external sender data
 */
DAVE_EXPORT void daveSessionSetExternalSender(DAVESessionHandle session,
                                              const uint8_t* externalSender,
                                              size_t length);

/**
 * @brief Processes MLS proposals and generates commit/welcome messages
 * @param session Session handle
 * @param proposals Serialized proposal bytes
 * @param length Length of proposals
 * @param recognizedUserIds Array of recognized user ID strings
 * @param recognizedUserIdsLength Number of recognized user IDs
 * @param[out] commitWelcomeBytes Output buffer to commit/welcome message bytes (caller must free)
 * @param[out] commitWelcomeBytesLength Output length of the commit/welcome message
 */
DAVE_EXPORT void daveSessionProcessProposals(DAVESessionHandle session,
                                             const uint8_t* proposals,
                                             size_t length,
                                             const char** recognizedUserIds,
                                             size_t recognizedUserIdsLength,
                                             uint8_t** commitWelcomeBytes,
                                             size_t* commitWelcomeBytesLength);

/**
 * @brief Processes an incoming MLS commit message
 * @param session Session handle
 * @param commit Serialized commit message bytes
 * @param length Length of commit message
 * @return Commit result handle. Must be destroyed with daveCommitResultDestroy()
 */
DAVE_EXPORT DAVECommitResultHandle daveSessionProcessCommit(DAVESessionHandle session,
                                                            const uint8_t* commit,
                                                            size_t length);

/**
 * @brief Processes an incoming MLS welcome message to join a group
 * @param session Session handle
 * @param welcome Serialized welcome message bytes
 * @param length Length of welcome message
 * @param recognizedUserIds Array of recognized user ID strings
 * @param recognizedUserIdsLength Number of recognized user IDs
 * @return Welcome result handle. Must be destroyed with daveWelcomeResultDestroy()
 */
DAVE_EXPORT DAVEWelcomeResultHandle daveSessionProcessWelcome(DAVESessionHandle session,
                                                              const uint8_t* welcome,
                                                              size_t length,
                                                              const char** recognizedUserIds,
                                                              size_t recognizedUserIdsLength);

/**
 * @brief Gets the marshalled MLS key package for this session
 * @param session Session handle
 * @param[out] keyPackage Output buffer to key package bytes (caller must free)
 * @param[out] length Output length of the key package
 */
DAVE_EXPORT void daveSessionGetMarshalledKeyPackage(DAVESessionHandle session,
                                                    uint8_t** keyPackage,
                                                    size_t* length);

/**
 * @brief Gets a key ratchet for a specific user in the session
 * @param session Session handle
 * @param userId User ID to get key ratchet for
 * @return Key ratchet handle. Must be destroyed with daveKeyRatchetDestroy()
 */
DAVE_EXPORT DAVEKeyRatchetHandle daveSessionGetKeyRatchet(DAVESessionHandle session,
                                                          const char* userId);

/**
 * @brief Computes a pairwise fingerprint for identity verification with another user
 * @param session Session handle
 * @param version Protocol version currently in use
 * @param userId User ID of the remote user to compute the fingerprint for
 * @param callback Callback to receive the fingerprint
 * @param userData User data passed to callback
 */
DAVE_EXPORT void daveSessionGetPairwiseFingerprint(DAVESessionHandle session,
                                                   uint16_t version,
                                                   const char* userId,
                                                   DAVEPairwiseFingerprintCallback callback,
                                                   void* userData);


/*******************************************************************************
 * Key Ratchet
 ******************************************************************************/

/**
 * @brief Destroys a key ratchet and frees associated resources
 * @param keyRatchet Key ratchet handle to destroy
 */
DAVE_EXPORT void daveKeyRatchetDestroy(DAVEKeyRatchetHandle keyRatchet);

/*******************************************************************************
 * Commit Result
 ******************************************************************************/

/**
 * @brief Checks if processing the commit failed
 * @param commitResultHandle Commit result handle
 * @return true if commit processing failed
 */
DAVE_EXPORT bool daveCommitResultIsFailed(DAVECommitResultHandle commitResultHandle);

/**
 * @brief Checks if the commit should be ignored
 * @param commitResultHandle Commit result handle
 * @return true if commit should be ignored
 */
DAVE_EXPORT bool daveCommitResultIsIgnored(DAVECommitResultHandle commitResultHandle);

/**
 * @brief Gets the list of member IDs in the roster after the commit
 * @param commitResultHandle Commit result handle
 * @param[out] rosterIds Output buffer to array of roster member IDs (caller must free)
 * @param[out] rosterIdsLength Output length of the roster member IDs array
 */
DAVE_EXPORT void daveCommitResultGetRosterMemberIds(DAVECommitResultHandle commitResultHandle,
                                                    uint64_t** rosterIds,
                                                    size_t* rosterIdsLength);

/**
 * @brief Gets the signature for a specific roster member
 * @param commitResultHandle Commit result handle
 * @param rosterId Roster member ID
 * @param[out] signature Output buffer to signature bytes (caller must free)
 * @param[out] signatureLength Output length of the signature
 */
DAVE_EXPORT void daveCommitResultGetRosterMemberSignature(DAVECommitResultHandle commitResultHandle,
                                                          uint64_t rosterId,
                                                          uint8_t** signature,
                                                          size_t* signatureLength);

/**
 * @brief Destroys a commit result and frees associated resources
 * @param commitResultHandle Commit result handle to destroy
 */
DAVE_EXPORT void daveCommitResultDestroy(DAVECommitResultHandle commitResultHandle);

/*******************************************************************************
 * Welcome Result
 ******************************************************************************/

/**
 * @brief Gets the list of member IDs in the roster from the welcome message
 * @param welcomeResultHandle Welcome result handle
 * @param[out] rosterIds Output buffer to array of roster member IDs (caller must free)
 * @param[out] rosterIdsLength Output length of the roster member IDs array
 */
DAVE_EXPORT void daveWelcomeResultGetRosterMemberIds(DAVEWelcomeResultHandle welcomeResultHandle,
                                                     uint64_t** rosterIds,
                                                     size_t* rosterIdsLength);

/**
 * @brief Gets the signature for a specific roster member
 * @param welcomeResultHandle Welcome result handle
 * @param rosterId Roster member ID
 * @param[out] signature Output buffer to signature bytes (caller must free)
 * @param[out] signatureLength Output length of the signature
 */
DAVE_EXPORT void daveWelcomeResultGetRosterMemberSignature(DAVEWelcomeResultHandle welcomeResultHandle,
                                                           uint64_t rosterId,
                                                           uint8_t** signature,
                                                           size_t* signatureLength);

/**
 * @brief Destroys a welcome result and frees associated resources
 * @param welcomeResultHandle Welcome result handle to destroy
 */
DAVE_EXPORT void daveWelcomeResultDestroy(DAVEWelcomeResultHandle welcomeResultHandle);

/*******************************************************************************
 * Encryptor
 ******************************************************************************/

/**
 * @brief Creates a new media frame encryptor
 * @return New encryptor handle. Must be destroyed with daveEncryptorDestroy()
 */
DAVE_EXPORT DAVEEncryptorHandle daveEncryptorCreate(void);

/**
 * @brief Destroys an encryptor and frees associated resources
 * @param encryptor Encryptor handle to destroy
 */
DAVE_EXPORT void daveEncryptorDestroy(DAVEEncryptorHandle encryptor);

/**
 * @brief Sets the key ratchet for encryption 
 * @param encryptor Encryptor handle
 * @param keyRatchet Key ratchet to use for encryption (does *not* take ownership)
 */
DAVE_EXPORT void daveEncryptorSetKeyRatchet(DAVEEncryptorHandle encryptor,
                                            DAVEKeyRatchetHandle keyRatchet);

/**
 * @brief Enables or disables passthrough mode (frames pass through unencrypted)
 * @param encryptor Encryptor handle
 * @param passthroughMode true to enable passthrough, false to encrypt
 */
DAVE_EXPORT void daveEncryptorSetPassthroughMode(DAVEEncryptorHandle encryptor,
                                                 bool passthroughMode);

/**
 * @brief Associates an SSRC (Synchronization Source) with a specific codec
 * @param encryptor Encryptor handle
 * @param ssrc SSRC identifier
 * @param codecType Codec type for this SSRC
 */
DAVE_EXPORT void daveEncryptorAssignSsrcToCodec(DAVEEncryptorHandle encryptor,
                                                uint32_t ssrc,
                                                DAVECodec codecType);

/**
 * @brief Gets the current protocol version used by the encryptor
 * @param encryptor Encryptor handle
 * @return Protocol version number
 */
DAVE_EXPORT uint16_t daveEncryptorGetProtocolVersion(DAVEEncryptorHandle encryptor);

/**
 * @brief Calculates the maximum ciphertext size for a given plaintext frame size
 * @param encryptor Encryptor handle
 * @param mediaType Media type (audio or video)
 * @param frameSize Size of plaintext frame in bytes
 * @return Maximum possible ciphertext size in bytes
 */
DAVE_EXPORT size_t daveEncryptorGetMaxCiphertextByteSize(DAVEEncryptorHandle encryptor,
                                                         DAVEMediaType mediaType,
                                                         size_t frameSize);

/**
 * @brief Checks if the encryptor has a key ratchet
 * @param encryptor Encryptor handle
 * @return true if has key ratchet, false otherwise
 */
DAVE_EXPORT bool daveEncryptorHasKeyRatchet(DAVEEncryptorHandle encryptor);

/**
 * @brief Checks if the encryptor is in passthrough mode
 * @param encryptor Encryptor handle
 * @return true if in passthrough mode, false otherwise
 */
DAVE_EXPORT bool daveEncryptorIsPassthroughMode(DAVEEncryptorHandle encryptor);

/**
 * @brief Encrypts a media frame
 * @param encryptor Encryptor handle
 * @param mediaType Media type (audio or video)
 * @param ssrc SSRC of the stream
 * @param frame Pointer to plaintext frame data
 * @param frameLength Length of plaintext frame
 * @param[out] encryptedFrame Pointer to the output buffer the encrypted frame will be written to
 * @param encryptedFrameCapacity Capacity of the output buffer
 * @param[out] bytesWritten Number of bytes written to the output buffer
 * @return Result code indicating success or failure
 */
DAVE_EXPORT DAVEEncryptorResultCode daveEncryptorEncrypt(DAVEEncryptorHandle encryptor,
                                                         DAVEMediaType mediaType,
                                                         uint32_t ssrc,
                                                         const uint8_t* frame,
                                                         size_t frameLength,
                                                         uint8_t* encryptedFrame,
                                                         size_t encryptedFrameCapacity,
                                                         size_t* bytesWritten);

/**
 * @brief Sets a callback to be notified when the protocol version changes
 * @param encryptor Encryptor handle
 * @param callback Callback function
 * @param userData User data passed to callback
 */
DAVE_EXPORT void daveEncryptorSetProtocolVersionChangedCallback(
    DAVEEncryptorHandle encryptor,
    DAVEEncryptorProtocolVersionChangedCallback callback,
    void* userData);

/**
 * @brief Gets encryption statistics
 * @param encryptor Encryptor handle
 * @param mediaType Media type (audio or video)
 * @param[out] stats Pointer to the stats structure to be filled
 */
DAVE_EXPORT void daveEncryptorGetStats(DAVEEncryptorHandle encryptor,
                                       DAVEMediaType mediaType,
                                       DAVEEncryptorStats* stats);




/*******************************************************************************
 * Decryptor
 ******************************************************************************/

/**
 * @brief Creates a new media frame decryptor
 * @return New decryptor handle. Must be destroyed with daveDecryptorDestroy()
 */
DAVE_EXPORT DAVEDecryptorHandle daveDecryptorCreate(void);

/**
 * @brief Destroys a decryptor and frees associated resources
 * @param decryptor Decryptor handle to destroy
 */
DAVE_EXPORT void daveDecryptorDestroy(DAVEDecryptorHandle decryptor);

/**
 * @brief Transitions the decryptor to use a new key ratchet
 * @param decryptor Decryptor handle
 * @param keyRatchet New key ratchet to transition to (does *not* take ownership)
 */
DAVE_EXPORT void daveDecryptorTransitionToKeyRatchet(DAVEDecryptorHandle decryptor,
                                                     DAVEKeyRatchetHandle keyRatchet);

/**
 * @brief Transitions to or from passthrough mode
 * @param decryptor Decryptor handle
 * @param passthroughMode true to enable passthrough, false to decrypt
 */
DAVE_EXPORT void daveDecryptorTransitionToPassthroughMode(DAVEDecryptorHandle decryptor,
                                                          bool passthroughMode);

/**
 * @brief Decrypts an encrypted media frame
 * @param decryptor Decryptor handle
 * @param mediaType Media type (audio or video)
 * @param encryptedFrame Pointer to the encrypted frame data
 * @param encryptedFrameLength Length of the encrypted frame
 * @param[out] frame Pointer to the output buffer the decrypted frame will be written to
 * @param frameCapacity Capacity of the output buffer
 * @param[out] bytesWritten Number of bytes written to the output buffer
 * @return Result code indicating success or failure
 */
DAVE_EXPORT DAVEDecryptorResultCode daveDecryptorDecrypt(DAVEDecryptorHandle decryptor,
                                                         DAVEMediaType mediaType,
                                                         const uint8_t* encryptedFrame,
                                                         size_t encryptedFrameLength,
                                                         uint8_t* frame,
                                                         size_t frameCapacity,
                                                         size_t* bytesWritten);

/**
 * @brief Calculates the maximum plaintext size for a given ciphertext frame size
 * @param decryptor Decryptor handle
 * @param mediaType Media type (audio or video)
 * @param encryptedFrameSize Size of encrypted frame in bytes
 * @return Maximum possible plaintext size in bytes
 */
DAVE_EXPORT size_t daveDecryptorGetMaxPlaintextByteSize(DAVEDecryptorHandle decryptor,
                                                        DAVEMediaType mediaType,
                                                        size_t encryptedFrameSize);

/**
 * @brief Gets decryption statistics
 * @param decryptor Decryptor handle
 * @param mediaType Media type (audio or video)
 * @param[out] stats Pointer to the stats structure to be filled
 */
DAVE_EXPORT void daveDecryptorGetStats(DAVEDecryptorHandle decryptor,
                                       DAVEMediaType mediaType,
                                       DAVEDecryptorStats* stats);

/*******************************************************************************
 * Logging
 ******************************************************************************/

/**
 * @brief Sets a global callback for receiving log messages from the library
 * @param callback Log sink callback function
 */
DAVE_EXPORT void daveSetLogSinkCallback(DAVELogSinkCallback callback);

#ifdef __cplusplus
}
#endif
