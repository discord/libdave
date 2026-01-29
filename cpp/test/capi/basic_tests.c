#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef CRITICAL_SECTION mutex_t;
typedef CONDITION_VARIABLE cond_t;
#else
#include <pthread.h>
#include <unistd.h>
typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t cond_t;
#endif

#include <dave/dave.h>

#include "external_sender_wrapper.h"
#include "test_helpers.h"

#define RUN_TEST(test)                    \
    do {                                  \
        printf("Running %s...\n", #test); \
        if (test()) {                     \
            printf("  PASSED\n");         \
            passed++;                     \
        }                                 \
        else {                            \
            printf("  FAILED\n");         \
            failed++;                     \
        }                                 \
    } while (0)

static int TestEncryptorCreateDestroy(void)
{
    DAVEEncryptorHandle encryptor = daveEncryptorCreate();
    TEST_ASSERT(encryptor != NULL, "Failed to create encryptor");

    daveEncryptorDestroy(encryptor);

    return 1;
}

static int TestDecryptorCreateDestroy(void)
{
    DAVEDecryptorHandle decryptor = daveDecryptorCreate();
    TEST_ASSERT(decryptor != NULL, "Failed to create decryptor");

    daveDecryptorDestroy(decryptor);

    return 1;
}

static int TestMaxProtocolVersion(void)
{
    uint16_t maxProtocolVersion = daveMaxSupportedProtocolVersion();
    TEST_ASSERT_EQ(maxProtocolVersion, 1, "Max protocol version should be 1");

    return 1;
}

static int TestEncryptorPassthrough(void)
{
    DAVEEncryptorHandle encryptor = daveEncryptorCreate();
    TEST_ASSERT(encryptor != NULL, "Failed to create encryptor");

    TEST_ASSERT_EQ(daveEncryptorHasKeyRatchet(encryptor), false, "Encryptor should not have a key ratchet");
    TEST_ASSERT_EQ(daveEncryptorIsPassthroughMode(encryptor), false, "Encryptor should not be in passthrough mode");

    // Set passthrough mode
    daveEncryptorSetPassthroughMode(encryptor, true);

    TEST_ASSERT_EQ(daveEncryptorIsPassthroughMode(encryptor), true, "Encryptor should be in passthrough mode");
    TEST_ASSERT_EQ(daveEncryptorHasKeyRatchet(encryptor), false, "Encryptor should not have a key ratchet");

    daveEncryptorAssignSsrcToCodec(encryptor, 0, DAVE_CODEC_OPUS);

    // Create test data
    const char* hexData = "0dc5aedd5bdc3f20be5697e54dd1f437";
    size_t inputDataLength = 0;
    uint8_t* inputData = GetBufferFromHex(hexData, &inputDataLength);
    TEST_ASSERT(inputData != NULL, "Failed to get input data");

    // Allocate output buffer
    size_t outputDataLength =
      daveEncryptorGetMaxCiphertextByteSize(encryptor, DAVE_MEDIA_TYPE_AUDIO, inputDataLength);
    uint8_t* outputData = (uint8_t*)malloc(outputDataLength);

    size_t bytesWritten = 0;

    // Encrypt in passthrough mode
    DAVEEncryptorResultCode result = daveEncryptorEncrypt(encryptor,
                                                          DAVE_MEDIA_TYPE_AUDIO,
                                                          0,
                                                          inputData,
                                                          inputDataLength,
                                                          outputData,
                                                          outputDataLength,
                                                          &bytesWritten);

    TEST_ASSERT_EQ(result, DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS, "Encryption should succeed");
    TEST_ASSERT_EQ(bytesWritten, inputDataLength, "Bytes written should match input length");
    TEST_ASSERT(memcmp(inputData, outputData, inputDataLength) == 0,
                "Output should match input in passthrough mode");

    // Cleanup
    free(inputData);
    free(outputData);
    daveEncryptorDestroy(encryptor);

    return 1;
}

static int TestDecryptorPassthrough(void)
{
    DAVEDecryptorHandle decryptor = daveDecryptorCreate();
    TEST_ASSERT(decryptor != NULL, "Decryptor should be created");

    // Set passthrough mode
    daveDecryptorTransitionToPassthroughMode(decryptor, 1);

    // Create test data
    const char* hexData = "0dc5aedd5bdc3f20be5697e54dd1f437";
    size_t inputDataLength = 0;
    uint8_t* inputData = GetBufferFromHex(hexData, &inputDataLength);
    TEST_ASSERT(inputData != NULL, "Input data should be allocated");

    // Allocate output buffer
    size_t outputDataLength =
      daveDecryptorGetMaxPlaintextByteSize(decryptor, DAVE_MEDIA_TYPE_AUDIO, inputDataLength);
    uint8_t* outputData = (uint8_t*)malloc(outputDataLength);
    size_t bytesWritten = 0;

    // Decrypt in passthrough mode
    DAVEDecryptorResultCode result = daveDecryptorDecrypt(decryptor,
                                                          DAVE_MEDIA_TYPE_AUDIO,
                                                          inputData,
                                                          inputDataLength,
                                                          outputData,
                                                          outputDataLength,
                                                          &bytesWritten);

    TEST_ASSERT_EQ(result, DAVE_DECRYPTOR_RESULT_CODE_SUCCESS, "Decryption should succeed");
    TEST_ASSERT_EQ(bytesWritten, inputDataLength, "Bytes written should match input length");
    TEST_ASSERT(memcmp(inputData, outputData, inputDataLength) == 0,
                "Output should match input in passthrough mode");

    // Cleanup
    free(inputData);
    free(outputData);
    daveDecryptorDestroy(decryptor);

    return 1;
}

static int TestPassthroughInOutBuffer(void)
{
    const char* RandomBytes =
      "0dc5aedd5bdc3f20be5697e54dd1f437b896a36f858c6f20bbd69e2a493ca170c4f0c1b9acd4"
      "9d324b92afa788d09b12b29115a2feb3552b60fff983234a6c9608af3933683efc6b0f5579a9";

    size_t incomingFrameLength = 0;
    uint8_t* incomingFrame = GetBufferFromHex(RandomBytes, &incomingFrameLength);
    TEST_ASSERT(incomingFrame != NULL, "Failed to allocate incoming frame");

    uint8_t* frameCopy = (uint8_t*)malloc(incomingFrameLength);
    TEST_ASSERT(frameCopy != NULL, "Failed to allocate frame copy");
    memcpy(frameCopy, incomingFrame, incomingFrameLength);

    // Encryptor test
    DAVEEncryptorHandle encryptor = daveEncryptorCreate();
    TEST_ASSERT(encryptor != NULL, "Failed to create encryptor");
    daveEncryptorAssignSsrcToCodec(encryptor, 0, DAVE_CODEC_OPUS);
    daveEncryptorSetPassthroughMode(encryptor, true);

    size_t bytesWritten = 0;
    DAVEEncryptorResultCode encryptResult = daveEncryptorEncrypt(encryptor,
                                                                 DAVE_MEDIA_TYPE_AUDIO,
                                                                 0,
                                                                 incomingFrame,
                                                                 incomingFrameLength,
                                                                 incomingFrame,
                                                                 incomingFrameLength,
                                                                 &bytesWritten);

    TEST_ASSERT_EQ(encryptResult, DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS, "Encryption should succeed");
    TEST_ASSERT_EQ(bytesWritten, incomingFrameLength, "Bytes written should match input length");
    TEST_ASSERT(memcmp(incomingFrame, frameCopy, bytesWritten) == 0,
                "Encrypted data should match input in passthrough mode");

    // Decryptor test
    DAVEDecryptorHandle decryptor = daveDecryptorCreate();
    TEST_ASSERT(decryptor != NULL, "Failed to create decryptor");
    daveDecryptorTransitionToPassthroughMode(decryptor, true);

    bytesWritten = 0;
    DAVEDecryptorResultCode decryptResult = daveDecryptorDecrypt(decryptor,
                                                                 DAVE_MEDIA_TYPE_AUDIO,
                                                                 incomingFrame,
                                                                 incomingFrameLength,
                                                                 incomingFrame,
                                                                 incomingFrameLength,
                                                                 &bytesWritten);

    TEST_ASSERT_EQ(decryptResult, DAVE_DECRYPTOR_RESULT_CODE_SUCCESS, "Decryption should succeed");
    TEST_ASSERT_EQ(bytesWritten, incomingFrameLength, "Bytes written should match input length");
    TEST_ASSERT(memcmp(incomingFrame, frameCopy, bytesWritten) == 0,
                "Decrypted data should match input in passthrough mode");

    // Cleanup
    free(incomingFrame);
    free(frameCopy);
    daveEncryptorDestroy(encryptor);
    daveDecryptorDestroy(decryptor);

    return 1;
}

static int TestPassthroughTwoBuffers(void)
{
    const char* RandomBytes =
      "0dc5aedd5bdc3f20be5697e54dd1f437b896a36f858c6f20bbd69e2a493ca170c4f0c1b9acd4"
      "9d324b92afa788d09b12b29115a2feb3552b60fff983234a6c9608af3933683efc6b0f5579a9";

    size_t incomingFrameLength = 0;
    uint8_t* incomingFrame = GetBufferFromHex(RandomBytes, &incomingFrameLength);
    TEST_ASSERT(incomingFrame != NULL, "Failed to allocate incoming frame");

    uint8_t* encryptedFrame = (uint8_t*)malloc(incomingFrameLength * 2);
    TEST_ASSERT(encryptedFrame != NULL, "Failed to allocate encrypted frame");

    uint8_t* decryptedFrame = (uint8_t*)malloc(incomingFrameLength);
    TEST_ASSERT(decryptedFrame != NULL, "Failed to allocate decrypted frame");

    // Encryptor test
    DAVEEncryptorHandle encryptor = daveEncryptorCreate();
    TEST_ASSERT(encryptor != NULL, "Failed to create encryptor");
    daveEncryptorAssignSsrcToCodec(encryptor, 0, DAVE_CODEC_OPUS);
    daveEncryptorSetPassthroughMode(encryptor, true);

    size_t bytesWritten = 0;
    DAVEEncryptorResultCode encryptResult = daveEncryptorEncrypt(encryptor,
                                                                 DAVE_MEDIA_TYPE_AUDIO,
                                                                 0,
                                                                 incomingFrame,
                                                                 incomingFrameLength,
                                                                 encryptedFrame,
                                                                 incomingFrameLength * 2,
                                                                 &bytesWritten);

    TEST_ASSERT_EQ(encryptResult, DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS, "Encryption should succeed");
    TEST_ASSERT_EQ(bytesWritten, incomingFrameLength, "Bytes written should match input length");
    TEST_ASSERT(memcmp(incomingFrame, encryptedFrame, bytesWritten) == 0,
                "Encrypted data should match input in passthrough mode");

    // Decryptor test
    DAVEDecryptorHandle decryptor = daveDecryptorCreate();
    TEST_ASSERT(decryptor != NULL, "Failed to create decryptor");
    daveDecryptorTransitionToPassthroughMode(decryptor, true);

    size_t bytesDecrypted = 0;
    DAVEDecryptorResultCode decryptResult = daveDecryptorDecrypt(decryptor,
                                                                 DAVE_MEDIA_TYPE_AUDIO,
                                                                 encryptedFrame,
                                                                 bytesWritten,
                                                                 decryptedFrame,
                                                                 incomingFrameLength,
                                                                 &bytesDecrypted);

    TEST_ASSERT_EQ(decryptResult, DAVE_DECRYPTOR_RESULT_CODE_SUCCESS, "Decryption should succeed");
    TEST_ASSERT_EQ(
      bytesDecrypted, incomingFrameLength, "Bytes decrypted should match input length");
    TEST_ASSERT(memcmp(encryptedFrame, decryptedFrame, bytesDecrypted) == 0,
                "Decrypted data should match encrypted data");

    // Cleanup
    free(incomingFrame);
    free(encryptedFrame);
    free(decryptedFrame);
    daveEncryptorDestroy(encryptor);
    daveDecryptorDestroy(decryptor);

    return 1;
}

static void TestSessionFailureCallback(const char* source, const char* reason, void* userData)
{
    (void)userData;
    printf("Session failure: %s: %s\n", source, reason);
}

typedef struct {
    mutex_t mutex;
    cond_t cond;
    uint8_t* pairwiseFingerprint;
    size_t pairwiseFingerprintLength;
} PairwiseFingerprintData;

static void PairwiseFingerprintDataInit(PairwiseFingerprintData* data)
{
#ifdef _WIN32
    InitializeCriticalSection(&data->mutex);
    InitializeConditionVariable(&data->cond);
#else
    pthread_mutex_init(&data->mutex, NULL);
    pthread_cond_init(&data->cond, NULL);
#endif
    data->pairwiseFingerprint = NULL;
    data->pairwiseFingerprintLength = 0;
}

static void PairwiseFingerprintDataDestroy(PairwiseFingerprintData* data)
{
#ifdef _WIN32
    DeleteCriticalSection(&data->mutex);
    // CONDITION_VARIABLE does not need cleanup
#else
    pthread_mutex_destroy(&data->mutex);
    pthread_cond_destroy(&data->cond);
#endif
    free(data->pairwiseFingerprint);
    data->pairwiseFingerprint = NULL;
    data->pairwiseFingerprintLength = 0;
}

static void PairwiseFingerprintDataWait(PairwiseFingerprintData* data)
{
#ifdef _WIN32
    EnterCriticalSection(&data->mutex);
    if (data->pairwiseFingerprint == NULL) {
        SleepConditionVariableCS(&data->cond, &data->mutex, INFINITE);
    }
    LeaveCriticalSection(&data->mutex);
#else
    pthread_mutex_lock(&data->mutex);
    if (data->pairwiseFingerprint == NULL) {
        pthread_cond_wait(&data->cond, &data->mutex);
    }
    pthread_mutex_unlock(&data->mutex);
#endif
}

static void PairwiseFingerprintCallback(const uint8_t* pairwiseFingerprint,
                                        size_t pairwiseFingerprintLength,
                                        void* userData)
{
    if (userData == NULL) {
        return;
    }
    PairwiseFingerprintData* data = (PairwiseFingerprintData*)userData;
#ifdef _WIN32
    EnterCriticalSection(&data->mutex);
    data->pairwiseFingerprint = (uint8_t*)malloc(pairwiseFingerprintLength);
    memcpy(data->pairwiseFingerprint, pairwiseFingerprint, pairwiseFingerprintLength);
    data->pairwiseFingerprintLength = pairwiseFingerprintLength;
    WakeConditionVariable(&data->cond);
    LeaveCriticalSection(&data->mutex);
#else
    pthread_mutex_lock(&data->mutex);
    data->pairwiseFingerprint = (uint8_t*)malloc(pairwiseFingerprintLength);
    memcpy(data->pairwiseFingerprint, pairwiseFingerprint, pairwiseFingerprintLength);
    data->pairwiseFingerprintLength = pairwiseFingerprintLength;
    pthread_cond_signal(&data->cond);
    pthread_mutex_unlock(&data->mutex);
#endif
}

static int TestSession(void)
{
    uint64_t groupId = 1234567890;
    const char* userA = "1234123412341234";
    const char* userB = "5678567856785678";

    printf("Creating external sender\n");
    DAVEExternalSenderHandle externalSender = daveExternalSenderCreate(groupId);
    TEST_ASSERT(externalSender != NULL, "Failed to create external sender");

    // Create sessions
    printf("Creating sessions\n");
    DAVESessionHandle sessionA = daveSessionCreate(NULL, NULL, TestSessionFailureCallback, NULL);
    DAVESessionHandle sessionB = daveSessionCreate(NULL, NULL, TestSessionFailureCallback, NULL);
    TEST_ASSERT(sessionA != NULL, "Failed to create session");
    TEST_ASSERT(sessionB != NULL, "Failed to create session");

    // Set external sender
    printf("Setting external sender\n");
    uint8_t* marshalledExternalSender = NULL;
    size_t marshalledExternalSenderLength = 0;
    daveExternalSenderGetMarshalledExternalSender(
      externalSender, &marshalledExternalSender, &marshalledExternalSenderLength);
    TEST_ASSERT(marshalledExternalSender != NULL, "Failed to get marshalled external sender");
    daveSessionSetExternalSender(
      sessionA, marshalledExternalSender, marshalledExternalSenderLength);
    daveSessionSetExternalSender(
      sessionB, marshalledExternalSender, marshalledExternalSenderLength);
    daveFree(marshalledExternalSender);

    // Init sessions
    daveSessionInit(sessionA, 1, groupId, userA);
    daveSessionInit(sessionB, 1, groupId, userB);
    TEST_ASSERT_EQ(daveSessionGetProtocolVersion(sessionA), 1, "Protocol version should be 1");
    TEST_ASSERT_EQ(daveSessionGetProtocolVersion(sessionB), 1, "Protocol version should be 1");

    // Get key packages
    printf("Getting key packages\n");
    uint8_t* keyPackageA = NULL;
    size_t keyPackageALength = 0;
    daveSessionGetMarshalledKeyPackage(sessionA, &keyPackageA, &keyPackageALength);
    TEST_ASSERT(keyPackageA != NULL, "Failed to get key package");

    uint8_t* keyPackageB = NULL;
    size_t keyPackageBLength = 0;
    daveSessionGetMarshalledKeyPackage(sessionB, &keyPackageB, &keyPackageBLength);
    TEST_ASSERT(keyPackageB != NULL, "Failed to get key package");

    // Make add proposal for user B
    printf("Proposing add\n");
    uint8_t* proposal = NULL;
    size_t proposalLength = 0;
    daveExternalSenderProposeAdd(
      externalSender, 0, keyPackageB, keyPackageBLength, &proposal, &proposalLength);
    TEST_ASSERT(proposal != NULL, "Failed to propose add user B");
    daveFree(keyPackageA);
    daveFree(keyPackageB);

    // Process proposal of user B
    printf("Processing proposals\n");
    uint8_t* commitWelcome = NULL;
    size_t commitWelcomeLength = 0;
    const char* recognizedUserIds[] = {userA, userB};
    daveSessionProcessProposals(sessionA,
                                proposal,
                                proposalLength,
                                recognizedUserIds,
                                2,
                                &commitWelcome,
                                &commitWelcomeLength);
    TEST_ASSERT(commitWelcome != NULL, "Failed to process proposals");
    daveFree(proposal);

    // Split commit welcome
    printf("Splitting commit welcome\n");
    uint8_t* commit = NULL;
    size_t commitLength = 0;
    uint8_t* welcome = NULL;
    size_t welcomeLength = 0;
    daveExternalSenderSplitCommitWelcome(externalSender,
                                         commitWelcome,
                                         commitWelcomeLength,
                                         &commit,
                                         &commitLength,
                                         &welcome,
                                         &welcomeLength);
    TEST_ASSERT(commit != NULL, "Failed to split commit welcome");
    TEST_ASSERT(welcome != NULL, "Failed to split commit welcome");
    daveFree(commitWelcome);

    // Process commit generated by user A
    printf("Processing commit welcome\n");
    DAVECommitResultHandle commitResult = daveSessionProcessCommit(sessionA, commit, commitLength);
    DAVEWelcomeResultHandle welcomeResult =
      daveSessionProcessWelcome(sessionB, welcome, welcomeLength, recognizedUserIds, 2);
    daveFree(commit);
    daveFree(welcome);

    // Check commit welcome results
    printf("Checking commit welcome results\n");
    TEST_ASSERT_EQ(daveCommitResultIsFailed(commitResult), false, "Commit should not be failed");
    TEST_ASSERT_EQ(daveCommitResultIsIgnored(commitResult), false, "Commit should not be ignored");
    uint64_t* rosterIds = NULL;
    size_t rosterIdsLength = 0;
    daveCommitResultGetRosterMemberIds(commitResult, &rosterIds, &rosterIdsLength);
    TEST_ASSERT(rosterIds != NULL, "Failed to get roster member ids");
    TEST_ASSERT_EQ(rosterIdsLength, 2, "Roster member ids length should be 2");
    TEST_ASSERT(rosterIds[0] == 1234123412341234, "Roster member id should be user A");
    TEST_ASSERT(rosterIds[1] == 5678567856785678, "Roster member id should be user B");
    daveFree(rosterIds);
    daveWelcomeResultGetRosterMemberIds(welcomeResult, &rosterIds, &rosterIdsLength);
    TEST_ASSERT(rosterIds != NULL, "Failed to get roster member ids");
    TEST_ASSERT_EQ(rosterIdsLength, 2, "Roster member ids length should be 2");
    TEST_ASSERT(rosterIds[0] == 1234123412341234, "Roster member id should be user A");
    TEST_ASSERT(rosterIds[1] == 5678567856785678, "Roster member id should be user B");

    uint8_t* signature = NULL;
    size_t signatureLength = 0;
    daveCommitResultGetRosterMemberSignature(
      commitResult, rosterIds[0], &signature, &signatureLength);
    TEST_ASSERT(signature != NULL, "Failed to get signature");
    TEST_ASSERT(signatureLength > 0, "Signature length should be greater than 0");
    daveFree(signature);
    daveCommitResultGetRosterMemberSignature(
      commitResult, rosterIds[1], &signature, &signatureLength);
    TEST_ASSERT(signature != NULL, "Failed to get signature");
    TEST_ASSERT(signatureLength > 0, "Signature length should be greater than 0");
    daveFree(signature);
    daveWelcomeResultGetRosterMemberSignature(
      welcomeResult, rosterIds[0], &signature, &signatureLength);
    TEST_ASSERT(signature != NULL, "Failed to get signature");
    TEST_ASSERT(signatureLength > 0, "Signature length should be greater than 0");
    daveFree(signature);
    daveWelcomeResultGetRosterMemberSignature(
      welcomeResult, rosterIds[1], &signature, &signatureLength);
    TEST_ASSERT(signature != NULL, "Failed to get signature");
    TEST_ASSERT(signatureLength > 0, "Signature length should be greater than 0");
    daveFree(signature);

    daveFree(rosterIds);
    daveCommitResultDestroy(commitResult);
    daveWelcomeResultDestroy(welcomeResult);

    // Match authenticators
    printf("Matching authenticators\n");
    uint8_t* authenticatorA = NULL;
    size_t authenticatorALength = 0;
    daveSessionGetLastEpochAuthenticator(sessionA, &authenticatorA, &authenticatorALength);
    TEST_ASSERT(authenticatorA != NULL, "Failed to get authenticator");
    uint8_t* authenticatorB = NULL;
    size_t authenticatorBLength = 0;
    daveSessionGetLastEpochAuthenticator(sessionB, &authenticatorB, &authenticatorBLength);
    TEST_ASSERT(authenticatorB != NULL, "Failed to get authenticator");
    TEST_ASSERT(memcmp(authenticatorA, authenticatorB, authenticatorALength) == 0,
                "Authenticators should match");
    daveFree(authenticatorA);
    daveFree(authenticatorB);

    // Get pairwise fingerprints
    printf("Matching pairwise fingerprints\n");
    PairwiseFingerprintData pairwiseFingerprintDataA;
    PairwiseFingerprintDataInit(&pairwiseFingerprintDataA);
    PairwiseFingerprintData pairwiseFingerprintDataB;
    PairwiseFingerprintDataInit(&pairwiseFingerprintDataB);
    daveSessionGetPairwiseFingerprint(
      sessionA, 1, userB, &PairwiseFingerprintCallback, &pairwiseFingerprintDataA);
    daveSessionGetPairwiseFingerprint(
      sessionB, 1, userA, &PairwiseFingerprintCallback, &pairwiseFingerprintDataB);
    PairwiseFingerprintDataWait(&pairwiseFingerprintDataA);
    PairwiseFingerprintDataWait(&pairwiseFingerprintDataB);
    TEST_ASSERT(pairwiseFingerprintDataA.pairwiseFingerprintLength ==
                  pairwiseFingerprintDataB.pairwiseFingerprintLength,
                "Pairwise fingerprint lengths should match");
    TEST_ASSERT(memcmp(pairwiseFingerprintDataA.pairwiseFingerprint,
                       pairwiseFingerprintDataB.pairwiseFingerprint,
                       pairwiseFingerprintDataA.pairwiseFingerprintLength) == 0,
                "Pairwise fingerprint should match");
    PairwiseFingerprintDataDestroy(&pairwiseFingerprintDataA);
    PairwiseFingerprintDataDestroy(&pairwiseFingerprintDataB);

    // Get key ratchets
    printf("Getting key ratchets\n");
    DAVEKeyRatchetHandle keyRatchetA = daveSessionGetKeyRatchet(sessionA, userA);
    DAVEKeyRatchetHandle keyRatchetB = daveSessionGetKeyRatchet(sessionB, userA);
    TEST_ASSERT(keyRatchetA != NULL, "Failed to get key ratchet");
    TEST_ASSERT(keyRatchetB != NULL, "Failed to get key ratchet");

    // Setup encryptor
    printf("Setting up encryptor\n");
    DAVEEncryptorHandle encryptorA = daveEncryptorCreate();
    daveEncryptorAssignSsrcToCodec(encryptorA, 0, DAVE_CODEC_OPUS);
    daveEncryptorSetPassthroughMode(encryptorA, false);
    daveEncryptorSetKeyRatchet(encryptorA, keyRatchetA);
    daveKeyRatchetDestroy(keyRatchetA);

    TEST_ASSERT_EQ(daveEncryptorHasKeyRatchet(encryptorA), true, "Encryptor should have a key ratchet");
    TEST_ASSERT_EQ(daveEncryptorIsPassthroughMode(encryptorA), false, "Encryptor should not be in passthrough mode");

    // Setup decryptor
    printf("Setting up decryptor\n");
    DAVEDecryptorHandle decryptorA = daveDecryptorCreate();
    daveDecryptorTransitionToPassthroughMode(decryptorA, false);
    daveDecryptorTransitionToKeyRatchet(decryptorA, keyRatchetB);
    daveKeyRatchetDestroy(keyRatchetB);

    // Create test data
    printf("Creating test data\n");
    const char* hexData = "0dc5aedd5bdc3f20be5697e54dd1f437";
    size_t inputDataLength = 0;
    uint8_t* inputData = GetBufferFromHex(hexData, &inputDataLength);
    TEST_ASSERT(inputData != NULL, "Failed to get input data");

    // Encrypt data
    printf("Encrypting data\n");
    size_t encryptedFrameLength =
      daveEncryptorGetMaxCiphertextByteSize(encryptorA, DAVE_MEDIA_TYPE_AUDIO, inputDataLength);
    uint8_t* encryptedFrame = (uint8_t*)malloc(encryptedFrameLength);
    daveEncryptorEncrypt(encryptorA,
                         DAVE_MEDIA_TYPE_AUDIO,
                         0,
                         inputData,
                         inputDataLength,
                         encryptedFrame,
                         encryptedFrameLength,
                         &encryptedFrameLength);
    TEST_ASSERT(encryptedFrame != NULL, "Failed to encrypt data");
    TEST_ASSERT(encryptedFrameLength > inputDataLength,
                "Encrypted data length should be greater than input data length");
    TEST_ASSERT(memcmp(inputData, encryptedFrame, inputDataLength) != 0,
                "Encrypted data should not match input data");

    // Decrypt data
    printf("Decrypting data\n");
    size_t decryptedFrameLength =
      daveDecryptorGetMaxPlaintextByteSize(decryptorA, DAVE_MEDIA_TYPE_AUDIO, encryptedFrameLength);
    uint8_t* decryptedFrame = (uint8_t*)malloc(decryptedFrameLength);
    daveDecryptorDecrypt(decryptorA,
                         DAVE_MEDIA_TYPE_AUDIO,
                         encryptedFrame,
                         encryptedFrameLength,
                         decryptedFrame,
                         decryptedFrameLength,
                         &decryptedFrameLength);
    TEST_ASSERT(decryptedFrame != NULL, "Failed to decrypt data");
    TEST_ASSERT_EQ(decryptedFrameLength,
                   inputDataLength,
                   "Decrypted data length should be equal to input data length");
    TEST_ASSERT(memcmp(inputData, decryptedFrame, inputDataLength) == 0,
                "Decrypted data should match input data");

    // Check encryptor stats
    printf("Checking encryptor stats\n");
    DAVEEncryptorStats encryptorStats;
    daveEncryptorGetStats(encryptorA, DAVE_MEDIA_TYPE_AUDIO, &encryptorStats);
    TEST_ASSERT_EQ(encryptorStats.encryptSuccessCount,
                   1,
                   "Encryptor should have at least one successful encryption");
    TEST_ASSERT_EQ(
      encryptorStats.encryptFailureCount, 0, "Encryptor should have no failed encryptions");
    TEST_ASSERT(encryptorStats.encryptDuration > 0, "Encryptor should have a duration");
    TEST_ASSERT_EQ(
      encryptorStats.encryptAttempts, 1, "Encryptor should have at least one encryption attempt");
    TEST_ASSERT_EQ(encryptorStats.encryptMaxAttempts,
                   1,
                   "Encryptor should have a maximum number of encryption attempts");
    TEST_ASSERT_EQ(
      encryptorStats.encryptMissingKeyCount, 0, "Encryptor should have no missing keys");

    // Check decryptor stats
    printf("Checking decryptor stats\n");
    DAVEDecryptorStats decryptorStats;
    daveDecryptorGetStats(decryptorA, DAVE_MEDIA_TYPE_AUDIO, &decryptorStats);
    TEST_ASSERT_EQ(decryptorStats.decryptSuccessCount,
                   1,
                   "Decryptor should have at least one successful decryption");
    TEST_ASSERT_EQ(
      decryptorStats.decryptFailureCount, 0, "Decryptor should have no failed decryptions");
    TEST_ASSERT(decryptorStats.decryptDuration > 0, "Decryptor should have a duration");
    TEST_ASSERT_EQ(
      decryptorStats.decryptAttempts, 1, "Decryptor should have at least one decryption attempt");
    TEST_ASSERT_EQ(
      decryptorStats.decryptMissingKeyCount, 0, "Decryptor should have no missing keys");
    TEST_ASSERT_EQ(
      decryptorStats.decryptInvalidNonceCount, 0, "Decryptor should have no invalid nonces");

    // Clean up
    printf("Cleaning up\n");
    free(inputData);
    free(encryptedFrame);
    free(decryptedFrame);
    daveEncryptorDestroy(encryptorA);
    daveDecryptorDestroy(decryptorA);
    daveSessionDestroy(sessionA);
    daveSessionDestroy(sessionB);
    daveExternalSenderDestroy(externalSender);

    return 1;
}

static int TestExceptions(void)
{
    printf("Testing exception catching\n");
    DAVESessionHandle session = daveSessionCreate(NULL, NULL, TestSessionFailureCallback, NULL);
    TEST_ASSERT(session != NULL, "Failed to create session");


    PairwiseFingerprintData pairwiseFingerprintData;
    PairwiseFingerprintDataInit(&pairwiseFingerprintData);
    daveSessionGetPairwiseFingerprint(
      session, 1, "1234123412341234", &PairwiseFingerprintCallback, &pairwiseFingerprintData);
    PairwiseFingerprintDataWait(&pairwiseFingerprintData);
    TEST_ASSERT_EQ(pairwiseFingerprintData.pairwiseFingerprintLength, 0,
                   "Expected empty fingerprint when exception is caught");

    PairwiseFingerprintDataDestroy(&pairwiseFingerprintData);
    daveSessionDestroy(session);

    return 1;
}

int main(void)
{
    int passed = 0;
    int failed = 0;

    printf("\n=== Running C API Tests ===\n\n");

    RUN_TEST(TestEncryptorCreateDestroy);
    RUN_TEST(TestDecryptorCreateDestroy);
    RUN_TEST(TestMaxProtocolVersion);
    RUN_TEST(TestEncryptorPassthrough);
    RUN_TEST(TestDecryptorPassthrough);
    RUN_TEST(TestPassthroughInOutBuffer);
    RUN_TEST(TestPassthroughTwoBuffers);
    RUN_TEST(TestSession);
    RUN_TEST(TestExceptions);

    printf("\n=== Test Results ===\n");
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", failed);
    printf("Total:  %d\n", passed + failed);

    return (failed == 0) ? 0 : 1;
}
