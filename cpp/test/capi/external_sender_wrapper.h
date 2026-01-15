
#include <dave/dave.h>

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_OPAQUE_HANDLE(DAVEExternalSenderHandle);

DAVE_EXPORT DAVEExternalSenderHandle daveExternalSenderCreate(uint64_t groupId);
DAVE_EXPORT void daveExternalSenderDestroy(DAVEExternalSenderHandle externalSender);
DAVE_EXPORT void daveExternalSenderGetMarshalledExternalSender(
  DAVEExternalSenderHandle externalSender,
  uint8_t** marshalledExternalSender,
  size_t* length);
DAVE_EXPORT void daveExternalSenderProposeAdd(DAVEExternalSenderHandle externalSender,
                                              uint32_t epoch,
                                              uint8_t* keyPackage,
                                              size_t keyPackageLength,
                                              uint8_t** proposal,
                                              size_t* proposalLength);
DAVE_EXPORT void daveExternalSenderSplitCommitWelcome(DAVEExternalSenderHandle externalSender,
                                                      uint8_t* commitWelcome,
                                                      size_t commitWelcomeLength,
                                                      uint8_t** commit,
                                                      size_t* commitLength,
                                                      uint8_t** welcome,
                                                      size_t* welcomeLength);

#ifdef __cplusplus
}
#endif
