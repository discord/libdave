#include "external_sender_wrapper.h"

#include <cstring>
#include <vector>

#include "../external_sender.h"

namespace {

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

} // anonymous namespace

DAVEExternalSenderHandle daveExternalSenderCreate(uint64_t groupId)
{
    auto protocolVersion = daveMaxSupportedProtocolVersion();
    auto externalSender =
      std::make_unique<discord::dave::test::ExternalSender>(protocolVersion, groupId);
    return reinterpret_cast<DAVEExternalSenderHandle>(externalSender.release());
}

void daveExternalSenderDestroy(DAVEExternalSenderHandle externalSenderHandle)
{
    auto externalSender =
      reinterpret_cast<discord::dave::test::ExternalSender*>(externalSenderHandle);
    delete externalSender;
}

void daveExternalSenderGetMarshalledExternalSender(DAVEExternalSenderHandle externalSenderHandle,
                                                   uint8_t** marshalledExternalSender,
                                                   size_t* length)
{
    auto externalSender =
      reinterpret_cast<discord::dave::test::ExternalSender*>(externalSenderHandle);
    auto externalSenderVec = externalSender->GetMarshalledExternalSender();
    CopyVectorToOutputBuffer(externalSenderVec, marshalledExternalSender, length);
}

void daveExternalSenderProposeAdd(DAVEExternalSenderHandle externalSenderHandle,
                                  uint32_t epoch,
                                  uint8_t* keyPackage,
                                  size_t keyPackageLength,
                                  uint8_t** proposal,
                                  size_t* proposalLength)
{
    auto externalSender =
      reinterpret_cast<discord::dave::test::ExternalSender*>(externalSenderHandle);
    auto keyPackageVec = std::vector<uint8_t>(keyPackage, keyPackage + keyPackageLength);
    auto result = externalSender->ProposeAdd(epoch, std::move(keyPackageVec));
    CopyVectorToOutputBuffer(result, proposal, proposalLength);
}

void daveExternalSenderSplitCommitWelcome(DAVEExternalSenderHandle externalSenderHandle,
                                          uint8_t* commitWelcome,
                                          size_t commitWelcomeLength,
                                          uint8_t** commit,
                                          size_t* commitLength,
                                          uint8_t** welcome,
                                          size_t* welcomeLength)
{
    auto externalSender =
      reinterpret_cast<discord::dave::test::ExternalSender*>(externalSenderHandle);
    auto commitWelcomeVec =
      std::vector<uint8_t>(commitWelcome, commitWelcome + commitWelcomeLength);
    auto [commitBytes, welcomeBytes] =
      externalSender->SplitCommitWelcome(std::move(commitWelcomeVec));
    CopyVectorToOutputBuffer(commitBytes, commit, commitLength);
    CopyVectorToOutputBuffer(welcomeBytes, welcome, welcomeLength);
}