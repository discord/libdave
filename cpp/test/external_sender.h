#pragma once

#include <dave/version.h>
#include <mls/messages.h>

namespace discord {
namespace dave {
namespace test {

class ExternalSender {
public:
    ExternalSender(discord::dave::ProtocolVersion protocolVersion, uint64_t groupId);

    std::vector<uint8_t> GetMarshalledExternalSender();
    std::vector<uint8_t> ProposeAdd(uint32_t epoch, std::vector<uint8_t> const& keyPackage);
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> SplitCommitWelcome(
      std::vector<uint8_t> const& commitWelcome);

private:
    uint32_t signerIndex_{0};
    ::mlspp::CipherSuite ciphersuite_;
    ::mlspp::bytes_ns::bytes groupId_;
    std::shared_ptr<::mlspp::SignaturePrivateKey> signaturePrivateKey_;
    ::mlspp::ExternalSender externalSender_;
};

} // namespace test
} // namespace dave
} // namespace discord