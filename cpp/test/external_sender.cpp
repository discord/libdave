#include "external_sender.h"

#include "mls/parameters.h"
#include "mls/util.h"

namespace discord {
namespace dave {
namespace test {

::mlspp::bytes_ns::bytes BigEndianBytesFrom(uint64_t value) noexcept
{
    auto buffer = ::mlspp::bytes_ns::bytes();
    buffer.reserve(sizeof(value));

    for (int i = sizeof(value) - 1; i >= 0; --i) {
        buffer.push_back(static_cast<uint8_t>(value >> (i * 8)));
    }

    return buffer;
}

::mlspp::CipherSuite CiphersuiteForProtocolVersion(
  [[maybe_unused]] ProtocolVersion version) noexcept
{
    return ::mlspp::CipherSuite{::mlspp::CipherSuite::ID::P256_AES128GCM_SHA256_P256};
}

ExternalSender::ExternalSender(discord::dave::ProtocolVersion protocolVersion, uint64_t groupId)
{
    ciphersuite_ = CiphersuiteForProtocolVersion(protocolVersion);
    groupId_ = std::move(BigEndianBytesFrom(groupId).as_vec());
    signaturePrivateKey_ = std::make_shared<::mlspp::SignaturePrivateKey>(
      ::mlspp::SignaturePrivateKey::generate(ciphersuite_));
    externalSender_.signature_key = signaturePrivateKey_->public_key;
    externalSender_.credential = ::mlspp::Credential::basic({0x00, 0x01, 0x01, 0x00});
}

std::vector<uint8_t> ExternalSender::GetMarshalledExternalSender()
{
    return ::mlspp::tls::marshal(externalSender_);
}

std::vector<uint8_t> ExternalSender::ProposeAdd(uint32_t epoch,
                                                std::vector<uint8_t> const& keyPackage)
{
    const auto keyPackageBytes = ::mlspp::bytes_ns::bytes(keyPackage);
    auto proposal =
      ::mlspp::Proposal{::mlspp::Add{{::mlspp::tls::get<::mlspp::KeyPackage>(keyPackageBytes)}}};
    auto message = ::mlspp::external_proposal(
      ciphersuite_, groupId_, epoch, proposal, signerIndex_, *signaturePrivateKey_);

    bool isRevoke = false;
    ::mlspp::tls::ostream out;
    out << isRevoke;
    out << std::vector<::mlspp::MLSMessage>{message};
    return out.bytes();
}

std::vector<uint8_t> ExternalSender::ProposeRemove(uint32_t epoch, uint32_t leafIndex)
{
    auto proposal = ::mlspp::Proposal{::mlspp::Remove{::mlspp::LeafIndex{leafIndex}}};
    auto message = ::mlspp::external_proposal(
      ciphersuite_, groupId_, epoch, proposal, signerIndex_, *signaturePrivateKey_);

    bool isRevoke = false;
    ::mlspp::tls::ostream out;
    out << isRevoke;
    out << std::vector<::mlspp::MLSMessage>{message};
    return out.bytes();
}

std::vector<uint8_t> ExternalSender::Revoke(std::vector<uint8_t> const& proposals)
{
    std::vector<::mlspp::bytes_ns::bytes> refs;
    for (const auto& message : ParseProposals(proposals)) {
        const auto& publicMessage = ::mlspp::tls::var::get<::mlspp::PublicMessage>(message.message);
        refs.push_back(ciphersuite_.ref(publicMessage.authenticated_content()));
    }

    bool isRevoke = true;
    ::mlspp::tls::ostream out;
    out << isRevoke;
    out << refs;
    return out.bytes();
}

std::vector<::mlspp::MLSMessage> ExternalSender::ParseProposals(
  std::vector<uint8_t> const& proposals)
{
    auto proposalsBytes = ::mlspp::bytes_ns::bytes(proposals);
    ::mlspp::tls::istream in(proposalsBytes);
    bool isRevoke = false;
    std::vector<::mlspp::MLSMessage> messages;
    in >> isRevoke;
    in >> messages;
    return messages;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> ExternalSender::SplitCommitWelcome(
  std::vector<uint8_t> const& commitWelcome)
{
    auto commitWelcomeBytes = ::mlspp::bytes_ns::bytes(commitWelcome);
    ::mlspp::tls::istream in(commitWelcomeBytes);
    ::mlspp::MLSMessage commitMessage;
    in >> commitMessage;

    ::mlspp::tls::ostream commitOut;
    commitOut << commitMessage;
    auto commitBytes = commitOut.bytes();

    // a commit without any add proposals is not followed by a welcome
    if (in.empty()) {
        return std::make_pair(commitBytes, std::vector<uint8_t>{});
    }

    ::mlspp::Welcome welcomeMessage;
    in >> welcomeMessage;
    ::mlspp::tls::ostream welcomeOut;
    welcomeOut << welcomeMessage;
    auto welcomeBytes = welcomeOut.bytes();
    return std::make_pair(commitBytes, welcomeBytes);
}

} // namespace test
} // namespace dave
} // namespace discord