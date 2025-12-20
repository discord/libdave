#include "external_sender.h"

#include "dave/mls/parameters.h"
#include "dave/mls/util.h"

namespace discord::dave::test {

ExternalSender::ExternalSender(discord::dave::ProtocolVersion protocolVersion, uint64_t groupId)
{
    ciphersuite_ = discord::dave::mls::CiphersuiteForProtocolVersion(protocolVersion);
    groupId_ = std::move(discord::dave::mls::BigEndianBytesFrom(groupId).as_vec());
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

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> ExternalSender::SplitCommitWelcome(
  std::vector<uint8_t> const& commitWelcome)
{
    auto commitWelcomeBytes = ::mlspp::bytes_ns::bytes(commitWelcome);
    ::mlspp::tls::istream in(commitWelcomeBytes);
    ::mlspp::MLSMessage commitMessage;
    ::mlspp::Welcome welcomeMessage;
    in >> commitMessage;
    in >> welcomeMessage;

    ::mlspp::tls::ostream commitOut;
    commitOut << commitMessage;
    auto commitBytes = commitOut.bytes();
    ::mlspp::tls::ostream welcomeOut;
    welcomeOut << welcomeMessage;
    auto welcomeBytes = welcomeOut.bytes();
    return std::make_pair(commitBytes, welcomeBytes);
}

} // namespace discord::dave::test
