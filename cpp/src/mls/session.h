#pragma once

#include <functional>
#include <list>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <dave/dave_interfaces.h>
#include <dave/version.h>

#include "mls/persisted_key_pair.h"
#include "mls_key_ratchet.h"

namespace mlspp {
struct AuthenticatedContent;
struct Credential;
struct ExternalSender;
struct HPKEPrivateKey;
struct KeyPackage;
struct LeafNode;
struct MLSMessage;
struct SignaturePrivateKey;
class State;
} // namespace mlspp

namespace discord {
namespace dave {
namespace mls {

struct QueuedProposal;

class Session final : public ISession {
public:
    Session(KeyPairContextType context,
            std::string authSessionId,
            MLSFailureCallback callback) noexcept;

    virtual ~Session() noexcept;

    virtual void Init(
      ProtocolVersion version,
      uint64_t groupId,
      std::string const& selfUserId,
      std::shared_ptr<::mlspp::SignaturePrivateKey>& transientKey) noexcept override;
    virtual void Reset() noexcept override;

    virtual void SetProtocolVersion(ProtocolVersion version) noexcept override;
    virtual ProtocolVersion GetProtocolVersion() const noexcept override
    {
        return protocolVersion_;
    }

    virtual std::vector<uint8_t> GetLastEpochAuthenticator() const noexcept override;

    virtual void SetExternalSender(
      std::vector<uint8_t> const& externalSenderPackage) noexcept override;

    virtual std::optional<std::vector<uint8_t>> ProcessProposals(
      std::vector<uint8_t> proposals,
      std::set<std::string> const& recognizedUserIDs) noexcept override;

    virtual RosterVariant ProcessCommit(std::vector<uint8_t> commit) noexcept override;

    virtual std::optional<RosterMap> ProcessWelcome(
      std::vector<uint8_t> welcome,
      std::set<std::string> const& recognizedUserIDs) noexcept override;

    virtual std::vector<uint8_t> GetMarshalledKeyPackage() noexcept override;

    virtual std::unique_ptr<IKeyRatchet> GetKeyRatchet(
      std::string const& userId) const noexcept override;

    using PairwiseFingerprintCallback = std::function<void(std::vector<uint8_t> const&)>;

    virtual void GetPairwiseFingerprint(
      uint16_t version,
      std::string const& userId,
      PairwiseFingerprintCallback callback) const noexcept override;

private:
    void InitLeafNode(std::string const& selfUserId,
                      std::shared_ptr<::mlspp::SignaturePrivateKey>& transientKey) noexcept;
    void ResetJoinKeyPackage() noexcept;

    void CreatePendingGroup() noexcept;

    bool HasCryptographicStateForWelcome() const noexcept;

    bool IsRecognizedUserID(const ::mlspp::Credential& cred,
                            std::set<std::string> const& recognizedUserIDs) const;
    bool ValidateProposalMessage(::mlspp::AuthenticatedContent const& message,
                                 ::mlspp::State const& targetState,
                                 std::set<std::string> const& recognizedUserIDs) const;
    bool VerifyWelcomeState(::mlspp::State const& state,
                            std::set<std::string> const& recognizedUserIDs) const;

    bool CanProcessCommit(const ::mlspp::MLSMessage& commit) noexcept;

    RosterMap ReplaceState(std::unique_ptr<::mlspp::State>&& state);

    void ClearPendingState();

    inline static const std::string USER_MEDIA_KEY_BASE_LABEL = "Discord Secure Frames v0";

    ProtocolVersion protocolVersion_;
    std::vector<uint8_t> groupId_;
    std::string signingKeyId_;
    std::string selfUserId_;
    KeyPairContextType keyPairContext_{nullptr};

    std::unique_ptr<::mlspp::LeafNode> selfLeafNode_;
    std::shared_ptr<::mlspp::SignaturePrivateKey> selfSigPrivateKey_;
    std::unique_ptr<::mlspp::HPKEPrivateKey> selfHPKEPrivateKey_;

    std::unique_ptr<::mlspp::HPKEPrivateKey> joinInitPrivateKey_;
    std::unique_ptr<::mlspp::KeyPackage> joinKeyPackage_;

    std::unique_ptr<::mlspp::ExternalSender> externalSender_;

    std::unique_ptr<::mlspp::State> pendingGroupState_;
    std::unique_ptr<::mlspp::MLSMessage> pendingGroupCommit_;

    std::unique_ptr<::mlspp::State> outboundCachedGroupState_;

    std::unique_ptr<::mlspp::State> currentState_;
    RosterMap roster_;

    std::unique_ptr<::mlspp::State> stateWithProposals_;
    std::list<QueuedProposal> proposalQueue_;

    MLSFailureCallback onMLSFailureCallback_{};
};

} // namespace mls
} // namespace dave
} // namespace discord
