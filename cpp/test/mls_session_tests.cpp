#include <gtest/gtest.h>

#include <algorithm>
#include <initializer_list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <mls/state.h>

#include "mls/parameters.h"
#include "mls/session.h"
#include "mls/user_credential.h"

#include "dave_test.h"
#include "external_sender.h"

using namespace testing;

namespace discord {
namespace dave {
namespace test {

namespace {

constexpr ProtocolVersion kTestProtocolVersion = 1;
constexpr uint64_t kTestGroupId = 1234567890;
constexpr uint64_t kOtherGroupId = 9876543210;

const std::string kUserA = "1234123412341234";
const std::string kUserB = "5678567856785678";
const std::string kUserC = "9012901290129012";
const std::string kUserD = "3456345634563456";

// Wraps a session with a failure-callback recorder so tests can assert on the
// precise error reported through the MLSFailureCallback.
struct TestSession {
    explicit TestSession(std::string user)
      : userId(std::move(user))
    {
        session = std::make_unique<mls::Session>(
          nullptr, "", [this](std::string const&, std::string const& reason) {
              failureReasons.push_back(reason);
          });
    }

    void InitAndSetExternalSender(ExternalSender& externalSender, uint64_t groupId)
    {
        session->Init(kTestProtocolVersion, groupId, userId, transientKey);
        session->SetExternalSender(externalSender.GetMarshalledExternalSender());
    }

    void Recognize(std::initializer_list<std::string> userIds)
    {
        for (const auto& recognizedUserId : userIds) {
            session->AddRecognizedUser(recognizedUserId);
        }
    }

    void Forget(std::string const& forgottenUserId)
    {
        session->RemoveRecognizedUser(forgottenUserId);
    }

    bool HasFailureReason(std::string const& reason) const
    {
        return std::find(failureReasons.begin(), failureReasons.end(), reason) !=
          failureReasons.end();
    }

    std::string userId;
    std::shared_ptr<::mlspp::SignaturePrivateKey> transientKey;
    std::unique_ptr<mls::Session> session;
    std::vector<std::string> failureReasons;
};

struct CommitWelcomePair {
    std::vector<uint8_t> commit;
    std::vector<uint8_t> welcome;
};

// Has the external sender propose adding `joiner` to `creator`'s pending group
// and returns the commit and welcome that `creator` produces for it.
std::optional<CommitWelcomePair> ProposeAddAndCommit(ExternalSender& externalSender,
                                                     TestSession& creator,
                                                     TestSession& joiner)
{
    auto keyPackage = joiner.session->GetMarshalledKeyPackage();
    if (keyPackage.empty()) {
        return std::nullopt;
    }

    auto proposal = externalSender.ProposeAdd(0, keyPackage);

    creator.Recognize({joiner.userId});
    auto commitWelcome = creator.session->ProcessProposals(proposal);
    if (!commitWelcome) {
        return std::nullopt;
    }

    auto [commit, welcome] = externalSender.SplitCommitWelcome(*commitWelcome);
    return CommitWelcomePair{std::move(commit), std::move(welcome)};
}

// Establishes a group containing `creator` and `joiner`, with `creator` having
// processed its own group-initialization commit and `joiner` the welcome.
bool EstablishGroup(ExternalSender& externalSender, TestSession& creator, TestSession& joiner)
{
    auto commitWelcome = ProposeAddAndCommit(externalSender, creator, joiner);
    if (!commitWelcome) {
        return false;
    }

    auto commitResult = creator.session->ProcessCommit(commitWelcome->commit);
    if (!std::holds_alternative<RosterMap>(commitResult)) {
        return false;
    }

    joiner.Recognize({creator.userId});
    return joiner.session->ProcessWelcome(commitWelcome->welcome).has_value();
}

// Has `committer` prepare a commit for the given proposals, returning the commit
// on its own (without any welcome).
std::optional<std::vector<uint8_t>> PrepareCommit(ExternalSender& externalSender,
                                                  TestSession& committer,
                                                  std::vector<uint8_t> const& proposals)
{
    auto commitWelcome = committer.session->ProcessProposals(proposals);
    if (!commitWelcome) {
        return std::nullopt;
    }

    return externalSender.SplitCommitWelcome(*commitWelcome).first;
}

std::vector<uint8_t> ProposeAddFor(ExternalSender& externalSender,
                                   uint32_t epoch,
                                   TestSession& joiner)
{
    return externalSender.ProposeAdd(epoch, joiner.session->GetMarshalledKeyPackage());
}

// An MLS member driven directly through mlspp, for commits a Session would never produce.
struct RawMember {
    explicit RawMember(std::string const& userId)
      : suite(mls::CiphersuiteForProtocolVersion(kTestProtocolVersion))
      , signaturePrivateKey(::mlspp::SignaturePrivateKey::generate(suite))
      , hpkePrivateKey(::mlspp::HPKEPrivateKey::generate(suite))
      , initPrivateKey(::mlspp::HPKEPrivateKey::generate(suite))
      , keyPackage(
          suite,
          initPrivateKey.public_key,
          ::mlspp::LeafNode(suite,
                            hpkePrivateKey.public_key,
                            signaturePrivateKey.public_key,
                            mls::CreateUserCredential(userId, kTestProtocolVersion),
                            mls::LeafNodeCapabilitiesForProtocolVersion(kTestProtocolVersion),
                            ::mlspp::Lifetime::create_default(),
                            mls::LeafNodeExtensionsForProtocolVersion(kTestProtocolVersion),
                            signaturePrivateKey),
          mls::LeafNodeExtensionsForProtocolVersion(kTestProtocolVersion),
          signaturePrivateKey)
    {
    }

    void JoinFromWelcome(std::vector<uint8_t> const& welcome)
    {
        state.emplace(initPrivateKey,
                      hpkePrivateKey,
                      signaturePrivateKey,
                      keyPackage,
                      ::mlspp::tls::get<::mlspp::Welcome>(welcome),
                      std::nullopt,
                      std::map<::mlspp::bytes_ns::bytes, ::mlspp::bytes_ns::bytes>());
    }

    void HandleProposals(std::vector<uint8_t> const& proposals)
    {
        for (const auto& message : ExternalSender::ParseProposals(proposals)) {
            state->handle(message);
        }
    }

    std::vector<uint8_t> CommitWithCredential(::mlspp::Credential credential)
    {
        auto opts = ::mlspp::CommitOpts{{}, true, true, {std::move(credential), {}, {}}};
        auto [commit, welcome, next] =
          state->commit(::mlspp::hpke::random_bytes(suite.secret_size()), opts, {});
        return ::mlspp::tls::marshal(commit);
    }

    ::mlspp::CipherSuite suite;
    ::mlspp::SignaturePrivateKey signaturePrivateKey;
    ::mlspp::HPKEPrivateKey hpkePrivateKey;
    ::mlspp::HPKEPrivateKey initPrivateKey;
    ::mlspp::KeyPackage keyPackage;
    std::optional<::mlspp::State> state;
};

} // namespace

class MlsSessionTests : public DaveTests {};

TEST_F(MlsSessionTests, SessionJoinViaCommitAndWelcome)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);

    auto commitWelcome = ProposeAddAndCommit(externalSender, a, b);
    ASSERT_TRUE(commitWelcome.has_value());

    // the creator processes its own group-initialization commit
    auto commitResult = a.session->ProcessCommit(commitWelcome->commit);
    auto* commitRoster = std::get_if<RosterMap>(&commitResult);
    ASSERT_NE(commitRoster, nullptr);
    EXPECT_EQ(commitRoster->size(), 2u);

    b.Recognize({kUserA});
    auto welcomeRoster = b.session->ProcessWelcome(commitWelcome->welcome);
    ASSERT_TRUE(welcomeRoster.has_value());
    EXPECT_EQ(welcomeRoster->size(), 2u);

    auto authenticatorA = a.session->GetLastEpochAuthenticator();
    auto authenticatorB = b.session->GetLastEpochAuthenticator();
    ASSERT_FALSE(authenticatorA.empty());
    EXPECT_EQ(authenticatorA, authenticatorB);
}

TEST_F(MlsSessionTests, SessionWelcomeRejectsUnrecognizedRosterUser)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);

    auto commitWelcome = ProposeAddAndCommit(externalSender, a, b);
    ASSERT_TRUE(commitWelcome.has_value());

    // the welcomed group's roster includes user A, which b does not recognize
    auto welcomeRoster = b.session->ProcessWelcome(commitWelcome->welcome);
    EXPECT_FALSE(welcomeRoster.has_value());
    EXPECT_TRUE(b.HasFailureReason("Welcome message lists unrecognized user ID"));
}

TEST_F(MlsSessionTests, SessionWelcomeRejectsMismatchedGroupId)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);

    // b was initialized for a different group than the welcome is for
    b.InitAndSetExternalSender(externalSender, kOtherGroupId);

    auto commitWelcome = ProposeAddAndCommit(externalSender, a, b);
    ASSERT_TRUE(commitWelcome.has_value());

    b.Recognize({kUserA});
    auto welcomeRoster = b.session->ProcessWelcome(commitWelcome->welcome);
    EXPECT_FALSE(welcomeRoster.has_value());
    EXPECT_TRUE(b.HasFailureReason("Unexpected group ID in Welcome"));
}

TEST_F(MlsSessionTests, SessionCommitBeforeWelcomeIsRejected)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);

    // a prepares the winning group-initialization commit (adding b)
    auto commitWelcomeA = ProposeAddAndCommit(externalSender, a, b);
    ASSERT_TRUE(commitWelcomeA.has_value());

    // b also processed proposals for its own pending group (adding c), so it
    // has a prepared commit of its own that does not match a's
    auto commitWelcomeB = ProposeAddAndCommit(externalSender, b, c);
    ASSERT_TRUE(commitWelcomeB.has_value());

    // b has not been welcomed into any group, so a's commit must be rejected
    // rather than applied to b's unrelated pending group
    auto commitResult = b.session->ProcessCommit(commitWelcomeA->commit);
    EXPECT_TRUE(std::holds_alternative<failed_t>(commitResult));
    EXPECT_TRUE(b.HasFailureReason("Unexpected commit before welcome"));
}

TEST_F(MlsSessionTests, SessionOwnEarlierPreparedCommitUsesItsCachedState)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    TestSession d(kUserD);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);
    d.InitAndSetExternalSender(externalSender, kTestGroupId);

    ASSERT_TRUE(EstablishGroup(externalSender, a, b));
    a.Recognize({kUserC, kUserD});
    b.Recognize({kUserC, kUserD});

    auto proposeAddC = externalSender.ProposeAdd(1, c.session->GetMarshalledKeyPackage());
    auto firstCommit = PrepareCommit(externalSender, a, proposeAddC);
    ASSERT_TRUE(firstCommit.has_value());

    auto proposeAddD = externalSender.ProposeAdd(1, d.session->GetMarshalledKeyPackage());
    auto secondCommit = PrepareCommit(externalSender, a, proposeAddD);
    ASSERT_TRUE(secondCommit.has_value());
    ASSERT_NE(*firstCommit, *secondCommit);

    // d leaves before being added, so the first commit again covers exactly what is queued
    auto revokeAddD = externalSender.Revoke(proposeAddD);
    auto thirdCommit = PrepareCommit(externalSender, a, revokeAddD);
    ASSERT_TRUE(thirdCommit.has_value());

    ASSERT_TRUE(b.session->ProcessProposals(proposeAddC).has_value());
    auto commitResultB = b.session->ProcessCommit(*firstCommit);
    auto* rosterChangeB = std::get_if<RosterMap>(&commitResultB);
    ASSERT_NE(rosterChangeB, nullptr);
    EXPECT_EQ(rosterChangeB->size(), 1u);
    EXPECT_EQ(rosterChangeB->count(std::stoull(kUserC)), 1u);

    // the voice gateway selected a's first commit even though a has since prepared two more
    auto commitResultA = a.session->ProcessCommit(*firstCommit);
    auto* rosterChangeA = std::get_if<RosterMap>(&commitResultA);
    ASSERT_NE(rosterChangeA, nullptr);
    EXPECT_EQ(*rosterChangeA, *rosterChangeB);

    auto authenticatorA = a.session->GetLastEpochAuthenticator();
    ASSERT_FALSE(authenticatorA.empty());
    EXPECT_EQ(authenticatorA, b.session->GetLastEpochAuthenticator());

    // retained commits do not outlive the epoch they were prepared for
    EXPECT_TRUE(std::holds_alternative<failed_t>(a.session->ProcessCommit(*secondCommit)));
}

TEST_F(MlsSessionTests, SessionOwnCommitReferencingRevokedProposalIsRejected)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    TestSession d(kUserD);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);
    d.InitAndSetExternalSender(externalSender, kTestGroupId);

    ASSERT_TRUE(EstablishGroup(externalSender, a, b));
    a.Recognize({kUserC, kUserD});
    b.Recognize({kUserC, kUserD});

    auto proposeAddC = externalSender.ProposeAdd(1, c.session->GetMarshalledKeyPackage());
    auto firstCommit = PrepareCommit(externalSender, a, proposeAddC);
    ASSERT_TRUE(firstCommit.has_value());

    auto proposeAddD = externalSender.ProposeAdd(1, d.session->GetMarshalledKeyPackage());
    auto secondCommit = PrepareCommit(externalSender, a, proposeAddD);
    ASSERT_TRUE(secondCommit.has_value());

    auto revokeAddD = externalSender.Revoke(proposeAddD);
    auto thirdCommit = PrepareCommit(externalSender, a, revokeAddD);
    ASSERT_TRUE(thirdCommit.has_value());

    ASSERT_TRUE(b.session->ProcessProposals(proposeAddC).has_value());
    ASSERT_TRUE(b.session->ProcessProposals(proposeAddD).has_value());
    ASSERT_TRUE(b.session->ProcessProposals(revokeAddD).has_value());

    // the second commit still references the add of d, which has since been revoked, so a must
    // reject it just as any other member does
    EXPECT_TRUE(std::holds_alternative<failed_t>(a.session->ProcessCommit(*secondCommit)));
    EXPECT_TRUE(a.HasFailureReason("Commit does not cover queued proposals"));
    EXPECT_TRUE(std::holds_alternative<failed_t>(b.session->ProcessCommit(*secondCommit)));
    EXPECT_TRUE(b.HasFailureReason("Commit does not cover queued proposals"));

    // the first commit only references the add of c and remains valid after the revocation
    auto commitResultB = b.session->ProcessCommit(*firstCommit);
    auto* rosterChangeB = std::get_if<RosterMap>(&commitResultB);
    ASSERT_NE(rosterChangeB, nullptr);
    EXPECT_EQ(rosterChangeB->size(), 1u);
    EXPECT_EQ(rosterChangeB->count(std::stoull(kUserC)), 1u);

    auto commitResultA = a.session->ProcessCommit(*firstCommit);
    auto* rosterChangeA = std::get_if<RosterMap>(&commitResultA);
    ASSERT_NE(rosterChangeA, nullptr);
    EXPECT_EQ(*rosterChangeA, *rosterChangeB);

    auto authenticatorA = a.session->GetLastEpochAuthenticator();
    ASSERT_FALSE(authenticatorA.empty());
    EXPECT_EQ(authenticatorA, b.session->GetLastEpochAuthenticator());
}

TEST_F(MlsSessionTests, SessionRetainsBoundedOutboundCommits)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);

    ASSERT_TRUE(EstablishGroup(externalSender, a, b));
    a.Recognize({kUserC});
    b.Recognize({kUserC});

    // alternately proposing and revoking the same add makes a prepare a distinct commit each time
    auto proposeAddC = externalSender.ProposeAdd(1, c.session->GetMarshalledKeyPackage());
    auto revokeAddC = externalSender.Revoke(proposeAddC);

    // two more commits than the cap, ending on a revocation so nothing is left queued
    std::vector<std::vector<uint8_t>> commits;
    while (commits.size() < mls::Session::kMaxRetainedOutboundCommits + 2) {
        auto const& proposals = commits.size() % 2 == 0 ? proposeAddC : revokeAddC;
        auto commit = PrepareCommit(externalSender, a, proposals);
        ASSERT_TRUE(commit.has_value());
        commits.push_back(std::move(*commit));
    }

    // the empty commits following each revocation cover a's queue; the first was evicted
    EXPECT_TRUE(std::holds_alternative<failed_t>(a.session->ProcessCommit(commits[1])));
    EXPECT_TRUE(a.HasFailureReason("Handle own commits with caching"));

    ASSERT_TRUE(b.session->ProcessProposals(proposeAddC).has_value());
    ASSERT_TRUE(b.session->ProcessProposals(revokeAddC).has_value());
    auto commitResultB = b.session->ProcessCommit(commits[3]);
    auto* rosterChangeB = std::get_if<RosterMap>(&commitResultB);
    ASSERT_NE(rosterChangeB, nullptr);
    EXPECT_TRUE(rosterChangeB->empty());

    auto commitResultA = a.session->ProcessCommit(commits[3]);
    auto* rosterChangeA = std::get_if<RosterMap>(&commitResultA);
    ASSERT_NE(rosterChangeA, nullptr);
    EXPECT_TRUE(rosterChangeA->empty());

    auto authenticatorA = a.session->GetLastEpochAuthenticator();
    ASSERT_FALSE(authenticatorA.empty());
    EXPECT_EQ(authenticatorA, b.session->GetLastEpochAuthenticator());
}

TEST_F(MlsSessionTests, SessionOwnLatestPreparedCommitUsesCachedState)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    TestSession d(kUserD);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);
    d.InitAndSetExternalSender(externalSender, kTestGroupId);

    ASSERT_TRUE(EstablishGroup(externalSender, a, b));
    a.Recognize({kUserC, kUserD});
    b.Recognize({kUserC, kUserD});

    auto proposeAddC = externalSender.ProposeAdd(1, c.session->GetMarshalledKeyPackage());
    auto firstCommit = PrepareCommit(externalSender, a, proposeAddC);
    ASSERT_TRUE(firstCommit.has_value());

    auto proposeAddD = externalSender.ProposeAdd(1, d.session->GetMarshalledKeyPackage());
    auto secondCommit = PrepareCommit(externalSender, a, proposeAddD);
    ASSERT_TRUE(secondCommit.has_value());

    ASSERT_TRUE(b.session->ProcessProposals(proposeAddC).has_value());
    ASSERT_TRUE(b.session->ProcessProposals(proposeAddD).has_value());
    auto commitResultB = b.session->ProcessCommit(*secondCommit);
    auto* rosterChangeB = std::get_if<RosterMap>(&commitResultB);
    ASSERT_NE(rosterChangeB, nullptr);
    EXPECT_EQ(rosterChangeB->size(), 2u);
    EXPECT_EQ(rosterChangeB->count(std::stoull(kUserC)), 1u);
    EXPECT_EQ(rosterChangeB->count(std::stoull(kUserD)), 1u);

    auto commitResultA = a.session->ProcessCommit(*secondCommit);
    auto* rosterChangeA = std::get_if<RosterMap>(&commitResultA);
    ASSERT_NE(rosterChangeA, nullptr);
    EXPECT_EQ(*rosterChangeA, *rosterChangeB);

    auto authenticatorA = a.session->GetLastEpochAuthenticator();
    ASSERT_FALSE(authenticatorA.empty());
    EXPECT_EQ(authenticatorA, b.session->GetLastEpochAuthenticator());
}

TEST_F(MlsSessionTests, SessionCommitWithoutQueuedProposalsFails)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);

    auto commitWelcome = ProposeAddAndCommit(externalSender, a, b);
    ASSERT_TRUE(commitWelcome.has_value());

    auto commitResult = a.session->ProcessCommit(commitWelcome->commit);
    ASSERT_TRUE(std::holds_alternative<RosterMap>(commitResult));

    // a is in an established group with no queued proposals; a replayed commit
    // is a hard failure that should request a reset, not a silent ignore
    auto replayResult = a.session->ProcessCommit(commitWelcome->commit);
    EXPECT_TRUE(std::holds_alternative<failed_t>(replayResult));
    EXPECT_TRUE(a.HasFailureReason("ProcessCommit called without queued proposals"));
}

TEST_F(MlsSessionTests, SessionCommitWithoutAnyStateIsIgnored)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);

    auto commitWelcome = ProposeAddAndCommit(externalSender, a, b);
    ASSERT_TRUE(commitWelcome.has_value());

    // a session with no pending or established state ignores in-flight commits
    // (e.g. during a reset) instead of failing and causing thrashing
    TestSession fresh(kUserC);
    auto commitResult = fresh.session->ProcessCommit(commitWelcome->commit);
    EXPECT_TRUE(std::holds_alternative<ignored_t>(commitResult));
    EXPECT_TRUE(fresh.HasFailureReason("Received commit without state"));
}

TEST_F(MlsSessionTests, SessionCommitRejectsAddOfNoLongerRecognizedUser)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);
    ASSERT_TRUE(EstablishGroup(externalSender, a, b));

    a.Recognize({kUserC});
    b.Recognize({kUserC});
    auto proposal = ProposeAddFor(externalSender, 1, c);
    ASSERT_TRUE(a.session->ProcessProposals(proposal).has_value());
    auto commitWelcomeB = b.session->ProcessProposals(proposal);
    ASSERT_TRUE(commitWelcomeB.has_value());
    auto commitB = externalSender.SplitCommitWelcome(*commitWelcomeB).first;

    // c disconnects after a queued its add, but the gateway announces b's commit anyway
    a.Forget(kUserC);
    auto commitResult = a.session->ProcessCommit(commitB);
    EXPECT_TRUE(std::holds_alternative<failed_t>(commitResult));
    EXPECT_TRUE(a.HasFailureReason("Unexpected user ID in add proposal"));
    EXPECT_TRUE(a.HasFailureReason("Commit includes invalid queued proposal"));

    auto controlResult = b.session->ProcessCommit(commitB);
    auto* controlRoster = std::get_if<RosterMap>(&controlResult);
    ASSERT_NE(controlRoster, nullptr);
    EXPECT_EQ(controlRoster->count(std::stoull(kUserC)), 1u);
}

TEST_F(MlsSessionTests, SessionOwnCommitRejectsAddOfNoLongerRecognizedUser)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);
    ASSERT_TRUE(EstablishGroup(externalSender, a, b));

    a.Recognize({kUserC});
    auto commitWelcomeA = a.session->ProcessProposals(ProposeAddFor(externalSender, 1, c));
    ASSERT_TRUE(commitWelcomeA.has_value());
    auto commitA = externalSender.SplitCommitWelcome(*commitWelcomeA).first;

    a.Forget(kUserC);
    auto commitResult = a.session->ProcessCommit(commitA);
    EXPECT_TRUE(std::holds_alternative<failed_t>(commitResult));
    EXPECT_TRUE(a.HasFailureReason("Unexpected user ID in add proposal"));
    EXPECT_TRUE(a.HasFailureReason("Commit includes invalid queued proposal"));
}

TEST_F(MlsSessionTests, SessionCommitAcceptsExistingUnrecognizedLeaf)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);
    ASSERT_TRUE(EstablishGroup(externalSender, a, b));

    // b is no longer recognized, but the commit leaves b's leaf in place
    a.Forget(kUserB);
    a.Recognize({kUserC});
    auto commitWelcomeA = a.session->ProcessProposals(ProposeAddFor(externalSender, 1, c));
    ASSERT_TRUE(commitWelcomeA.has_value());
    auto commitA = externalSender.SplitCommitWelcome(*commitWelcomeA).first;

    auto commitResult = a.session->ProcessCommit(commitA);
    EXPECT_TRUE(std::holds_alternative<RosterMap>(commitResult));
}

TEST_F(MlsSessionTests, SessionProposalsDoNotCommitStaleQueuedAdd)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);

    a.Recognize({kUserB, kUserC});
    auto proposalC = ProposeAddFor(externalSender, 0, c);
    ASSERT_TRUE(a.session->ProcessProposals(proposalC).has_value());

    // c disconnects before an unrelated add arrives
    a.Forget(kUserC);
    auto commitWelcome = a.session->ProcessProposals(ProposeAddFor(externalSender, 0, b));
    EXPECT_FALSE(commitWelcome.has_value());
    EXPECT_TRUE(a.HasFailureReason("Unexpected user ID in add proposal"));

    // once the voice gateway revokes c's add, a commits the remaining add of b
    commitWelcome = a.session->ProcessProposals(externalSender.Revoke(proposalC));
    ASSERT_TRUE(commitWelcome.has_value());
    auto commit = externalSender.SplitCommitWelcome(*commitWelcome).first;
    auto commitResult = a.session->ProcessCommit(commit);
    auto* roster = std::get_if<RosterMap>(&commitResult);
    ASSERT_NE(roster, nullptr);
    EXPECT_EQ(roster->size(), 2u);
    EXPECT_EQ(roster->count(std::stoull(kUserC)), 0u);
}

TEST_F(MlsSessionTests, SessionRevokeDoesNotCommitStaleQueuedAdd)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);

    a.Recognize({kUserB, kUserC});
    auto proposalB = ProposeAddFor(externalSender, 0, b);
    ASSERT_TRUE(a.session->ProcessProposals(ProposeAddFor(externalSender, 0, c)).has_value());
    ASSERT_TRUE(a.session->ProcessProposals(proposalB).has_value());

    // rebuilding after the revoke must not commit c's add now that c has disconnected
    a.Forget(kUserC);
    auto commitWelcome = a.session->ProcessProposals(externalSender.Revoke(proposalB));
    EXPECT_FALSE(commitWelcome.has_value());
    EXPECT_TRUE(a.HasFailureReason("Unexpected user ID in add proposal"));
}

TEST_F(MlsSessionTests, SessionCommitRejectsMissingQueuedProposal)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    TestSession d(kUserD);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);
    d.InitAndSetExternalSender(externalSender, kTestGroupId);
    ASSERT_TRUE(EstablishGroup(externalSender, a, b));

    a.Recognize({kUserC, kUserD});
    b.Recognize({kUserC, kUserD});
    auto proposalC = ProposeAddFor(externalSender, 1, c);
    ASSERT_TRUE(a.session->ProcessProposals(proposalC).has_value());
    ASSERT_TRUE(a.session->ProcessProposals(ProposeAddFor(externalSender, 1, d)).has_value());

    // b never saw the add of d, so its commit leaves out a proposal a has queued
    auto commitWelcomeB = b.session->ProcessProposals(proposalC);
    ASSERT_TRUE(commitWelcomeB.has_value());
    auto commitB = externalSender.SplitCommitWelcome(*commitWelcomeB).first;

    auto commitResult = a.session->ProcessCommit(commitB);
    EXPECT_TRUE(std::holds_alternative<failed_t>(commitResult));
    EXPECT_TRUE(a.HasFailureReason("Commit does not cover queued proposals"));
}

TEST_F(MlsSessionTests, SessionCommitRejectsCommitterCredentialChange)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession c(kUserC);
    RawMember b(kUserB);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);

    a.Recognize({kUserB, kUserC, kUserD});
    auto commitWelcome = a.session->ProcessProposals(
      externalSender.ProposeAdd(0, ::mlspp::tls::marshal(b.keyPackage)));
    ASSERT_TRUE(commitWelcome.has_value());
    auto [commit, welcome] = externalSender.SplitCommitWelcome(*commitWelcome);
    ASSERT_TRUE(std::holds_alternative<RosterMap>(a.session->ProcessCommit(commit)));
    b.JoinFromWelcome(welcome);

    auto proposalC = ProposeAddFor(externalSender, 1, c);
    ASSERT_TRUE(a.session->ProcessProposals(proposalC).has_value());
    b.HandleProposals(proposalC);

    // b's update path swaps its leaf credential over to d
    auto commitB = b.CommitWithCredential(mls::CreateUserCredential(kUserD, kTestProtocolVersion));

    auto commitResult = a.session->ProcessCommit(commitB);
    EXPECT_TRUE(std::holds_alternative<failed_t>(commitResult));
    EXPECT_TRUE(a.HasFailureReason("Commit changes committer credential"));
}

TEST_F(MlsSessionTests, SessionCommitRemovingDisconnectedUserIsAccepted)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    c.InitAndSetExternalSender(externalSender, kTestGroupId);
    ASSERT_TRUE(EstablishGroup(externalSender, a, b));

    a.Recognize({kUserC});
    b.Recognize({kUserC});
    auto proposalC = ProposeAddFor(externalSender, 1, c);
    ASSERT_TRUE(a.session->ProcessProposals(proposalC).has_value());
    auto commitWelcomeB = b.session->ProcessProposals(proposalC);
    ASSERT_TRUE(commitWelcomeB.has_value());
    auto [addCommit, welcome] = externalSender.SplitCommitWelcome(*commitWelcomeB);
    ASSERT_TRUE(std::holds_alternative<RosterMap>(a.session->ProcessCommit(addCommit)));
    ASSERT_TRUE(std::holds_alternative<RosterMap>(b.session->ProcessCommit(addCommit)));
    c.Recognize({kUserA, kUserB});
    ASSERT_TRUE(c.session->ProcessWelcome(welcome).has_value());

    // c disconnects and the voice gateway proposes its removal; a commit with a remove carries an
    // update path that rewrites the committer's leaf
    a.Forget(kUserC);
    b.Forget(kUserC);
    auto removeC = externalSender.ProposeRemove(2, 2);
    ASSERT_TRUE(a.session->ProcessProposals(removeC).has_value());
    auto removeCommitWelcome = b.session->ProcessProposals(removeC);
    ASSERT_TRUE(removeCommitWelcome.has_value());
    auto removeCommit = ::mlspp::tls::marshal(
      ::mlspp::tls::get<::mlspp::MLSMessage>(::mlspp::bytes_ns::bytes(*removeCommitWelcome)));

    auto commitResultA = a.session->ProcessCommit(removeCommit);
    auto* rosterChangeA = std::get_if<RosterMap>(&commitResultA);
    ASSERT_NE(rosterChangeA, nullptr);
    ASSERT_EQ(rosterChangeA->count(std::stoull(kUserC)), 1u);
    EXPECT_TRUE(rosterChangeA->at(std::stoull(kUserC)).empty());
    EXPECT_TRUE(std::holds_alternative<RosterMap>(b.session->ProcessCommit(removeCommit)));
    EXPECT_EQ(a.session->GetLastEpochAuthenticator(), b.session->GetLastEpochAuthenticator());
}

TEST_F(MlsSessionTests, SessionRecognizedUsersPersistAcrossReinit)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);
    a.Recognize({kUserB});

    // an in-call MLS reset re-initializes the session without new client connects
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    EXPECT_TRUE(a.session->ProcessProposals(ProposeAddFor(externalSender, 0, b)).has_value());
}

TEST_F(MlsSessionTests, SessionSetExternalSenderAfterJoinReportsError)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);

    auto commitWelcome = ProposeAddAndCommit(externalSender, a, b);
    ASSERT_TRUE(commitWelcome.has_value());

    auto commitResult = a.session->ProcessCommit(commitWelcome->commit);
    ASSERT_TRUE(std::holds_alternative<RosterMap>(commitResult));

    a.session->SetExternalSender(externalSender.GetMarshalledExternalSender());
    EXPECT_TRUE(
      a.HasFailureReason("Cannot set external sender after joining/creating an MLS group"));
}

TEST_F(MlsSessionTests, SessionChangedExternalSenderDiscardsPendingCommit)
{
    ExternalSender oldExternalSender(kTestProtocolVersion, kTestGroupId);
    ExternalSender newExternalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    TestSession c(kUserC);
    a.InitAndSetExternalSender(oldExternalSender, kTestGroupId);
    b.InitAndSetExternalSender(oldExternalSender, kTestGroupId);
    c.InitAndSetExternalSender(newExternalSender, kTestGroupId);

    auto staleCommitWelcome = ProposeAddAndCommit(oldExternalSender, a, b);
    ASSERT_TRUE(staleCommitWelcome.has_value());

    a.session->SetExternalSender(newExternalSender.GetMarshalledExternalSender());

    auto staleCommitResult = a.session->ProcessCommit(staleCommitWelcome->commit);
    EXPECT_FALSE(std::holds_alternative<RosterMap>(staleCommitResult));

    auto staleProposal = oldExternalSender.ProposeAdd(0, b.session->GetMarshalledKeyPackage());
    EXPECT_FALSE(a.session->ProcessProposals(staleProposal).has_value());

    ASSERT_TRUE(EstablishGroup(newExternalSender, a, c));
}

TEST_F(MlsSessionTests, SessionRepeatedExternalSenderKeepsPendingCommit)
{
    ExternalSender externalSender(kTestProtocolVersion, kTestGroupId);
    TestSession a(kUserA);
    TestSession b(kUserB);
    a.InitAndSetExternalSender(externalSender, kTestGroupId);
    b.InitAndSetExternalSender(externalSender, kTestGroupId);

    auto commitWelcome = ProposeAddAndCommit(externalSender, a, b);
    ASSERT_TRUE(commitWelcome.has_value());

    a.session->SetExternalSender(externalSender.GetMarshalledExternalSender());

    auto commitResult = a.session->ProcessCommit(commitWelcome->commit);
    EXPECT_TRUE(std::holds_alternative<RosterMap>(commitResult));
}

TEST_F(MlsSessionTests, SessionKeyPackageWithoutInitReportsError)
{
    TestSession s(kUserA);
    auto keyPackage = s.session->GetMarshalledKeyPackage();
    EXPECT_TRUE(keyPackage.empty());
    EXPECT_TRUE(s.HasFailureReason("Missing leaf node"));
}

TEST_F(MlsSessionTests, SessionProposalsWithoutStateReportsError)
{
    TestSession s(kUserA);
    auto result = s.session->ProcessProposals({});
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(s.HasFailureReason("Got proposal without MLS state"));
}

} // namespace test
} // namespace dave
} // namespace discord
