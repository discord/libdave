#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "mls/session.h"

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

    auto commitWelcome =
      creator.session->ProcessProposals(proposal, {creator.userId, joiner.userId});
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

    auto welcomeRoster =
      joiner.session->ProcessWelcome(commitWelcome->welcome, {creator.userId, joiner.userId});
    return welcomeRoster.has_value();
}

// Has `committer` prepare a commit for the given proposals, returning the commit
// on its own (without any welcome).
std::optional<std::vector<uint8_t>> PrepareCommit(ExternalSender& externalSender,
                                                  TestSession& committer,
                                                  std::vector<uint8_t> const& proposals,
                                                  std::set<std::string> const& recognizedUserIDs)
{
    auto commitWelcome = committer.session->ProcessProposals(proposals, recognizedUserIDs);
    if (!commitWelcome) {
        return std::nullopt;
    }

    return externalSender.SplitCommitWelcome(*commitWelcome).first;
}

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

    auto welcomeRoster = b.session->ProcessWelcome(commitWelcome->welcome, {kUserA, kUserB});
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
    auto welcomeRoster = b.session->ProcessWelcome(commitWelcome->welcome, {kUserB});
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

    auto welcomeRoster = b.session->ProcessWelcome(commitWelcome->welcome, {kUserA, kUserB});
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

TEST_F(MlsSessionTests, SessionOwnCommitMustMatchPreparedCommit)
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

    auto proposeAddC = externalSender.ProposeAdd(1, c.session->GetMarshalledKeyPackage());
    auto firstCommit = PrepareCommit(externalSender, a, proposeAddC, {kUserA, kUserB, kUserC});
    ASSERT_TRUE(firstCommit.has_value());

    // a second commit for the same epoch replaces a's cached outbound state
    auto proposeAddD = externalSender.ProposeAdd(1, d.session->GetMarshalledKeyPackage());
    auto secondCommit =
      PrepareCommit(externalSender, a, proposeAddD, {kUserA, kUserB, kUserC, kUserD});
    ASSERT_TRUE(secondCommit.has_value());
    ASSERT_NE(*firstCommit, *secondCommit);

    ASSERT_TRUE(b.session->ProcessProposals(proposeAddC, {kUserA, kUserB, kUserC}).has_value());
    auto commitResultB = b.session->ProcessCommit(*firstCommit);
    auto* rosterChangeB = std::get_if<RosterMap>(&commitResultB);
    ASSERT_NE(rosterChangeB, nullptr);
    EXPECT_EQ(rosterChangeB->size(), 1u);
    EXPECT_EQ(rosterChangeB->count(std::stoull(kUserC)), 1u);

    // a's cached state has the group, epoch and leaf index the first commit would produce, but
    // it is the result of the second commit
    auto commitResultA = a.session->ProcessCommit(*firstCommit);
    EXPECT_TRUE(std::holds_alternative<failed_t>(commitResultA));
    // mlspp refuses to handle our own commit without a cached state
    EXPECT_TRUE(a.HasFailureReason("Handle own commits with caching"));
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

    auto proposeAddC = externalSender.ProposeAdd(1, c.session->GetMarshalledKeyPackage());
    auto firstCommit = PrepareCommit(externalSender, a, proposeAddC, {kUserA, kUserB, kUserC});
    ASSERT_TRUE(firstCommit.has_value());

    auto proposeAddD = externalSender.ProposeAdd(1, d.session->GetMarshalledKeyPackage());
    auto secondCommit =
      PrepareCommit(externalSender, a, proposeAddD, {kUserA, kUserB, kUserC, kUserD});
    ASSERT_TRUE(secondCommit.has_value());

    ASSERT_TRUE(b.session->ProcessProposals(proposeAddC, {kUserA, kUserB, kUserC}).has_value());
    ASSERT_TRUE(
      b.session->ProcessProposals(proposeAddD, {kUserA, kUserB, kUserC, kUserD}).has_value());
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
    auto result = s.session->ProcessProposals({}, {});
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(s.HasFailureReason("Got proposal without MLS state"));
}

} // namespace test
} // namespace dave
} // namespace discord
