#include <gtest/gtest.h>

#include "decryptor.h"
#include "encryptor.h"
#include "frame_processors.h"

#include "dave_test.h"
#include "mock_clock.h"
#include "static_key_ratchet.h"

using namespace testing;
using namespace std::chrono_literals;

namespace discord {
namespace dave {
namespace test {

constexpr std::string_view RandomBytes =
  "0dc5aedd5bdc3f20be5697e54dd1f437b896a36f858c6f20bbd69e2a493ca170c4f0c1b9acd4"
  "9d324b92afa788d09b12b29115a2feb3552b60fff983234a6c9608af3933683efc6b0f5579a9";

class CryptorTests : public DaveTests {};

namespace {

std::vector<uint8_t> EncryptFrame(Encryptor& encryptor, const std::vector<uint8_t>& frame)
{
    auto encryptedFrame = std::vector<uint8_t>(frame.size() * 2);
    size_t bytesWritten = 0;
    auto encryptResult = encryptor.Encrypt(MediaType::Audio,
                                           0,
                                           {frame.data(), frame.size()},
                                           {encryptedFrame.data(), encryptedFrame.size()},
                                           &bytesWritten);
    EXPECT_EQ(encryptResult, 0);
    encryptedFrame.resize(bytesWritten);
    return encryptedFrame;
}

std::vector<uint8_t> EncryptFrameForUser(const std::string& userId,
                                         const std::vector<uint8_t>& frame)
{
    Encryptor encryptor;
    encryptor.SetKeyRatchet(std::make_unique<StaticKeyRatchet>(userId));
    encryptor.AssignSsrcToCodec(0, Codec::Opus);
    return EncryptFrame(encryptor, frame);
}

Decryptor::ResultCode DecryptFrame(Decryptor& decryptor, const std::vector<uint8_t>& encryptedFrame)
{
    auto decryptedFrame = std::vector<uint8_t>(encryptedFrame.size());
    size_t bytesWritten = 0;
    return decryptor.Decrypt(MediaType::Audio,
                             {encryptedFrame.data(), encryptedFrame.size()},
                             {decryptedFrame.data(), decryptedFrame.size()},
                             &bytesWritten);
}

TruncatedSyncNonce TruncatedNonceOf(const std::vector<uint8_t>& encryptedFrame)
{
    InboundFrameProcessor frameProcessor;
    frameProcessor.ParseFrame({encryptedFrame.data(), encryptedFrame.size()});
    EXPECT_TRUE(frameProcessor.IsEncrypted());
    return frameProcessor.GetTruncatedNonce();
}

} // namespace

TEST_F(CryptorTests, PassthroughInOutBuffer)
{
    auto incomingFrame = GetBufferFromHex(RandomBytes);
    auto frameCopy = incomingFrame;

    auto frameViewIn = MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size());
    auto frameViewOut = MakeArrayView<uint8_t>(incomingFrame.data(), incomingFrame.size());

    EXPECT_NE(incomingFrame.data(), frameCopy.data());

    Encryptor encryptor;
    encryptor.AssignSsrcToCodec(0, Codec::Opus);
    encryptor.SetPassthroughMode(true);

    size_t bytesWritten = 0;
    auto encryptResult =
      encryptor.Encrypt(MediaType::Audio, 0, frameViewIn, frameViewOut, &bytesWritten);

    EXPECT_EQ(encryptResult, 0);
    EXPECT_EQ(bytesWritten, frameCopy.size());
    EXPECT_EQ(memcmp(incomingFrame.data(), frameCopy.data(), bytesWritten), 0);

    Decryptor decryptor;
    decryptor.TransitionToPassthroughMode(true, 0s);

    bytesWritten = 0;
    auto decryptResult =
      decryptor.Decrypt(MediaType::Audio, frameViewIn, frameViewOut, &bytesWritten);

    EXPECT_EQ(decryptResult, Decryptor::ResultCode::Success);
    EXPECT_EQ(bytesWritten, frameCopy.size());
    EXPECT_EQ(memcmp(incomingFrame.data(), frameCopy.data(), bytesWritten), 0);
}

TEST_F(CryptorTests, PassthroughTwoBuffers)
{
    auto incomingFrame = GetBufferFromHex(RandomBytes);
    auto encryptedFrame = std::vector<uint8_t>(incomingFrame.size() * 2);
    auto decryptedFrame = std::vector<uint8_t>(incomingFrame.size());

    Encryptor encryptor;
    encryptor.AssignSsrcToCodec(0, Codec::Opus);
    encryptor.SetPassthroughMode(true);

    size_t bytesWritten = 0;
    auto encryptResult = encryptor.Encrypt(MediaType::Audio,
                                           0,
                                           {incomingFrame.data(), incomingFrame.size()},
                                           {encryptedFrame.data(), encryptedFrame.size()},
                                           &bytesWritten);

    EXPECT_EQ(encryptResult, 0);
    EXPECT_EQ(bytesWritten, incomingFrame.size());
    EXPECT_EQ(memcmp(incomingFrame.data(), encryptedFrame.data(), bytesWritten), 0);

    Decryptor decryptor;
    decryptor.TransitionToPassthroughMode(true, 0s);

    size_t bytesDecrypted = 0;
    auto decryptResult = decryptor.Decrypt(MediaType::Audio,
                                           {encryptedFrame.data(), bytesWritten},
                                           {decryptedFrame.data(), decryptedFrame.size()},
                                           &bytesDecrypted);

    EXPECT_EQ(decryptResult, Decryptor::ResultCode::Success);
    EXPECT_EQ(bytesDecrypted, incomingFrame.size());
    EXPECT_EQ(memcmp(encryptedFrame.data(), decryptedFrame.data(), decryptResult), 0);
}

TEST_F(CryptorTests, SilencePacketPassthrough)
{
    const std::vector<uint8_t> WorkerSilencePacket = {248, 255, 254};

    Decryptor decryptor;
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>("0123456789876543210"), 0s);

    auto decryptedFrame = std::vector<uint8_t>(WorkerSilencePacket.size());
    size_t bytesWritten = 0;
    auto decryptResult = decryptor.Decrypt(MediaType::Audio,
                                           {WorkerSilencePacket.data(), WorkerSilencePacket.size()},
                                           {decryptedFrame.data(), decryptedFrame.size()},
                                           &bytesWritten);

    EXPECT_EQ(decryptResult, Decryptor::ResultCode::Success);
    EXPECT_EQ(bytesWritten, WorkerSilencePacket.size());
    EXPECT_EQ(memcmp(WorkerSilencePacket.data(), decryptedFrame.data(), decryptResult), 0);
}

TEST_F(CryptorTests, RandomOpusFrameEncryptDecrypt)
{
    Encryptor encryptor;
    Decryptor decryptor;

    // set static key ratchet for testing
    encryptor.SetKeyRatchet(std::make_unique<StaticKeyRatchet>("0123456789876543210"));
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>("0123456789876543210"), 0s);

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(RandomBytes);
    auto encryptedFrame = std::vector<uint8_t>(incomingFrame.size() * 2);
    auto decryptedFrame = std::vector<uint8_t>(incomingFrame.size());

    for (size_t i = 0; i < 1; i++) {
        // encrypt frame
        size_t bytesWritten = 0;
        encryptor.AssignSsrcToCodec(0, Codec::Opus);
        auto encryptResult = encryptor.Encrypt(MediaType::Audio,
                                               0,
                                               {incomingFrame.data(), incomingFrame.size()},
                                               {encryptedFrame.data(), encryptedFrame.size()},
                                               &bytesWritten);

        EXPECT_EQ(encryptResult, 0);
        EXPECT_GE(bytesWritten, incomingFrame.size());

        // decrypt frame
        size_t bytesDecrypted = 0;
        auto decryptResult = decryptor.Decrypt(MediaType::Audio,
                                               {encryptedFrame.data(), bytesWritten},
                                               {decryptedFrame.data(), decryptedFrame.size()},
                                               &bytesDecrypted);
        EXPECT_EQ(decryptResult, Decryptor::ResultCode::Success);
        EXPECT_EQ(bytesDecrypted, incomingFrame.size());
        EXPECT_EQ(memcmp(incomingFrame.data(), decryptedFrame.data(), incomingFrame.size()), 0);
    }
}

TEST_F(CryptorTests, DuplicateRatchetInstallRejectsReplay)
{
    constexpr auto UserId = "0123456789876543210";
    auto frame = GetBufferFromHex(RandomBytes);
    auto encryptedFrame = EncryptFrameForUser(UserId, frame);

    Decryptor decryptor;
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(UserId));

    EXPECT_EQ(DecryptFrame(decryptor, encryptedFrame), Decryptor::ResultCode::Success);

    // a same-domain re-install must not reset replay protection
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(UserId));

    EXPECT_EQ(DecryptFrame(decryptor, encryptedFrame), Decryptor::ResultCode::InvalidNonce);
}

TEST_F(CryptorTests, RepeatedRatchetInstallsSingleAcceptance)
{
    constexpr auto UserId = "0123456789876543210";
    constexpr size_t ReinstallCount = 50;

    auto frame = GetBufferFromHex(RandomBytes);
    auto encryptedFrame = EncryptFrameForUser(UserId, frame);

    Decryptor decryptor;
    for (size_t i = 0; i < ReinstallCount + 1; ++i) {
        decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(UserId));
    }

    size_t acceptedCount = 0;
    for (size_t i = 0; i < ReinstallCount + 2; ++i) {
        if (DecryptFrame(decryptor, encryptedFrame) == Decryptor::ResultCode::Success) {
            ++acceptedCount;
        }
    }
    EXPECT_EQ(acceptedCount, 1u);
}

TEST_F(CryptorTests, GenuineTransitionStillFallsBackToPreviousRatchet)
{
    // distinct users stand in for the distinct key domains of an epoch transition
    constexpr auto FirstUserId = "1111111111111111111";
    constexpr auto SecondUserId = "2222222222222222222";

    auto frame = GetBufferFromHex(RandomBytes);
    auto oldDomainFrame = EncryptFrameForUser(FirstUserId, frame);

    Decryptor decryptor;
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(FirstUserId));
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(SecondUserId));

    // an in-flight frame from before the transition still decrypts via fallback
    EXPECT_EQ(DecryptFrame(decryptor, oldDomainFrame), Decryptor::ResultCode::Success);
    // but replaying it is still rejected
    EXPECT_NE(DecryptFrame(decryptor, oldDomainFrame), Decryptor::ResultCode::Success);

    auto newDomainFrame = EncryptFrameForUser(SecondUserId, frame);
    EXPECT_EQ(DecryptFrame(decryptor, newDomainFrame), Decryptor::ResultCode::Success);
}

// Deduplication must not weaken authentication: a tag-tampered frame is rejected,
// and the genuine frame still decrypts.
TEST_F(CryptorTests, TamperedFrameRejected)
{
    constexpr auto UserId = "0123456789876543210";
    auto frame = GetBufferFromHex(RandomBytes);
    auto encryptedFrame = EncryptFrameForUser(UserId, frame);

    Decryptor decryptor;
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(UserId));

    // corrupt a ciphertext byte so authentication fails
    auto tamperedFrame = encryptedFrame;
    tamperedFrame[tamperedFrame.size() / 2] ^= 0x01;
    EXPECT_NE(DecryptFrame(decryptor, tamperedFrame), Decryptor::ResultCode::Success);

    EXPECT_EQ(DecryptFrame(decryptor, encryptedFrame), Decryptor::ResultCode::Success);
}

TEST_F(CryptorTests, DuplicateInstallDoesNotExtendExpiry)
{
    constexpr auto FirstUserId = "1111111111111111111";
    constexpr auto SecondUserId = "2222222222222222222";

    auto frame = GetBufferFromHex(RandomBytes);

    Encryptor encryptor;
    encryptor.SetKeyRatchet(std::make_unique<StaticKeyRatchet>(FirstUserId));
    encryptor.AssignSsrcToCodec(0, Codec::Opus);
    auto firstOldDomainFrame = EncryptFrame(encryptor, frame);
    auto secondOldDomainFrame = EncryptFrame(encryptor, frame);

    MockClock clock;
    Decryptor decryptor(clock);
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(FirstUserId));
    // a genuine transition gives the previous manager a short expiry
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(SecondUserId), 10s);
    // a duplicate install must not extend the previous manager's lifetime
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(SecondUserId), 30s);

    // halfway through the transition window the previous manager still decrypts
    clock.Advance(5s);
    EXPECT_EQ(DecryptFrame(decryptor, firstOldDomainFrame), Decryptor::ResultCode::Success);

    // beyond the original window it must be gone, even though the duplicate
    // install asked for a longer expiry
    clock.Advance(6s);
    EXPECT_NE(DecryptFrame(decryptor, secondOldDomainFrame), Decryptor::ResultCode::Success);
}

// Deduplication only collapses matching key domains: ratchets for distinct domains
// must both install and both decrypt.
TEST_F(CryptorTests, DistinctDomainRatchetsAreNotDeduplicated)
{
    constexpr auto FirstUserId = "1111111111111111111";
    constexpr auto SecondUserId = "2222222222222222222";

    auto frame = GetBufferFromHex(RandomBytes);
    auto firstFrame = EncryptFrameForUser(FirstUserId, frame);
    auto secondFrame = EncryptFrameForUser(SecondUserId, frame);

    Decryptor decryptor;
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(FirstUserId));
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(SecondUserId));

    EXPECT_EQ(DecryptFrame(decryptor, firstFrame), Decryptor::ResultCode::Success);
    EXPECT_EQ(DecryptFrame(decryptor, secondFrame), Decryptor::ResultCode::Success);
}

TEST_F(CryptorTests, SameDomainReinstallKeepsNonceSequence)
{
    constexpr auto UserId = "0123456789876543210";
    auto frame = GetBufferFromHex(RandomBytes);

    Encryptor encryptor;
    encryptor.AssignSsrcToCodec(0, Codec::Opus);
    encryptor.SetKeyRatchet(std::make_unique<StaticKeyRatchet>(UserId));
    auto firstFrame = EncryptFrame(encryptor, frame);
    auto secondFrame = EncryptFrame(encryptor, frame);

    encryptor.SetKeyRatchet(std::make_unique<StaticKeyRatchet>(UserId));
    auto thirdFrame = EncryptFrame(encryptor, frame);

    EXPECT_EQ(TruncatedNonceOf(thirdFrame), TruncatedNonceOf(secondFrame) + 1);
    EXPECT_NE(thirdFrame, firstFrame);

    Decryptor decryptor;
    decryptor.TransitionToKeyRatchet(std::make_unique<StaticKeyRatchet>(UserId));
    EXPECT_EQ(DecryptFrame(decryptor, firstFrame), Decryptor::ResultCode::Success);
    EXPECT_EQ(DecryptFrame(decryptor, secondFrame), Decryptor::ResultCode::Success);
    EXPECT_EQ(DecryptFrame(decryptor, thirdFrame), Decryptor::ResultCode::Success);
}

TEST_F(CryptorTests, SameDomainReinstallAfterClearKeepsNonceSequence)
{
    constexpr auto UserId = "0123456789876543210";
    auto frame = GetBufferFromHex(RandomBytes);

    Encryptor encryptor;
    encryptor.AssignSsrcToCodec(0, Codec::Opus);
    encryptor.SetKeyRatchet(std::make_unique<StaticKeyRatchet>(UserId));
    auto firstFrame = EncryptFrame(encryptor, frame);

    encryptor.SetKeyRatchet(nullptr);
    EXPECT_FALSE(encryptor.HasKeyRatchet());

    encryptor.SetKeyRatchet(std::make_unique<StaticKeyRatchet>(UserId));
    auto secondFrame = EncryptFrame(encryptor, frame);

    EXPECT_EQ(TruncatedNonceOf(secondFrame), TruncatedNonceOf(firstFrame) + 1);
}

TEST_F(CryptorTests, NewDomainInstallRestartsNonceSequence)
{
    constexpr auto FirstUserId = "1111111111111111111";
    constexpr auto SecondUserId = "2222222222222222222";
    auto frame = GetBufferFromHex(RandomBytes);

    Encryptor encryptor;
    encryptor.AssignSsrcToCodec(0, Codec::Opus);
    encryptor.SetKeyRatchet(std::make_unique<StaticKeyRatchet>(FirstUserId));
    auto firstDomainFrame = EncryptFrame(encryptor, frame);
    EncryptFrame(encryptor, frame);

    encryptor.SetKeyRatchet(std::make_unique<StaticKeyRatchet>(SecondUserId));
    auto secondDomainFrame = EncryptFrame(encryptor, frame);

    EXPECT_EQ(TruncatedNonceOf(secondDomainFrame), TruncatedNonceOf(firstDomainFrame));
}

} // namespace test
} // namespace dave
} // namespace discord
