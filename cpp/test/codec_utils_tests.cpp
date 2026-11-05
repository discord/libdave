#include <algorithm>
#include <vector>
#include "gtest/gtest.h"

#include <dave/array_view.h>

#include "codec_utils.h"
#include "decryptor.h"
#include "encryptor.h"
#include "frame_processors.h"

#include "dave_test.h"
#include "static_key_ratchet.h"

namespace discord {
namespace dave {
namespace test {

class CodecUtilsTests : public DaveTests {};

namespace {

using ProcessFrameFn = bool (*)(OutboundFrameProcessor&, ArrayView<const uint8_t>);

struct MalformedFrame {
    std::string_view hex;
    const char* assertMessage;
};

void ExpectRejectsFrames(ProcessFrameFn processFrame, std::initializer_list<MalformedFrame> frames)
{
    for (const auto& [hex, assertMessage] : frames) {
        auto frame = GetBufferFromHex(hex);
        OutboundFrameProcessor processor;
        [[maybe_unused]] bool processed = true;
        EXPECT_DEBUG_DEATH(processed = processFrame(
                             processor, MakeArrayView<const uint8_t>(frame.data(), frame.size())),
                           assertMessage)
          << "frame: " << hex;
#ifdef NDEBUG
        EXPECT_FALSE(processed) << "frame: " << hex;
#endif
    }
}

void ExpectProcessesFrame(ProcessFrameFn processFrame,
                          std::string_view hex,
                          size_t unencryptedHeaderSize,
                          std::string_view expectedEncryptedHex)
{
    auto frame = GetBufferFromHex(hex);
    OutboundFrameProcessor processor;
    EXPECT_TRUE(processFrame(processor, MakeArrayView<const uint8_t>(frame.data(), frame.size())));

    auto& unencryptedRanges = processor.GetUnencryptedRanges();
    ASSERT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, unencryptedHeaderSize);
    EXPECT_EQ(processor.GetEncryptedBytes(), GetBufferFromHex(expectedEncryptedHex));
}

// expectedFrameHex is the frame rebuilt from its unencrypted and encrypted bytes, which has
// every start code rewritten as a 4 byte start code
void ExpectPassesThroughFrame(Codec codec,
                              std::string_view hex,
                              std::string_view expectedFrameHex,
                              std::string_view expectedEncryptedHex)
{
    auto frame = GetBufferFromHex(hex);
    OutboundFrameProcessor processor;
    processor.ProcessFrame(MakeArrayView<const uint8_t>(frame.data(), frame.size()), codec);
    EXPECT_EQ(processor.GetEncryptedBytes(), GetBufferFromHex(expectedEncryptedHex))
      << "frame: " << hex;

    processor.GetCiphertextBytes() = processor.GetEncryptedBytes();
    std::vector<uint8_t> reconstructed(processor.GetUnencryptedBytes().size() +
                                       processor.GetEncryptedBytes().size());
    reconstructed.resize(processor.ReconstructFrame(
      MakeArrayView<uint8_t>(reconstructed.data(), reconstructed.size())));
    EXPECT_EQ(reconstructed, GetBufferFromHex(expectedFrameHex)) << "frame: " << hex;
}

} // namespace

TEST_F(CodecUtilsTests, RandomOpusFrame)
{
    constexpr std::string_view randomBytes =
      "0dc5aedd5bdc3f20be5697e54dd1f437b896a36f858c6f20bbd69e2a493ca170c4f0c1b9acd4"
      "9d324b92afa788d09b12b29115a2feb3552b60fff983234a6c9608af3933683efc6b0f5579a9";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(randomBytes);

    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;

    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::Opus);
    auto& unencryptedBytes = frameProcessor.GetUnencryptedBytes();
    auto& encryptedBytes = frameProcessor.GetEncryptedBytes();
    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(incomingFrame.size(), 76u);
    EXPECT_EQ(unencryptedBytes.size(), 0u);
    EXPECT_EQ(encryptedBytes.size(), incomingFrame.size());
    EXPECT_EQ(unencryptedRanges.size(), 0u);
}

TEST_F(CodecUtilsTests, SplitReconstruct)
{
    std::string randomBytes =
      "0dc5aedd5bdc3f20be5697e54dd1f437b896a36f858c6f20bbd69e2a493ca170c4f0c1b9acd4"
      "9d324b92afa788d09b12b29115a2feb3552b60fff983234a6c9608af3933683efc6b0f5579a9"
      "0000000000000000 00 000a 140a 280a 3c0a 14 fafa";
    randomBytes.erase(std::remove(randomBytes.begin(), randomBytes.end(), ' '), randomBytes.end());

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(randomBytes);

    auto reconstructedFrame = std::make_unique<uint8_t[]>(incomingFrame.size());

    InboundFrameProcessor frameProcessor;

    frameProcessor.ParseFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()));
    memcpy(frameProcessor.GetPlaintext().data(),
           frameProcessor.GetCiphertext().data(),
           frameProcessor.GetCiphertext().size());
    auto bytesWritten = frameProcessor.ReconstructFrame(
      MakeArrayView<uint8_t>(reconstructedFrame.get(), incomingFrame.size()));

    EXPECT_EQ(bytesWritten, 76u);
    EXPECT_EQ(memcmp(incomingFrame.data(), reconstructedFrame.get(), bytesWritten), 0);
}

TEST_F(CodecUtilsTests, H264SliceOneByteExpGolomb)
{
    // start code, nal unit header
    // 3 exponential golomb values (first_mb_in_slice, slice_type, pic_parameter_set_id)
    // then slice payloads
    constexpr std::string_view kH264SliceHex = "0000000161e0fafafa";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH264SliceHex);

    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H264);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, 6u);
}

TEST_F(CodecUtilsTests, H264ShortIDROneByteExpGolomb)
{
    // SPS NAL UNIT, PPS NAL UNIT, then IDR NAL Unit
    // for IDR: nal unit header, then 3 exponential golomb values (first_mb_in_slice, slice_type,
    // pic_parameter_set_id) then IDR payloads
    constexpr std::string_view kH264ShortIDR =
      "000000016742c00d8c8d40d0fbc900f08846a00000000168ce3c800000000165b8fafafa";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH264ShortIDR);
    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H264);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, 33u);
}

TEST_F(CodecUtilsTests, H264ShortIDRTwoByteExpGolomb)
{
    // SPS NAL UNIT, PPS NAL UNIT, then IDR NAL Unit
    // for IDR: nal unit header, then 3 exponential golomb values (first_mb_in_slice, slice_type,
    // pic_parameter_set_id) then IDR payloads
    constexpr std::string_view kH264ShortIDR =
      "000000016742c00d8c8d40d0fbc900f08846a00000000168ce3c8000000001654760fafafa";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH264ShortIDR);
    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H264);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, 34u);
}

TEST_F(CodecUtilsTests, H264LongIDROneByteExpGolomb)
{
    // SPS NAL UNIT, PPS NAL UNIT, SEI NAL unit, then IDR NAL Unit
    // which has nal unit header,
    // then 3 exponential golomb values (first_mb_in_slice, slice_type, pic_parameter_set_id)
    // then IDR payloads
    constexpr std::string_view kH264LongIDR =
      "00000001274d0033ab402802dd00da08846a000000000128ee3c800000000106051a47564adc5c4c433f94efc511"
      "3cd143a801ffccccff020004ca90800000000125b8fafafa";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH264LongIDR);
    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H264);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, 67u);
}

TEST_F(CodecUtilsTests, H264LongIDRTwoByteExpGolomb)
{
    // SPS NAL UNIT, PPS NAL UNIT, SEI NAL unit, then IDR NAL Unit
    // which has nal unit header, then 3 exponential golomb values
    // (first_mb_in_slice, slice_type, pic_parameter_set_id) then IDR payloads
    constexpr std::string_view kH264LongIDR =
      "00000001274d0033ab402802dd00da08846a000000000128ee3c800000000106051a47564adc5c4c433f94efc5"
      "11"
      "3cd143a801ffccccff020004ca908000000001254760fafafa";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH264LongIDR);
    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H264);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, 68u);
}

TEST_F(CodecUtilsTests, H264EmulationPreventionInEarlyExpGolomb)
{
    constexpr std::string_view kH264SliceHex = "00000001610000038000e0fafafa";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH264SliceHex);

    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H264);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, 11u);
}

TEST_F(CodecUtilsTests, H264ThreeByteShortCodeExtension)
{
    constexpr std::string_view kH264MixedShortCodes =
      "000000012764001fac2b602802dd8088000003000800000301b46d0e1970"
      "00000128ee3cb0000001258880ababab";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH264MixedShortCodes);
    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H264);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, 45u);

    auto bytesToEncrypt = frameProcessor.GetEncryptedBytes();
    auto encryptedBytes = frameProcessor.GetCiphertextBytes();
    EXPECT_EQ(bytesToEncrypt.size(), encryptedBytes.size());
    memcpy(encryptedFrame.get(), bytesToEncrypt.data(), bytesToEncrypt.size());

    frameProcessor.ReconstructFrame(MakeArrayView<uint8_t>(
      encryptedFrame.get(), bytesToEncrypt.size() + frameProcessor.GetUnencryptedBytes().size()));

    constexpr std::string_view kExpectedUnencryptedHeaderHex =
      "000000012764001fac2b602802dd8088000003000800000301b46d0e19700000000128ee3cb000000001258880";
    auto expectedUnencryptedHeader = GetBufferFromHex(kExpectedUnencryptedHeaderHex);

    auto compareResultExpected = memcmp(
      encryptedFrame.get(), expectedUnencryptedHeader.data(), expectedUnencryptedHeader.size());

    EXPECT_EQ(compareResultExpected, 0);
}

TEST_F(CodecUtilsTests, H264TwoSliceTest)
{
    // start code, nal unit header
    // 3 exponential golomb values (first_mb_in_slice, slice_type, pic_parameter_set_id)
    // then slice payload
    // and repeated again
    constexpr std::string_view kH264TwoSliceHex = "0000000161e0fafafa0000000161e0fafafa";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH264TwoSliceHex);

    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H264);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 2u);
    EXPECT_EQ(unencryptedRanges[0].offset, 0u);
    EXPECT_EQ(unencryptedRanges[0].size, 6u);
    EXPECT_EQ(unencryptedRanges[1].offset, 9u);
    EXPECT_EQ(unencryptedRanges[1].size, 6u);
}

TEST_F(CodecUtilsTests, H265IdrSlice)
{
    constexpr std::string_view kH265IdrSliceHex =
      "0000000140010c01ffff016000000300b0000003000003005d17024"
      "000000001420101016000000300b0000003000003005da00280802d16205ee45914bff2e7f13fa2"
      "000000014401c072f05324000000014e01051a47564adc5c4c433f94efc5113cd143a803ee0000ee02001fc8b88"
      "0000000012801abab";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH265IdrSliceHex);
    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H265);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, 119u);
}

TEST_F(CodecUtilsTests, H265TsaSlice)
{
    constexpr std::string_view kH265TsaSliceHex = "000000010201abab";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH265TsaSliceHex);
    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H265);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, 6u);
}

TEST_F(CodecUtilsTests, H265SimpleThreeByteCodeExtension)
{
    constexpr std::string_view kH265TsaSliceHexShort = "0000010201abab";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH265TsaSliceHexShort);
    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H265);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, 6u);
}

TEST_F(CodecUtilsTests, H265MultipleThreeByteCodeExtensions)
{
    constexpr std::string_view kH265IdrSliceHex =
      "00000140010c01ffff016000000300b0000003000003005d17024"
      "0000001420101016000000300b0000003000003005da00280802d16205ee45914bff2e7f13fa2"
      "000000014401c072f05324000000014e01051a47564adc5c4c433f94efc5113cd143a803ee0000ee02001fc8b88"
      "00000012801abab";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH265IdrSliceHex);
    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H265);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 1u);
    EXPECT_EQ(unencryptedRanges.front().offset, 0u);
    EXPECT_EQ(unencryptedRanges.front().size, 119u);
}

TEST_F(CodecUtilsTests, H265TwoIdrSlice)
{
    constexpr std::string_view kH265TwoIdrSliceHex = "0000010201abab0000010201abab";

    // load the hex encoded sample frame to a buffer
    auto incomingFrame = GetBufferFromHex(kH265TwoIdrSliceHex);
    auto encryptedFrame = std::make_unique<uint8_t[]>(incomingFrame.size() * 2);

    OutboundFrameProcessor frameProcessor;
    frameProcessor.ProcessFrame(
      MakeArrayView<const uint8_t>(incomingFrame.data(), incomingFrame.size()), Codec::H265);

    auto unencryptedRanges = frameProcessor.GetUnencryptedRanges();

    EXPECT_EQ(unencryptedRanges.size(), 2u);
    EXPECT_EQ(unencryptedRanges[0].offset, 0u);
    EXPECT_EQ(unencryptedRanges[0].size, 6u);
    EXPECT_EQ(unencryptedRanges[1].offset, 8u);
    EXPECT_EQ(unencryptedRanges[1].size, 6u);
}

TEST_F(CodecUtilsTests, Vp8RejectsShortFrames)
{
    ExpectRejectsFrames(codec_utils::ProcessFrameVp8,
                        {
                          {"", "VP8 frame is empty"},
                          // key frames need a 10 byte payload header
                          {"00", "too small to contain its payload header"},
                          {"0000000000", "too small to contain its payload header"},
                        });
}

TEST_F(CodecUtilsTests, Vp8ProcessesWellFormedFrames)
{
    ExpectProcessesFrame(codec_utils::ProcessFrameVp8, "50010203040506070809aabb", 10, "aabb");
    ExpectProcessesFrame(codec_utils::ProcessFrameVp8, "51aabbcc", 1, "aabbcc");
}

TEST_F(CodecUtilsTests, H264RejectsShortAndMalformedFrames)
{
    ExpectRejectsFrames(
      codec_utils::ProcessFrameH264,
      {
        {"", "too small to contain a NAL unit"},
        {"00", "too small to contain a NAL unit"},
        {"0000", "too small to contain a NAL unit"},
        // start code with no NAL unit header
        {"00000001", "does not contain a NAL unit"},
        // slice whose PPS ID runs past the end of the NAL unit
        {"000000016100", "PPS ID overflows NAL unit"},
        // PPS ID exp-golomb code is cut off by the next start code
        {"0000000161680000000165b8", "PPS ID overflows NAL unit"},
        {"000001050000000101", "PPS ID overflows NAL unit"},
        // IDR NAL unit that is only its header byte
        {"0000010500000101", "PPS ID overflows NAL unit"},
        // PPS ID runs past the end of the frame
        {"0000010510", "PPS ID overflows NAL unit"},
        {"0000016100000000", "Unexpectedly large exponential golomb encoded value"},
        {"ab0000000161e0fafa", "does not start with an Annex B start code"},
        // length prefixed NAL units, the second length (261) reads as a start code
        {"0000000309f0aa0000010561e0fafa", "does not start with an Annex B start code"},
        // back to back start codes give a zero length non-VCL NAL unit
        {"0000000109f000000100000161e0fafa", "NAL unit header is truncated"},
      });
}

TEST_F(CodecUtilsTests, H264ProcessesWellFormedFrame)
{
    ExpectProcessesFrame(codec_utils::ProcessFrameH264, "0000000161e0fafafa", 6, "fafafa");
}

TEST_F(CodecUtilsTests, H264AcceptsLeadingZeroBytes)
{
    ExpectProcessesFrame(codec_utils::ProcessFrameH264, "00000000000161e0fafa", 6, "fafa");
}

TEST_F(CodecUtilsTests, H264KeepsTrailingOneByteNalUnit)
{
    // end of sequence NAL units are only their header byte
    auto frame = GetBufferFromHex("0000000161e0fafa0000010a");
    OutboundFrameProcessor processor;
    EXPECT_TRUE(codec_utils::ProcessFrameH264(
      processor, MakeArrayView<const uint8_t>(frame.data(), frame.size())));
    EXPECT_EQ(processor.GetUnencryptedBytes(), GetBufferFromHex("0000000161e0000000010a"));
    EXPECT_EQ(processor.GetEncryptedBytes(), GetBufferFromHex("fafa"));
}

TEST_F(CodecUtilsTests, H265RejectsShortAndMalformedFrames)
{
    ExpectRejectsFrames(
      codec_utils::ProcessFrameH265,
      {
        {"", "too small to contain a NAL unit"},
        {"00", "too small to contain a NAL unit"},
        {"0000", "too small to contain a NAL unit"},
        // start code followed by one byte of the two byte NAL unit header
        {"0000000140", "NAL unit header is truncated"},
        {"000000010201abab00000102", "NAL unit header is truncated"},
        // VCL NAL unit cut to one byte by the next start code
        {"00000001020000014001abab", "NAL unit header is truncated"},
        {"0000010200000140", "NAL unit header is truncated"},
        {"ab000000010201abab", "does not start with an Annex B start code"},
        // length prefixed NAL units, the second length (261) reads as a start code
        {"00000003460150000001050201abab", "does not start with an Annex B start code"},
        // back to back start codes give a zero length NAL unit
        {"000000014601500000010000010201abab", "NAL unit header is truncated"},
        // non-VCL NAL unit cut to one byte by the next start code
        {"0000000140010c01000001400000010201abab", "NAL unit header is truncated"},
      });
}

TEST_F(CodecUtilsTests, H265ProcessesWellFormedFrame)
{
    ExpectProcessesFrame(codec_utils::ProcessFrameH265, "000000010201abab", 6, "abab");
}

TEST_F(CodecUtilsTests, H265AcceptsLeadingZeroBytes)
{
    ExpectProcessesFrame(codec_utils::ProcessFrameH265, "0000000000010201abab", 6, "abab");
}

TEST_F(CodecUtilsTests, H264PassesThroughEncoderFrameLayouts)
{
    // access unit delimiter and SEI ahead of an IDR slice
    ExpectPassesThroughFrame(Codec::H264,
                             "0000000109f0"
                             "000000010605011a80"
                             "0000000165b8fafa",
                             "0000000109f0000000010605011a800000000165b8fafa",
                             "fafa");
    // filler data after a slice, as emitted by CBR hardware encoders
    ExpectPassesThroughFrame(Codec::H264,
                             "0000000161e0fafa"
                             "000000010cffffff80",
                             "0000000161e0fafa000000010cffffff80",
                             "fafa");
    // trailing zero bytes between NAL units and at the end of the frame
    ExpectPassesThroughFrame(Codec::H264,
                             "0000000161e0fafa00"
                             "0000000161e0abab0000",
                             "0000000161e0fafa000000000161e0abab0000",
                             "fafa00abab0000");
    // three byte start codes
    ExpectPassesThroughFrame(Codec::H264,
                             "00000109f0"
                             "00000165b8fafa",
                             "0000000109f00000000165b8fafa",
                             "fafa");
}

TEST_F(CodecUtilsTests, H265PassesThroughEncoderFrameLayouts)
{
    // access unit delimiter, prefix SEI, IDR slice and suffix SEI
    ExpectPassesThroughFrame(Codec::H265,
                             "00000001460150"
                             "000000014e0105011a80"
                             "000000012601afafaf"
                             "0000000150010401ab80",
                             "00000001460150000000014e0105011a80000000012601afafaf"
                             "0000000150010401ab80",
                             "afafaf");
    // filler data after a slice, as emitted by CBR hardware encoders
    ExpectPassesThroughFrame(Codec::H265,
                             "000000010201abab"
                             "000000014c01ffffff80",
                             "000000010201abab000000014c01ffffff80",
                             "abab");
    // trailing zero bytes between NAL units and at the end of the frame
    ExpectPassesThroughFrame(Codec::H265,
                             "000000010201abab00"
                             "000000010201cdcd0000",
                             "000000010201abab00000000010201cdcd0000",
                             "abab00cdcd0000");
    // nonzero temporal ID and three byte start codes
    ExpectPassesThroughFrame(
      Codec::H265, "00000146035000000102030abc", "000000014603500000000102030abc", "0abc");
}

TEST_F(CodecUtilsTests, MalformedFrameFallsBackToFullEncryption)
{
    struct MalformedCodecFrame {
        Codec codec;
        std::string_view hex;
        const char* assertMessage;
    };

    for (const auto& [codec, hex, assertMessage] : {
           MalformedCodecFrame{Codec::VP8, "00aabb", "too small to contain its payload header"},
           MalformedCodecFrame{Codec::H264, "000000016100", "PPS ID overflows NAL unit"},
           MalformedCodecFrame{
             Codec::H265, "00000001020000014001abab", "NAL unit header is truncated"},
         }) {
        auto frame = GetBufferFromHex(hex);

        OutboundFrameProcessor processor;
        EXPECT_DEBUG_DEATH(
          processor.ProcessFrame(MakeArrayView<const uint8_t>(frame.data(), frame.size()), codec),
          assertMessage)
          << "frame: " << hex;
#ifdef NDEBUG
        EXPECT_TRUE(processor.GetUnencryptedRanges().empty()) << "frame: " << hex;
        EXPECT_EQ(processor.GetEncryptedBytes(), frame) << "frame: " << hex;
#endif
    }
}

} // namespace test
} // namespace dave
} // namespace discord
