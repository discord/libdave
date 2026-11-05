#include "codec_utils.h"

#include <algorithm>
#include <limits>
#include <optional>

#include <dave/logger.h>

#include "common.h"
#include "utils/leb128.h"

namespace discord {
namespace dave {
namespace codec_utils {

UnencryptedFrameHeaderSize BytesCoveringH264PPS(const uint8_t* payload,
                                                const uint64_t sizeRemaining)
{
    // the payload starts with three exponential golomb encoded values
    // (first_mb_in_slice, sps_id, pps_id)
    // the depacketizer needs the pps_id unencrypted
    // and the payload has RBSP encoding that we need to work around

    constexpr uint8_t kEmulationPreventionByte = 0x03;

    uint64_t payloadBitIndex = 0;
    auto zeroBitCount = 0;
    auto parsedExpGolombValues = 0;

    while (payloadBitIndex < sizeRemaining * 8 && parsedExpGolombValues < 3) {
        auto bitIndex = payloadBitIndex % 8;
        auto byteIndex = payloadBitIndex / 8;
        auto payloadByte = payload[byteIndex];

        // if we're starting a new byte
        // check if this is an emulation prevention byte
        // which we skip over
        if (bitIndex == 0) {
            if (byteIndex >= 2 && payloadByte == kEmulationPreventionByte &&
                payload[byteIndex - 1] == 0 && payload[byteIndex - 2] == 0) {
                payloadBitIndex += 8;
                continue;
            }
        }

        if ((payloadByte & (1 << (7 - bitIndex))) == 0) {
            // still in the run of leading zero bits
            ++zeroBitCount;
            ++payloadBitIndex;

            if (zeroBitCount >= 32) {
                REPORT_MALFORMED("Unexpectedly large exponential golomb encoded value");
                return 0;
            }
        }
        else {
            // we hit a one
            // skip forward the number of bits dictated by the leading number of zeroes
            parsedExpGolombValues += 1;
            payloadBitIndex += 1 + zeroBitCount;
            zeroBitCount = 0;
        }
    }

    // return the number of bytes that covers the last exp golomb encoded value
    auto result = (payloadBitIndex / 8) + 1;
    if (result > std::numeric_limits<UnencryptedFrameHeaderSize>::max()) {
        DISCORD_LOG(LS_WARNING)
          << "BytesCoveringH264PPS result cannot fit in UnencryptedFrameHeaderSize";
        return 0;
    }
    else {
        return static_cast<UnencryptedFrameHeaderSize>(result);
    }
}

const uint8_t kH26XNaluLongStartCode[] = {0, 0, 0, 1};
constexpr uint8_t kH26XNaluShortStartSequenceSize = 3;

struct H26XStartCode {
    size_t offset;
    size_t nalUnitOffset;
};

// the returned start code begins at or after searchStartIndex
std::optional<H26XStartCode> FindNextH26XStartCode(const uint8_t* buffer,
                                                   const size_t bufferSize,
                                                   const size_t searchStartIndex = 0)
{
    constexpr uint8_t kH26XStartCodeHighestPossibleValue = 1;
    constexpr uint8_t kH26XStartCodeEndByteValue = 1;
    constexpr uint8_t kH26XStartCodeLeadingBytesValue = 0;

    if (bufferSize < kH26XNaluShortStartSequenceSize) {
        return std::nullopt;
    }

    // look for NAL unit 3 or 4 byte start code
    for (size_t i = searchStartIndex; i < bufferSize - kH26XNaluShortStartSequenceSize;) {
        if (buffer[i + 2] > kH26XStartCodeHighestPossibleValue) {
            // third byte is not 0 or 1, can't be a start code
            i += kH26XNaluShortStartSequenceSize;
        }
        else if (buffer[i + 2] == kH26XStartCodeEndByteValue) {
            // third byte matches the start code end byte, might be a start code sequence
            if (buffer[i + 1] == kH26XStartCodeLeadingBytesValue &&
                buffer[i] == kH26XStartCodeLeadingBytesValue) {
                // confirmed start sequence {0, 0, 1}
                auto nalUnitOffset = i + kH26XNaluShortStartSequenceSize;

                if (i > searchStartIndex && buffer[i - 1] == kH26XStartCodeLeadingBytesValue) {
                    // 4 byte start code
                    return H26XStartCode{i - 1, nalUnitOffset};
                }
                else {
                    // 3 byte start code
                    return H26XStartCode{i, nalUnitOffset};
                }
            }

            i += kH26XNaluShortStartSequenceSize;
        }
        else {
            // third byte is 0, might be a four byte start code
            ++i;
        }
    }

    return std::nullopt;
}

bool ContainsH26XStartCode(const uint8_t* buffer, const size_t bufferSize)
{
    return FindNextH26XStartCode(buffer, bufferSize).has_value();
}

// splits an Annex B frame into NAL units, unencryptedPrefixSize returns how many bytes of each NAL
// unit the packetizer needs in the clear, or nullopt if the NAL unit is malformed
template <typename UnencryptedPrefixSizeFn>
bool ProcessFrameH26X(OutboundFrameProcessor& processor,
                      ArrayView<const uint8_t> frame,
                      const size_t nalUnitHeaderSize,
                      UnencryptedPrefixSizeFn unencryptedPrefixSize)
{
    // this frame can be packetized as a STAP-A or a FU-A
    // so we need to look at the first NAL units to determine how many bytes
    // the packetizer/depacketizer will need into the payload
    if (frame.size() < kH26XNaluShortStartSequenceSize + nalUnitHeaderSize) {
        REPORT_MALFORMED("H26X frame is too small to contain a NAL unit");
        return false;
    }

    auto startCode = FindNextH26XStartCode(frame.data(), frame.size());
    if (!startCode) {
        REPORT_MALFORMED("H26X frame does not contain a NAL unit");
        return false;
    }

    if (std::any_of(
          frame.data(), frame.data() + startCode->offset, [](uint8_t byte) { return byte != 0; })) {
        REPORT_MALFORMED("H26X frame does not start with an Annex B start code");
        return false;
    }

    while (startCode) {
        auto nalUnitOffset = startCode->nalUnitOffset;
        auto nextStartCode = FindNextH26XStartCode(frame.data(), frame.size(), nalUnitOffset);
        auto nalUnitSize = (nextStartCode ? nextStartCode->offset : frame.size()) - nalUnitOffset;

        if (nalUnitSize < nalUnitHeaderSize) {
            REPORT_MALFORMED("Malformed H26X frame: NAL unit header is truncated");
            return false;
        }

        auto nalUnit = frame.data() + nalUnitOffset;
        auto prefixSize = unencryptedPrefixSize(nalUnit, nalUnitSize);
        if (!prefixSize) {
            return false;
        }

        // Because WebRTC will convert them all start codes to 4-byte on the receiver side
        // always write a long start code and then the NAL unit
        processor.AddUnencryptedBytes(kH26XNaluLongStartCode, sizeof(kH26XNaluLongStartCode));
        processor.AddUnencryptedBytes(nalUnit, *prefixSize);
        if (*prefixSize < nalUnitSize) {
            processor.AddEncryptedBytes(nalUnit + *prefixSize, nalUnitSize - *prefixSize);
        }

        startCode = nextStartCode;
    }

    return true;
}

bool ProcessFrameOpus(OutboundFrameProcessor& processor, ArrayView<const uint8_t> frame)
{
    processor.AddEncryptedBytes(frame.data(), frame.size());
    return true;
}

bool ProcessFrameVp8(OutboundFrameProcessor& processor, ArrayView<const uint8_t> frame)
{
    constexpr uint8_t kVP8KeyFrameUnencryptedBytes = 10;
    constexpr uint8_t kVP8DeltaFrameUnencryptedBytes = 1;

    // parse the VP8 payload header to determine if it's a key frame
    // https://datatracker.ietf.org/doc/html/rfc7741#section-4.3

    // 0 1 2 3 4 5 6 7
    // +-+-+-+-+-+-+-+-+
    // |Size0|H| VER |P|
    // +-+-+-+-+-+-+-+-+
    // P is an inverse key frame flag

    // if this is a key frame the depacketizer will read 10 bytes into the payload header
    // if this is a delta frame the depacketizer only needs the first byte of the payload
    // header (since that's where the key frame flag is)

    if (frame.size() == 0) {
        REPORT_MALFORMED("VP8 frame is empty");
        return false;
    }

    size_t unencryptedHeaderBytes = 0;
    if ((frame.data()[0] & 0x01) == 0) {
        unencryptedHeaderBytes = kVP8KeyFrameUnencryptedBytes;
    }
    else {
        unencryptedHeaderBytes = kVP8DeltaFrameUnencryptedBytes;
    }

    if (frame.size() < unencryptedHeaderBytes) {
        REPORT_MALFORMED("VP8 frame is too small to contain its payload header");
        return false;
    }

    processor.AddUnencryptedBytes(frame.data(), unencryptedHeaderBytes);
    processor.AddEncryptedBytes(frame.data() + unencryptedHeaderBytes,
                                frame.size() - unencryptedHeaderBytes);
    return true;
}

bool ProcessFrameVp9(OutboundFrameProcessor& processor, ArrayView<const uint8_t> frame)
{
    // payload descriptor is unencrypted in each packet
    // and includes all information the depacketizer needs
    processor.AddEncryptedBytes(frame.data(), frame.size());
    return true;
}

bool ProcessFrameH264(OutboundFrameProcessor& processor, ArrayView<const uint8_t> frame)
{
    // minimize the amount of unencrypted header data for H264 depending on the NAL unit
    // type from WebRTC, see: src/modules/rtp_rtcp/source/rtp_format_h264.cc
    // src/common_video/h264/h264_common.cc
    // src/modules/rtp_rtcp/source/video_rtp_depacketizer_h264.cc

    static constexpr uint8_t kH264NalHeaderTypeMask = 0x1F;
    static constexpr uint8_t kH264NalTypeSlice = 1;
    static constexpr uint8_t kH264NalTypeIdr = 5;
    static constexpr uint8_t kH264NalUnitHeaderSize = 1;

    return ProcessFrameH26X(
      processor,
      frame,
      kH264NalUnitHeaderSize,
      [](const uint8_t* nalUnit, size_t nalUnitSize) -> std::optional<size_t> {
          auto nalType = nalUnit[0] & kH264NalHeaderTypeMask;
          if (nalType != kH264NalTypeSlice && nalType != kH264NalTypeIdr) {
              return nalUnitSize;
          }

          // once we've hit a slice or an IDR
          // we just need to cover getting to the PPS ID
          auto payloadSize = nalUnitSize - kH264NalUnitHeaderSize;
          auto ppsBytes = BytesCoveringH264PPS(nalUnit + kH264NalUnitHeaderSize, payloadSize);
          if (ppsBytes == 0) {
              return std::nullopt;
          }
          if (ppsBytes > payloadSize) {
              REPORT_MALFORMED("Malformed H264 frame: PPS ID overflows NAL unit");
              return std::nullopt;
          }

          return kH264NalUnitHeaderSize + ppsBytes;
      });
}

bool ProcessFrameH265(OutboundFrameProcessor& processor, ArrayView<const uint8_t> frame)
{
    // minimize the amount of unencrypted header data for H265 depending on the NAL unit
    // type from WebRTC, see: src/modules/rtp_rtcp/source/rtp_format_h265.cc
    // src/common_video/h265/h265_common.cc
    // src/modules/rtp_rtcp/source/video_rtp_depacketizer_h265.cc

    static constexpr uint8_t kH265NalHeaderTypeMask = 0x7E;
    static constexpr uint8_t kH265NalTypeVclCutoff = 32;
    static constexpr uint8_t kH265NalUnitHeaderSize = 2;

    return ProcessFrameH26X(
      processor,
      frame,
      kH265NalUnitHeaderSize,
      [](const uint8_t* nalUnit, size_t nalUnitSize) -> std::optional<size_t> {
          uint8_t nalType = (nalUnit[0] & kH265NalHeaderTypeMask) >> 1;
          // only VCL NAL unit payloads are encrypted
          return nalType < kH265NalTypeVclCutoff ? kH265NalUnitHeaderSize : nalUnitSize;
      });
}

bool ProcessFrameAv1(OutboundFrameProcessor& processor, ArrayView<const uint8_t> frame)
{
    constexpr uint8_t kAv1ObuHeaderHasExtensionMask = 0b0'0000'100;
    constexpr uint8_t kAv1ObuHeaderHasSizeMask = 0b0'0000'010;
    constexpr uint8_t kAv1ObuHeaderTypeMask = 0b0'1111'000;
    constexpr uint8_t kObuTypeTemporalDelimiter = 2;
    constexpr uint8_t kObuTypeTileList = 8;
    constexpr uint8_t kObuTypePadding = 15;
    constexpr uint8_t kObuExtensionSizeBytes = 1;

    size_t i = 0;
    while (i < frame.size()) {
        // Read the OBU header.
        size_t obuHeaderIndex = i;
        uint8_t obuHeader = frame.data()[obuHeaderIndex];
        i += sizeof(obuHeader);

        bool obuHasExtension = obuHeader & kAv1ObuHeaderHasExtensionMask;
        bool obuHasSize = obuHeader & kAv1ObuHeaderHasSizeMask;
        int obuType = (obuHeader & kAv1ObuHeaderTypeMask) >> 3;

        if (obuHasExtension) {
            // Skip extension byte
            i += kObuExtensionSizeBytes;
        }

        if (i >= frame.size()) {
            // Malformed frame
            REPORT_MALFORMED("Malformed AV1 frame: header overflows frame");
            return false;
        }

        size_t obuPayloadSize = 0;
        if (obuHasSize) {
            // Read payload size
            const uint8_t* start = frame.data() + i;
            const uint8_t* ptr = start;
            auto payloadSize = ReadLeb128(ptr, frame.end());
            if (!ptr) {
                // Malformed frame
                REPORT_MALFORMED("Malformed AV1 frame: invalid LEB128 size");
                return false;
            }
            i += ptr - start;

            if (payloadSize > frame.size() - i) {
                // Malformed frame
                REPORT_MALFORMED("Malformed AV1 frame: payload overflows frame");
                return false;
            }
            obuPayloadSize = static_cast<size_t>(payloadSize);
        }
        else {
            // If the size is not present, the OBU extends to the end of the frame.
            obuPayloadSize = frame.size() - i;
        }

        const auto obuPayloadIndex = i;

        i += obuPayloadSize;

        // We only copy the OBUs that will not get dropped by the packetizer
        if (obuType != kObuTypeTemporalDelimiter && obuType != kObuTypeTileList &&
            obuType != kObuTypePadding) {
            // if this is the last OBU, we may need to flip the "has size" bit
            // which allows us to append necessary protocol data to the frame
            bool rewrittenWithoutSize = false;

            if (i == frame.size() && obuHasSize) {
                // Flip the "has size" bit
                obuHeader &= ~kAv1ObuHeaderHasSizeMask;
                rewrittenWithoutSize = true;
            }

            // write the OBU header unencrypted
            processor.AddUnencryptedBytes(&obuHeader, sizeof(obuHeader));
            if (obuHasExtension) {
                // write the extension byte unencrypted
                processor.AddUnencryptedBytes(frame.data() + obuHeaderIndex + sizeof(obuHeader),
                                              kObuExtensionSizeBytes);
            }

            // write the OBU payload size unencrypted if it was present and we didn't rewrite
            // without it
            if (obuHasSize && !rewrittenWithoutSize) {
                // The AMD AV1 encoder may pad LEB128 encoded sizes with a zero byte which the
                // webrtc packetizer removes. To prevent the packetizer from changing the frame,
                // we sanitize the size by re-writing it ourselves
                uint8_t leb128Buffer[Leb128MaxSize];
                size_t additionalBytesToWrite = WriteLeb128(obuPayloadSize, leb128Buffer);
                processor.AddUnencryptedBytes(leb128Buffer, additionalBytesToWrite);
            }

            // add the OBU payload, encrypted
            processor.AddEncryptedBytes(frame.data() + obuPayloadIndex, obuPayloadSize);
        }
    }

    return true;
}

bool ValidateEncryptedFrame(OutboundFrameProcessor& processor, ArrayView<uint8_t> frame)
{
    auto codec = processor.GetCodec();
    if (codec != Codec::H264 && codec != Codec::H265) {
        return true;
    }

    static_assert(kH26XNaluShortStartSequenceSize - 1 >= 0, "Padding will overflow!");
    constexpr size_t Padding = kH26XNaluShortStartSequenceSize - 1;

    const auto& unencryptedRanges = processor.GetUnencryptedRanges();

    // H264 and H265 ciphertexts cannot contain a 3 or 4 byte start code {0, 0, 1}
    // otherwise the packetizer gets confused
    // and the frame we get on the decryption side will be shifted and fail to decrypt
    size_t encryptedSectionStart = 0;
    for (auto& range : unencryptedRanges) {
        if (encryptedSectionStart == range.offset) {
            encryptedSectionStart += range.size;
            continue;
        }

        auto start = encryptedSectionStart - std::min(encryptedSectionStart, size_t{Padding});
        auto end = std::min(range.offset + Padding, frame.size());
        if (ContainsH26XStartCode(frame.data() + start, end - start)) {
            return false;
        }

        encryptedSectionStart = range.offset + range.size;
    }

    if (encryptedSectionStart == frame.size()) {
        return true;
    }

    auto start = encryptedSectionStart - std::min(encryptedSectionStart, size_t{Padding});
    auto end = frame.size();
    if (ContainsH26XStartCode(frame.data() + start, end - start)) {
        return false;
    }

    return true;
}

} // namespace codec_utils
} // namespace dave
} // namespace discord
