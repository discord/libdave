#include <gtest/gtest.h>

#include <array>

#include <bytes/bytes.h>

#include "common.h"
#include "mls/util.h"

#include "dave_test.h"

namespace discord {
namespace dave {
namespace test {

TEST_F(DaveTests, ExpandTruncatedNonceIsLittleEndian)
{
    auto expected = std::array<uint8_t, kAesGcm128NonceBytes>{
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01};
    EXPECT_EQ(ExpandTruncatedNonce(0x01020304), expected);
}

TEST_F(DaveTests, LittleEndianBytesFrom)
{
    auto expected = ::mlspp::bytes_ns::bytes({0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01});
    EXPECT_EQ(mls::LittleEndianBytesFrom(0x0102030405060708), expected);
}

TEST_F(DaveTests, BigEndianBytesRoundTrip)
{
    auto expected = ::mlspp::bytes_ns::bytes({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
    EXPECT_EQ(mls::BigEndianBytesFrom(0x0102030405060708), expected);
    EXPECT_EQ(mls::FromBigEndianBytes(expected), 0x0102030405060708u);
}

TEST_F(DaveTests, MarkerBytes)
{
    auto expected = std::array<uint8_t, sizeof(MagicMarker)>{0xFA, 0xFA};
    EXPECT_EQ(kMarkerBytes, expected);
}

} // namespace test
} // namespace dave
} // namespace discord
