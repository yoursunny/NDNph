#include "ndnph/tlv/nni.hpp"

#include "../test-common.hpp"

namespace ndnph {
namespace {

TEST(NNI, Decode)
{
  std::vector<uint8_t> wire({
    0xC0, 0x00,                                                       // C0
    0xC1, 0x01, 0xA0,                                                 // C1
    0xC2, 0x02, 0xA0, 0xA1,                                           // C2
    0xC3, 0x03, 0xA0, 0xA1, 0xA2,                                     // C3
    0xC4, 0x04, 0xA0, 0xA1, 0xA2, 0xA3,                               // C4
    0xC5, 0x05, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4,                         // C5
    0xC6, 0x06, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,                   // C6
    0xC7, 0x07, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,             // C7
    0xC8, 0x08, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,       // C8
    0xC9, 0x09, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, // C9
  });
  Decoder decoder(wire.data(), wire.size());

  {
    auto it = decoder.begin(), end = decoder.end();
    uint8_t n = 0;
    EXPECT_FALSE(tlv::NNI1::decode(*it++, n));
    EXPECT_TRUE(tlv::NNI1::decode(*it++, n));
    EXPECT_EQ(n, 0xA0);
    EXPECT_FALSE(tlv::NNI1::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI1::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI1::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI1::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI1::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI1::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI1::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI1::decode(*it++, n));
    EXPECT_TRUE(it == end);
    EXPECT_FALSE(it.hasError());
  }

  {
    auto it = decoder.begin(), end = decoder.end();
    uint32_t n = 0;
    EXPECT_FALSE(tlv::NNI4::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI4::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI4::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI4::decode(*it++, n));
    EXPECT_TRUE(tlv::NNI4::decode(*it++, n));
    EXPECT_EQ(n, 0xA0A1A2A3);
    EXPECT_FALSE(tlv::NNI4::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI4::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI4::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI4::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI4::decode(*it++, n));
    EXPECT_TRUE(it == end);
    EXPECT_FALSE(it.hasError());
  }

  {
    auto it = decoder.begin(), end = decoder.end();
    uint64_t n = 0;
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_TRUE(tlv::NNI::decode(*it++, n));
    EXPECT_EQ(n, 0xA0);
    EXPECT_TRUE(tlv::NNI::decode(*it++, n));
    EXPECT_EQ(n, 0xA0A1);
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_TRUE(tlv::NNI::decode(*it++, n));
    EXPECT_EQ(n, 0xA0A1A2A3);
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_TRUE(tlv::NNI::decode(*it++, n));
    EXPECT_EQ(n, 0xA0A1A2A3A4A5A6A7);
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_TRUE(it == end);
    EXPECT_FALSE(it.hasError());
  }

  {
    auto it = decoder.begin(), end = decoder.end();
    uint32_t n = 0;
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_TRUE(tlv::NNI::decode(*it++, n));
    EXPECT_EQ(n, 0xA0);
    EXPECT_TRUE(tlv::NNI::decode(*it++, n));
    EXPECT_EQ(n, 0xA0A1);
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_TRUE(tlv::NNI::decode(*it++, n));
    EXPECT_EQ(n, 0xA0A1A2A3);
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI::decode(*it++, n)); // exceed limit of uint32_t
    EXPECT_FALSE(tlv::NNI::decode(*it++, n));
    EXPECT_TRUE(it == end);
    EXPECT_FALSE(it.hasError());
  }

  {
    auto it = decoder.begin(), end = decoder.end();
    uint32_t n = 0;
    EXPECT_FALSE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2));
    EXPECT_TRUE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2));
    EXPECT_EQ(n, 0xA0);
    EXPECT_TRUE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2));
    EXPECT_EQ(n, 0xA0A1);
    EXPECT_FALSE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2));
    EXPECT_FALSE(
      tlv::NNI::decode(*it++, n, 0xA0A1A2A2)); // valid NNI but exceed max
    EXPECT_FALSE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2));
    EXPECT_FALSE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2));
    EXPECT_FALSE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2));
    EXPECT_FALSE(
      tlv::NNI::decode(*it++, n, 0xA0A1A2A2)); // valid NNI but exceed max
    EXPECT_FALSE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2));
    EXPECT_TRUE(it == end);
  }
}

TEST(NNI, Encode)
{
  StaticRegion<100> region;
  Encoder encoder(region);
  encoder.prependTlv(0x10, tlv::NNI1(0x00));
  encoder.prependTlv(0x11, tlv::NNI1(0xA0));
  encoder.prependTlv(0x40, tlv::NNI4(0x00));
  encoder.prependTlv(0x41, tlv::NNI4(0x0100));
  encoder.prependTlv(0x42, tlv::NNI4(0xA0A1A2A3));
  encoder.prependTlv(0xC0, tlv::NNI(0x00));
  encoder.prependTlv(0xC1, tlv::NNI(0x0100));
  encoder.prependTlv(0xC2, tlv::NNI(0xA0A1A2A3));
  encoder.prependTlv(0xC3, tlv::NNI(0xB0B1B2B3B4B5B6B7));

  ASSERT_FALSE(!encoder);
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()),
              T::ElementsAre(0xC3, 0x08, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
                             0xB6, 0xB7,                         // C3
                             0xC2, 0x04, 0xA0, 0xA1, 0xA2, 0xA3, // C2
                             0xC1, 0x02, 0x01, 0x00,             // C1
                             0xC0, 0x01, 0x00,                   // C0
                             0x42, 0x04, 0xA0, 0xA1, 0xA2, 0xA3, // 42
                             0x41, 0x04, 0x00, 0x00, 0x01, 0x00, // 41
                             0x40, 0x04, 0x00, 0x00, 0x00, 0x00, // 40
                             0x11, 0x01, 0xA0,                   // 11
                             0x10, 0x01, 0x00                    // 10
                             ));

  encoder.trim();
  encoder.prepend(tlv::NNI1(0x00), tlv::NNI4(0x00), tlv::NNI(0x00),
                  tlv::NNI(0x0100), tlv::NNI(0x00010000),
                  tlv::NNI(0x0000000100000000));
  EXPECT_TRUE(!encoder);
}

} // namespace
} // namespace ndnph
