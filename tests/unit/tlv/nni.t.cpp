#include "ndnph/tlv/nni.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(NNI, Decode)
{
  auto wire = test::fromHex("C000"
                            "C101A0"
                            "C202A0A1"
                            "C303A0A1A2"
                            "C404A0A1A2A3"
                            "C505A0A1A2A3A4"
                            "C606A0A1A2A3A4A5"
                            "C707A0A1A2A3A4A5A6"
                            "C808A0A1A2A3A4A5A6A7"
                            "C909A0A1A2A3A4A5A6A7A8");
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
    EXPECT_FALSE(tlv::NNI8::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI8::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI8::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI8::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI8::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI8::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI8::decode(*it++, n));
    EXPECT_FALSE(tlv::NNI8::decode(*it++, n));
    EXPECT_TRUE(tlv::NNI8::decode(*it++, n));
    EXPECT_EQ(n, 0xA0A1A2A3A4A5A6A7);
    EXPECT_FALSE(tlv::NNI8::decode(*it++, n));
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
    EXPECT_FALSE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2)); // valid NNI but exceed max
    EXPECT_FALSE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2));
    EXPECT_FALSE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2));
    EXPECT_FALSE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2));
    EXPECT_FALSE(tlv::NNI::decode(*it++, n, 0xA0A1A2A2)); // valid NNI but exceed max
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
  encoder.prependTlv(0x80, tlv::NNI8(0x00));
  encoder.prependTlv(0x81, tlv::NNI8(0x0000A0A1A2A3A4A5));
  encoder.prependTlv(0xC0, tlv::NNI(0x00));
  encoder.prependTlv(0xC1, tlv::NNI(0x0100));
  encoder.prependTlv(0xC2, tlv::NNI(0xA0A1A2A3));
  encoder.prependTlv(0xC3, tlv::NNI(0x00B0B1B2B3B4B5B6));

  ASSERT_FALSE(!encoder);
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()),
              g::ElementsAreArray(test::fromHex("C30800B0B1B2B3B4B5B6"
                                                "C204A0A1A2A3"
                                                "C1020100"
                                                "C00100"
                                                "81080000A0A1A2A3A4A5"
                                                "80080000000000000000"
                                                "4204A0A1A2A3"
                                                "410400000100"
                                                "400400000000"
                                                "1101A0"
                                                "100100")));

  encoder.trim();
  encoder.prepend(tlv::NNI1(0x00), tlv::NNI4(0x00), tlv::NNI8(0x00), tlv::NNI(0x00),
                  tlv::NNI(0x0100), tlv::NNI(0x00010000), tlv::NNI(0x0000000100000000));
  EXPECT_TRUE(!encoder);
}

} // namespace
} // namespace ndnph
