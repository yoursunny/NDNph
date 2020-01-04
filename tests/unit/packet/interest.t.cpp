#include "ndnph/packet/interest.hpp"

#include "../test-common.hpp"

namespace ndnph {
namespace {

TEST(Interest, EncodeMinimal)
{
  StaticRegion<256> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  EXPECT_THAT(interest.getName(), T::SizeIs(0));
  EXPECT_FALSE(interest.getCanBePrefix());
  EXPECT_FALSE(interest.getMustBeFresh());
  EXPECT_EQ(interest.getNonce(), 0);

  std::vector<uint8_t> wire({
    0x05, 0x0B,                         // Interest
    0x07, 0x03, 0x08, 0x01, 0x41,       // Name
    0x0A, 0x04, 0xA0, 0xA1, 0xA2, 0xA3, // Nonce
  });
  interest.setName(Name(&wire[4], 3));
  interest.setNonce(0xA0A1A2A3);

  Encoder encoder(region);
  bool ok = encoder.prepend(interest);
  ASSERT_TRUE(ok);
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()),
              T::ElementsAreArray(wire));
  encoder.discard();

  Decoder::Tlv d;
  Decoder::readTlv(d, wire.data(), wire.size());
  Interest decoded = region.create<Interest>();
  ASSERT_TRUE(decoded.decodeFrom(d));
  EXPECT_TRUE(decoded.getName() == interest.getName());
  EXPECT_EQ(decoded.getCanBePrefix(), false);
  EXPECT_EQ(decoded.getMustBeFresh(), false);
  EXPECT_EQ(decoded.getNonce(), 0xA0A1A2A3);
}

TEST(Interest, EncodeFull)
{
  StaticRegion<256> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);

  std::vector<uint8_t> wire({
    0x05, 0x16,                         // Interest
    0x07, 0x03, 0x08, 0x01, 0x41,       // Name
    0x21, 0x00,                         // CanBePrefix
    0x12, 0x00,                         // MustBeFresh
    0x0A, 0x04, 0xA0, 0xA1, 0xA2, 0xA3, // Nonce
    0x0C, 0x02, 0x20, 0x06,             // InterestLifetime
    0x22, 0x01, 0x05,                   // HopLimit
  });
  interest.setName(Name(&wire[4], 3));
  interest.setCanBePrefix(true);
  interest.setMustBeFresh(true);
  interest.setNonce(0xA0A1A2A3);
  interest.setLifetime(8198);
  interest.setHopLimit(5);

  Encoder encoder(region);
  bool ok = encoder.prepend(interest);
  ASSERT_TRUE(ok);
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()),
              T::ElementsAreArray(wire));
  encoder.discard();

  Decoder::Tlv d;
  Decoder::readTlv(d, wire.data(), wire.size());
  Interest decoded = region.create<Interest>();
  ASSERT_TRUE(decoded.decodeFrom(d));
  EXPECT_TRUE(decoded.getName() == interest.getName());
  EXPECT_EQ(decoded.getCanBePrefix(), true);
  EXPECT_EQ(decoded.getMustBeFresh(), true);
  EXPECT_EQ(decoded.getNonce(), 0xA0A1A2A3);
  EXPECT_EQ(decoded.getLifetime(), 8198);
  EXPECT_EQ(decoded.getHopLimit(), 5);
}

} // namespace
} // namespace ndnph
