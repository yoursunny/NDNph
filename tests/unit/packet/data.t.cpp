#include "ndnph/packet/data.hpp"

#include "../test-common.hpp"

namespace ndnph {
namespace {

TEST(Data, EncodeMinimal)
{
  StaticRegion<256> region;
  Data data = region.create<Data>();
  ASSERT_FALSE(!data);
  EXPECT_THAT(data.getName(), T::SizeIs(0));
  EXPECT_EQ(data.getContentType(), 0x00);
  EXPECT_EQ(data.getFreshnessPeriod(), 0);
  EXPECT_EQ(data.getIsFinalBlock(), false);
  EXPECT_THAT(data.getContent(), T::SizeIs(0));

  std::vector<uint8_t> wire({
    0x06, 0x05,                   // Data
    0x07, 0x03, 0x08, 0x01, 0x41, // Name
  });
  data.setName(Name(&wire[4], 3));

  Encoder encoder(region);
  bool ok = encoder.prepend(data);
  ASSERT_TRUE(ok);
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()),
              T::ElementsAreArray(wire));
  encoder.discard();

  Decoder::Tlv d;
  Decoder::readTlv(d, wire.data(), wire.size());
  Data decoded = region.create<Data>();
  ASSERT_TRUE(decoded.decodeFrom(d));
  EXPECT_TRUE(decoded.getName() == data.getName());
  EXPECT_EQ(decoded.getContentType(), 0x00);
  EXPECT_EQ(decoded.getFreshnessPeriod(), 0);
  EXPECT_EQ(decoded.getIsFinalBlock(), false);
  EXPECT_THAT(decoded.getContent(), T::SizeIs(0));
}

TEST(Interest, EncodeFull)
{
  StaticRegion<256> region;
  Data data = region.create<Data>();
  ASSERT_FALSE(!data);

  std::vector<uint8_t> wire({
    0x06, 0x1A,                                     // Data
    0x07, 0x06, 0x08, 0x01, 0x41, 0x08, 0x01, 0x42, // Name
    0x14, 0x0C,                                     // MetaInfo
    0x18, 0x01, 0x01,                               // ContentType
    0x19, 0x02, 0x01, 0xF4,                         // FreshnessPeriod
    0x1A, 0x03, 0x08, 0x01, 0x42,                   // FinalBlockId
    0x15, 0x02, 0xC0, 0xC1,                         // Content
  });
  data.setName(Name(&wire[4], 6));
  data.setContentType(0x01);
  data.setFreshnessPeriod(500);
  data.setIsFinalBlock(true);
  data.setContent(tlv::Value(&wire[26], 2));

  Encoder encoder(region);
  bool ok = encoder.prepend(data);
  ASSERT_TRUE(ok);
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()),
              T::ElementsAreArray(wire));
  encoder.discard();

  Decoder::Tlv d;
  Decoder::readTlv(d, wire.data(), wire.size());
  Data decoded = region.create<Data>();
  ASSERT_TRUE(decoded.decodeFrom(d));
  EXPECT_TRUE(decoded.getName() == data.getName());
  EXPECT_EQ(decoded.getContentType(), 0x01);
  EXPECT_EQ(decoded.getFreshnessPeriod(), 500);
  EXPECT_EQ(decoded.getIsFinalBlock(), true);
  EXPECT_THAT(decoded.getContent(), T::SizeIs(2));
}

} // namespace
} // namespace ndnph
