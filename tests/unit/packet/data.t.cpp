#include "ndnph/packet/data.hpp"
#include "ndnph/port/crypto/port.hpp"

#include "../mock-key.hpp"
#include "../test-common.hpp"

namespace ndnph {
namespace {

TEST(Data, EncodeMinimal)
{
  StaticRegion<1024> region;
  Data data = region.create<Data>();
  ASSERT_FALSE(!data);
  EXPECT_THAT(data.getName(), g::SizeIs(0));
  EXPECT_EQ(data.getContentType(), 0x00);
  EXPECT_EQ(data.getFreshnessPeriod(), 0);
  EXPECT_EQ(data.getIsFinalBlock(), false);
  EXPECT_THAT(data.getContent(), g::SizeIs(0));

  std::vector<uint8_t> wire({
    0x06, 0x0C,                   // Data
    0x07, 0x03, 0x08, 0x01, 0x41, // Name
    0x16, 0x03, 0x1B, 0x01, 0x00, // DSigInfo
    0x17, 0x00,                   // DSigValue
  });
  data.setName(Name(&wire[4], 3));

  Encoder encoder(region);
  ASSERT_TRUE(encoder.prepend(data.sign(NullPrivateKey())));
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()), g::ElementsAreArray(wire));
  encoder.discard();

  Data decoded = region.create<Data>();
  ASSERT_FALSE(!decoded);
  ASSERT_TRUE(Decoder(wire.data(), wire.size()).decode(decoded));
  EXPECT_TRUE(decoded.getName() == data.getName());
  EXPECT_EQ(decoded.getContentType(), 0x00);
  EXPECT_EQ(decoded.getFreshnessPeriod(), 0);
  EXPECT_EQ(decoded.getIsFinalBlock(), false);
  EXPECT_THAT(decoded.getContent(), g::SizeIs(0));
}

TEST(Data, EncodeFull)
{
  StaticRegion<1024> region;
  Data data = region.create<Data>();
  ASSERT_FALSE(!data);

  std::vector<uint8_t> wire({
    0x06, 0x2C,                                     // Data
    0x07, 0x06, 0x08, 0x01, 0x41, 0x08, 0x01, 0x42, // Name
    0x14, 0x0C,                                     // MetaInfo
    0x18, 0x01, 0x01,                               // MetaInfo.ContentType
    0x19, 0x02, 0x01, 0xF4,                         // MetaInfo.FreshnessPeriod
    0x1A, 0x03, 0x08, 0x01, 0x42,                   // MetaInfo.FinalBlockId
    0x15, 0x02, 0xC0, 0xC1,                         // Content
    0x16, 0x0A,                                     // DSigInfo
    0x1B, 0x01, 0x10,                               // DSigInfo.SigType
    0x1C, 0x05, 0x07, 0x03, 0x08, 0x01, 0x4B,       // DSigInfo.KeyLocator
    0x17, 0x04, 0xF0, 0xF1, 0xF2, 0xF3              // DSigValue
  });
  data.setName(Name(&wire[4], 6));
  data.setContentType(0x01);
  data.setFreshnessPeriod(500);
  data.setIsFinalBlock(true);
  data.setContent(tlv::Value(&wire[26], 2));

  Encoder encoder(region);
  {
    MockPrivateKey<32> key;
    EXPECT_CALL(key, updateSigInfo).WillOnce([&wire](SigInfo& sigInfo) {
      sigInfo.sigType = 0x10;
      sigInfo.name = Name(&wire[37], 3);
    });
    EXPECT_CALL(key, doSign(g::ElementsAreArray(&wire[2], &wire[40]), g::_))
      .WillOnce(g::DoAll(g::SetArrayArgument<1>(&wire[42], &wire[46]), g::Return(4)));
    ASSERT_TRUE(encoder.prepend(data.sign(key)));
  }
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()), g::ElementsAreArray(wire));
  encoder.discard();

  Data decoded = region.create<Data>();
  ASSERT_FALSE(!decoded);
  ASSERT_TRUE(Decoder(wire.data(), wire.size()).decode(decoded));
  EXPECT_TRUE(decoded.getName() == data.getName());
  EXPECT_EQ(decoded.getContentType(), 0x01);
  EXPECT_EQ(decoded.getFreshnessPeriod(), 500);
  EXPECT_EQ(decoded.getIsFinalBlock(), true);
  EXPECT_THAT(decoded.getContent(), g::SizeIs(2));

  {
    MockPublicKey key;
    EXPECT_CALL(key, doVerify(g::ElementsAreArray(&wire[2], &wire[40]),
                              g::ElementsAreArray(&wire[42], &wire[46])))
      .WillOnce(g::Return(true));
    EXPECT_TRUE(decoded.verify(key));
  }

  {
    MockPublicKey key;
    EXPECT_CALL(key, doVerify(g::_, g::_)).WillOnce(g::Return(false));
    EXPECT_FALSE(decoded.verify(key));
  }
}

} // namespace
} // namespace ndnph
