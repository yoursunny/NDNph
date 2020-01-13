#include "ndnph/packet/interest.hpp"
#include "ndnph/port/mbedtls/typedef.hpp"

#include "../mock-key.hpp"
#include "../test-common.hpp"

namespace ndnph {
namespace {

TEST(Interest, EncodeMinimal)
{
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  EXPECT_THAT(interest.getName(), T::SizeIs(0));
  EXPECT_FALSE(interest.getCanBePrefix());
  EXPECT_FALSE(interest.getMustBeFresh());
  EXPECT_EQ(interest.getNonce(), 0);

  std::vector<uint8_t> wire({
    0x05,
    0x0B, // Interest
    0x07, 0x03, 0x08, 0x01,
    0x41, // Name
    0x0A, 0x04, 0xA0, 0xA1, 0xA2,
    0xA3, // Nonce
  });
  interest.setName(Name(&wire[4], 3));
  interest.setNonce(0xA0A1A2A3);

  Encoder encoder(region);
  bool ok = encoder.prepend(interest);
  ASSERT_TRUE(ok);
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()), T::ElementsAreArray(wire));
  encoder.discard();

  Interest decoded = region.create<Interest>();
  ASSERT_FALSE(!decoded);
  ASSERT_TRUE(Decoder(wire.data(), wire.size()).decode(decoded));
  EXPECT_TRUE(decoded.getName() == interest.getName());
  EXPECT_EQ(decoded.getCanBePrefix(), false);
  EXPECT_EQ(decoded.getMustBeFresh(), false);
  EXPECT_EQ(decoded.getNonce(), 0xA0A1A2A3);
}

TEST(Interest, EncodeFull)
{
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);

  std::vector<uint8_t> wire({
    0x05,
    0x16, // Interest
    0x07, 0x03, 0x08, 0x01,
    0x41, // Name
    0x21,
    0x00, // CanBePrefix
    0x12,
    0x00, // MustBeFresh
    0x0A, 0x04, 0xA0, 0xA1, 0xA2,
    0xA3, // Nonce
    0x0C, 0x02, 0x20,
    0x06, // InterestLifetime
    0x22, 0x01,
    0x05, // HopLimit
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
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()), T::ElementsAreArray(wire));
  encoder.discard();

  Interest decoded = region.create<Interest>();
  ASSERT_FALSE(!decoded);
  ASSERT_TRUE(Decoder(wire.data(), wire.size()).decode(decoded));
  EXPECT_TRUE(decoded.getName() == interest.getName());
  EXPECT_EQ(decoded.getCanBePrefix(), true);
  EXPECT_EQ(decoded.getMustBeFresh(), true);
  EXPECT_EQ(decoded.getNonce(), 0xA0A1A2A3);
  EXPECT_EQ(decoded.getLifetime(), 8198);
  EXPECT_EQ(decoded.getHopLimit(), 5);
}

TEST(Interest, EncodeParameterizedReplace)
{
  std::vector<uint8_t> appParamsV({ 0xC0, 0xC1 });
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name(region, { 0xB1, 0x01, 0x41, 0x02, 0x02, 0xA0, 0xA1, 0xB3, 0x01, 0x43 }));
  tlv::Value appParams(appParamsV.data(), appParamsV.size());

  Encoder encoder(region);
  ASSERT_TRUE(encoder.prepend(interest.parameterize(appParams)));
  encoder.trim();

  Interest decoded = region.create<Interest>();
  ASSERT_FALSE(!decoded);
  ASSERT_TRUE(Decoder(encoder.begin(), encoder.size()).decode(decoded));

  auto name = decoded.getName();
  EXPECT_THAT(name, T::SizeIs(3));
  EXPECT_EQ(name[0].type(), 0xB1);
  EXPECT_EQ(name[2].type(), 0xB3);
  EXPECT_EQ(name[1].type(), TT::ParametersSha256DigestComponent);
  EXPECT_EQ(name[1].length(), NDNPH_SHA256_LEN);

  EXPECT_TRUE(decoded.checkDigest());
  EXPECT_THAT(decoded.getAppParameters(), T::SizeIs(2));
}

TEST(Interest, EncodeParameterizedAppend)
{
  std::vector<uint8_t> appParamsV({ 0xC0, 0xC1 });
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name(region, { 0xB1, 0x01, 0x41, 0xB3, 0x01, 0x43 }));
  tlv::Value appParams(appParamsV.data(), appParamsV.size());

  Encoder encoder(region);
  ASSERT_TRUE(encoder.prepend(interest.parameterize(appParams)));
  encoder.trim();

  Interest decoded = region.create<Interest>();
  ASSERT_FALSE(!decoded);
  ASSERT_TRUE(Decoder(encoder.begin(), encoder.size()).decode(decoded));

  auto name = decoded.getName();
  EXPECT_THAT(name, T::SizeIs(3));
  EXPECT_EQ(name[0].type(), 0xB1);
  EXPECT_EQ(name[1].type(), 0xB3);
  EXPECT_EQ(name[2].type(), TT::ParametersSha256DigestComponent);
  EXPECT_EQ(name[2].length(), NDNPH_SHA256_LEN);

  EXPECT_TRUE(decoded.checkDigest());
  EXPECT_THAT(decoded.getAppParameters(), T::SizeIs(2));
}

TEST(Interest, EncodeSignedBadPlaceholder)
{
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name(region, { 0xB1, 0x01, 0x41, 0x02, 0x02, 0xA0, 0xA1, 0xB3, 0x01, 0x43 }));

  Encoder encoder(region);
  {
    MockPrivateKey<32> key;
    EXPECT_CALL(key, updateSigInfo).Times(0);
    EXPECT_CALL(key, doSign).Times(0);
    EXPECT_FALSE(encoder.prepend(interest.sign(key)));
  }
}

TEST(Interest, EncodeSignedReplace)
{
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name(region, { 0xB1, 0x01, 0x41, 0xB3, 0x01, 0x43, 0x02, 0x02, 0xA0, 0xA1 }));

  std::vector<uint8_t> signedPortion(
    { 0xB1, 0x01, 0x41, 0xB3, 0x01, 0x43, 0x24, 0x00, 0x2C, 0x03, 0x1B, 0x01, 0x10 });
  std::vector<uint8_t> sig({ 0xF0, 0xF1, 0xF2, 0xF3 });
  Encoder encoder(region);
  {
    MockPrivateKey<32> key;
    EXPECT_CALL(key, updateSigInfo).WillOnce([](SigInfo& sigInfo) { sigInfo.sigType = 0x10; });
    EXPECT_CALL(key, doSign(T::ElementsAreArray(signedPortion), T::_))
      .WillOnce(T::DoAll(T::SetArrayArgument<1>(sig.begin(), sig.end()), T::Return(4)));
    EXPECT_TRUE(encoder.prepend(interest.sign(key)));
  }
  encoder.trim();

  Interest decoded = region.create<Interest>();
  ASSERT_FALSE(!decoded);
  ASSERT_TRUE(Decoder(encoder.begin(), encoder.size()).decode(decoded));

  auto name = decoded.getName();
  EXPECT_THAT(name, T::SizeIs(3));
  EXPECT_EQ(name[0].type(), 0xB1);
  EXPECT_EQ(name[1].type(), 0xB3);
  EXPECT_EQ(name[2].type(), TT::ParametersSha256DigestComponent);
  EXPECT_EQ(name[2].length(), NDNPH_SHA256_LEN);

  EXPECT_TRUE(decoded.checkDigest());
  EXPECT_THAT(decoded.getAppParameters(), T::SizeIs(0));

  {
    MockPublicKey key;
    EXPECT_CALL(key, doVerify(T::ElementsAreArray(signedPortion), T::ElementsAreArray(sig)))
      .WillOnce(T::Return(true));
    EXPECT_TRUE(decoded.verify(key));
  }

  {
    MockPublicKey key;
    EXPECT_CALL(key, doVerify(T::_, T::_)).WillOnce(T::Return(false));
    EXPECT_FALSE(decoded.verify(key));
  }
}

} // namespace
} // namespace ndnph
