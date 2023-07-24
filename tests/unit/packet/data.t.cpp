#include "ndnph/packet/data.hpp"
#include "ndnph/keychain/null.hpp"
#include "ndnph/packet/lp.hpp"

#include "mock/mock-key.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Data, EncodeMinimal) {
  StaticRegion<1024> region;
  Data data = region.create<Data>();
  ASSERT_FALSE(!data);
  EXPECT_THAT(data.getName(), g::SizeIs(0));
  EXPECT_EQ(data.getContentType(), 0x00);
  EXPECT_EQ(data.getFreshnessPeriod(), 0);
  EXPECT_EQ(data.getIsFinalBlock(), false);
  EXPECT_THAT(data.getContent(), g::SizeIs(0));

  auto wire = test::fromHex("060C name=0703080141 siginfo=16031B01C8 sigvalue=1700");
  data.setName(Name(&wire[4], 3));
  {
    ScopedEncoder encoder(region);
    ASSERT_TRUE(encoder.prepend(data.sign(NullKey::get())));
    EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()), g::ElementsAreArray(wire));
  }

  Data decoded = region.create<Data>();
  ASSERT_FALSE(!decoded);
  ASSERT_TRUE(Decoder(wire.data(), wire.size()).decode(decoded));
  EXPECT_EQ(decoded.getName(), data.getName());
  EXPECT_EQ(decoded.getContentType(), 0x00);
  EXPECT_EQ(decoded.getFreshnessPeriod(), 0);
  EXPECT_EQ(decoded.getIsFinalBlock(), false);
  EXPECT_THAT(decoded.getContent(), g::SizeIs(0));
}

TEST(Data, EncodeFull) {
  StaticRegion<1024> region;
  Data data = region.create<Data>();
  ASSERT_FALSE(!data);

  auto wire =
    test::fromHex("lppacket=6436 pittoken=6204B0B1B2B3 lppayload=502E data=062C"
                  "name=0706080141080142 metainfo=140C contenttype=180101 freshness=190201F4 "
                  "finalblock=1A03080142"
                  "content=1502C0C1"
                  "siginfo=160A sigtype=1B0110 keylocator=1C05070308014B sigvalue=1704F0F1F2F3");
  data.setName(Name::parse(region, "/A/B"));
  data.setContentType(0x01);
  data.setFreshnessPeriod(500);
  data.setIsFinalBlock(true);
  data.setContent(tlv::Value(&wire[36], 2));
  auto keyLocatorName = Name::parse(region, "/K");
  {
    ScopedEncoder encoder(region);
    {
      g::InSequence seq;
      MockPrivateKey<32> key;
      EXPECT_CALL(key, updateSigInfo).WillOnce([keyLocatorName](SigInfo& sigInfo) {
        sigInfo.sigType = 0x10;
        sigInfo.name = keyLocatorName;
      });
      EXPECT_CALL(key, doSign(g::ElementsAreArray(&wire[12], &wire[50]), g::_))
        .WillOnce(g::DoAll(g::SetArrayArgument<1>(&wire[52], &wire[56]), g::Return(4)));
      ASSERT_TRUE(encoder.prepend(lp::encode(data.sign(key), lp::PitToken::from4(0xB0B1B2B3))));
    }
    EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()), g::ElementsAreArray(wire));
  }

  lp::PacketClassify classify;
  ASSERT_TRUE(Decoder(wire.data(), wire.size()).decode(classify));
  ASSERT_EQ(classify.getType(), lp::PacketClassify::Type::Data);
  EXPECT_EQ(classify.getPitToken().to4(), 0xB0B1B2B3);
  Data decoded = region.create<Data>();
  ASSERT_FALSE(!decoded);
  ASSERT_TRUE(classify.decodeData(decoded));
  EXPECT_EQ(decoded.getName(), data.getName());
  EXPECT_EQ(decoded.getContentType(), 0x01);
  EXPECT_EQ(decoded.getFreshnessPeriod(), 500);
  EXPECT_EQ(decoded.getIsFinalBlock(), true);
  EXPECT_THAT(decoded.getContent(), g::SizeIs(2));
  EXPECT_EQ(test::toString(decoded), "/8=A/8=B");

  {
    MockPublicKey key;
    EXPECT_CALL(key, doVerify(g::ElementsAreArray(&wire[12], &wire[50]),
                              g::ElementsAreArray(&wire[52], &wire[56])))
      .WillOnce(g::Return(true));
    EXPECT_TRUE(decoded.verify(key));
  }

  {
    MockPublicKey key;
    EXPECT_CALL(key, doVerify(g::_, g::_)).WillOnce(g::Return(false));
    EXPECT_FALSE(decoded.verify(key));
  }
}

TEST(Data, CanSatisfySimple) {
  StaticRegion<1024> region;

  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name::parse(region, "/A"));

  Data data = region.create<Data>();
  ASSERT_FALSE(!data);
  data.setName(Name::parse(region, "/A"));
  EXPECT_TRUE(data.canSatisfy(interest));

  data.setName(Name::parse(region, "/A/B"));
  EXPECT_FALSE(data.canSatisfy(interest));

  interest.setCanBePrefix(true);
  EXPECT_TRUE(data.canSatisfy(interest));

  data.setFreshnessPeriod(0);
  interest.setMustBeFresh(true);
  EXPECT_TRUE(data.canSatisfy(interest));
  EXPECT_FALSE(data.canSatisfy(interest, Data::CanSatisfyInCache));

  data.setFreshnessPeriod(1000);
  EXPECT_TRUE(data.canSatisfy(interest));
  EXPECT_TRUE(data.canSatisfy(interest, Data::CanSatisfyInCache));

  interest.setName(Name::parse(region, "/C"));
  EXPECT_FALSE(data.canSatisfy(interest));
}

TEST(Data, CanSatisfyImplicitDigest) {
  StaticRegion<1024> region;

  Data data = region.create<Data>();
  ASSERT_FALSE(!data);
  data.setName(Name::parse(region, "/A"));
  {
    g::NiceMock<MockPrivateKey<0>> key;
    auto data2 = region.create<Data>();
    ASSERT_TRUE(data2.decodeFrom(data.sign(key)));
    data = data2;
  }

  uint8_t digest[NDNPH_SHA256_LEN]{};
  EXPECT_TRUE(data.computeImplicitDigest(digest));
  EXPECT_LT(std::count(digest, digest + NDNPH_SHA256_LEN, 0), NDNPH_SHA256_LEN);

  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(data.getName().append(region, convention::ImplicitDigest(), digest));
  EXPECT_TRUE(data.canSatisfy(interest));

  interest.setName(
    Name::parse(region, "/A/B").append(region, convention::ImplicitDigest(), digest));
  EXPECT_FALSE(data.canSatisfy(interest));
}

} // namespace
} // namespace ndnph
