#include "ndnph/packet/interest.hpp"
#include "ndnph/packet/lp.hpp"

#include "mock/mock-key.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Interest, EncodeMinimal)
{
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  EXPECT_THAT(interest.getName(), g::SizeIs(0));
  EXPECT_FALSE(interest.getCanBePrefix());
  EXPECT_FALSE(interest.getMustBeFresh());
  EXPECT_FALSE(!!interest.getFwHint());
  {
    std::set<uint32_t> nonces({ interest.getNonce() });
    DynamicRegion region2(4096);
    for (int i = 0; i < 4; ++i) {
      Interest interest2 = region.create<Interest>();
      ASSERT_FALSE(!interest2);
      nonces.insert(interest2.getNonce());
    }
    EXPECT_THAT(nonces, g::SizeIs(g::Ge(3)));
  }

  std::vector<uint8_t> wire({
    0x05, 0x0B,                         // Interest
    0x07, 0x03, 0x08, 0x01, 0x41,       // Name
    0x0A, 0x04, 0xA0, 0xA1, 0xA2, 0xA3, // Nonce
  });
  interest.setName(Name(&wire[4], 3));
  interest.setNonce(0xA0A1A2A3);
  EXPECT_EQ(test::toString(interest), "/8=A");
  {
    ScopedEncoder encoder(region);
    bool ok = encoder.prepend(interest);
    ASSERT_TRUE(ok);
    EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()), g::ElementsAreArray(wire));
  }

  Interest decoded = region.create<Interest>();
  ASSERT_FALSE(!decoded);
  ASSERT_TRUE(Decoder(wire.data(), wire.size()).decode(decoded));
  EXPECT_EQ(decoded.getName(), interest.getName());
  EXPECT_EQ(decoded.getCanBePrefix(), false);
  EXPECT_EQ(decoded.getMustBeFresh(), false);
  EXPECT_EQ(decoded.getFwHint(), interest.getFwHint());
  EXPECT_EQ(decoded.getNonce(), 0xA0A1A2A3);
}

TEST(Interest, EncodeFull)
{
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);

  std::vector<uint8_t> wire({
    0x64, 0x2D,                               // LpPacket
    0x62, 0x04, 0xB0, 0xB1, 0xB2, 0xB3,       // PitToken
    0x50, 0x25,                               // LpPayload
    0x05, 0x23,                               // Interest
    0x07, 0x03, 0x08, 0x01, 0x41,             // Name
    0x21, 0x00,                               // CanBePrefix
    0x12, 0x00,                               // MustBeFresh
    0x1E, 0x0B, 0x1F, 0x09, 0x1E, 0x01, 0x00, // ForwardingHint
    0x07, 0x04, 0x08, 0x02, 0x66, 0x68,       // ForwardingHint
    0x0A, 0x04, 0xA0, 0xA1, 0xA2, 0xA3,       // Nonce
    0x0C, 0x02, 0x20, 0x06,                   // InterestLifetime
    0x22, 0x01, 0x05,                         // HopLimit
  });
  interest.setName(Name::parse(region, "/A"));
  interest.setCanBePrefix(true);
  interest.setMustBeFresh(true);
  interest.setFwHint(Name::parse(region, "/fh"));
  interest.setNonce(0xA0A1A2A3);
  interest.setLifetime(8198);
  interest.setHopLimit(5);
  EXPECT_EQ(test::toString(interest), "/8=A[P][F]");
  {
    ScopedEncoder encoder(region);
    bool ok = encoder.prepend(lp::encode(interest, lp::PitToken::from4(0xB0B1B2B3)));
    ASSERT_TRUE(ok);
    EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()), g::ElementsAreArray(wire));
  }

  lp::PacketClassify classify;
  ASSERT_TRUE(Decoder(wire.data(), wire.size()).decode(classify));
  ASSERT_EQ(classify.getType(), lp::PacketClassify::Type::Interest);
  EXPECT_EQ(classify.getPitToken().to4(), 0xB0B1B2B3);

  Interest decoded = region.create<Interest>();
  ASSERT_FALSE(!decoded);
  ASSERT_TRUE(classify.decodeInterest(decoded));
  EXPECT_EQ(decoded.getName(), interest.getName());
  EXPECT_EQ(decoded.getCanBePrefix(), true);
  EXPECT_EQ(decoded.getMustBeFresh(), true);
  EXPECT_EQ(decoded.getFwHint(), interest.getFwHint());
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
  interest.setName(Name::parse(region, "/101=A/2=N/103=C"));
  tlv::Value appParams(appParamsV.data(), appParamsV.size());

  Interest decoded = region.create<Interest>();
  ASSERT_TRUE(decoded.decodeFrom(interest.parameterize(appParams)));

  auto name = decoded.getName();
  EXPECT_THAT(name, g::SizeIs(3));
  EXPECT_EQ(name[0].type(), 101);
  EXPECT_EQ(name[2].type(), 103);
  EXPECT_TRUE(name[1].is<convention::ParamsDigest>());

  EXPECT_TRUE(decoded.checkDigest());
  EXPECT_THAT(decoded.getAppParameters(), g::SizeIs(2));
}

TEST(Interest, EncodeParameterizedAppend)
{
  std::vector<uint8_t> appParamsV({ 0xC0, 0xC1 });
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name::parse(region, "/101=A/102=B"));
  tlv::Value appParams(appParamsV.data(), appParamsV.size());

  Interest decoded = region.create<Interest>();
  ASSERT_TRUE(decoded.decodeFrom(lp::encode(interest.parameterize(appParams))));

  auto name = decoded.getName();
  EXPECT_THAT(name, g::SizeIs(3));
  EXPECT_EQ(name[0].type(), 101);
  EXPECT_EQ(name[1].type(), 102);
  EXPECT_TRUE(name[2].is<convention::ParamsDigest>());

  EXPECT_TRUE(decoded.checkDigest());
  EXPECT_THAT(decoded.getAppParameters(), g::SizeIs(2));
}

TEST(Interest, EncodeSignedBadPlaceholder)
{
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name::parse(region, "/101=A/2=N/103=C"));

  Encoder encoder(region);
  {
    MockPrivateKey<32> key;
    EXPECT_CALL(key, updateSigInfo).Times(1);
    EXPECT_CALL(key, doSign).Times(0);
    EXPECT_FALSE(encoder.prepend(interest.sign(key)));
  }
}

TEST(Interest, EncodeSignedReplace)
{
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name::parse(region, "/101=A/102=B/2=N"));

  Interest decoded = region.create<Interest>();
  std::vector<uint8_t> signedPortion(
    { 0x65, 0x01, 0x41, 0x66, 0x01, 0x42, 0x24, 0x00, 0x2C, 0x03, 0x1B, 0x01, 0x10 });
  std::vector<uint8_t> sig({ 0xF0, 0xF1, 0xF2, 0xF3 });
  {
    g::InSequence seq;
    MockPrivateKey<32> key;
    EXPECT_CALL(key, updateSigInfo).WillOnce([](SigInfo& sigInfo) { sigInfo.sigType = 0x10; });
    EXPECT_CALL(key, doSign(g::ElementsAreArray(signedPortion), g::_))
      .WillOnce(g::DoAll(g::SetArrayArgument<1>(sig.begin(), sig.end()), g::Return(4)));

    ASSERT_TRUE(decoded.decodeFrom(lp::encode(interest.sign(key))));
  }

  auto name = decoded.getName();
  EXPECT_THAT(name, g::SizeIs(3));
  EXPECT_EQ(name[0].type(), 101);
  EXPECT_EQ(name[1].type(), 102);
  EXPECT_TRUE(name[2].is<convention::ParamsDigest>());

  EXPECT_TRUE(decoded.checkDigest());
  EXPECT_THAT(decoded.getAppParameters(), g::SizeIs(0));

  {
    MockPublicKey key;
    EXPECT_CALL(key, doVerify(g::ElementsAreArray(signedPortion), g::ElementsAreArray(sig)))
      .WillOnce(g::Return(true));
    EXPECT_TRUE(decoded.verify(key));
  }

  {
    MockPublicKey key;
    EXPECT_CALL(key, doVerify(g::_, g::_)).WillOnce(g::Return(false));
    EXPECT_FALSE(decoded.verify(key));
  }
}

TEST(Interest, MatchSimple)
{
  StaticRegion<1024> region;

  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name::parse(region, "/A"));

  Data data = region.create<Data>();
  ASSERT_FALSE(!data);
  data.setName(Name::parse(region, "/A"));
  EXPECT_TRUE(interest.match(data));

  data.setName(Name::parse(region, "/A/B"));
  EXPECT_FALSE(interest.match(data));

  interest.setCanBePrefix(true);
  EXPECT_TRUE(interest.match(data));

  data.setFreshnessPeriod(0);
  interest.setMustBeFresh(true);
  EXPECT_FALSE(interest.match(data));

  data.setFreshnessPeriod(1000);
  EXPECT_TRUE(interest.match(data));

  interest.setName(Name::parse(region, "/C"));
  EXPECT_FALSE(interest.match(data));
}

TEST(Interest, MatchImplicitDigest)
{
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

  uint8_t digest[NDNPH_SHA256_LEN] = { 0 };
  EXPECT_TRUE(data.computeImplicitDigest(digest));
  EXPECT_LT(std::count(digest, digest + NDNPH_SHA256_LEN, 0), NDNPH_SHA256_LEN);

  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(data.getName().append<convention::ImplicitDigest>(region, digest));
  EXPECT_TRUE(interest.match(data));

  interest.setName(Name::parse(region, "/A/B").append<convention::ImplicitDigest>(region, digest));
  EXPECT_FALSE(interest.match(data));
}

template<typename MakePolicy>
void
testSigPolicy(MakePolicy makePolicy, bool canDetectReorder = true,
              bool canDetectDuplicateLater = true)
{
  DynamicRegion region(4096);
  auto policyS = makePolicy();
  auto policyV = makePolicy();
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);

  Interest interest0 = region.create<Interest>();
  Interest interest1 = region.create<Interest>();
  Interest interest2 = region.create<Interest>();
  {
    g::NiceMock<MockPrivateKey<32>> key;
    ASSERT_TRUE(interest0.decodeFrom(lp::encode(interest.sign(key, region, policyS))));
    ASSERT_TRUE(interest1.decodeFrom(lp::encode(interest.sign(key, region, policyS))));
    ASSERT_TRUE(interest2.decodeFrom(lp::encode(interest.sign(key, region, policyS))));
  }

  const ISigInfo* si0 = interest0.getSigInfo();
  ASSERT_THAT(si0, g::NotNull());
  const ISigInfo* si1 = interest1.getSigInfo();
  ASSERT_THAT(si1, g::NotNull());
  const ISigInfo* si2 = interest2.getSigInfo();
  ASSERT_THAT(si2, g::NotNull());

  EXPECT_TRUE(policyV.check(*si0));
  EXPECT_FALSE(policyV.check(*si0));
  EXPECT_TRUE(policyV.check(*si2));
  EXPECT_EQ(policyV.check(*si1), !canDetectReorder);
  EXPECT_EQ(policyV.check(*si0), !canDetectDuplicateLater);
}

TEST(InterestSigPolicy, Nonce)
{
  testSigPolicy([] { return isig::makePolicy(isig::Nonce<>()); }, false);
}

TEST(InterestSigPolicy, Nonce1)
{
  testSigPolicy([] { return isig::makePolicy(isig::Nonce<1, 1>()); }, false, false);
}

TEST(InterestSigPolicy, Time)
{
  testSigPolicy([] { return isig::makePolicy(isig::Time<>()); });
}

TEST(InterestSigPolicy, SeqNum)
{
  testSigPolicy([] { return isig::makePolicy(isig::SeqNum()); });
}

TEST(InterestSigPolicy, All)
{
  testSigPolicy([] { return isig::makePolicy(isig::Nonce<>(), isig::Time<>(), isig::SeqNum()); });
}

} // namespace
} // namespace ndnph
