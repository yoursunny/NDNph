#include "ndnph/keychain/ec.hpp"

#include "key-common.hpp"
#include "mock/tempdir-fixture.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

using EcKeyFixture = TempDirFixture;

TEST_F(EcKeyFixture, SignVerify)
{
  DynamicRegion regionA0(4096);
  Name nameKA = Name::parse(regionA0, "/KA");
  EcPrivateKey pvtA;
  EcPublicKey pubA0;
  ASSERT_TRUE(ec::generate(regionA0, nameKA, pvtA, pubA0));
  EXPECT_EQ(pvtA.getName(), pubA0.getName());
  EXPECT_TRUE(certificate::isKeyName(pubA0.getName()));

  DynamicRegion regionA1(4096);
  EcPublicKey pubA1;
  {
    auto certA = pubA0.selfSign(regionA1, ValidityPeriod::getMax(), pvtA);
    ASSERT_FALSE(!certA);

    Data dataA = regionA1.create<Data>();
    ASSERT_TRUE(dataA.decodeFrom(certA));

    EXPECT_TRUE(ec::isCertificate(dataA));
    ASSERT_TRUE(pubA1.import(regionA1, dataA));
  }
  EXPECT_EQ(pubA1.getName(), pubA0.getName());
  testSignVerify<Data>(pvtA, pubA0, pvtA, pubA1, true, true);

  KeyChain keyChain;
  ASSERT_TRUE(keyChain.open(tempDir.data()));

  DynamicRegion regionB0(4096);
  Name nameKB = certificate::toKeyName(regionB0, Name::parse(regionB0, "/KB"));
  EcPrivateKey pvtB0;
  EcPublicKey pubB0;
  ASSERT_TRUE(ec::generate(regionB0, nameKB, pvtB0, pubB0, keyChain, "b"));
  EXPECT_EQ(pvtB0.getName(), nameKB);
  EXPECT_EQ(pubB0.getName(), nameKB);

  DynamicRegion regionB1(4096);
  EcPrivateKey pvtB1;
  EcPublicKey pubB1;
  ASSERT_TRUE(ec::load(keyChain, "b", regionB1, pvtB1, pubB1));
  EXPECT_EQ(pvtB1.getName(), nameKB);
  EXPECT_EQ(pubB1.getName(), nameKB);
  testSignVerify<Data>(pvtB0, pubB0, pvtB1, pubB1, true, true);

  testSignVerify<Interest>(pvtA, pubA1, pvtB1, pubB1, true);
  testSignVerify<Data>(pvtA, pubA1, pvtB1, pubB1, true);
}

TEST(EcKey, BadPrivate)
{
  StaticRegion<1024> region;
  Name name = certificate::toKeyName(region, Name::parse(region, "/KA"));
  std::vector<uint8_t> fakeKey(EcPrivateKey::KeyLen::value);
  std::vector<uint8_t> sig(EcPrivateKey::MaxSigLen::value);

  EcPrivateKey key;
  EXPECT_FALSE(key.import(name, fakeKey.data()));
  EXPECT_EQ(key.sign({}, sig.data()), -1);
}

TEST(EcKey, BadPublic)
{
  StaticRegion<1024> region;
  Name name = certificate::toKeyName(region, Name::parse(region, "/KA"));
  std::vector<uint8_t> fakeKey(EcPublicKey::KeyLen::value);
  std::vector<uint8_t> sig(2);

  EcPublicKey key;
  EXPECT_FALSE(key.import(name, fakeKey.data()));
  EXPECT_FALSE(key.verify({}, sig.data(), sig.size()));
}

} // namespace
} // namespace ndnph
