#include "ndnph/keychain/ecdsa-certificate.hpp"
#include "ndnph/keychain/ecdsa-private-key.hpp"
#include "ndnph/keychain/ecdsa-public-key.hpp"

#include "key-common.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(EcdsaKey, SignVerify)
{
  DynamicRegion region(4096);
  Name nameKA(region, { 0x08, 0x02, 0x4B, 0x41 });
  EcdsaPrivateKey pvtA;
  EcdsaPublicKey pubA;
  ASSERT_TRUE(EcdsaPrivateKey::generate(nameKA, pvtA, pubA));

  uint8_t pvtRawB[EcdsaPrivateKey::KeyLen::value];
  uint8_t pubRawB[EcdsaPublicKey::KeyLen::value];
  ASSERT_TRUE(EcdsaPrivateKey::generateRaw(pvtRawB, pubRawB));

  Name subjectNameB(region, { 0x08, 0x02, 0x4B, 0x42 });
  Name keyNameB = Certificate::toKeyName(region, subjectNameB);
  ASSERT_FALSE(!keyNameB);

  EcdsaPrivateKey pvtB;
  ASSERT_TRUE(EcdsaPrivateKey::import(pvtB, keyNameB, pvtRawB));
  EcdsaPublicKey pubB;
  {
    ValidityPeriod validityB;
    auto certB = EcdsaCertificate::build(region, keyNameB, pubRawB, validityB, pvtB);
    ASSERT_FALSE(!certB);

    Encoder encoder(region);
    encoder.prepend(certB);
    encoder.trim();

    Data dataB = region.create<Data>();
    ASSERT_TRUE(Decoder(encoder.begin(), encoder.size()).decode(dataB));
    encoder.discard();

    ASSERT_TRUE(EcdsaCertificate::isCertificate(dataB));
    ASSERT_TRUE(EcdsaCertificate::loadKey(region, dataB, pubB));
  }

  testSignVerify<Interest>(pvtA, pubA, pvtB, pubB, true);
  testSignVerify<Data>(pvtA, pubA, pvtB, pubB, true);
}

TEST(EcdsaKey, BadPrivate)
{
  StaticRegion<1024> region;
  Name name(region, { 0x08, 0x02, 0x4B, 0x41 });
  std::vector<uint8_t> fakeKey(EcdsaPrivateKey::KeyLen::value);
  std::vector<uint8_t> sig(EcdsaPrivateKey::MaxSigLen::value);

  EcdsaPrivateKey key;
  EXPECT_FALSE(EcdsaPrivateKey::import(key, name, fakeKey.data()));
  EXPECT_EQ(key.sign({}, sig.data()), -1);
}

TEST(EcdsaKey, BadPublic)
{
  StaticRegion<1024> region;
  Name name(region, { 0x08, 0x02, 0x4B, 0x41 });
  std::vector<uint8_t> fakeKey(EcdsaPublicKey::KeyLen::value);
  std::vector<uint8_t> sig(2);

  EcdsaPublicKey key;
  EXPECT_FALSE(EcdsaPublicKey::import(key, name, fakeKey.data()));
  EXPECT_FALSE(key.verify({}, sig.data(), sig.size()));
}

} // namespace
} // namespace ndnph
