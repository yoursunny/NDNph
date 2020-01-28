#include "ndnph/keychain/ecdsa-private-key.hpp"
#include "ndnph/keychain/ecdsa-public-key.hpp"

#include "key-common.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(EcdsaKey, SignVerify)
{
  StaticRegion<1024> region;
  Name nameKA(region, { 0x08, 0x02, 0x4B, 0x41 });
  Name nameKB(region, { 0x08, 0x02, 0x4B, 0x42 });
  EcdsaPrivateKey pvtA, pvtB;
  EcdsaPublicKey pubA, pubB;
  ASSERT_TRUE(EcdsaPrivateKey::generate(nameKA, pvtA, pubA));
  ASSERT_TRUE(EcdsaPrivateKey::generate(nameKB, pvtB, pubB));

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
