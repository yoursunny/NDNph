#include "ndnph/keychain/ecdsa-key.hpp"

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

} // namespace
} // namespace ndnph
