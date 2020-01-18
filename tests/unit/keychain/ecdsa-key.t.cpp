#include "ndnph/keychain/ecdsa-key.hpp"
#include "ndnph/port/crypto/port.hpp"
#include "ndnph/port/random/null.hpp"
#include "ndnph/port/random/port.hpp"

#include "../test-common.hpp"
#include "key-common.hpp"

namespace ndnph {
namespace {

TEST(EcdsaKey, SignVerify)
{
  StaticRegion<1024> region;
  Name nameKA(region, { 0x08, 0x02, 0x4B, 0x41 });
  Name nameKB(region, { 0x08, 0x02, 0x4B, 0x42 });
  RandomSource rng;
  EcdsaPrivateKey pvtA, pvtB;
  EcdsaPublicKey pubA, pubB;
  ASSERT_TRUE(EcdsaPrivateKey::generate(rng, nameKA, pvtA, pubA));
  ASSERT_TRUE(EcdsaPrivateKey::generate(rng, nameKB, pvtB, pubB));

  testSignVerify<Interest>(pvtA, pubA, pvtB, pubB, true);
  testSignVerify<Data>(pvtA, pubA, pvtB, pubB, true);
}

TEST(EcdsaKey, NullRandomSource)
{
  StaticRegion<1024> region;
  Name nameKA(region, { 0x08, 0x02, 0x4B, 0x41 });
  port_random_null::RandomSource rng;
  EcdsaPrivateKey pvt;
  EcdsaPublicKey pub;
  EXPECT_FALSE(EcdsaPrivateKey::generate(rng, nameKA, pvt, pub));
}

} // namespace
} // namespace ndnph
