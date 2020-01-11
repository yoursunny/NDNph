#include "ndnph/keychain/ecdsa-key.hpp"
#include "ndnph/packet/data.hpp"
#include "ndnph/packet/interest.hpp"
#include "ndnph/port/mbedtls/typedef.hpp"
#include "ndnph/port/null/random-source.hpp"
#include "ndnph/port/urandom/random-source.hpp"

#include "../test-common.hpp"
#include "key-common.hpp"

namespace ndnph {
namespace {

TEST(EcdsaKey, SignVerify)
{
  std::vector<uint8_t> nameV({ 0x08, 0x02, 0x4B, 0x41, 0x08, 0x02, 0x4B, 0x42 });
  port_urandom::RandomSource rng;
  EcdsaPrivateKey pvtA, pvtB;
  EcdsaPublicKey pubA, pubB;
  ASSERT_TRUE(EcdsaPrivateKey::generate(rng, Name(&nameV[0], 4), pvtA, pubA));
  ASSERT_TRUE(EcdsaPrivateKey::generate(rng, Name(&nameV[4], 4), pvtB, pubB));

  testSignVerify<Interest>(pvtA, pubA, pvtB, pubB, true);
  testSignVerify<Data>(pvtA, pubA, pvtB, pubB, true);
}

TEST(EcdsaKey, NullRandomSource)
{
  std::vector<uint8_t> nameV({ 0x08, 0x02, 0x4B, 0x41 });
  port_null::RandomSource rng;
  EcdsaPrivateKey pvt;
  EcdsaPublicKey pub;
  EXPECT_FALSE(EcdsaPrivateKey::generate(rng, Name(nameV.data(), nameV.size()), pvt, pub));
}

} // namespace
} // namespace ndnph
