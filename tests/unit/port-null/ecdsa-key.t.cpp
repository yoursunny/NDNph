#define NDNPH_PORT_CRYPTO_NULL
#include "ndnph/port/crypto/null/typedef.hpp"
#include "ndnph/port/random/port.hpp"

#include "../mock-key.hpp"
#include "../test-common.hpp"

namespace ndnph {
namespace {

TEST(PortNull, EcdsaKey)
{
  StaticRegion<1024> region;
  RandomSource rng;
  EcdsaPrivateKey pvt;
  EcdsaPublicKey pub;
  EXPECT_FALSE(EcdsaPrivateKey::generate(rng, Name(region, { 0x08, 0x01, 0x4B }), pvt, pub));

  Data data = region.create<Data>();
  ASSERT_FALSE(!data);
  data.setName(Name(region, { 0x08, 0x01, 0x41 }));
  Encoder encoder(region);
  EXPECT_FALSE(encoder.prepend(data.sign(pvt)));
  EXPECT_FALSE(data.verify(pub));
}

} // namespace
} // namespace ndnph
