#define NDNPH_PORT_CRYPTO_NULL
#include "ndnph/port/crypto/null/typedef.hpp"

#include "mock/mock-key.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(PortNull, Interest)
{
  StaticRegion<1024> region;
  std::vector<uint8_t> appParamsV({ 0xC0, 0xC1 });
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name(region, { 0x08, 0x01, 0x41 }));
  tlv::Value appParams(appParamsV.data(), appParamsV.size());

  {
    Encoder encoder(region);
    EXPECT_FALSE(encoder.prepend(interest.parameterize(appParams)));
    encoder.discard();
  }

  {
    Encoder encoder(region);
    g::NiceMock<MockPrivateKey<32>> key;
    ON_CALL(key, doSign).WillByDefault(g::Return(true));
    EXPECT_FALSE(encoder.prepend(interest.sign(key)));
    encoder.discard();
  }
}

TEST(PortNull, Data)
{
  StaticRegion<1024> region;
  Data data = region.create<Data>();
  ASSERT_FALSE(!data);
  data.setName(Name(region, { 0x08, 0x01, 0x41 }));

  data.setName(Name::parse(region, "/A"));
  {
    Encoder encoder(region);
    g::NiceMock<MockPrivateKey<0>> key;
    ASSERT_TRUE(encoder.prepend(data.sign(key)));
    encoder.trim();

    data = region.create<Data>();
    ASSERT_FALSE(!data);
    ASSERT_TRUE(Decoder(encoder.begin(), encoder.size()).decode(data));
  }

  uint8_t digest[NDNPH_SHA256_LEN] = { 0 };
  EXPECT_FALSE(data.computeImplicitDigest(digest));
}

} // namespace
} // namespace ndnph
