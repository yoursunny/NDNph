#include "ndnph/port/null/typedef.hpp"

#include "../mock-key.hpp"
#include "../test-common.hpp"

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
    T::NiceMock<MockPrivateKey<32>> key;
    ON_CALL(key, doSign).WillByDefault(T::Return(true));
    EXPECT_FALSE(encoder.prepend(interest.sign(key)));
    encoder.discard();
  }
}

} // namespace
} // namespace ndnph
