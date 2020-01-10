#include "ndnph/port/null/typedef.hpp"

#include "../mock-key.hpp"
#include "../test-common.hpp"

namespace ndnph {
namespace {

TEST(PortNull, Interest)
{
  std::vector<uint8_t> nameV({ 0x08, 0x01, 0x41 });
  std::vector<uint8_t> appParamsV({ 0xC0, 0xC1 });
  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name(nameV.data(), nameV.size()));
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
