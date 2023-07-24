#include "ndnph/packet/nack.hpp"
#include "ndnph/packet/lp.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

class NackP : public g::TestWithParam<std::tuple<int, NackReason>> {};

INSTANTIATE_TEST_SUITE_P(Nack, NackP,
                         g::Values(std::make_tuple(50, NackReason::Congestion),
                                   std::make_tuple(100, NackReason::Duplicate),
                                   std::make_tuple(150, NackReason::NoRoute),
                                   std::make_tuple(-1, NackReason::Unspecified),
                                   std::make_tuple(0, NackReason::Unspecified),
                                   std::make_tuple(255, NackReason::Unspecified)));

static std::vector<uint8_t>
makeNackWire(int reasonV) {
  std::vector<uint8_t> wire({
    0x64, 0x13,                         // LpPacket
    0xFD, 0x03, 0x20, 0x00,             // Nack
    0x50, 0x0D,                         // LpPayload
    0x05, 0x0B,                         // Interest
    0x07, 0x03, 0x08, 0x01, 0x41,       // Name
    0x0A, 0x04, 0xA0, 0xA1, 0xA2, 0xA3, // Nonce
  });
  if (reasonV >= 0) {
    wire[1] = 0x18;
    wire[5] = 0x05;
    wire.insert(wire.begin() + 6, {0xFD, 0x03, 0x21, 0x01, static_cast<uint8_t>(reasonV)});
  }
  return wire;
}

TEST_P(NackP, LpDecode) {
  int reasonV = 0;
  NackReason reason{};
  std::tie(reasonV, reason) = GetParam();
  auto wire = makeNackWire(reasonV);

  lp::PacketClassify classify;
  ASSERT_TRUE(Decoder(wire.data(), wire.size()).decode(classify));
  ASSERT_EQ(classify.getType(), lp::PacketClassify::Type::Nack);

  StaticRegion<1024> region;
  Nack nack = region.create<Nack>();
  ASSERT_FALSE(!nack);
  ASSERT_TRUE(classify.decodeNack(nack));

  EXPECT_EQ(nack.getHeader().getReason(), reason);
  EXPECT_EQ(nack.getInterest().getNonce(), 0xA0A1A2A3);
}

TEST_P(NackP, LpEncode) {
  int reasonV = 0;
  NackReason reason{};
  std::tie(reasonV, reason) = GetParam();
  if (reason == NackReason::Unspecified && reasonV >= 0) {
    return; // skip decode-only test case
  }

  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name::parse(region, "/A"));
  interest.setNonce(0xA0A1A2A3);
  Nack nack = Nack::create(interest, reason);
  ASSERT_FALSE(!nack);

  Encoder encoder(region);
  encoder.prepend(lp::encode(nack));
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()),
              g::ElementsAreArray(makeNackWire(reasonV)));
}

} // namespace
} // namespace ndnph
