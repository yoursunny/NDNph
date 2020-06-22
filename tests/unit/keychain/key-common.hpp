#ifndef NDNPH_TEST_KEYCHAIN_KEY_COMMON_HPP
#define NDNPH_TEST_KEYCHAIN_KEY_COMMON_HPP

#include "ndnph/packet/data.hpp"
#include "ndnph/packet/interest.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

template<typename Pkt>
static Pkt
makePacket(Region& region, const Name& name);

template<>
Interest
makePacket<Interest>(Region& region, const Name& name)
{
  Interest interest = region.create<Interest>();
  interest.setName(name);
  interest.setNonce(0x7A156BB2);
  return interest;
}

template<>
Data
makePacket<Data>(Region& region, const Name& name)
{
  Data data = region.create<Data>();
  data.setName(name);
  return data;
}

template<typename Pkt>
static void
testSignVerify(const PrivateKey& pvtA, const PublicKey& pubA, const PrivateKey& pvtB,
               const PublicKey& pubB, bool deterministic = false, bool sameAB = false)
{
  StaticRegion<1024> region;
  Name nameA(region, { 0x08, 0x01, 0x41 });
  Name nameB(region, { 0x08, 0x01, 0x42 });

  Pkt pktA = makePacket<Pkt>(region, nameA);
  Encoder encoderA(region);
  ASSERT_TRUE(encoderA.prepend(pktA.sign(pvtA)));
  encoderA.trim();

  {
    Pkt pktAr = makePacket<Pkt>(region, nameA);
    Encoder encoderAr(region);
    ASSERT_TRUE(encoderAr.prepend(pktAr.sign(pvtA)));
    if (deterministic) {
      EXPECT_THAT(std::vector<uint8_t>(encoderAr.begin(), encoderAr.end()),
                  g::ElementsAreArray(encoderA.begin(), encoderA.end()));
    } else {
      EXPECT_THAT(std::vector<uint8_t>(encoderAr.begin(), encoderAr.end()),
                  g::Not(g::ElementsAreArray(encoderA.begin(), encoderA.end())));
    }
    encoderAr.discard();
  }

  using SigInfoT = typename std::remove_cv<
    typename std::remove_pointer<decltype(std::declval<Pkt>().getSigInfo())>::type>::type;
  SigInfoT sigInfoB;
  std::vector<uint8_t> sigInfoExtB({ 0x20, 0x00 });
  sigInfoB.extensions = tlv::Value(sigInfoExtB.data(), sigInfoExtB.size());

  Pkt pktB = makePacket<Pkt>(region, nameB);
  Encoder encoderB(region);
  ASSERT_TRUE(encoderB.prepend(pktB.sign(pvtB, sigInfoB)));
  encoderB.trim();

  {
    Pkt pktAd = region.create<Pkt>();
    ASSERT_FALSE(!pktAd);
    ASSERT_TRUE(Decoder(encoderA.begin(), encoderA.size()).decode(pktAd));

    EXPECT_TRUE(pktAd.verify(pubA));
    EXPECT_EQ(pktAd.verify(pubB), sameAB);
  }

  {
    Pkt pktBd = region.create<Pkt>();
    ASSERT_FALSE(!pktBd);
    ASSERT_TRUE(Decoder(encoderB.begin(), encoderB.size()).decode(pktBd));

    EXPECT_TRUE(pktBd.verify(pubB));

    const SigInfoT* sigInfoBd = pktBd.getSigInfo();
    ASSERT_THAT(sigInfoBd, g::NotNull());
    EXPECT_THAT(std::vector<uint8_t>(sigInfoBd->extensions.begin(), sigInfoBd->extensions.end()),
                g::ElementsAreArray(sigInfoExtB));

    EXPECT_TRUE(pubB.matchSigInfo(*sigInfoBd));
    EXPECT_EQ(pubA.matchSigInfo(*sigInfoBd), sameAB);
  }
}

} // namespace
} // namespace ndnph

#endif // NDNPH_TEST_KEYCHAIN_KEY_COMMON_HPP
