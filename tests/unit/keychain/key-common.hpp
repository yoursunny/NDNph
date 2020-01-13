#ifndef NDNPH_TEST_KEY_COMMON_TEST_HPP
#define NDNPH_TEST_KEY_COMMON_TEST_HPP

#include "../test-common.hpp"

namespace ndnph {
namespace {

template<typename Pkt, typename PvtKey, typename PubKey>
void
testSignVerify(const PvtKey& pvtA, const PubKey& pubA, const PvtKey& pvtB, const PubKey& pubB,
               bool deterministic = false, bool sameAB = false)
{
  StaticRegion<1024> region;
  Name nameA(region, { 0x08, 0x01, 0x41 });
  Name nameB(region, { 0x08, 0x01, 0x42 });

  Pkt pktA = region.create<Pkt>();
  ASSERT_FALSE(!pktA);
  pktA.setName(nameA);
  Encoder encoderA(region);
  ASSERT_TRUE(encoderA.prepend(pktA.sign(pvtA)));
  encoderA.trim();

  {
    Pkt pktAr = region.create<Pkt>();
    ASSERT_FALSE(!pktAr);
    pktAr.setName(nameA);
    Encoder encoderAr(region);
    ASSERT_TRUE(encoderAr.prepend(pktAr.sign(pvtA)));
    if (deterministic) {
      EXPECT_THAT(std::vector<uint8_t>(encoderAr.begin(), encoderAr.end()),
                  T::ElementsAreArray(encoderA.begin(), encoderA.end()));
    } else {
      EXPECT_THAT(std::vector<uint8_t>(encoderAr.begin(), encoderAr.end()),
                  T::Not(T::ElementsAreArray(encoderA.begin(), encoderA.end())));
    }
    encoderAr.discard();
  }

  using SigInfoT = typename std::remove_cv<
    typename std::remove_pointer<decltype(std::declval<Pkt>().getSigInfo())>::type>::type;
  SigInfoT sigInfoB;
  std::vector<uint8_t> sigInfoExtB({ 0x20, 0x00 });
  sigInfoB.extensions = tlv::Value(sigInfoExtB.data(), sigInfoExtB.size());

  Pkt pktB = region.create<Pkt>();
  ASSERT_FALSE(!pktB);
  pktB.setName(nameB);
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
    ASSERT_THAT(sigInfoBd, T::NotNull());
    EXPECT_THAT(std::vector<uint8_t>(sigInfoBd->extensions.begin(), sigInfoBd->extensions.end()),
                T::ElementsAreArray(sigInfoExtB));
  }
}

} // namespace
} // namespace ndnph

#endif // NDNPH_TEST_KEY_COMMON_TEST_HPP
