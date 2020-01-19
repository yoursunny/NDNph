#ifndef NDNPH_TEST_FACE_TRANSPORT_COMMON_HPP
#define NDNPH_TEST_FACE_TRANSPORT_COMMON_HPP

#include "ndnph/face/face.hpp"
#include "ndnph/port/crypto/port.hpp"

#include "../test-common.hpp"
#include <atomic>
#include <chrono>
#include <thread>

namespace ndnph {
namespace {

class TransportTest
{
public:
  TransportTest(Face& faceA, Face& faceB, size_t nPkts = 64)
    : faceA(faceA)
    , faceB(faceB)
    , nPkts(nPkts)
  {
    faceA.setTxCallback(txA, this);
    faceB.setRxCallback(rxSuccessB, rxFailureB, this);
  }

  TransportTest& run(uint32_t opDelayMillis = 1, uint32_t endDelayMillis = 100)
  {
    std::chrono::milliseconds opDelay(opDelayMillis);
    std::chrono::milliseconds endDelay(endDelayMillis);
    std::atomic_bool continueB(true);

    std::thread threadA([=] {
      for (size_t i = 0; i < nPkts; ++i) {
        StaticRegion<1024> region;
        Interest interest = region.create<Interest>();
        ASSERT_FALSE(!interest);
        interest.setName(Name(region, { 0x08, 0x01, 0x41 }));
        interest.setNonce(static_cast<uint32_t>(i));

        size_t nSent = sendSuccess.size() + sendFailure.size();
        faceA.asyncSend(reinterpret_cast<void*>(i), interest);
        EXPECT_EQ(sendSuccess.size() + sendFailure.size(), nSent + 1);

        std::this_thread::sleep_for(opDelay);
      }
    });

    std::thread threadB([=, &continueB] {
      while (continueB) {
        RxRegionT region;
        faceB.asyncReceive(&region, region);

        std::this_thread::sleep_for(opDelay);
      }
    });

    threadA.join();
    std::this_thread::sleep_for(endDelay);
    continueB = false;
    threadB.join();
    return *this;
  }

  void check(double threshold = 0.9)
  {
    EXPECT_GT(sendSuccess.size(), nPkts * threshold);
    EXPECT_LT(sendFailure.size(), nPkts * (1.0 - threshold));
    EXPECT_GT(received.size(), nPkts * threshold);
  }

private:
  static void txA(void* self0, void* pctx0, bool ok)
  {
    TransportTest& self = *reinterpret_cast<TransportTest*>(self0);
    uint32_t i = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pctx0));
    (ok ? self.sendSuccess : self.sendFailure).push_back(i);
  }

  using RxRegionT = StaticRegion<1024>;

  static void rxSuccessB(void* self0, void* pctx0, Decoder& decoder, uint64_t)
  {
    TransportTest& self = *reinterpret_cast<TransportTest*>(self0);
    RxRegionT& region = *reinterpret_cast<RxRegionT*>(pctx0);

    Interest interest = region.create<Interest>();
    ASSERT_FALSE(!interest);
    EXPECT_TRUE(decoder.decode(interest));
    self.received.push_back(interest.getNonce());
  }

  static void rxFailureB(void*, void*) {}

public:
  Face& faceA;
  Face& faceB;
  const size_t nPkts;

  std::vector<uint32_t> sendSuccess;
  std::vector<uint32_t> sendFailure;
  std::vector<uint32_t> received;
};

} // namespace
} // namespace ndnph

#endif // NDNPH_TEST_FACE_TRANSPORT_COMMON_HPP
