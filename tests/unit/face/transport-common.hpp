#ifndef NDNPH_TEST_FACE_TRANSPORT_COMMON_HPP
#define NDNPH_TEST_FACE_TRANSPORT_COMMON_HPP

#include "ndnph/face/face.hpp"

#include "test-common.hpp"
#include <set>

namespace ndnph {
namespace {

class TransportTest {
public:
  class TxHandler : public PacketHandler {
  public:
    TxHandler(Face& face)
      : PacketHandler(face) {}

    void sendOne(uint32_t i) {
      StaticRegion<1024> region;
      Interest interest = region.create<Interest>();
      ASSERT_FALSE(!interest);
      interest.setName(Name(region, {0x08, 0x01, 0x41}));
      interest.setNonce(i);

      bool ok = send(interest);
      if (ok) {
        ++nSendSuccess;
      } else {
        ++nSendFailure;
      }
    }

  public:
    size_t nSendSuccess = 0;
    size_t nSendFailure = 0;
  };

  class RxHandler : public PacketHandler {
  public:
    RxHandler(Face& face)
      : PacketHandler(face) {}

  private:
    bool processInterest(Interest interest) final {
      EXPECT_EQ(received.count(interest.getNonce()), 0);
      received.insert(interest.getNonce());
      return true;
    }

  public:
    std::set<uint32_t> received;
  };

  TransportTest(Face& faceA, Face& faceB, size_t nPkts = 64)
    : faceA(faceA)
    , faceB(faceB)
    , txA(faceA)
    , rxB(faceB)
    , nPkts(nPkts) {}

  TransportTest& run(uint32_t opDelayMillis = 1, uint32_t endDelayMillis = 100) {
    std::chrono::milliseconds opDelay(opDelayMillis);
    std::chrono::milliseconds endDelay(endDelayMillis);
    std::atomic_bool continueB(true);

    std::thread threadA([=] {
      for (size_t i = 0; i < nPkts; ++i) {
        faceA.loop();
        txA.sendOne(i);
        std::this_thread::sleep_for(opDelay);
      }
      faceA.loop();
    });

    std::thread threadB([=, &continueB] {
      while (continueB) {
        faceB.loop();
        std::this_thread::sleep_for(opDelay);
      }
    });

    threadA.join();
    std::this_thread::sleep_for(endDelay);
    continueB = false;
    threadB.join();
    return *this;
  }

  void check(double threshold = 0.9) {
    EXPECT_GT(txA.nSendSuccess, nPkts * threshold);
    EXPECT_EQ(txA.nSendSuccess + txA.nSendFailure, nPkts);
    EXPECT_LE(rxB.received.size(), txA.nSendSuccess);
    EXPECT_GT(rxB.received.size(), nPkts * threshold);
  }

public:
  Face& faceA;
  Face& faceB;
  TxHandler txA;
  RxHandler rxB;
  const size_t nPkts;
};

} // namespace
} // namespace ndnph

#endif // NDNPH_TEST_FACE_TRANSPORT_COMMON_HPP
