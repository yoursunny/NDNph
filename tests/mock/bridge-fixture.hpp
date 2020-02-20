#ifndef NDNPH_TEST_BRIDGE_FIXTURE_HPP
#define NDNPH_TEST_BRIDGE_FIXTURE_HPP

#include "ndnph/face/bridge-transport.hpp"
#include "ndnph/face/face.hpp"

#include "test-common.hpp"

namespace ndnph {

class BridgeFixture : public g::Test
{
public:
  explicit BridgeFixture()
    : faceA(transportA)
    , faceB(transportB)
  {
    transportA.begin(transportB);
  }

  template<typename InitB, typename CondB, typename FinalB = void (*)()>
  void runInThreads(const InitB& initB, const CondB& condB, const FinalB& finalB = [] {})
  {
    std::atomic_bool stopA(false);
    std::thread threadA([&] {
      while (!stopA) {
        faceA.loop();
        port::Clock::sleep(1);
      }
    });

    std::thread threadB([&] {
      initB();
      while (condB()) {
        faceB.loop();
        port::Clock::sleep(1);
      }
      finalB();
    });

    threadB.join();
    stopA = true;
    threadA.join();
  }

protected:
  BridgeTransport transportA;
  BridgeTransport transportB;
  Face faceA;
  Face faceB;
};

} // namespace ndnph

#endif // NDNPH_TEST_BRIDGE_FIXTURE_HPP
