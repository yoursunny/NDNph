#ifndef NDNPH_TEST_MOCK_TRANSPORT_HPP
#define NDNPH_TEST_MOCK_TRANSPORT_HPP

#include "ndnph/face/transport.hpp"
#include "ndnph/tlv/encoder.hpp"

#include "test-common.hpp"

namespace ndnph {

class MockTransport : public Transport {
public:
  MOCK_METHOD(bool, doIsUp, (), (const, override));

  MOCK_METHOD(void, doLoop, (), (override));

  MOCK_METHOD(bool, doSend, (std::vector<uint8_t>, uint64_t), ());

  bool doSend(const uint8_t* pkt, size_t pktLen, uint64_t endpointId) override {
    return doSend(std::vector<uint8_t>(pkt, pkt + pktLen), endpointId);
  }

  bool receive(const std::vector<uint8_t>& wire, uint64_t endpointId = 0) {
    invokeRxCallback(wire.data(), wire.size(), endpointId);
    return true;
  }

  template<typename Packet>
  bool receive(Packet packet, uint64_t endpointId = 0) {
    StaticRegion<2048> region;
    Encoder encoder(region);
    if (!encoder.prepend(packet)) {
      return false;
    }
    encoder.trim();
    invokeRxCallback(encoder.begin(), encoder.size(), endpointId);
    return true;
  }
};

} // namespace ndnph

#endif // NDNPH_TEST_MOCK_TRANSPORT_HPP
