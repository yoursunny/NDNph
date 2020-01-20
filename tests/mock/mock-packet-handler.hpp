#ifndef NDNPH_TEST_MOCK_PACKET_HANDLER_HPP
#define NDNPH_TEST_MOCK_PACKET_HANDLER_HPP

#include "ndnph/face/packet-handler.hpp"
#include "ndnph/port/crypto/port.hpp"

#include "test-common.hpp"

namespace ndnph {

class MockPacketHandler : public PacketHandler
{
public:
  MockPacketHandler(Face& face, int8_t prio)
    : PacketHandler(face, prio)
  {}

  MOCK_METHOD(bool, processInterest, (Interest, uint64_t), (override));

  MOCK_METHOD(bool, processData, (Data, uint64_t), (override));
};

} // namespace ndnph

#endif // NDNPH_TEST_MOCK_PACKET_HANDLER_HPP
