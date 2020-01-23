#ifndef NDNPH_TEST_MOCK_PACKET_HANDLER_HPP
#define NDNPH_TEST_MOCK_PACKET_HANDLER_HPP

#include "ndnph/face/packet-handler.hpp"
#include "ndnph/port/crypto/port.hpp"

#include "test-common.hpp"

namespace ndnph {

class MockPacketHandler : public PacketHandler
{
public:
  explicit MockPacketHandler(Face& face, int8_t prio = 0)
    : PacketHandler(face, prio)
  {}

  using PacketHandler::getCurrentPacketInfo;
  using PacketHandler::reply;
  using PacketHandler::send;

  MOCK_METHOD(bool, processInterest, (Interest), (override));

  MOCK_METHOD(bool, processData, (Data), (override));

  MOCK_METHOD(bool, processNack, (Nack), (override));
};

} // namespace ndnph

#endif // NDNPH_TEST_MOCK_PACKET_HANDLER_HPP
