#ifndef NDNPH_TEST_MOCK_PACKET_HANDLER_HPP
#define NDNPH_TEST_MOCK_PACKET_HANDLER_HPP

#include "ndnph/face/packet-handler.hpp"
#include "ndnph/port/crypto/port.hpp"

#include "test-common.hpp"

namespace ndnph {

class MockPacketHandler : public PacketHandler
{
public:
  using PacketHandler::getCurrentPacketInfo;
  using PacketHandler::PacketHandler;

  MOCK_METHOD(bool, processInterest, (Interest), (override));
  MOCK_METHOD(bool, processData, (Data), (override));
  MOCK_METHOD(bool, processNack, (Nack), (override));
};

} // namespace ndnph

#endif // NDNPH_TEST_MOCK_PACKET_HANDLER_HPP
