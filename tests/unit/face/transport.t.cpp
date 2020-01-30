#include "ndnph/face/bridge-transport.hpp"
#include "ndnph/face/transport-force-endpointid.hpp"
#include "ndnph/port/transport/port.hpp"

#include "mock/mock-transport.hpp"
#include "transport-common.hpp"

namespace ndnph {
namespace {

TEST(Transport, Bridge)
{
  BridgeTransport transportA;
  BridgeTransport transportB;
  BridgeTransport transportC;
  EXPECT_TRUE(transportA.begin(transportB));
  EXPECT_FALSE(transportA.begin(transportC));
  EXPECT_FALSE(transportC.begin(transportA));

  EXPECT_TRUE(transportA.isUp());
  EXPECT_TRUE(transportB.isUp());
  EXPECT_FALSE(transportC.isUp());

  Face faceA(transportA);
  Face faceB(transportB);
  TransportTest(faceA, faceB).run().check();
  TransportTest(faceB, faceA).run().check();

  EXPECT_TRUE(transportB.end());
  EXPECT_FALSE(transportB.end());
}

TEST(Transport, ForceEndpointId)
{
  MockTransport transportA;
  MockTransport transportB;

  EXPECT_CALL(transportA, doIsUp).Times(g::AtLeast(1)).WillRepeatedly(g::Return(true));
  EXPECT_CALL(transportA, doLoop).Times(g::AtLeast(1));
  EXPECT_CALL(transportA, doSend)
    .Times(g::AtLeast(1))
    .WillRepeatedly([&](std::vector<uint8_t> pkt, uint64_t endpointId) {
      EXPECT_EQ(endpointId, 0);
      return transportB.receive(pkt, endpointId);
    });

  EXPECT_CALL(transportB, doIsUp).Times(g::AtLeast(1)).WillRepeatedly(g::Return(true));
  EXPECT_CALL(transportB, doLoop).Times(g::AtLeast(1));
  EXPECT_CALL(transportB, doSend)
    .Times(g::AtLeast(1))
    .WillRepeatedly([&](std::vector<uint8_t> pkt, uint64_t endpointId) {
      EXPECT_EQ(endpointId, 1933);
      return transportA.receive(pkt, endpointId);
    });

  transport::ForceEndpointId transportAw(transportA);
  transport::ForceEndpointId transportBw(transportB, 1933);

  EXPECT_TRUE(transportAw.isUp());
  EXPECT_TRUE(transportBw.isUp());

  Face faceA(transportAw);
  Face faceB(transportBw);
  TransportTest(faceA, faceB).run().check();
  TransportTest(faceB, faceA).run().check();
}

TEST(Transport, UdpUnicast)
{
  uint16_t freePort = 0;
  {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in laddr = {};
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = INADDR_ANY;
    socklen_t laddrLen = sizeof(laddr);
    ASSERT_EQ(bind(fd, reinterpret_cast<sockaddr*>(&laddr), laddrLen), 0);
    ASSERT_EQ(getsockname(fd, reinterpret_cast<sockaddr*>(&laddr), &laddrLen), 0);
    ASSERT_EQ(close(fd), 0);
    freePort = ntohs(laddr.sin_port);
  }

  UdpUnicastTransport transportA;
  UdpUnicastTransport transportB;
  EXPECT_FALSE(transportA.isUp());
  EXPECT_FALSE(transportB.isUp());

  ASSERT_TRUE(transportA.beginTunnel({ 127, 0, 0, 1 }, freePort));
  ASSERT_TRUE(transportB.beginListen(freePort));
  EXPECT_TRUE(transportA.isUp());
  EXPECT_TRUE(transportB.isUp());

  Face faceA(transportA);
  Face faceB(transportB);
  TransportTest(faceA, faceB).run().check();
}

} // namespace
} // namespace ndnph
