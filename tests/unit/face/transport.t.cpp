#include "ndnph/port/transport/port.hpp"

#include "transport-common.hpp"

namespace ndnph {
namespace {

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
  ASSERT_TRUE(transportB.beginListen(freePort));
  ASSERT_TRUE(transportA.beginTunnel({ 127, 0, 0, 1 }, freePort));

  Face faceA(transportA);
  Face faceB(transportB);

  TransportTest(faceA, faceB).run().check();
}

} // namespace
} // namespace ndnph
