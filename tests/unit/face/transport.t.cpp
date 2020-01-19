#define NDNPH_SOCKET_PERROR
#include "ndnph/port/transport/port.hpp"

#include "transport-common.hpp"

namespace ndnph {
namespace {

TEST(Transport, UdpUnicast)
{
  UdpUnicastTransport transportA;
  ASSERT_TRUE(transportA.beginTunnel({ 127, 0, 0, 1 }, 6363));
  UdpUnicastTransport transportB;
  ASSERT_TRUE(transportB.beginListen(6363));

  Face faceA(transportA);
  Face faceB(transportB);

  TransportTest(faceA, faceB).run().check();
}

} // namespace
} // namespace ndnph
