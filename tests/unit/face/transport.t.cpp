#include "ndnph/face/bridge-transport.hpp"
#include "ndnph/face/transport-force-endpointid.hpp"
#include "ndnph/port/transport/port.hpp"

static FILE* tracerFile = nullptr;
#define NDNPH_LOG_FILE tracerFile
#include "ndnph/face/transport-tracer.hpp"

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

  tracerFile = tmpfile();
  transport::Tracer tracerA(transportA, "A");
  EXPECT_TRUE(tracerA.isUp());

  Face faceA(tracerA);
  Face faceB(transportB);
  size_t nPktsAB = 100, nPktsBA = 80;
  TransportTest(faceA, faceB, nPktsAB).run().check();
  TransportTest(faceB, faceA, nPktsBA).run().check();

  EXPECT_TRUE(transportB.end());
  EXPECT_FALSE(transportB.end());

  rewind(tracerFile);
  char traceLine[1024];
  size_t nTraceTx = 0, nTraceRx = 0;
  while (fgets(traceLine, sizeof(traceLine), tracerFile) != nullptr) {
    if (strstr(traceLine, " [A] < ") != nullptr) {
      ++nTraceTx;
    }
    if (strstr(traceLine, " [A] > ") != nullptr) {
      ++nTraceRx;
    }
  }
  EXPECT_EQ(nTraceTx, nPktsAB);
  EXPECT_EQ(nTraceRx, nPktsBA);
  fclose(tracerFile);
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

TEST(Transport, Ipv6EndpointIdHelper)
{
  port_transport_socket::Ipv6EndpointIdHelper<15> h;
  uint8_t addr4[] = { 192, 168, 5, 1 };
  uint64_t endpoint4 = h.encode(addr4, sizeof(addr4), 6363);

  struct AddrPort
  {
    uint64_t endpointId;
    std::array<uint8_t, 16> addr;
    uint16_t port;
  };
  std::vector<AddrPort> endpoints;

  int oldRejected = 0;
  int oldMistaken = 0;
  for (size_t i = 0; i < 50; ++i) {
    SCOPED_TRACE(i);
    AddrPort n{};
    port::RandomSource::generate(n.addr.data(), n.addr.size());
    port::RandomSource::generate(reinterpret_cast<uint8_t*>(&n.port), sizeof(n.port));
    n.endpointId = h.encode(n.addr.data(), n.addr.size(), n.port);
    EXPECT_NE(n.endpointId, 0);
    endpoints.push_back(n);
    uint64_t endpointId = h.encode(n.addr.data(), n.addr.size(), n.port);
    EXPECT_EQ(endpointId, n.endpointId);

    std::array<uint8_t, 16> addr{};
    uint16_t port = 0;
    int addrLen = h.decode(endpoint4, addr.data(), &port);
    EXPECT_EQ(addrLen, 4);
    EXPECT_EQ(addr[0], addr4[0]);
    EXPECT_EQ(addr[1], addr4[1]);
    EXPECT_EQ(addr[2], addr4[2]);
    EXPECT_EQ(addr[3], addr4[3]);
    EXPECT_EQ(port, 6363);

    for (size_t j = 0; j <= i; ++j) {
      SCOPED_TRACE(j);
      const auto& a = endpoints[j];
      int addrLen = h.decode(a.endpointId, addr.data(), &port);
      if (i - j < 15) {
        EXPECT_EQ(addrLen, 16);
        EXPECT_EQ(addr, a.addr);
        EXPECT_EQ(port, a.port);
      } else {
        if (addrLen == 0) {
          ++oldRejected;
        } else {
          ++oldMistaken;
        }
      }
    }
  }
  EXPECT_LT(oldMistaken, oldRejected);
}

TEST(Transport, UdpUnicast)
{
  uint16_t freePort = 0;
  {
    sockaddr_in6 laddr{};
    laddr.sin6_family = AF_INET6;
    laddr.sin6_addr = in6addr_any;
    int fd = socket(laddr.sin6_family, SOCK_DGRAM, 0);
    ASSERT_GE(fd, 0);
    socklen_t laddrLen = sizeof(laddr);
    ASSERT_EQ(bind(fd, reinterpret_cast<sockaddr*>(&laddr), laddrLen), 0);
    ASSERT_EQ(getsockname(fd, reinterpret_cast<sockaddr*>(&laddr), &laddrLen), 0);
    ASSERT_EQ(close(fd), 0);
    freePort = ntohs(laddr.sin6_port);
  }

  UdpUnicastTransport transport4;
  UdpUnicastTransport transport6;
  UdpUnicastTransport transportR;
  EXPECT_FALSE(transport4.isUp());
  EXPECT_FALSE(transport6.isUp());
  EXPECT_FALSE(transportR.isUp());

  ASSERT_TRUE(transport4.beginTunnel({ 127, 0, 0, 1 }, freePort));
  {
    sockaddr_in6 addr6{};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(freePort);
    addr6.sin6_addr = in6addr_loopback;
    ASSERT_TRUE(transport6.beginTunnel(&addr6));
  }
  ASSERT_TRUE(transportR.beginListen(freePort));
  EXPECT_TRUE(transport4.isUp());
  EXPECT_TRUE(transport6.isUp());
  EXPECT_TRUE(transportR.isUp());

  Face face4(transport4);
  Face face6(transport6);
  Face faceR(transportR);
  TransportTest(face4, faceR).run().check();
  TransportTest(face6, faceR).run().check();
}

} // namespace
} // namespace ndnph
