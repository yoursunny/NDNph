#include "ndnph/app/ping-client.hpp"
#include "ndnph/app/ping-server.hpp"
#include "ndnph/face/bridge-transport.hpp"

#include "mock/mock-key.hpp"
#include "mock/mock-transport.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Ping, Client)
{
  g::NiceMock<MockTransport> transport;
  Face face(transport);

  StaticRegion<1024> region;
  PingClient client(Name::parse(region, "/ping"), face, 10);

  int nInterests = 0;
  EXPECT_CALL(transport, doSend)
    .Times(g::Between(5, 20))
    .WillRepeatedly([&](std::vector<uint8_t> wire, uint64_t) {
      StaticRegion<1024> region;
      Interest interest = region.create<Interest>();
      EXPECT_TRUE(Decoder(wire.data(), wire.size()).decode(interest));
      EXPECT_EQ(interest.getName().size(), 2);
      EXPECT_FALSE(interest.getCanBePrefix());
      EXPECT_TRUE(interest.getMustBeFresh());

      ++nInterests;
      if (nInterests == 2) {
        Data data = region.create<Data>();
        data.setName(interest.getName().getPrefix(-1));
        data.setFreshnessPeriod(1);
        transport.receive(data.sign(NullPrivateKey()));
      } else if (nInterests == 4) {
        // no response
      } else {
        Data data = region.create<Data>();
        data.setName(interest.getName());
        data.setFreshnessPeriod(1);
        transport.receive(data.sign(NullPrivateKey()));
      }
      return true;
    });

  for (int i = 0; i < 120; ++i) {
    face.loop();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  auto cnt = client.readCounters();
  EXPECT_EQ(cnt.nTxInterests, nInterests);
  EXPECT_EQ(cnt.nRxData, cnt.nTxInterests - 2);
}

TEST(Ping, Server)
{
  g::NiceMock<MockTransport> transport;
  Face face(transport);

  StaticRegion<1024> region;
  PingServer server(Name::parse(region, "/ping"), face);

  std::set<std::string> interestNames;
  std::set<std::string> dataNames;
  EXPECT_CALL(transport, doSend).Times(20).WillRepeatedly([&](std::vector<uint8_t> wire, uint64_t) {
    StaticRegion<1024> region;
    Data data = region.create<Data>();
    EXPECT_TRUE(Decoder(wire.data(), wire.size()).decode(data));
    std::string uri;
    boost::conversion::try_lexical_convert(data.getName(), uri);
    dataNames.insert(uri);
    EXPECT_THAT(dataNames, g::ElementsAreArray(interestNames));
    return true;
  });

  for (int i = 0; i < 20; ++i) {
    std::string uri = "/8=ping/8=" + std::to_string(i);
    interestNames.insert(uri);
    StaticRegion<1024> region2;
    Interest interest = region2.create<Interest>();
    interest.setName(Name::parse(region, uri.data()));
    interest.setMustBeFresh(true);
    transport.receive(interest);
    face.loop();
  }
  EXPECT_THAT(dataNames, g::ElementsAreArray(interestNames));
}

TEST(Ping, EndToEnd)
{
  BridgeTransport transportA;
  BridgeTransport transportB;
  transportA.begin(transportB);
  Face faceA(transportA);
  Face faceB(transportB);

  StaticRegion<1024> region;
  PingServer serverA(Name::parse(region, "/ping"), faceB);
  PingClient clientB(Name::parse(region, "/ping"), faceA, 10);
  std::atomic_bool stopServer(false);

  std::thread threadA([&] {
    while (!stopServer) {
      faceA.loop();
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  });

  std::thread threadB([&] {
    for (int i = 0; i < 120; ++i) {
      faceB.loop();
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  });

  threadB.join();
  stopServer = true;
  threadA.join();

  auto cnt = clientB.readCounters();
  EXPECT_GE(cnt.nTxInterests, 5);
  EXPECT_LE(cnt.nTxInterests, 20);
  EXPECT_EQ(cnt.nRxData, cnt.nTxInterests);
}

} // namespace
} // namespace ndnph
