#include "ndnph/app/ping-client.hpp"
#include "ndnph/app/ping-server.hpp"
#include "ndnph/keychain/ec.hpp"
#include "ndnph/keychain/null.hpp"

#include "mock/bridge-fixture.hpp"
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
        transport.receive(data.sign(NullKey::get()));
      } else if (nInterests == 4) {
        // no response
      } else {
        Data data = region.create<Data>();
        data.setName(interest.getName());
        data.setFreshnessPeriod(1);
        transport.receive(data.sign(NullKey::get()));
      }
      return true;
    });

  for (int i = 0; i < 120; ++i) {
    face.loop();
    port::Clock::sleep(1);
  }
  auto cnt = client.readCounters();
  EXPECT_EQ(cnt.nTxInterests, nInterests);
  EXPECT_EQ(cnt.nRxData, cnt.nTxInterests - 2);
}

TEST(Ping, Server)
{
  g::NiceMock<MockTransport> transport;
  Face face(transport);

  StaticRegion<1024> sRegion;
  EcPrivateKey pvt;
  EcPublicKey pub;
  ASSERT_TRUE(ec::generate(sRegion, Name::parse(sRegion, "/server"), pvt, pub));

  PingServer server(Name::parse(sRegion, "/ping"), face, pvt);

  std::set<std::string> interestNames;
  std::set<std::string> dataNames;
  EXPECT_CALL(transport, doSend).Times(20).WillRepeatedly([&](std::vector<uint8_t> wire, uint64_t) {
    StaticRegion<1024> tRegion;
    Data data = tRegion.create<Data>();
    EXPECT_TRUE(Decoder(wire.data(), wire.size()).decode(data));
    EXPECT_TRUE(data.verify(pub));
    std::string uri;
    boost::conversion::try_lexical_convert(data.getName(), uri);
    dataNames.insert(uri);
    EXPECT_THAT(dataNames, g::ElementsAreArray(interestNames));
    return true;
  });

  for (int i = 0; i < 20; ++i) {
    std::string uri = "/8=ping/8=" + std::to_string(i);
    interestNames.insert(uri);
    StaticRegion<1024> cRegion;
    Interest interest = cRegion.create<Interest>();
    interest.setName(Name::parse(cRegion, uri.data()));
    interest.setMustBeFresh(true);
    transport.receive(interest);
    face.loop();
  }
  EXPECT_THAT(dataNames, g::ElementsAreArray(interestNames));
}

using PingEndToEndFixture = BridgeFixture;

TEST_F(PingEndToEndFixture, EndToEnd)
{
  StaticRegion<1024> region;
  PingServer serverA(Name::parse(region, "/ping"), faceA);
  PingClient clientB(Name::parse(region, "/ping"), faceB, 10);

  int i = 120;
  runInThreads([] {}, [&] { return --i >= 0; });

  auto cnt = clientB.readCounters();
  EXPECT_GE(cnt.nTxInterests, 5);
  EXPECT_LE(cnt.nTxInterests, 20);
  EXPECT_GE(cnt.nRxData, cnt.nTxInterests - 2);
  EXPECT_LE(cnt.nRxData, cnt.nTxInterests);
}

} // namespace
} // namespace ndnph
