#include "ndnph/app/ping-client.hpp"
#include "mock/mock-key.hpp"
#include "mock/mock-transport.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(PingClient, Demo)
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

} // namespace
} // namespace ndnph
