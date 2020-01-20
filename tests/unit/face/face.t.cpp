#include "ndnph/face/face.hpp"
#include "ndnph/port/crypto/port.hpp"

#include "mock/mock-key.hpp"
#include "mock/mock-packet-handler.hpp"
#include "mock/mock-transport.hpp"

namespace ndnph {
namespace {

TEST(Face, Receive)
{
  MockTransport transport;
  Face face(transport);
  MockPacketHandler hA(face, 1);
  MockPacketHandler hB(face, 9);
  StaticRegion<1024> region;

  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name(region, { 0x08, 0x01, 0x41 }));
  {
    g::InSequence seq;
    auto matchInterestName = g::Property(&Interest::getName, g::Eq(interest.getName()));
    EXPECT_CALL(hA, processInterest(matchInterestName, 4946)).WillOnce(g::Return(false));
    EXPECT_CALL(hB, processInterest(matchInterestName, 4946)).WillOnce(g::Return(true));
  }
  ASSERT_TRUE(transport.receive(interest, 4946));

  Data data = region.create<Data>();
  ASSERT_FALSE(!data);
  data.setName(Name(region, { 0x08, 0x01, 0x42 }));
  {
    auto matchDataName = g::Property(&Data::getName, g::Eq(data.getName()));
    EXPECT_CALL(hA, processData(matchDataName, 2223)).WillOnce(g::Return(true));
    EXPECT_CALL(hB, processData).Times(0);
  }
  ASSERT_TRUE(transport.receive(data.sign(NullPrivateKey()), 2223));
}

TEST(Face, Send)
{
  MockTransport transport;
  Face face(transport);

  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name(region, { 0x08, 0x01, 0x41 }));
  Encoder encoder(region);
  encoder.prepend(interest);
  encoder.trim();

  EXPECT_CALL(transport, doSend(g::ElementsAreArray(encoder.begin(), encoder.end()), 3202))
    .WillOnce(g::Return(true));
  EXPECT_TRUE(face.send(interest, 3202));
}

} // namespace
} // namespace ndnph
