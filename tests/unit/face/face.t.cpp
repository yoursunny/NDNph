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
  auto matchInterestName = g::Property(&Interest::getName, g::Eq(interest.getName()));
  {
    g::InSequence seq;
    EXPECT_CALL(hA, processInterest(matchInterestName))
      .WillOnce(g::DoAll(g::WithoutArgs([&hA] {
                           auto pi = hA.getCurrentPacketInfo();
                           ASSERT_THAT(pi, g::NotNull());
                           EXPECT_EQ(pi->endpointId, 4946);
                         }),
                         g::Return(false)));
    EXPECT_CALL(hB, processInterest(matchInterestName)).WillOnce(g::Return(true));
  }
  ASSERT_TRUE(transport.receive(interest, 4946));

  Data data = region.create<Data>();
  ASSERT_FALSE(!data);
  data.setName(Name(region, { 0x08, 0x01, 0x42 }));
  {
    auto matchDataName = g::Property(&Data::getName, g::Eq(data.getName()));
    EXPECT_CALL(hA, processData(matchDataName)).WillOnce(g::Return(true));
    EXPECT_CALL(hB, processData).Times(0);
  }
  ASSERT_TRUE(transport.receive(data.sign(NullPrivateKey())));

  Nack nack = Nack::create(interest, NackReason::Congestion);
  ASSERT_FALSE(!nack);
  {
    g::InSequence seq;
    EXPECT_CALL(hA, processNack(g::AllOf(
                      g::Property(&Nack::getHeader, g::Property(&NackHeader::getReason,
                                                                g::Eq(NackReason::Congestion))),
                      g::Property(&Nack::getInterest, matchInterestName))))
      .WillOnce(g::DoAll(g::WithoutArgs([&hA] {
                           auto pi = hA.getCurrentPacketInfo();
                           ASSERT_THAT(pi, g::NotNull());
                           EXPECT_EQ(pi->pitToken, 0xDE249BD0398EC80F);
                         }),
                         g::Return(true)));
    EXPECT_CALL(hB, processNack).Times(0);
  }
  ASSERT_TRUE(transport.receive(region, lp::encode(nack, 0xDE249BD0398EC80F)));
}

TEST(Face, Send)
{
  MockTransport transport;
  Face face(transport);
  MockPacketHandler hA(face);
  StaticRegion<1024> region;

  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name::parse(region, "/A"));
  interest.setCanBePrefix(true);

  Data data = region.create<Data>();
  ASSERT_FALSE(!data);
  data.setName(Name::parse(region, "/A/1"));
  Encoder encoderD(region);
  encoderD.prepend(data.sign(NullPrivateKey()));
  encoderD.trim();

  Nack nack = Nack::create(interest, NackReason::NoRoute);
  ASSERT_FALSE(!nack);
  Encoder encoderN(region);
  encoderN.prepend(lp::encode(nack, 0xDE249BD0398EC80F));
  encoderN.trim();

  EXPECT_CALL(hA, processInterest(g::Property(&Interest::getName, g::Eq(interest.getName()))))
    .WillOnce(g::DoAll(g::WithoutArgs([&] {
                         hA.send(data.sign(NullPrivateKey()));
                         hA.reply(nack);
                         return true;
                       }),
                       g::Return(true)));
  {
    g::InSequence seq;
    EXPECT_CALL(transport, doSend(g::ElementsAreArray(encoderD.begin(), encoderD.end()), 0))
      .WillOnce(g::Return(true));
    EXPECT_CALL(transport, doSend(g::ElementsAreArray(encoderN.begin(), encoderN.end()), 3202))
      .WillOnce(g::Return(true));
  }
  EXPECT_TRUE(transport.receive(region, lp::encode(interest, 0xDE249BD0398EC80F), 3202));
}

} // namespace
} // namespace ndnph
