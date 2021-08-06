#include "ndnph/face/face.hpp"
#include "ndnph/keychain/null.hpp"

#include "mock/bridge-fixture.hpp"
#include "mock/mock-packet-handler.hpp"
#include "mock/mock-transport.hpp"

namespace ndnph {
namespace {

TEST(Face, Receive)
{
  MockTransport transport;
  Face face(transport);
  MockPacketHandler h(face, 1);
  MockPacketHandler hB(face, 9);
  StaticRegion<1024> region;

  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name(region, { 0x08, 0x01, 0x41 }));
  auto matchInterestName = g::Property(&Interest::getName, g::Eq(interest.getName()));
  {
    g::InSequence seq;
    EXPECT_CALL(h, processInterest(matchInterestName))
      .WillOnce(g::DoAll(g::WithoutArgs([&h] {
                           auto pi = h.getCurrentPacketInfo();
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
    EXPECT_CALL(h, processData(matchDataName)).WillOnce(g::Return(true));
    EXPECT_CALL(hB, processData).Times(0);
  }
  ASSERT_TRUE(transport.receive(data.sign(NullKey::get())));

  Nack nack = Nack::create(interest, NackReason::Congestion);
  ASSERT_FALSE(!nack);
  {
    g::InSequence seq;
    EXPECT_CALL(h, processNack(g::AllOf(
                     g::Property(&Nack::getHeader, g::Property(&NackHeader::getReason,
                                                               g::Eq(NackReason::Congestion))),
                     g::Property(&Nack::getInterest, matchInterestName))))
      .WillOnce(g::DoAll(g::WithoutArgs([&h] {
                           auto pi = h.getCurrentPacketInfo();
                           ASSERT_THAT(pi, g::NotNull());
                           EXPECT_EQ(pi->pitToken.to4(), 0xDE249BD0);
                         }),
                         g::Return(true)));
    EXPECT_CALL(hB, processNack).Times(0);
  }
  ASSERT_TRUE(transport.receive(lp::encode(nack, lp::PitToken::from4(0xDE249BD0))));
}

class TestSendHandler : public MockPacketHandler
{
public:
  using MockPacketHandler::MockPacketHandler;

  void setupExpect()
  {
    EXPECT_CALL(*this, processInterest(g::Property(&Interest::getName, g::Eq(request.getName()))))
      .WillOnce([this](Interest) {
        send(data.sign(NullKey::get()));
        reply(nack);
        send(interest, WithEndpointId(2035), WithPitToken(lp::PitToken::from4(0xA31A71CE)));
        return true;
      });
  }

public:
  Interest request;
  Data data;
  Nack nack;
  Interest interest;
};

TEST(Face, Send)
{
  MockTransport transport;
  Face face(transport);
  TestSendHandler h(face);
  StaticRegion<1024> region;

  h.request = region.create<Interest>();
  ASSERT_FALSE(!h.request);
  h.request.setName(Name::parse(region, "/A"));
  h.request.setCanBePrefix(true);

  h.data = region.create<Data>();
  ASSERT_FALSE(!h.data);
  h.data.setName(Name::parse(region, "/A/1"));
  Encoder encoderD(region);
  encoderD.prepend(h.data.sign(NullKey::get()));
  encoderD.trim();

  h.nack = Nack::create(h.request, NackReason::NoRoute);
  ASSERT_FALSE(!h.nack);
  Encoder encoderN(region);
  encoderN.prepend(lp::encode(h.nack, lp::PitToken::from4(0xDE249BD0)));
  encoderN.trim();

  h.interest = region.create<Interest>();
  ASSERT_FALSE(!h.interest);
  h.interest.setName(Name::parse(region, "/B"));
  Encoder encoderI(region);
  encoderI.prepend(lp::encode(h.interest, lp::PitToken::from4(0xA31A71CE)));
  encoderI.trim();

  h.setupExpect();
  {
    g::InSequence seq;
    EXPECT_CALL(transport, doSend(g::ElementsAreArray(encoderD.begin(), encoderD.end()), 0))
      .WillOnce(g::Return(true));
    EXPECT_CALL(transport, doSend(g::ElementsAreArray(encoderN.begin(), encoderN.end()), 3202))
      .WillOnce(g::Return(true));
    EXPECT_CALL(transport, doSend(g::ElementsAreArray(encoderI.begin(), encoderI.end()), 2035))
      .WillOnce(g::Return(true));
  }
  EXPECT_TRUE(transport.receive(lp::encode(h.request, lp::PitToken::from4(0xDE249BD0)), 3202));
}

TEST(Face, DetachedPacketHandler)
{
  MockPacketHandler ph;
  EXPECT_THAT(ph.getCurrentPacketInfo(), g::IsNull());

  StaticRegion<1024> region;
  auto data = region.create<Data>();
  ASSERT_FALSE(!data);
  data.setName(Name::parse(region, "/A"));
  EXPECT_FALSE(ph.send(region, data));
  EXPECT_FALSE(ph.reply(region, data));
}

class FaceFragmentationFixture : public BridgeFixture
{
public:
  explicit FaceFragmentationFixture()
    : fragRegionA(16384)
    , fragRegionB(16384)
    , fragmenterA(fragRegionA, 1500)
    , fragmenterB(fragRegionB, 1500)
    , reassemblerA(fragRegionA)
    , reassemblerB(fragRegionB)
  {
    faceA.setFragmenter(fragmenterA);
    faceA.setReassembler(reassemblerA);
    faceB.setFragmenter(fragmenterB);
    faceB.setReassembler(reassemblerB);
  }

protected:
  DynamicRegion fragRegionA;
  DynamicRegion fragRegionB;
  lp::Fragmenter fragmenterA;
  lp::Fragmenter fragmenterB;
  lp::Reassembler reassemblerA;
  lp::Reassembler reassemblerB;
};

TEST_F(FaceFragmentationFixture, Fragmentation)
{
  MockPacketHandler hA(faceA);
  std::vector<size_t> recvSizes;
  EXPECT_CALL(hA, processData).Times(20).WillRepeatedly([&](Data data) {
    recvSizes.push_back(data.getContent().size());
    return true;
  });

  MockPacketHandler hB(faceB);
  int nSent = 0;
  int sleepB = 0;
  runInThreads([] {},
               [&] {
                 if (++sleepB % 10 != 0) {
                   return true;
                 }

                 int contentL = nSent * 400;
                 StaticRegion<10000> region;
                 Data data = region.create<Data>();
                 EXPECT_FALSE(!data);

                 char name[32];
                 snprintf(name, sizeof(name), "/L/%d", contentL);
                 data.setName(Name::parse(region, name));

                 uint8_t content[8000];
                 std::fill_n(content, sizeof(content), 0xBB);
                 data.setContent(tlv::Value(content, contentL));

                 EXPECT_TRUE(hB.send(data.sign(NullKey::get())));
                 ++nSent;
                 return nSent < 20;
               },
               [] { port::Clock::sleep(100); });

  EXPECT_THAT(recvSizes, g::SizeIs(20));
  for (size_t i = 0; i < recvSizes.size(); ++i) {
    EXPECT_EQ(recvSizes[i], 400 * i);
  }
}

class FacePendingFixture : public g::Test
{
protected:
  class Handler : public MockPacketHandler
  {
  public:
    explicit Handler(Face& face)
      : MockPacketHandler(face)
      , m_pending(this)
    {}

    template<typename... Arg>
    bool send(Arg&&... arg)
    {
      return m_pending.send(std::forward<Arg>(arg)...);
    }

    bool expired() const
    {
      return m_pending.expired();
    }

    void setupExpect()
    {
      EXPECT_CALL(*this, processData).WillOnce([this](Data data) {
        matchPitToken = m_pending.matchPitToken();
        matchInterest = m_pending.match(data, interest);
        matchName = m_pending.match(data, name, canBePrefix);
        return true;
      });
    }

  public:
    Interest interest;
    Name name;
    bool canBePrefix = false;

    bool matchPitToken = false;
    bool matchInterest = false;
    bool matchName = false;

  private:
    OutgoingPendingInterest m_pending;
  };

  explicit FacePendingFixture()
    : face(transport)
    , h(face)
  {}

  void SetUp() override
  {
    interest = cRegion.create<Interest>();
    assert(!!interest);
    data = pRegion.create<Data>();
    assert(!!data);
  }

  void setupRespond(bool withPitToken = true)
  {
    EXPECT_CALL(transport, doSend).WillOnce([=](std::vector<uint8_t> wire, uint64_t) {
      lp::PacketClassify classify;
      EXPECT_TRUE(Decoder(wire.data(), wire.size()).decode(classify));
      EXPECT_EQ(classify.getType(), lp::PacketClassify::Type::Interest);

      h.setupExpect();
      if (withPitToken) {
        transport.receive(lp::encode(data.sign(NullKey::get()), classify.getPitToken()));
      } else {
        transport.receive(data.sign(NullKey::get()));
      }
      return true;
    });
  }

protected:
  MockTransport transport;
  Face face;
  Handler h;
  StaticRegion<2048> cRegion;
  StaticRegion<2048> pRegion;
  Interest interest;
  Data data;
};

TEST_F(FacePendingFixture, NormalMatch)
{
  interest.setName(Name::parse(cRegion, "/A"));
  interest.setCanBePrefix(true);
  interest.setMustBeFresh(true);
  data.setName(Name::parse(pRegion, "/A/B"));
  data.setFreshnessPeriod(1);

  setupRespond();
  h.interest = interest;
  h.name = interest.getName();
  h.canBePrefix = true;
  h.send(interest);

  EXPECT_TRUE(h.matchPitToken);
  EXPECT_TRUE(h.matchInterest);
  EXPECT_TRUE(h.matchName);
}

TEST_F(FacePendingFixture, DigestMatch)
{
  auto data1 = pRegion.create<Data>();
  assert(!!data1);
  data1.setName(Name::parse(pRegion, "/A/B"));
  data.decodeFrom(data1.sign(NullKey::get()));

  interest.setName(data.getFullName(cRegion));

  setupRespond();
  h.interest = interest;
  h.name = interest.getName();
  h.canBePrefix = false;
  h.send(interest);

  EXPECT_TRUE(h.matchPitToken);
  EXPECT_TRUE(h.matchInterest);
  EXPECT_TRUE(h.matchName);
}

TEST_F(FacePendingFixture, MismatchData)
{
  interest.setName(Name::parse(cRegion, "/A"));
  data.setName(Name::parse(pRegion, "/B"));

  setupRespond();
  h.interest = interest;
  h.name = interest.getName();
  h.canBePrefix = false;
  h.send(interest);

  EXPECT_TRUE(h.matchPitToken);
  EXPECT_FALSE(h.matchInterest);
  EXPECT_FALSE(h.matchName);
}

TEST_F(FacePendingFixture, MismatchPitToken)
{
  interest.setName(Name::parse(cRegion, "/A"));
  data.setName(interest.getName());

  setupRespond(false);
  h.interest = interest;
  h.name = interest.getName();
  h.canBePrefix = false;
  h.send(interest);

  EXPECT_FALSE(h.matchPitToken);
  EXPECT_FALSE(h.matchInterest);
  EXPECT_FALSE(h.matchName);
}

TEST_F(FacePendingFixture, Expire)
{
  interest.setName(Name::parse(cRegion, "/A"));

  EXPECT_CALL(transport, doSend).Times(1);
  h.send(interest, 100);

  EXPECT_FALSE(h.expired());
  port::Clock::sleep(200);
  EXPECT_TRUE(h.expired());
}

} // namespace
} // namespace ndnph
