#include "ndnph/app/segment-consumer.hpp"
#include "ndnph/app/segment-producer.hpp"

#include "mock/bridge-fixture.hpp"
#include "mock/mock-transport.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

static std::vector<uint8_t>
makeRandomContent(size_t size)
{
  std::vector<uint8_t> content(size);
  port::RandomSource::generate(content.data(), content.size());
  return content;
}

TEST(Segment, Consumer)
{
  g::NiceMock<MockTransport> transport;
  Face face(transport);

  std::vector<uint8_t> content = makeRandomContent(900);
  SegmentConsumer::Options optsA;
  optsA.retxLimit = 2;
  optsA.retxDelay = 5;
  SegmentConsumer consumerA(face, optsA);
  SegmentConsumer::Options optsB;
  optsB.retxLimit = 1;
  optsB.retxDelay = 5;
  BasicSegmentConsumer<convention::SequenceNum> consumerB(face, optsB);

  StaticRegion<1024> prefixRegion;
  Name prefixA = Name::parse(prefixRegion, "/A");
  Name nameA0 = prefixA.append(prefixRegion, convention::Segment(), 0);
  Name nameA1 = prefixA.append(prefixRegion, convention::Segment(), 1);
  Name prefixB = Name::parse(prefixRegion, "/B");
  Name nameB0 = prefixB.append(prefixRegion, convention::SequenceNum(), 0);
  port::Clock::Time timeA0;
  int countA0 = 0;
  int countA1 = 0;
  int countB0 = 0;

  EXPECT_CALL(transport, doSend).WillRepeatedly([&](std::vector<uint8_t> wire, uint64_t) {
    StaticRegion<1024> region;
    lp::PacketClassify classify;
    EXPECT_TRUE(Decoder(wire.data(), wire.size()).decode(classify));
    EXPECT_EQ(classify.getType(), lp::PacketClassify::Type::Interest);
    Interest interest = region.create<Interest>();
    NDNPH_ASSERT(!!interest);
    EXPECT_TRUE(classify.decodeInterest(interest));

    const Name& interestName = interest.getName();
    if (interestName == nameA0) {
      switch (++countA0) {
        case 1: // no reply
          timeA0 = port::Clock::now();
          break;
        case 2: { // reply has wrong name
          auto now = port::Clock::now();
          EXPECT_THAT(port::Clock::sub(now, timeA0), g::AllOf(g::Ge(5), g::Le(8)));
          timeA0 = now;

          Data data = region.create<Data>();
          NDNPH_ASSERT(!!data);
          data.setName(nameA1);
          std::vector<uint8_t> content({ 0xA0, 0xA1 });
          data.setContent(tlv::Value(content.data(), content.size()));
          transport.receive(lp::encode(data.sign(DigestKey::get()), classify.getPitToken()));
          break;
        }
        case 3: { // reply OK
          auto now = port::Clock::now();
          EXPECT_THAT(port::Clock::sub(now, timeA0), g::AllOf(g::Ge(5), g::Le(8)));
          timeA0 = now;

          Data data = region.create<Data>();
          NDNPH_ASSERT(!!data);
          data.setName(nameA0);
          std::vector<uint8_t> content({ 0xA2, 0xA3 });
          data.setContent(tlv::Value(content.data(), content.size()));
          transport.receive(lp::encode(data.sign(DigestKey::get()), classify.getPitToken()));
          break;
        }
        default:
          ADD_FAILURE();
          break;
      }
    } else if (interestName == nameA1) {
      switch (++countA1) {
        case 1: { // reply OK
          Data data = region.create<Data>();
          NDNPH_ASSERT(!!data);
          data.setName(nameA1);
          std::vector<uint8_t> content({ 0xA4, 0xA5 });
          data.setContent(tlv::Value(content.data(), content.size()));
          data.setIsFinalBlock(true);
          transport.receive(lp::encode(data.sign(DigestKey::get()), classify.getPitToken()));
          break;
        }
        default:
          ADD_FAILURE();
          break;
      }
    } else if (interestName == nameB0) {
      switch (++countB0) {
        case 1: // no reply
        case 2:
          break;
        default:
          ADD_FAILURE();
          break;
      }
    } else {
      ADD_FAILURE();
    }
    return true;
  });

  std::vector<uint8_t> outputA(64);
  SegmentConsumer::SaveDest destA(outputA.data(), outputA.size());
  consumerA.saveTo(destA);
  consumerA.start(prefixA);
  std::vector<uint8_t> outputB(64);
  SegmentConsumer::SaveDest destB(outputB.data(), outputB.size());
  consumerB.saveTo(destB);
  consumerB.start(prefixB);
  while (consumerA.isRunning() || consumerB.isRunning()) {
    face.loop();
    port::Clock::sleep(1);
  }

  EXPECT_EQ(countA0, 3);
  EXPECT_EQ(countA1, 1);
  EXPECT_EQ(countB0, 2);
  EXPECT_TRUE(destA.isCompleted);
  EXPECT_FALSE(destA.hasError);
  EXPECT_THAT(std::vector<uint8_t>(&destA.output[0], &destA.output[destA.length]),
              g::ElementsAre(0xA2, 0xA3, 0xA4, 0xA5));
  EXPECT_TRUE(destB.hasError);
}

TEST(Segment, Producer)
{
  g::NiceMock<MockTransport> transport;
  Face face(transport);

  std::vector<uint8_t> content = makeRandomContent(900);
  SegmentProducer::Options optsA;
  optsA.contentLen = 300; // ContentL=[300,300,300]
  optsA.discovery = 2;
  SegmentProducer producerA(face, optsA);
  SegmentProducer::Options optsB;
  optsB.contentLen = 200; // ContentL=[200,200,200,200,100]
  optsB.discovery = 0;
  BasicSegmentProducer<convention::SequenceNum> producerB(face, optsB);

  auto testOneInterest = [&](const char* interestName, bool canBePrefix, const char* dataName,
                             ssize_t contentL, bool isFinalBlock = false) {
    StaticRegion<1024> region;
    if (contentL < 0) {
      EXPECT_CALL(transport, doSend).Times(0);
    } else {
      EXPECT_CALL(transport, doSend).WillOnce([&](std::vector<uint8_t> wire, uint64_t) {
        Data data = region.create<Data>();
        NDNPH_ASSERT(!!data);
        EXPECT_TRUE(Decoder(wire.data(), wire.size()).decode(data));
        EXPECT_EQ(data.getName(),
                  Name::parse(region, dataName == nullptr ? interestName : dataName));
        EXPECT_EQ(data.getContent().size(), contentL);
        EXPECT_EQ(data.getIsFinalBlock(), isFinalBlock);
        return true;
      });
    }
    Interest interest = region.create<Interest>();
    NDNPH_ASSERT(!!interest);
    interest.setName(Name::parse(region, interestName));
    interest.setCanBePrefix(canBePrefix);
    transport.receive(interest);

    for (int i = 0; i < 5; ++i) {
      face.loop();
      port::Clock::sleep(1);
    }
    g::Mock::VerifyAndClearExpectations(&transport);
  };

  StaticRegion<1024> prefixRegion;
  producerA.setContent(Name::parse(prefixRegion, "/A/AA/AAA"), content.data(), content.size());

  testOneInterest("/A/AA/AAA/50=%00", false, nullptr, 300);
  testOneInterest("/A/AA/AAA/50=%00/X", false, nullptr, -1);
  testOneInterest("/A/AA/AAA/X", false, nullptr, -1);
  testOneInterest("/A/AA/AAA", false, nullptr, -1);
  testOneInterest("/A/AA/AAA", true, "/A/AA/AAA/50=%00", 300);
  testOneInterest("/A/AA", true, "/A/AA/AAA/50=%00", 300);
  testOneInterest("/A", true, nullptr, -1);
  testOneInterest("/B/BB/BBB/58=%00", false, nullptr, -1);

  producerB.setContent(Name::parse(prefixRegion, "/B/BB/BBB"), content.data(), content.size());
  testOneInterest("/B/BB/BBB/58=%00", false, nullptr, 200);
  testOneInterest("/B/BB/BBB/58=%01", false, nullptr, 200);
  testOneInterest("/B/BB/BBB/58=%02", false, nullptr, 200);
  testOneInterest("/B/BB/BBB/58=%03", false, nullptr, 200);
  testOneInterest("/B/BB/BBB/58=%04", false, nullptr, 100, true);
  testOneInterest("/B/BB/BBB/58=%05", false, nullptr, -1);
  testOneInterest("/B/BB/BBB", true, nullptr, -1);
  testOneInterest("/A/AA/AAA/50=%01", false, nullptr, 300);
  testOneInterest("/A/AA/AAA/50=%02", false, nullptr, 300, true);
  testOneInterest("/A/AA/AAA/50=%03", false, nullptr, -1);
}

class SegmentEndToEndFixture : public BridgeFixture
{
protected:
  void SetUp() override
  {
    SegmentProducer::Options optsA;
    optsA.contentLen = 256;
    producerA.reset(new SegmentProducer(faceA, optsA));

    prefix = Name::parse(prefixRegion, "/P");
    contentA = makeRandomContent(4096);
    producerA->setContent(prefix, contentA.data(), contentA.size());

    SegmentConsumer::Options optsB;
    optsB.retxLimit = 2;
    consumerB.reset(new SegmentConsumer(faceB, optsB));
  }

protected:
  std::unique_ptr<SegmentProducer> producerA;
  std::unique_ptr<SegmentConsumer> consumerB;

  StaticRegion<1024> prefixRegion;
  Name prefix;
  std::vector<uint8_t> contentA;
};

TEST_F(SegmentEndToEndFixture, SegmentCallback)
{
  struct CtxB
  {
    std::vector<uint8_t> content;
    uint64_t segment = 0;
  } ctxB;
  runInThreads(
    [&] {
      consumerB->setSegmentCallback(
        [](void* ctx, uint64_t segment, Data data) {
          CtxB& ctxB = *reinterpret_cast<CtxB*>(ctx);

          EXPECT_EQ(segment, ctxB.segment);
          ++ctxB.segment;
          EXPECT_LE(segment, 15);

          ASSERT_FALSE(!data);
          EXPECT_EQ(data.getIsFinalBlock(), segment == 15);

          auto content = data.getContent();
          std::copy(content.begin(), content.end(), std::back_inserter(ctxB.content));
        },
        &ctxB);
      consumerB->start(prefix);
    },
    [&] { return consumerB->isRunning(); });

  EXPECT_EQ(ctxB.segment, 16);
  EXPECT_EQ(ctxB.content, contentA);
}

TEST_F(SegmentEndToEndFixture, SaveToNormal)
{
  std::vector<uint8_t> contentB(contentA.size() + 1);
  SegmentConsumer::SaveDest destB(contentB.data(), contentB.size());

  runInThreads(
    [&] {
      consumerB->saveTo(destB);
      consumerB->start(prefix);
    },
    [&] { return consumerB->isRunning(); });

  EXPECT_TRUE(destB.isCompleted);
  EXPECT_FALSE(destB.hasError);
  EXPECT_EQ(destB.length, contentA.size());
  EXPECT_THAT(std::vector<uint8_t>(&destB.output[0], &destB.output[destB.length]),
              g::ElementsAreArray(contentA));
}

TEST_F(SegmentEndToEndFixture, SaveToTooShort)
{
  std::vector<uint8_t> contentB(contentA.size() - 1);
  SegmentConsumer::SaveDest destB(contentB.data(), contentB.size());

  runInThreads(
    [&] {
      consumerB->saveTo(destB);
      consumerB->start(prefix);
    },
    [&] { return consumerB->isRunning(); }, [] {});

  EXPECT_TRUE(destB.hasError);
}

} // namespace
} // namespace ndnph
