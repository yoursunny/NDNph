#include "ndnph/app/rdr-metadata-producer.hpp"
#include "ndnph/port/clock/port.hpp"

#include "mock/mock-transport.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Rdr, Producer)
{
  g::NiceMock<MockTransport> transport;
  Face face(transport);

  StaticRegion<1024> prefixRegion;
  Name rdrPrefix = Name::parse(prefixRegion, "/dataset/32=metadata");
  StaticRegion<1024> encodingRegion;
  RdrMetadataProducer producer(rdrPrefix, face, encodingRegion);

  uint64_t lastVersion = 0;
  auto testOneInterest = [&](const char* interestName, bool canBePrefix, bool mustBeFresh,
                             const char* respondDatasetPrefix) {
    StaticRegion<1024> region;
    if (respondDatasetPrefix == nullptr) {
      EXPECT_CALL(transport, doSend).Times(0);
    } else {
      EXPECT_CALL(transport, doSend).WillOnce([&](std::vector<uint8_t> wire, uint64_t) {
        Data data = region.create<Data>();
        assert(!!data);
        EXPECT_TRUE(Decoder(wire.data(), wire.size()).decode(data));
        const Name& name = data.getName();
        EXPECT_EQ(name.size(), 4);
        EXPECT_TRUE(rdrPrefix.isPrefixOf(name));
        EXPECT_TRUE(name[-2].is<convention::Version>());
        uint64_t version = name[-2].as<convention::Version>();
        EXPECT_GT(version, lastVersion);
        lastVersion = version;
        EXPECT_TRUE(name[-1].is<convention::Segment>());
        EXPECT_EQ(name[-1].as<convention::Segment>(), 0);
        auto content = data.getContent();
        Name datasetPrefix;
        EXPECT_TRUE(content.makeDecoder().decode(datasetPrefix));
        EXPECT_EQ(datasetPrefix, Name::parse(region, respondDatasetPrefix));
        return true;
      });
    }
    Interest interest = region.create<Interest>();
    assert(!!interest);
    interest.setName(Name::parse(region, interestName));
    interest.setCanBePrefix(canBePrefix);
    interest.setMustBeFresh(mustBeFresh);
    transport.receive(interest);

    for (int i = 0; i < 5; ++i) {
      face.loop();
      port::Clock::sleep(1);
    }
    g::Mock::VerifyAndClearExpectations(&transport);
  };

  testOneInterest("/dataset/32=metadata", true, true, nullptr);
  producer.setDatasetPrefix(Name::parse(prefixRegion, "/dataset/35=%07"));
  testOneInterest("/dataset/32=metadata", true, true, "/dataset/35=%07");

  testOneInterest("/dataset", true, true, nullptr);
  testOneInterest("/dataset/32=metadata", false, true, nullptr);
  testOneInterest("/dataset/32=metadata", true, false, nullptr);
  testOneInterest("/dataset/8=metadata", true, true, nullptr);
  testOneInterest("/dataset/32=metadata/35=%01", true, true, nullptr);
  testOneInterest("/dataset/32=metadata/35=%01/33=%00", true, true, nullptr);

  producer.setDatasetPrefix(Name::parse(prefixRegion, "/dataset/35=%1A"));
  testOneInterest("/dataset/32=metadata", true, true, "/dataset/35=%1A");
}

} // namespace
} // namespace ndnph
