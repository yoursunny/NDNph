#include "ndnph/tlv/encoder.hpp"
#include "ndnph/tlv/value.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Encoder, Room)
{
  uint8_t buf[60];
  Encoder encoder(buf, sizeof(buf));
  EXPECT_FALSE(!encoder);
  EXPECT_EQ(encoder.begin(), &buf[60]);
  EXPECT_EQ(encoder.end(), &buf[60]);
  EXPECT_EQ(encoder.size(), 0);

  uint8_t* room = encoder.prependRoom(20);
  EXPECT_EQ(room, &buf[40]);
  EXPECT_FALSE(!encoder);
  EXPECT_EQ(encoder.begin(), &buf[40]);
  EXPECT_EQ(encoder.end(), &buf[60]);
  EXPECT_EQ(encoder.size(), 20);

  room = encoder.prependRoom(15);
  EXPECT_EQ(room, &buf[25]);
  EXPECT_FALSE(!encoder);
  EXPECT_EQ(encoder.begin(), &buf[25]);
  EXPECT_EQ(encoder.end(), &buf[60]);
  EXPECT_EQ(encoder.size(), 35);

  room = encoder.prependRoom(30);
  EXPECT_THAT(room, g::IsNull());
  EXPECT_TRUE(!encoder);
  EXPECT_EQ(encoder.size(), 0);
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()), g::SizeIs(0));
}

TEST(Encoder, TrimDiscard)
{
  StaticRegion<60> region;
  Encoder encoder(region);
  EXPECT_EQ(region.available(), 0);

  uint8_t* room = encoder.prependRoom(20);
  EXPECT_THAT(room, g::NotNull());

  encoder.trim();
  EXPECT_EQ(region.available(), 40);
  EXPECT_FALSE(!encoder);
  encoder.trim();
  EXPECT_EQ(region.available(), 40);
  EXPECT_FALSE(!encoder);

  encoder.discard();
  EXPECT_TRUE(!encoder);
  EXPECT_EQ(region.available(), 60);
  encoder.discard();
}

TEST(Encoder, TrimErrorDiscard)
{
  StaticRegion<60> region;
  Encoder encoder(region);

  uint8_t* room = encoder.prependRoom(20);
  EXPECT_THAT(room, g::NotNull());

  encoder.trim();
  EXPECT_EQ(region.available(), 40);

  room = encoder.prependRoom(1);
  EXPECT_THAT(room, g::IsNull());
  EXPECT_TRUE(!encoder);

  encoder.discard();
  EXPECT_TRUE(!encoder);
  EXPECT_EQ(region.available(), 60);
}

TEST(Encoder, ErrorTrimDiscard)
{
  StaticRegion<60> region;
  Encoder encoder(region);

  uint8_t* room = encoder.prependRoom(61);
  EXPECT_THAT(room, g::IsNull());
  EXPECT_TRUE(!encoder);

  encoder.trim();
  EXPECT_EQ(region.available(), 60);

  encoder.discard();
  EXPECT_EQ(region.available(), 60);
}

TEST(Encoder, TrimDiscardNop)
{
  uint8_t buf[60];
  Encoder encoder(buf, sizeof(buf));

  uint8_t* room = encoder.prependRoom(20);
  EXPECT_THAT(room, g::NotNull());

  encoder.trim(); // no effect because Encoder is not created from Region
  EXPECT_FALSE(!encoder);

  room = encoder.prependRoom(15);
  EXPECT_THAT(room, g::NotNull());

  encoder.discard(); // no effect because Encoder is not created from Region
  EXPECT_FALSE(!encoder);

  room = encoder.prependRoom(25);
  EXPECT_THAT(room, g::NotNull());
}

template<int V>
class MyEncodable
{
public:
  void encodeTo(Encoder& encoder) const
  {
    uint8_t* room = encoder.prependRoom(1);
    if (room != nullptr) {
      room[0] = V;
    }
  }
};

TEST(Encoder, Prepend)
{
  uint8_t buf[60];
  Encoder encoder(buf, sizeof(buf));

  std::vector<uint8_t> value0({});
  std::vector<uint8_t> valueE({ 0xE0, 0xE1 });
  std::vector<uint8_t> valueF({ 0xF0, 0xF1 });

  bool ok = encoder.prepend(MyEncodable<0xA0>(), [](Encoder& encoder) { encoder.prependTlv(0xA1); },
                            MyEncodable<0xA2>());
  ok = ok && encoder.prependTlv(0xC0, Encoder::OmitEmpty, tlv::Value(value0.data(), value0.size()),
                                tlv::Value(value0.data(), value0.size()));
  ok = ok && encoder.prependTlv(0xC1, tlv::Value(value0.data(), value0.size()),
                                tlv::Value(value0.data(), value0.size()));
  ok = ok && encoder.prependTlv(0xC2, Encoder::OmitEmpty, tlv::Value(valueE.data(), valueE.size()),
                                tlv::Value(valueF.data(), valueF.size()), [=](Encoder& encoder) {
                                  encoder.prependTlv(0xC3, tlv::Value(valueE.data(), valueE.size()),
                                                     tlv::Value(valueF.data(), valueF.size()));
                                });

  EXPECT_TRUE(ok);
  EXPECT_FALSE(!encoder);
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()),
              g::ElementsAre(0xC2, 0x0A, 0xE0, 0xE1, 0xF0, 0xF1, 0xC3, 0x04, 0xE0, 0xE1, 0xF0,
                             0xF1, // C2 nested C3
                             0xC1,
                             0x00, // C1 not omitted, C0 omitted
                             0xA0, // MyEncodable<A0>
                             0xA1,
                             0x00, // prependTlv(A1)
                             0xA2  // MyEncodable<A0>
                             ));
}

} // namespace
} // namespace ndnph
