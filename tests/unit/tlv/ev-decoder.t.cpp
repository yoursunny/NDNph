#include "ndnph/tlv/ev-decoder.hpp"

#include "../test-common.hpp"

namespace ndnph {
namespace {

class Target0
{
public:
  int sum() const
  {
    return a1 * 1000 + a4 * 100 + a6 * 10 + a9;
  }

public:
  int a1 = 0;
  int a4 = 0;
  int a6 = 0;
  int a9 = 0;
};

class Target1 : public Target0
{
public:
  bool decodeFrom(const Decoder::Tlv& input)
  {
    return EvDecoder::decode(input, { 0xA0 }, EvDecoder::def<0xA1>([this](const Decoder::Tlv& d) {
                               EXPECT_EQ(d.type, 0xA1);
                               ASSERT_EQ(d.length, 1);
                               EXPECT_EQ(d.value[0], 0x10);
                               ++a1;
                             }),
                             EvDecoder::def<0xA4>([this](const Decoder::Tlv&) { ++a4; }),
                             EvDecoder::def<0xA6, true>([this](const Decoder::Tlv&) { ++a6; }),
                             EvDecoder::def<0xA9>([this](const Decoder::Tlv&) { ++a9; }));
  }
};

class Target2 : public Target0
{
public:
  bool decodeFrom(const Decoder::Tlv& input)
  {
    return EvDecoder::decodeEx(input, {}, EvDecoder::DefaultUnknownCb(),
                               [](uint32_t type) { return type == 0xA2; },
                               EvDecoder::def<0xA1>([this](const Decoder::Tlv&) { ++a1; }));
  }
};

class Target3 : public Target0
{
public:
  bool decodeFrom(const Decoder::Tlv& input)
  {
    return EvDecoder::decodeEx(
      input, { 0xA0, 0xAA },
      [this](const Decoder::Tlv& d, int& currentOrder) {
        unknownCbTypes.push_back(d.type);
        unknownCbOrders.push_back(currentOrder);
        if (d.type == 0xA1) {
          ++a1;
          return true;
        }
        return false;
      },
      EvDecoder::DefaultIsCritical(),
      EvDecoder::def<0xA4, false, 7>([this](const Decoder::Tlv&) { ++a4; }));
  }

public:
  std::vector<uint32_t> unknownCbTypes;
  std::vector<uint32_t> unknownCbOrders;
};

TEST(EvDecoder, All)
{
  std::vector<uint8_t> wire({
    // ---- Target1
    // packet 0
    0xA0,
    0x0B, // A0
    0xA1, 0x01,
    0x10, // A1
    0xA4,
    0x00, // A4
    0xA6,
    0x00, // A6
    0xA6,
    0x00, // A6 repeatable
    0xA9,
    0x00, // A9

    // packet 1
    0xA0,
    0x02, // A0
    0xA2,
    0x00, // A2 non-critical

    // packet 2
    0xA0,
    0x02, // A0
    0xA3,
    0x00, // A3 critical

    // packet 3
    0xA0,
    0x02, // A0
    0x10,
    0x00, // 10 critical

    // packet 4
    0xA0,
    0x05, // A0
    0xA1, 0x01,
    0x10, // A1
    0xA1,
    0x00, // A1 cannot repeat

    // packet 5
    0xA0,
    0x04, // A0
    0xA4,
    0x00, // A4
    0xA1,
    0x00, // A1 out of order

    // packet 6
    0xA0,
    0x06, // A0
    0xA6,
    0x00, // A6
    0xA9,
    0x00, // A9
    0xA6,
    0x00, // A6 out of order

    // packet 7
    0xB0,
    0x00, // B0 incorrect

    // ---- Target2 tests isCritical and ignores top TLV-TYPE
    // packet 8
    0xB0,
    0x04, // B0
    0xA1,
    0x00, // A1 recognized
    0xA3,
    0x00, // A3 non-critical

    // packet 9
    0xB1,
    0x04, // B1
    0xA1,
    0x00, // A1 recognized
    0xA2,
    0x00, // A2 critical

    // ---- Target3 tests unknownCb and accepts 0xA0,0xAA as top TLV-TYPE
    // packet 10
    0xAA,
    0x0A, // AA
    0xA2,
    0x00, // A2 ignored
    0xA1,
    0x00, // A1 handled by unknownCb
    0xA4,
    0x00, // A4 handled by rule
    0xA1,
    0x00, // A1 handled by unknownCb
    0xA6,
    0x00, // A6 ignored
  });
  Decoder decoder(wire.data(), wire.size());
  auto it = decoder.begin(), end = decoder.end();

  // packet 0: normal
  {
    Target1 target;
    ASSERT_TRUE((it++)->decode(target));
    EXPECT_EQ(target.sum(), 1121);
  }

  // packet 1: unknown non-critical
  {
    Target1 target;
    ASSERT_TRUE((it++)->decode(target));
    EXPECT_EQ(target.sum(), 0);
  }

  // packet 2: unknown critical
  {
    Target1 target;
    EXPECT_FALSE((it++)->decode(target));
  }

  // packet 3: unknown critical in grandfathered range
  {
    Target1 target;
    EXPECT_FALSE((it++)->decode(target));
  }

  // packet 4: non-repeatable
  {
    Target1 target;
    EXPECT_FALSE((it++)->decode(target));
  }

  // packet 5: out of order critical
  {
    Target1 target;
    EXPECT_FALSE((it++)->decode(target));
  }

  // packet 6: out of order non-critical
  {
    Target1 target;
    ASSERT_TRUE((it++)->decode(target));
    EXPECT_EQ(target.sum(), 11);
  }

  // packet 5: top TLV-TYPE incorrect
  {
    Target1 target;
    EXPECT_FALSE((it++)->decode(target));
  }

  // packet 8: isCritical returns non-critical
  {
    Target2 target;
    ASSERT_TRUE((it++)->decode(target));
    EXPECT_EQ(target.sum(), 1000);
  }

  // packet 9: isCritical returns critical
  {
    Target2 target;
    EXPECT_FALSE((it++)->decode(target));
  }

  // packet 10: unknownCb
  {
    Target3 target;
    ASSERT_TRUE((it++)->decode(target));
    EXPECT_EQ(target.sum(), 2100);
    EXPECT_THAT(target.unknownCbTypes, T::ElementsAre(0xA2, 0xA1, 0xA1, 0xA6));
    EXPECT_THAT(target.unknownCbOrders, T::ElementsAre(0, 0, 7, 7));
  }

  EXPECT_TRUE(it == end);
  EXPECT_FALSE(it.hasError());
}

} // namespace
} // namespace ndnph
