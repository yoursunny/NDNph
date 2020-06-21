#include "ndnph/tlv/ev-decoder.hpp"

#include "test-common.hpp"

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
    return EvDecoder::decodeEx(
      input, {}, EvDecoder::DefaultUnknownCb(), [](uint32_t type) { return type == 0xA2; },
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
  auto wire = test::fromHex(
    // ---- Target1
    "A00B A10110 A400 A600 A600 A900" // packet 0
    "A002 A200"                       // packet 1
    "A002 A300"                       // packet 2
    "A002 1000"                       // packet 3
    "A005 A10110 A100"                // packet 4
    "A004 A400 A100"                  // packet 5
    "A006 A600 A900 A600"             // packet 6
    "B000"                            // packet 7
    // ---- Target2 tests isCritical and ignores top TLV-TYPE
    "B004 A100 A300" // packet 8
    "B104 A100 A200" // packet 9
    // ---- Target3 tests unknownCb and accepts A0,AA as top TLV-TYPE
    "AA0A A200 A100 A400 A100 A600" // packet 10
  );
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
    EXPECT_THAT(target.unknownCbTypes, g::ElementsAre(0xA2, 0xA1, 0xA1, 0xA6));
    EXPECT_THAT(target.unknownCbOrders, g::ElementsAre(0, 0, 7, 7));
  }

  EXPECT_TRUE(it == end);
  EXPECT_FALSE(it.hasError());
}

} // namespace
} // namespace ndnph
