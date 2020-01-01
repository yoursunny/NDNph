#include "ndnph/tlv.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

#if NDNPH_HAS_BOOST_CONCEPT
BOOST_CONCEPT_ASSERT((boost::ForwardIterator<tlv::Decoder::Iterator>));
#endif

TEST(Tlv, VarNum)
{
  EXPECT_EQ(tlv::sizeofVarNum(0x01), 1);
  EXPECT_EQ(tlv::sizeofVarNum(0xFC), 1);
  EXPECT_EQ(tlv::sizeofVarNum(0xFD), 3);
  EXPECT_EQ(tlv::sizeofVarNum(0x0100), 3);
  EXPECT_EQ(tlv::sizeofVarNum(0xFFFF), 3);
  EXPECT_EQ(tlv::sizeofVarNum(0x00010000), 5);
  EXPECT_EQ(tlv::sizeofVarNum(0xFFFFFFFF), 5);

  std::vector<uint8_t> room(1);
  tlv::writeVarNum(room.data(), 0x01);
  EXPECT_THAT(room, T::ElementsAre(0x01));
  tlv::writeVarNum(room.data(), 0xFC);
  EXPECT_THAT(room, T::ElementsAre(0xFC));

  room.resize(3);
  tlv::writeVarNum(room.data(), 0xFD);
  EXPECT_THAT(room, T::ElementsAre(0xFD, 0x00, 0xFD));
  tlv::writeVarNum(room.data(), 0x0100);
  EXPECT_THAT(room, T::ElementsAre(0xFD, 0x01, 0x00));
  tlv::writeVarNum(room.data(), 0xFFFF);
  EXPECT_THAT(room, T::ElementsAre(0xFD, 0xFF, 0xFF));

  room.resize(5);
  tlv::writeVarNum(room.data(), 0x00010000);
  EXPECT_THAT(room, T::ElementsAre(0xFE, 0x00, 0x01, 0x00, 0x00));
  tlv::writeVarNum(room.data(), 0xFFFFFFFF);
  EXPECT_THAT(room, T::ElementsAre(0xFE, 0xFF, 0xFF, 0xFF, 0xFF));
}

TEST(Tlv, Decoder)
{
  std::vector<uint8_t> wire({
    0x01, 0x00,                               // 0100
    0x02, 0x01, 0xA1,                         // 0201 A1
    0xFD, 0x00, 0xFD, 0x03, 0xA3, 0xA3, 0xA3, // FD03 A3A3A3
    0xFD, 0x01, 0x00, 0x02, 0xA2, 0xA2,       // 010002 A2A2
    0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0xA1, // FFFFFFFF A1
  });
  tlv::Decoder decoder(wire.data(), wire.size());

  auto it = decoder.begin(), end = decoder.end();
  ASSERT_TRUE(it != end);
  EXPECT_EQ(it->type, 0x01);
  EXPECT_EQ(it->length, 0);

  ++it;
  ASSERT_TRUE(it != end);
  EXPECT_EQ(it->type, 0x02);
  EXPECT_EQ(it->length, 1);
  EXPECT_THAT(std::vector<uint8_t>(it->value, it->value + it->length),
              T::ElementsAre(0xA1));

  ++it;
  ASSERT_TRUE(it != end);
  EXPECT_EQ(it->type, 0xFD);
  EXPECT_EQ(it->length, 3);
  EXPECT_THAT(std::vector<uint8_t>(it->value, it->value + it->length),
              T::ElementsAre(0xA3, 0xA3, 0xA3));

  ++it;
  ASSERT_TRUE(it != end);
  EXPECT_EQ(it->type, 0x0100);
  EXPECT_EQ(it->length, 2);
  EXPECT_THAT(std::vector<uint8_t>(it->value, it->value + it->length),
              T::ElementsAre(0xA2, 0xA2));

  ++it;
  ASSERT_TRUE(it != end);
  EXPECT_EQ(it->type, 0xFFFFFFFF);
  EXPECT_EQ(it->length, 1);
  EXPECT_THAT(std::vector<uint8_t>(it->value, it->value + it->length),
              T::ElementsAre(0xA1));

  ++it;
  ASSERT_TRUE(it == end);

  // missing TLV-TYPE
  std::vector<uint8_t> wire1({});
  tlv::Decoder decoder1(wire1.data(), wire1.size());
  EXPECT_TRUE(decoder1.begin() == decoder1.end());

  // incomplete 3-octet TLV-TYPE
  std::vector<uint8_t> wire2({ 0xFD, 0x01 });
  tlv::Decoder decoder2(wire2.data(), wire2.size());
  EXPECT_TRUE(decoder2.begin() == decoder2.end());

  // incomplete 5-octet TLV-TYPE
  std::vector<uint8_t> wire3({ 0xFE, 0x01 });
  tlv::Decoder decoder3(wire3.data(), wire3.size());
  EXPECT_TRUE(decoder3.begin() == decoder3.end());

  // unacceptable 9-octet TLV-TYPE
  std::vector<uint8_t> wire4(
    { 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xA1 });
  tlv::Decoder decoder4(wire4.data(), wire4.size());
  EXPECT_TRUE(decoder4.begin() == decoder4.end());

  // missing TLV-LENGTH
  std::vector<uint8_t> wire5({ 0x01, 0x00, 0x01 });
  tlv::Decoder decoder5(wire5.data(), wire5.size());
  auto it5 = decoder5.begin(), end5 = decoder5.end();
  EXPECT_FALSE(it5.hasError());
  EXPECT_TRUE(it5++ != end5);
  EXPECT_TRUE(it5 == end5);
  EXPECT_TRUE(it5.hasError());

  // incomplete TLV-VALUE
  std::vector<uint8_t> wire6({ 0x01, 0x02, 0xA1 });
  tlv::Decoder decoder6(wire6.data(), wire6.size());
  EXPECT_TRUE(decoder6.begin() == decoder6.end());
}

} // namespace
} // namespace ndnph
