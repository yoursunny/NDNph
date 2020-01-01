#include "ndnph/tlv/varnum.hpp"

#include "../test-common.hpp"

namespace ndnph {
namespace {

TEST(Tlv, SizeofVarNum)
{
  EXPECT_EQ(tlv::sizeofVarNum(0x01), 1);
  EXPECT_EQ(tlv::sizeofVarNum(0xFC), 1);
  EXPECT_EQ(tlv::sizeofVarNum(0xFD), 3);
  EXPECT_EQ(tlv::sizeofVarNum(0x0100), 3);
  EXPECT_EQ(tlv::sizeofVarNum(0xFFFF), 3);
  EXPECT_EQ(tlv::sizeofVarNum(0x00010000), 5);
  EXPECT_EQ(tlv::sizeofVarNum(0xFFFFFFFF), 5);
}

TEST(Tlv, WriteVarNum)
{
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

} // namespace
} // namespace ndnph
