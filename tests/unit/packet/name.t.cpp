#include "ndnph/packet/name.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

BOOST_CONCEPT_ASSERT((boost::InputIterator<Name::Iterator>));

TEST(Name, Decode)
{
  Name name;
  EXPECT_TRUE(!name);

  std::vector<uint8_t> wire({ 0x08, 0x01, 0x41 });
  name = Name(wire.data(), wire.size());
  EXPECT_FALSE(!name);
  EXPECT_EQ(name.length(), 3);
  EXPECT_EQ(name.value(), wire.data());
  EXPECT_EQ(name.size(), 1);

  Component comp = name[0];
  EXPECT_FALSE(!comp);
  EXPECT_EQ(comp.type(), 0x08);
  EXPECT_EQ(comp.length(), 1);
  EXPECT_THAT(std::vector<uint8_t>(comp.value(), comp.value() + comp.length()),
              g::ElementsAre(0x41));
  EXPECT_EQ(comp.size(), 3);
  EXPECT_EQ(comp.tlv(), wire.data());

  Component comp2 = name[-1];
  EXPECT_FALSE(!comp2);
  EXPECT_EQ(comp2.tlv(), comp.tlv());

  comp2 = name[1];
  EXPECT_TRUE(!comp2);
  comp2 = name[-2];
  EXPECT_TRUE(!comp2);

  StaticRegion<1024> region;
  wire.assign({ 0x09, 0x01, 0x41, 0x08, 0x01, 0x42 });
  name = Name(region, wire.begin(), wire.end());
  EXPECT_FALSE(!name);
  EXPECT_NE(name.value(), wire.data());
  EXPECT_EQ(name.length(), 6);
  EXPECT_THAT(std::vector<uint8_t>(name.value(), name.value() + name.length()),
              g::ElementsAreArray(wire.begin(), wire.end()));
  EXPECT_EQ(name.size(), 2);

  comp = name[-2];
  EXPECT_FALSE(!comp);
  EXPECT_EQ(comp.type(), 0x09);
  EXPECT_EQ(comp.tlv(), name.value());

  std::vector<Component> comps(name.begin(), name.end());
  ASSERT_THAT(comps, g::SizeIs(2));
  EXPECT_EQ(comps[0].type(), 0x09);
  EXPECT_EQ(comps[1].type(), 0x08);

  // bad TLV
  wire.assign({ 0x08, 0x01, 0x41, 0x09 });
  name = Name(wire.data(), wire.size());
  EXPECT_TRUE(!name);

  // TLV-TYPE out of range for Component
  wire.assign({ 0xFE, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41 });
  name = Name(wire.data(), wire.size());
  EXPECT_TRUE(!name);
}

TEST(Name, Parse)
{
  StaticRegion<1024> region;

  {
    auto name = Name::parse(region, "/");
    ASSERT_FALSE(!name);
    EXPECT_EQ(name.size(), 0);
    region.reset();
  }

  {
    auto name = Name::parse(region, "/A");
    ASSERT_FALSE(!name);
    EXPECT_THAT(std::vector<uint8_t>(name.value(), name.value() + name.length()),
                g::ElementsAre(0x08, 0x01, 0x41));
    region.reset();
  }

  {
    auto name = Name::parse(region, "/A/56=B.");
    ASSERT_FALSE(!name);
    EXPECT_THAT(std::vector<uint8_t>(name.value(), name.value() + name.length()),
                g::ElementsAre(0x08, 0x01, 0x41, 0x38, 0x02, 0x42, 0x2E));
    region.reset();
  }

  {
    region.alloc(1020);
    auto name = Name::parse(region, "/ZZZ");
    ASSERT_TRUE(!name);
    region.reset();
  }
}

TEST(Name, Slice)
{
  std::vector<uint8_t> wire(
    { 0x81, 0x01, 0x41, 0x82, 0x01, 0x42, 0x83, 0x01, 0x43, 0x84, 0x01, 0x44 });
  Name name(wire.data(), wire.size());
  ASSERT_THAT(name, g::SizeIs(4));

  Name name2 = name.slice(1, 3);
  ASSERT_THAT(name2, g::SizeIs(2));
  EXPECT_EQ(name2[0].type(), 0x82);
  EXPECT_EQ(name2[1].type(), 0x83);

  name2 = name.slice(-1, 0);
  ASSERT_THAT(name2, g::SizeIs(1));
  EXPECT_EQ(name2[0].type(), 0x84);

  name2 = name.slice(-2, -1);
  ASSERT_THAT(name2, g::SizeIs(1));
  EXPECT_EQ(name2[0].type(), 0x83);

  name2 = name.getPrefix(2);
  ASSERT_THAT(name2, g::SizeIs(2));
  EXPECT_EQ(name2[0].type(), 0x81);
  EXPECT_EQ(name2[1].type(), 0x82);

  name2 = name.getPrefix(-1);
  ASSERT_THAT(name2, g::SizeIs(3));
  EXPECT_EQ(name2[0].type(), 0x81);
  EXPECT_EQ(name2[1].type(), 0x82);
  EXPECT_EQ(name2[2].type(), 0x83);

  name2 = name.getPrefix(0);
  ASSERT_THAT(name2, g::SizeIs(4));
  EXPECT_EQ(name2[3].type(), 0x84);

  EXPECT_TRUE(!name.slice(2, 2));   // first==last
  EXPECT_TRUE(!name.slice(-2, -2)); // first==last
  EXPECT_TRUE(!name.slice(2, -2));  // first==last
  EXPECT_TRUE(!name.slice(3, 2));   // first>last
  EXPECT_TRUE(!name.slice(-1, 2));  // first>last
  EXPECT_TRUE(!name.slice(5, 7));   // first>=size()
  EXPECT_TRUE(!name.slice(1, 6));   // last>=size()
  EXPECT_TRUE(!name.slice(-5, -1)); // first<0
  EXPECT_TRUE(!name.getPrefix(7));  // last>=size()
  EXPECT_TRUE(!name.getPrefix(-9)); // last<0
}

TEST(Name, Append)
{
  StaticRegion<1024> region;
  std::vector<uint8_t> wire(
    { 0x81, 0x01, 0x41, 0x82, 0x01, 0x42, 0x83, 0x01, 0x43, 0x82, 0x01, 0x42, 0x08, 0x01, 0x44 });
  Name name(wire.data(), 3);

  Name name2 = name.append(region, {});
  EXPECT_THAT(name2, g::SizeIs(1));

  Component comp1;
  Decoder(&wire[3], 3).decode(comp1);
  Component comp2(region, wire[6], wire[7], &wire[8]);
  Component comp3(region, wire[13], &wire[14]);
  name2 = name.append(region, { comp1, comp2, comp1, comp3 });
  EXPECT_THAT(std::vector<uint8_t>(name2.value(), name2.value() + name2.length()),
              g::ElementsAreArray(wire));
}

TEST(Name, CompareComponent)
{
  StaticRegion<1024> region;
  std::vector<uint8_t> wire({ 0xF0, 0x02, 0x41, 0x42 });
  Name name(region, wire.begin(), wire.end());

  wire.assign({ 0xF1, 0x02, 0x41, 0x42 });
  EXPECT_LT(name, Name(wire.data(), wire.size()));

  wire.assign({ 0xF0, 0x03, 0x41, 0x42, 0x43 });
  EXPECT_LT(name, Name(wire.data(), wire.size()));

  wire.assign({ 0xF0, 0x02, 0x41, 0x43 });
  EXPECT_LT(name, Name(wire.data(), wire.size()));

  wire.assign({ 0xF0, 0x02, 0x41, 0x42 });
  EXPECT_EQ(name, Name(wire.data(), wire.size()));
  EXPECT_EQ(name, name);

  wire.assign({ 0xF0, 0x02, 0x41, 0x41 });
  EXPECT_GT(name, Name(wire.data(), wire.size()));

  wire.assign({ 0xF0, 0x01, 0x41 });
  EXPECT_GT(name, Name(wire.data(), wire.size()));

  wire.assign({ 0xEF, 0x02, 0x41, 0x41 });
  EXPECT_GT(name, Name(wire.data(), wire.size()));
}

TEST(Name, CompareStructure)
{
  StaticRegion<1024> region;
  Name nameAB(region, { 0x08, 0x01, 0x41, 0x08, 0x01, 0x42 });
  Name nameAC(region, { 0x08, 0x01, 0x41, 0x08, 0x01, 0x43 });
  Name nameABC(region, { 0x08, 0x01, 0x41, 0x08, 0x01, 0x42, 0x08, 0x01, 0x43 });
  Name nameA(region, { 0x08, 0x01, 0x41 });
  Name nameAA(region, { 0x08, 0x01, 0x41, 0x08, 0x01, 0x41 });

  EXPECT_EQ(nameAB.compare(nameAC), Name::CMP_LT);
  EXPECT_EQ(nameAB.compare(nameABC), Name::CMP_LPREFIX);
  EXPECT_EQ(nameAB.compare(nameAB), Name::CMP_EQUAL);
  EXPECT_EQ(nameAB.compare(nameA), Name::CMP_RPREFIX);
  EXPECT_EQ(nameAB.compare(nameAA), Name::CMP_GT);

  EXPECT_NE(nameAB, nameAC);
  EXPECT_LT(nameAB, nameAC);
  EXPECT_LE(nameAB, nameAC);
  EXPECT_LT(nameAB, nameABC);
  EXPECT_EQ(nameAB, nameAB);
  EXPECT_GT(nameAB, nameA);
  EXPECT_GE(nameAB, nameA);
  EXPECT_GT(nameAB, nameAA);

  EXPECT_TRUE(nameAB.isPrefixOf(nameABC));
  EXPECT_TRUE(nameAB.isPrefixOf(nameAB));
  EXPECT_FALSE(nameAB.isPrefixOf(nameA));
  EXPECT_FALSE(nameAB.isPrefixOf(nameAC));
}

} // namespace
} // namespace ndnph
