#include "ndnph/packet/component.hpp"

#include "../test-common.hpp"

namespace ndnph {
namespace {

TEST(Component, Construct)
{
  StaticRegion<1024> region;
  std::vector<uint8_t> value({ 0xC0, 0xC1, 0xC2, 0xC3 });

  {
    Component comp(region, 0xA1, value.size(), value.data());
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), 0xA1);
    EXPECT_EQ(comp.size(), 6);
    EXPECT_THAT(std::vector<uint8_t>(comp.tlv(), comp.tlv() + comp.size()),
                g::ElementsAre(0xA1, 0x04, 0xC0, 0xC1, 0xC2, 0xC3));
    region.reset();
  }

  {
    Component comp(region, value.size(), value.data());
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), TT::GenericNameComponent);
    EXPECT_EQ(comp.size(), 6);
    EXPECT_THAT(std::vector<uint8_t>(comp.tlv(), comp.tlv() + comp.size()),
                g::ElementsAre(0x08, 0x04, 0xC0, 0xC1, 0xC2, 0xC3));
    region.reset();
  }

  {
    region.alloc(1020);
    Component comp(region, value.size(), value.data());
    EXPECT_TRUE(!comp);
    region.reset();
  }
}

TEST(Component, Parse)
{
  StaticRegion<1024> region;

  {
    auto comp = Component::parse(region, "A");
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), TT::GenericNameComponent);
    EXPECT_THAT(std::vector<uint8_t>(comp.value(), comp.value() + comp.length()),
                g::ElementsAre(0x41));
    region.reset();
  }

  {
    auto comp = Component::parse(region, "56=9%3D%a6");
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), 56);
    EXPECT_THAT(std::vector<uint8_t>(comp.value(), comp.value() + comp.length()),
                g::ElementsAre(0x39, 0x3D, 0xA6));
    region.reset();
  }

  {
    auto comp = Component::parse(region, "...");
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), TT::GenericNameComponent);
    EXPECT_EQ(comp.length(), 0);
    region.reset();
  }

  {
    auto comp = Component::parse(region, "56=....");
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), 56);
    EXPECT_THAT(std::vector<uint8_t>(comp.value(), comp.value() + comp.length()),
                g::ElementsAre(0x2E));
    region.reset();
  }

  {
    auto comp = Component::parse(region, "255=..D..");
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), 255);
    EXPECT_THAT(std::vector<uint8_t>(comp.value(), comp.value() + comp.length()),
                g::ElementsAre(0x2E, 0x2E, 0x44, 0x2E, 0x2E));
    region.reset();
  }

  {
    auto comp = Component::parse(region, "56=9%3D%a6");
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), 56);
    EXPECT_THAT(std::vector<uint8_t>(comp.value(), comp.value() + comp.length()),
                g::ElementsAre(0x39, 0x3D, 0xA6));
    region.reset();
  }

  {
    region.alloc(1020);
    auto comp = Component::parse(region, "ZZZ");
    EXPECT_TRUE(!comp);
    region.reset();
  }
}

} // namespace
} // namespace ndnph
