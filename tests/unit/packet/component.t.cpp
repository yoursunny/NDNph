#include "ndnph/packet/component.hpp"
#include "ndnph/tlv/value.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Component, Construct) {
  StaticRegion<1024> region;
  std::vector<uint8_t> value({0xC0, 0xC1, 0xC2, 0xC3});

  {
    Component comp(region, 0xA1, value.size(), value.data());
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), 0xA1);
    EXPECT_EQ(comp.size(), 6);
    EXPECT_THAT(std::vector<uint8_t>(comp.tlv(), comp.tlv() + comp.size()),
                g::ElementsAre(0xA1, 0x04, 0xC0, 0xC1, 0xC2, 0xC3));
    EXPECT_EQ(test::toString(comp), "161=%C0%C1%C2%C3");
    region.reset();
  }

  {
    Component comp(region, value.size(), value.data());
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), TT::GenericNameComponent);
    EXPECT_EQ(comp.size(), 6);
    EXPECT_THAT(std::vector<uint8_t>(comp.tlv(), comp.tlv() + comp.size()),
                g::ElementsAre(0x08, 0x04, 0xC0, 0xC1, 0xC2, 0xC3));
    EXPECT_EQ(test::toString(comp), "8=%C0%C1%C2%C3");
    region.reset();
  }

  {
    region.alloc(1020);
    Component comp(region, value.size(), value.data());
    EXPECT_TRUE(!comp);
    region.reset();
  }
}

TEST(Component, From) {
  StaticRegion<1024> region;

  std::vector<uint8_t> value1({0xA0, 0xA1});
  std::vector<uint8_t> value2({0xB0, 0xB1, 0xB2});

  Component comp = Component::from(region, 0x04, tlv::Value(value1.data(), value1.size()),
                                   tlv::Value(value2.data(), value2.size()));
  Encoder encoder(region);
  encoder.prepend(comp);
  EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()),
              g::ElementsAre(0x04, 0x05, 0xA0, 0xA1, 0xB0, 0xB1, 0xB2));
}

TEST(Component, Parse) {
  StaticRegion<1024> region;

  {
    auto comp = Component::parse(region, "A");
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), TT::GenericNameComponent);
    EXPECT_EQ(comp.length(), 1);
    EXPECT_THAT(std::vector<uint8_t>(comp.value(), comp.value() + comp.length()),
                g::ElementsAre(0x41));
    EXPECT_EQ(test::toString(comp), "8=A");
    region.reset();
  }

  {
    auto comp = Component::parse(region, "56=%009%3D%00%a6%00");
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), 56);
    EXPECT_EQ(comp.length(), 6);
    EXPECT_THAT(std::vector<uint8_t>(comp.value(), comp.value() + comp.length()),
                g::ElementsAre(0x00, 0x39, 0x3D, 0x00, 0xA6, 0x00));
    EXPECT_EQ(test::toString(comp), "56=%009%3D%00%A6%00");
    region.reset();
  }

  {
    auto comp = Component::parse(region, "...");
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), TT::GenericNameComponent);
    EXPECT_EQ(comp.length(), 0);
    EXPECT_EQ(test::toString(comp), "8=...");
    region.reset();
  }

  {
    auto comp = Component::parse(region, "56=....");
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), 56);
    EXPECT_EQ(comp.length(), 1);
    EXPECT_THAT(std::vector<uint8_t>(comp.value(), comp.value() + comp.length()),
                g::ElementsAre(0x2E));
    EXPECT_EQ(test::toString(comp), "56=....");
    region.reset();
  }

  {
    auto comp = Component::parse(region, "255=..D..");
    ASSERT_FALSE(!comp);
    EXPECT_EQ(comp.type(), 255);
    EXPECT_EQ(comp.length(), 5);
    EXPECT_THAT(std::vector<uint8_t>(comp.value(), comp.value() + comp.length()),
                g::ElementsAre(0x2E, 0x2E, 0x44, 0x2E, 0x2E));
    EXPECT_EQ(test::toString(comp), "255=..D..");
    region.reset();
  }

  {
    region.alloc(1020);
    auto comp = Component::parse(region, "ZZZ");
    EXPECT_TRUE(!comp);
    region.reset();
  }
}

TEST(Component, Equality) {
  Component compA, compB;
  EXPECT_EQ(compA, compB);

  StaticRegion<1024> region;
  compA = Component::parse(region, "8=A");
  EXPECT_NE(compA, compB);

  compB = Component::parse(region, "8=B");
  EXPECT_NE(compA, compB);

  compB = Component::parse(region, "8=AA");
  EXPECT_NE(compA, compB);

  compA = Component::parse(region, "8=AA");
  EXPECT_EQ(compA, compB);
}

} // namespace
} // namespace ndnph
