#include "ndnph/packet/convention.hpp"
#include "ndnph/packet/name.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Convention, ImplicitDigest)
{
  StaticRegion<1024> region;
  Name name(region, { 0x08, 0x01, 0x41, 0x01, 0x00 });
  EXPECT_FALSE(name[0].is<convention::ImplicitDigest>());
  EXPECT_FALSE(name[1].is<convention::ImplicitDigest>());

  std::vector<uint8_t> value(NDNPH_SHA256_LEN);
  std::fill(value.begin(), value.end(), 0xA0);
  name = name.append(region, convention::ImplicitDigest(), value.data());
  EXPECT_EQ(test::toString(name[-1]), "1=%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0"
                                      "%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0%A0");
  EXPECT_TRUE(name[-1].is<convention::ImplicitDigest>());

  const uint8_t* digest = name[-1].as<convention::ImplicitDigest>();
  ASSERT_THAT(digest, g::NotNull());
  EXPECT_THAT(std::vector<uint8_t>(digest, digest + NDNPH_SHA256_LEN), g::ElementsAreArray(value));
}

TEST(Convention, Keyword)
{
  StaticRegion<1024> region;
  Name name(region, { 0x08, 0x01, 0x41, 0x20, 0x00 });
  EXPECT_FALSE(name[0].is<convention::Keyword>());
  EXPECT_TRUE(name[1].is<convention::Keyword>());

  name = name.append(region, convention::Keyword(), "hello", convention::Keyword(), "world");
  EXPECT_EQ(test::toString(name[-2]), "32=hello");
  EXPECT_TRUE(name[-2].is<convention::Keyword>());
  EXPECT_EQ(test::toString(name[-1]), "32=world");
  EXPECT_TRUE(name[-1].is<convention::Keyword>());

  const char* keyword = name[-2].as<convention::Keyword>(region);
  EXPECT_EQ(keyword, std::string("hello"));
}

TEST(Convention, Segment)
{
  StaticRegion<1024> region;
  Name name(region, { 0x08, 0x01, 0x41, TT::SegmentNameComponent, 0x00 });
  EXPECT_FALSE(name[0].is<convention::Segment>());
  EXPECT_FALSE(name[1].is<convention::Segment>());

  name = name.append(region, convention::Segment(), 700);
  EXPECT_EQ(test::toString(name[-1]), "50=%02%BC");
  EXPECT_TRUE(name[-1].is<convention::Segment>());

  uint64_t segment = name[-1].as<convention::Segment>();
  EXPECT_EQ(segment, 700);
}

} // namespace
} // namespace ndnph
