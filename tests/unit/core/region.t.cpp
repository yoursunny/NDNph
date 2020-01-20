#include "ndnph/core/region.hpp"
#include "ndnph/core/in-region.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Region, Alloc)
{
  StaticRegion<60> region;
  EXPECT_EQ(region.size(), 0);
  EXPECT_EQ(region.available(), 60);

  uint8_t* a0 = region.alloc(12);
  EXPECT_THAT(a0, g::NotNull());
  EXPECT_EQ(region.size(), 12);
  EXPECT_EQ(region.available(), 48);

  uint8_t* a1 = region.alloc(5);
  EXPECT_THAT(a1, g::NotNull());
  EXPECT_EQ(a0 - a1, 5);
  EXPECT_EQ(region.size(), 17);
  EXPECT_EQ(region.available(), 43);

  uint8_t* a2 = region.alloc(50);
  EXPECT_THAT(a2, g::IsNull());
}

TEST(Region, AllocA)
{
  DynamicRegion region(60);
  EXPECT_EQ(region.size(), 0);

  uint8_t* a0 = region.allocA(9);
  EXPECT_THAT(a0, g::NotNull());
  EXPECT_EQ(region.size(), Region::ALIGNMENT == 8 ? 16 : 12);
  EXPECT_EQ(region.available(), Region::ALIGNMENT == 8 ? 44 : 48);

  uint8_t* a1 = region.allocA(8);
  EXPECT_THAT(a1, g::NotNull());
  EXPECT_EQ(a1 - a0, Region::ALIGNMENT == 8 ? 16 : 12);
  EXPECT_EQ(region.size(), Region::ALIGNMENT == 8 ? 24 : 20);
  EXPECT_EQ(region.available(), Region::ALIGNMENT == 8 ? 36 : 40);

  uint8_t* a2 = region.allocA(50);
  EXPECT_THAT(a2, g::IsNull());
}

class MyObj : public detail::InRegion
{
public:
  explicit MyObj(Region& region, uint32_t x = 1)
    : InRegion(region)
    , x(x)
  {}

public:
  uint32_t x;
};

class MyRef : public detail::RefRegion<MyObj>
{
public:
  using RefRegion::RefRegion;

  MyObj* getObj()
  {
    return obj;
  }
};

TEST(Region, Create)
{
  static_assert(sizeof(MyObj) > Region::ALIGNMENT && sizeof(MyObj) <= 2 * Region::ALIGNMENT, "");
  StaticRegion<Region::ALIGNMENT * 5 - 1> region;

  MyRef ref = region.create<MyRef>();
  ASSERT_FALSE(!ref);
  EXPECT_THAT(ref.getObj(), g::NotNull());
  EXPECT_EQ(ref.getObj()->x, 1);

  ref = region.create<MyRef>(42);
  ASSERT_FALSE(!ref);
  EXPECT_EQ(ref.getObj()->x, 42);
  EXPECT_EQ(region.size(), Region::ALIGNMENT * 4);

  ref = region.create<MyRef>();
  ASSERT_TRUE(!ref);
  EXPECT_THAT(ref.getObj(), g::IsNull());
}

TEST(Region, Free)
{
  StaticRegion<60> region;
  region.allocA(8);
  uint8_t* buf0 = region.alloc(15);
  uint8_t* buf1 = region.alloc(20);
  EXPECT_EQ(region.size(), 43);

  // cannot free other than the last buffer
  EXPECT_FALSE(region.free(buf0, 15));

  // cannot free out of range
  EXPECT_FALSE(region.free(buf1, 36));

  EXPECT_TRUE(region.free(buf1, 5));
  EXPECT_EQ(region.size(), 38);

  uint8_t* buf2 = region.alloc(5);
  EXPECT_EQ(buf2, buf1);

  region.reset();
  EXPECT_EQ(region.size(), 0);
}

TEST(Region, SubRegion)
{
  size_t total = sizeofSubRegions(18, 5);
  EXPECT_GE(total, 18 * 5);
  DynamicRegion parent(total);

  std::vector<uint8_t*> subRegionRooms;
  for (uint8_t i = 0; i < 5; ++i) {
    Region* sub = makeSubRegion(parent, 18);
    ASSERT_THAT(sub, g::NotNull());
    EXPECT_GE(sub->available(), 18);
    uint8_t* room = sub->alloc(18);
    ASSERT_THAT(room, g::NotNull());
    std::fill_n(room, 18, i);
    subRegionRooms.push_back(room);
  }

  for (uint8_t i = 0; i < 5; ++i) {
    uint8_t* room = subRegionRooms[i];
    EXPECT_EQ(std::count(room, room + 18, i), 18);
  }
}

} // namespace
} // namespace ndnph
