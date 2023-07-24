#include "ndnph/core/region.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Region, AllocFree) {
  static_assert(Region::ALIGNMENT == 8, "");

  StaticRegion<60> region;
  EXPECT_EQ(region.size(), 0);

  uint8_t* a0 = region.allocA(9); // left=9, right=60
  ASSERT_THAT(a0, g::NotNull());
  EXPECT_EQ(region.size(), 9);
  EXPECT_EQ(region.available(), 51);
  EXPECT_EQ(region.availableA(), 44);

  EXPECT_FALSE(region.free(a0 - 1, 10));
  EXPECT_FALSE(region.free(a0 + 6, 2));
  EXPECT_TRUE(region.free(a0 + 6, 3)); // left=6, right=60
  EXPECT_EQ(region.size(), 6);
  EXPECT_EQ(region.available(), 54);
  EXPECT_EQ(region.availableA(), 52);

  uint8_t* a1 = region.alloc(54); // left=6, right=6
  ASSERT_THAT(a1, g::NotNull());
  EXPECT_EQ(a1 - a0, 6);
  EXPECT_EQ(region.size(), 60);
  EXPECT_EQ(region.available(), 0);
  EXPECT_EQ(region.availableA(), 0);

  EXPECT_THAT(region.alloc(1), g::IsNull());

  EXPECT_FALSE(region.free(a1 - 1, a1 + 1));
  EXPECT_FALSE(region.free(a1, 56));
  EXPECT_TRUE(region.free(a1, 27)); // left=6, right=33
  EXPECT_EQ(region.size(), 33);
  EXPECT_EQ(region.available(), 27);
  EXPECT_EQ(region.availableA(), 25);
  EXPECT_THAT(region.allocA(26), g::IsNull());

  uint8_t* a2 = region.allocA(21); // left=29, right=33
  ASSERT_THAT(a2, g::NotNull());
  EXPECT_EQ(a2 - a0, 8);
  EXPECT_EQ(region.size(), 56);
  EXPECT_EQ(region.available(), 4);
  EXPECT_EQ(region.availableA(), 1);
}

class MyObj : public InRegion {
public:
  explicit MyObj(Region& region, uint32_t x = 1)
    : InRegion(region)
    , x(x) {}

public:
  uint32_t x;
};

class MyRef : public RefRegion<MyObj> {
public:
  using RefRegion::RefRegion;

  MyObj* getObj() {
    return obj;
  }
};

TEST(Region, Create) {
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

TEST(Region, SubRegion) {
  constexpr size_t capacity = 18;
  constexpr size_t count = 5;
  size_t total = sizeofSubRegions(capacity, count);
  EXPECT_GE(total, capacity * count);
  DynamicRegion parent(total);

  std::vector<uint8_t*> subRegionRooms;
  for (uint8_t i = 0; i < count; ++i) {
    Region* sub = makeSubRegion(parent, capacity);
    ASSERT_THAT(sub, g::NotNull());
    EXPECT_GE(sub->available(), capacity);
    uint8_t* room = sub->alloc(capacity);
    ASSERT_THAT(room, g::NotNull());
    std::fill_n(room, capacity, i);
    subRegionRooms.push_back(room);
  }
  EXPECT_THAT(makeSubRegion(parent, capacity), g::IsNull());

  for (uint8_t i = 0; i < count; ++i) {
    uint8_t* room = subRegionRooms[i];
    EXPECT_EQ(std::count(room, room + capacity, i), capacity);
  }
}

} // namespace
} // namespace ndnph
