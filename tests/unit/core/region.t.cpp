#include "ndnph/core/in-region.hpp"
#include "ndnph/core/region.hpp"

#include "../test-common.hpp"

namespace ndnph {
namespace {

TEST(Region, Alloc_Dup)
{
  StaticRegion<60> region;
  EXPECT_EQ(region.size(), 0);
  EXPECT_EQ(region.available(), 60);

  uint8_t* a0 = region.alloc(12);
  EXPECT_THAT(a0, T::NotNull());
  EXPECT_EQ(region.size(), 12);
  EXPECT_EQ(region.available(), 48);

  std::vector<uint8_t> b1({ 0xB0, 0xB1, 0xB2, 0xB3, 0xB4 });
  uint8_t* a1 = region.dup(b1.data(), b1.size());
  EXPECT_THAT(a1, T::NotNull());
  EXPECT_EQ(a0 - a1, 5);
  EXPECT_EQ(region.size(), 17);
  EXPECT_EQ(region.available(), 43);
  EXPECT_TRUE(std::equal(b1.begin(), b1.end(), a1));

  uint8_t* a2 = region.alloc(50);
  EXPECT_THAT(a2, T::IsNull());

  std::vector<uint8_t> b3(50);
  uint8_t* a3 = region.dup(b3.data(), b3.size());
  EXPECT_THAT(a3, T::IsNull());
}

TEST(Region, AllocA)
{
  DynamicRegion region(60);
  EXPECT_EQ(region.size(), 0);

  uint8_t* a0 = region.allocA(9);
  EXPECT_THAT(a0, T::NotNull());
  EXPECT_EQ(region.size(), NDNPH_ALIGNMENT == 8 ? 16 : 12);
  EXPECT_EQ(region.available(), NDNPH_ALIGNMENT == 8 ? 44 : 48);

  uint8_t* a1 = region.allocA(8);
  EXPECT_THAT(a1, T::NotNull());
  EXPECT_EQ(a1 - a0, NDNPH_ALIGNMENT == 8 ? 16 : 12);
  EXPECT_EQ(region.size(), NDNPH_ALIGNMENT == 8 ? 24 : 20);
  EXPECT_EQ(region.available(), NDNPH_ALIGNMENT == 8 ? 36 : 40);

  uint8_t* a2 = region.allocA(50);
  EXPECT_THAT(a2, T::IsNull());
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

  MyObj* getObj() { return obj; }
};

TEST(Region, Create)
{
  static_assert(sizeof(MyObj) > NDNPH_ALIGNMENT &&
                  sizeof(MyObj) <= 2 * NDNPH_ALIGNMENT,
                "");
  StaticRegion<NDNPH_ALIGNMENT * 5 - 1> region;

  MyRef ref = region.create<MyRef>();
  ASSERT_FALSE(!ref);
  EXPECT_THAT(ref.getObj(), T::NotNull());
  EXPECT_EQ(ref.getObj()->x, 1);

  ref = region.create<MyRef>(42);
  ASSERT_FALSE(!ref);
  EXPECT_EQ(ref.getObj()->x, 42);
  EXPECT_EQ(region.size(), NDNPH_ALIGNMENT * 4);

  ref = region.create<MyRef>();
  ASSERT_TRUE(!ref);
  EXPECT_THAT(ref.getObj(), T::IsNull());
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

} // namespace
} // namespace ndnph
