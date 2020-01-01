#include "ndnph/core/region.hpp"

#include "../test-common.hpp"

namespace ndnph {
namespace {

TEST(Region, Alloc_Dup)
{
  StaticRegion<60> region;
  EXPECT_EQ(region.size(), 0);

  uint8_t* a0 = region.alloc(12);
  EXPECT_THAT(a0, T::NotNull());
  EXPECT_EQ(region.size(), 12);

  std::vector<uint8_t> b1({ 0xB0, 0xB1, 0xB2, 0xB3, 0xB4 });
  uint8_t* a1 = region.dup(b1.data(), b1.size());
  EXPECT_THAT(a1, T::NotNull());
  EXPECT_EQ(a0 - a1, 5);
  EXPECT_EQ(region.size(), 17);
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

  uint8_t* a1 = region.allocA(8);
  EXPECT_THAT(a1, T::NotNull());
  EXPECT_EQ(a1 - a0, NDNPH_ALIGNMENT == 8 ? 16 : 12);
  EXPECT_EQ(region.size(), NDNPH_ALIGNMENT == 8 ? 24 : 20);

  uint8_t* a2 = region.allocA(50);
  EXPECT_THAT(a2, T::IsNull());
}

class MyRef;

class MyObj
{
public:
  using RefType = MyRef;

  explicit MyObj(Region& region, uint32_t x = 1)
    : x(x)
  {}

public:
  uint32_t x;
};

class MyRef
{
public:
  using ObjType = MyObj;

  MyRef() = default;

  explicit MyRef(MyObj& obj)
    : obj(&obj)
  {}

public:
  MyObj* obj = nullptr;
};

TEST(Region, Create)
{
  static_assert(sizeof(MyObj) <= NDNPH_ALIGNMENT, "");
  StaticRegion<NDNPH_ALIGNMENT * 3 - 1> region;

  MyRef ref = region.create<MyRef>();
  ASSERT_THAT(ref.obj, T::NotNull());
  EXPECT_EQ(ref.obj->x, 1);

  ref = region.create<MyRef>(42);
  ASSERT_THAT(ref.obj, T::NotNull());
  EXPECT_EQ(ref.obj->x, 42);
  EXPECT_EQ(region.size(), NDNPH_ALIGNMENT * 2);

  ref = region.create<MyRef>();
  EXPECT_THAT(ref.obj, T::IsNull());
}

} // namespace
} // namespace ndnph
