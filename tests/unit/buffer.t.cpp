#include "ndnph/buffer.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Buffer, Alloc_Dup)
{
  StaticBuffer<60> buffer;
  EXPECT_EQ(buffer.size(), 0);

  uint8_t* a0 = buffer.alloc(12);
  EXPECT_THAT(a0, T::NotNull());
  EXPECT_EQ(buffer.size(), 12);

  std::vector<uint8_t> b1({ 0xB0, 0xB1, 0xB2, 0xB3, 0xB4 });
  uint8_t* a1 = buffer.dup(b1.data(), b1.size());
  EXPECT_THAT(a1, T::NotNull());
  EXPECT_EQ(a0 - a1, 5);
  EXPECT_EQ(buffer.size(), 17);
  EXPECT_TRUE(std::equal(b1.begin(), b1.end(), a1));

  uint8_t* a2 = buffer.alloc(50);
  EXPECT_THAT(a2, T::IsNull());

  std::vector<uint8_t> b3(50);
  uint8_t* a3 = buffer.dup(b3.data(), b3.size());
  EXPECT_THAT(a3, T::IsNull());
}

TEST(Buffer, AllocA)
{
  DynamicBuffer buffer(60);
  EXPECT_EQ(buffer.size(), 0);

  uint8_t* a0 = buffer.allocA(9);
  EXPECT_THAT(a0, T::NotNull());
  EXPECT_EQ(buffer.size(), NDNPH_ALIGNMENT == 8 ? 16 : 12);

  uint8_t* a1 = buffer.allocA(8);
  EXPECT_THAT(a1, T::NotNull());
  EXPECT_EQ(a1 - a0, NDNPH_ALIGNMENT == 8 ? 16 : 12);
  EXPECT_EQ(buffer.size(), NDNPH_ALIGNMENT == 8 ? 24 : 20);

  uint8_t* a2 = buffer.allocA(50);
  EXPECT_THAT(a2, T::IsNull());
}

class MyRef;

class MyObj
{
public:
  using RefType = MyRef;

  explicit MyObj(Buffer& buffer, uint32_t x = 1)
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

TEST(Buffer, Create)
{
  static_assert(sizeof(MyObj) <= NDNPH_ALIGNMENT, "");
  StaticBuffer<NDNPH_ALIGNMENT * 3 - 1> buffer;

  MyRef ref = buffer.create<MyRef>();
  ASSERT_THAT(ref.obj, T::NotNull());
  EXPECT_EQ(ref.obj->x, 1);

  ref = buffer.create<MyRef>(42);
  ASSERT_THAT(ref.obj, T::NotNull());
  EXPECT_EQ(ref.obj->x, 42);
  EXPECT_EQ(buffer.size(), NDNPH_ALIGNMENT * 2);

  ref = buffer.create<MyRef>();
  EXPECT_THAT(ref.obj, T::IsNull());
}

} // namespace
} // namespace ndnph
