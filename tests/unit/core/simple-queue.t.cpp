#include "ndnph/core/simple-queue.hpp"

#include "../test-common.hpp"

namespace ndnph {
namespace {

class MyItem
{
public:
  explicit MyItem(uint32_t x = 0)
    : x(x)
  {}

  MyItem(MyItem&&) = default;
  MyItem(const MyItem&) = delete;
  MyItem& operator=(MyItem&&) = default;
  MyItem& operator=(const MyItem&) = delete;

public:
  uint32_t x = 0;
};

TEST(SimpleQueue, Push)
{
  SimpleQueue<MyItem, 4> queue;
  EXPECT_EQ(queue.size(), 0);
  MyItem item;
  bool ok;
  std::tie(item, ok) = queue.pop();
  EXPECT_FALSE(ok);

  EXPECT_TRUE(queue.push(MyItem(1)));
  EXPECT_TRUE(queue.push(MyItem(2)));
  EXPECT_TRUE(queue.push(MyItem(3)));
  EXPECT_EQ(queue.size(), 3);

  std::tie(item, ok) = queue.pop();
  EXPECT_TRUE(ok);
  EXPECT_EQ(item.x, 1);
  EXPECT_EQ(queue.size(), 2);
  EXPECT_FALSE(queue.isFull());

  EXPECT_TRUE(queue.push(MyItem(4)));
  EXPECT_TRUE(queue.push(MyItem(5)));
  EXPECT_FALSE(queue.push(MyItem(6)));
  EXPECT_EQ(queue.size(), 4);
  EXPECT_TRUE(queue.isFull());

  std::tie(item, ok) = queue.pop();
  std::tie(item, ok) = queue.pop();
  std::tie(item, ok) = queue.pop();
  std::tie(item, ok) = queue.pop();
  EXPECT_TRUE(ok);
  EXPECT_EQ(item.x, 5);
  EXPECT_EQ(queue.size(), 0);
}

} // namespace
} // namespace ndnph
