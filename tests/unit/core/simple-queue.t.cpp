#include "ndnph/core/simple-queue.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

class MyItem {
public:
  explicit MyItem(uint32_t x = 0)
    : x(x) {}

  MyItem(MyItem&&) = default;
  MyItem(const MyItem&) = delete;
  MyItem& operator=(MyItem&&) = default;
  MyItem& operator=(const MyItem&) = delete;

public:
  uint32_t x = 0;
};

void
testSimpleQueue(SimpleQueue<MyItem>& queue) {
  EXPECT_EQ(queue.capacity(), 4);
  EXPECT_EQ(queue.size(), 0);
  EXPECT_EQ(queue.available(), 4);
  MyItem item;
  bool ok;
  std::tie(item, ok) = queue.pop();
  EXPECT_FALSE(ok);

  EXPECT_TRUE(queue.push(MyItem(1)));
  EXPECT_TRUE(queue.push(MyItem(2)));
  EXPECT_TRUE(queue.push(MyItem(3)));
  EXPECT_EQ(queue.size(), 3);
  EXPECT_EQ(queue.available(), 1);

  std::tie(item, ok) = queue.pop();
  EXPECT_TRUE(ok);
  EXPECT_EQ(item.x, 1);
  EXPECT_EQ(queue.size(), 2);
  EXPECT_EQ(queue.available(), 2);

  EXPECT_TRUE(queue.push(MyItem(4)));
  EXPECT_TRUE(queue.push(MyItem(5)));
  EXPECT_FALSE(queue.push(MyItem(6)));
  EXPECT_EQ(queue.size(), 4);
  EXPECT_EQ(queue.available(), 0);

  std::tie(item, ok) = queue.pop();
  std::tie(item, ok) = queue.pop();
  std::tie(item, ok) = queue.pop();
  std::tie(item, ok) = queue.pop();
  EXPECT_TRUE(ok);
  EXPECT_EQ(item.x, 5);
  EXPECT_EQ(queue.size(), 0);
  EXPECT_EQ(queue.available(), 4);
}

TEST(SimpleQueue, Static) {
  StaticSimpleQueue<MyItem, 4> queue;
  testSimpleQueue(queue);
}

TEST(SimpleQueue, Dynamic) {
  DynamicSimpleQueue<MyItem> queue(4);
  testSimpleQueue(queue);
}

} // namespace
} // namespace ndnph
