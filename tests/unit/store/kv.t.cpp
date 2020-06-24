#include "ndnph/store/kv.hpp"

#include "mock/tempdir-fixture.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

using KvStoreFixture = TempDirFixture;

TEST_F(KvStoreFixture, Simple)
{
  KvStore store;
  bool ok = store.open((tempDir + "/sub/dir").data());
  ASSERT_TRUE(ok);

  StaticRegion<1024> region;
  tlv::Value v0 = store.get("non-existent", region);
  EXPECT_EQ(v0.size(), 0);
  EXPECT_EQ(region.available(), 1024);

  uint8_t buf[257];
  memset(buf, 0xA1, sizeof(buf));
  ok = store.set("UPPER", tlv::Value(buf, sizeof(buf)));
  EXPECT_FALSE(ok);
  ok = store.set("item", tlv::Value(buf, sizeof(buf)));
  ASSERT_TRUE(ok);

  tlv::Value v1 = store.get("item", region);
  EXPECT_THAT(std::vector<uint8_t>(v1.begin(), v1.end()), g::ElementsAreArray(buf, sizeof(buf)));
  EXPECT_EQ(region.available(), 767);

  ok = store.del("item");
  EXPECT_TRUE(ok);
  tlv::Value v2 = store.get("item", region);
  EXPECT_EQ(v2.size(), 0);
}

} // namespace
} // namespace ndnph
