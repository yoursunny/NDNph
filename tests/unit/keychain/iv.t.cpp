#include "ndnph/keychain/iv.hpp"

#include "key-common.hpp"
#include "mock/tempdir-fixture.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(AesGcmIvHelper, Generate) {
  AesGcmIvHelper h;
  ASSERT_TRUE(h.randomize());

  uint8_t iv00[12];
  EXPECT_TRUE(h.write(iv00));
  EXPECT_THAT(std::vector<uint8_t>(&iv00[8], &iv00[12]), g::ElementsAre(0x00, 0x00, 0x00, 0x00));
  EXPECT_TRUE(h.advance(16 * 0x18));

  uint8_t iv18[12];
  EXPECT_TRUE(h.write(iv18));
  EXPECT_THAT(std::vector<uint8_t>(&iv18[8], &iv18[12]), g::ElementsAre(0x00, 0x00, 0x00, 0x18));
  EXPECT_EQ(std::vector<uint8_t>(&iv18[0], &iv18[8]), std::vector<uint8_t>(&iv00[0], &iv00[8]));
  EXPECT_TRUE(h.advance(16 * static_cast<uint64_t>(0xFFFFFFE6) - 1));

  uint8_t ivFFFFFFFE[12];
  EXPECT_TRUE(h.write(ivFFFFFFFE));
  EXPECT_THAT(std::vector<uint8_t>(&ivFFFFFFFE[8], &ivFFFFFFFE[12]),
              g::ElementsAre(0xFF, 0xFF, 0xFF, 0xFE));
  EXPECT_EQ(std::vector<uint8_t>(&ivFFFFFFFE[0], &ivFFFFFFFE[8]),
            std::vector<uint8_t>(&iv00[0], &iv00[8]));
  EXPECT_FALSE(h.advance(16 * 0x03 - 2)); // counter overflow
}

TEST(AesGcmIvHelper, Check) {
  AesGcmIvHelper h;

  uint8_t iv00[12] = {0x11, 0xFF, 0xCD, 0x96, 0x03, 0x98, 0x14, 0x59, 0x00, 0x00, 0x00, 0x00};
  EXPECT_TRUE(h.check(iv00, 16 * 0x18));

  {
    AesGcmIvHelper w = h;
    uint8_t iv[12] = {0x12, 0xFF, 0xCD, 0x96, 0x03, 0x98, 0x14, 0x59, 0x00, 0x00, 0x00, 0x18};
    EXPECT_FALSE(w.check(iv, 1)); // different random portion
  }

  {
    AesGcmIvHelper w = h;
    uint8_t iv[12] = {0x11, 0xFF, 0xCD, 0x96, 0x03, 0x98, 0x14, 0x59, 0x00, 0x00, 0x00, 0x17};
    EXPECT_FALSE(w.check(iv, 1)); // counter overlap
  }

  uint8_t iv18[12] = {0x11, 0xFF, 0xCD, 0x96, 0x03, 0x98, 0x14, 0x59, 0x00, 0x00, 0x00, 0x18};
  EXPECT_TRUE(h.check(iv18, 16 * static_cast<uint64_t>(0xFFFFFFE6) - 1));

  uint8_t ivFFFFFFFE[12] = {0x11, 0xFF, 0xCD, 0x96, 0x03, 0x98, 0x14, 0x59, 0xFF, 0xFF, 0xFF, 0xFE};
  EXPECT_FALSE(h.check(ivFFFFFFFE, 16 * 0x03 - 2)); // counter overflow
}

} // namespace
} // namespace ndnph
