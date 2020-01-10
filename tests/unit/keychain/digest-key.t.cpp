#include "ndnph/keychain/digest-key.hpp"
#include "ndnph/packet/data.hpp"
#include "ndnph/packet/interest.hpp"
#include "ndnph/port/mbedtls/typedef.hpp"

#include "../test-common.hpp"
#include "key-common.hpp"

namespace ndnph {
namespace {

TEST(DigestKey, Minimal)
{
  std::vector<uint8_t> wire({ 0xA0, 0xA1, 0xB0, 0xB1, 0xB2, 0xB3 });
  tlv::Value chunk0(&wire[0], 2);
  tlv::Value chunk1(&wire[2], 4);

  DigestKey key;
  uint8_t sig[NDNPH_SHA256_LEN];
  EXPECT_EQ(decltype(key)::MaxSigLen::value, sizeof(sig));
  EXPECT_EQ(key.sign({ chunk0, chunk1 }, sig), sizeof(sig));
  EXPECT_THAT(std::vector<uint8_t>(sig, sig + sizeof(sig)),
              T::ElementsAre(0x4F, 0xBF, 0x10, 0xA6, 0x42, 0xCA, 0xF3, 0xC2,
                             0x15, 0x78, 0x3D, 0x89, 0x3F, 0x2E, 0x88, 0xCF,
                             0x2D, 0x00, 0x67, 0xE5, 0x22, 0x00, 0x5B, 0x17,
                             0x9A, 0x5C, 0x80, 0x9A, 0xF8, 0x44, 0xB8, 0xB5));
  // echo -ne '\xA0\xA1\xB0\xB1\xB2\xB3' | openssl sha256 -binary | xxd -i -u | tr 'X' 'x'

  EXPECT_TRUE(key.verify({ chunk0, chunk1 }, sig, sizeof(sig)));

  EXPECT_FALSE(key.verify({ chunk0, chunk1 }, sig, sizeof(sig) - 1));

  sig[15] ^= 0x01;
  EXPECT_FALSE(key.verify({ chunk0, chunk1 }, sig, sizeof(sig)));
}

TEST(DigestKey, SignVerify)
{
  DigestKey key;
  testSignVerify<Interest>(key, key, key, key, true, true);
  testSignVerify<Data>(key, key, key, key, true, true);
}

} // namespace
} // namespace ndnph
