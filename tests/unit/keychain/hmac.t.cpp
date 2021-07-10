#include "ndnph/keychain/hmac.hpp"
#include "ndnph/keychain/certificate.hpp"

#include "key-common.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(HmacKey, Short)
{
  // https://datatracker.ietf.org/doc/html/rfc4231#section-4.3
  std::vector<uint8_t> raw({ 0x4A, 0x65, 0x66, 0x65 });
  std::vector<uint8_t> wire({ 0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x79, 0x61,
                              0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x66, 0x6F, 0x72, 0x20,
                              0x6E, 0x6F, 0x74, 0x68, 0x69, 0x6E, 0x67, 0x3F });
  tlv::Value chunk0(&wire[0], 12);
  tlv::Value chunk1(&wire[12], 16);

  HmacKey key;
  ASSERT_TRUE(key.import(raw.data(), raw.size()));

  uint8_t sig[NDNPH_SHA256_LEN];
  EXPECT_EQ(key.getMaxSigLen(), sizeof(sig));
  EXPECT_EQ(key.sign({ chunk0, chunk1 }, sig), sizeof(sig));
  EXPECT_THAT(std::vector<uint8_t>(sig, sig + sizeof(sig)),
              g::ElementsAre(0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E, 0x6A, 0x04, 0x24, 0x26,
                             0x08, 0x95, 0x75, 0xC7, 0x5A, 0x00, 0x3F, 0x08, 0x9D, 0x27, 0x39, 0x83,
                             0x9D, 0xEC, 0x58, 0xB9, 0x64, 0xEC, 0x38, 0x43));

  EXPECT_TRUE(key.verify({ chunk0, chunk1 }, sig, sizeof(sig)));
  EXPECT_TRUE(key.verify({ tlv::Value(wire.data(), wire.size()) }, sig, sizeof(sig)));

  EXPECT_FALSE(key.verify({ chunk0, chunk1 }, sig, sizeof(sig) - 1));

  sig[15] ^= 0x01;
  EXPECT_FALSE(key.verify({ chunk0, chunk1 }, sig, sizeof(sig)));
}

TEST(HmacKey, Long)
{
  // https://datatracker.ietf.org/doc/html/rfc4231#section-4.8
  std::vector<uint8_t> raw(131, 0xAA);
  std::vector<uint8_t> wire(
    { 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74,
      0x20, 0x75, 0x73, 0x69, 0x6E, 0x67, 0x20, 0x61, 0x20, 0x6C, 0x61, 0x72, 0x67, 0x65,
      0x72, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x2D, 0x73,
      0x69, 0x7A, 0x65, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x61, 0x20,
      0x6C, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x62, 0x6C,
      0x6F, 0x63, 0x6B, 0x2D, 0x73, 0x69, 0x7A, 0x65, 0x20, 0x64, 0x61, 0x74, 0x61, 0x2E,
      0x20, 0x54, 0x68, 0x65, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x6E, 0x65, 0x65, 0x64, 0x73,
      0x20, 0x74, 0x6F, 0x20, 0x62, 0x65, 0x20, 0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x20,
      0x62, 0x65, 0x66, 0x6F, 0x72, 0x65, 0x20, 0x62, 0x65, 0x69, 0x6E, 0x67, 0x20, 0x75,
      0x73, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x74, 0x68, 0x65, 0x20, 0x48, 0x4D, 0x41,
      0x43, 0x20, 0x61, 0x6C, 0x67, 0x6F, 0x72, 0x69, 0x74, 0x68, 0x6D, 0x2E });
  tlv::Value chunk0(&wire[0], 3);
  tlv::Value chunk1(&wire[3], 142);
  tlv::Value chunk2(&wire[145], 7);

  HmacKey key;
  ASSERT_TRUE(key.import(raw.data(), raw.size()));

  uint8_t sig[NDNPH_SHA256_LEN];
  EXPECT_EQ(key.sign({ chunk0, chunk1, chunk2 }, sig), sizeof(sig));
  EXPECT_THAT(std::vector<uint8_t>(sig, sig + sizeof(sig)),
              g::ElementsAre(0x9B, 0x09, 0xFF, 0xA7, 0x1B, 0x94, 0x2F, 0xCB, 0x27, 0x63, 0x5F, 0xBC,
                             0xD5, 0xB0, 0xE9, 0x44, 0xBF, 0xDC, 0x63, 0x64, 0x4F, 0x07, 0x13, 0x93,
                             0x8A, 0x7F, 0x51, 0x53, 0x5C, 0x3A, 0x35, 0xE2));

  EXPECT_TRUE(key.verify({ chunk0, chunk1, chunk2 }, sig, sizeof(sig)));
  EXPECT_TRUE(key.verify({ tlv::Value(wire.data(), wire.size()) }, sig, sizeof(sig)));

  EXPECT_FALSE(key.verify({ chunk0, chunk1 }, sig, sizeof(sig) - 1));

  sig[15] ^= 0x01;
  EXPECT_FALSE(key.verify({ chunk0, chunk1 }, sig, sizeof(sig)));
}

TEST(HmacKey, SignVerify)
{
  StaticRegion<1024> region;
  Name nameA = certificate::toKeyName(region, Name::parse(region, "/KA"));
  Name nameB = certificate::toKeyName(region, Name::parse(region, "/KB"));

  std::vector<uint8_t> rawA(20, 0x0B);
  std::vector<uint8_t> rawB(20, 0xAA);
  HmacKey keyA, keyB;
  keyA.setName(nameA);
  keyB.setName(nameB);
  ASSERT_TRUE(keyA.import(rawA.data(), rawA.size()));
  ASSERT_TRUE(keyB.import(rawB.data(), rawB.size()));

  testSignVerify<Interest>(keyA, keyA, keyB, keyB, true, false);
  testSignVerify<Data>(keyA, keyA, keyB, keyB, true, false);
}

} // namespace
} // namespace ndnph