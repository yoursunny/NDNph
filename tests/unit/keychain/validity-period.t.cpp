#include "ndnph/keychain/validity-period.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(ValidityPeriod, Normal) {
  auto wire = test::fromHex("FD00FD26"
                            "FD00FE0F 323031383131313354303835383439" // 20181113T085849
                            "FD00FF0F 323032303130313154313633383033" // 20201011T163803
  );
  ValidityPeriod vp;
  vp.notBefore = 1542099529;
  vp.notAfter = 1602434283;
  {
    StaticRegion<1024> region;
    Encoder encoder(region);
    bool ok = encoder.prepend(vp);
    ASSERT_TRUE(ok);
    EXPECT_THAT(std::vector<uint8_t>(encoder.begin(), encoder.end()), g::ElementsAreArray(wire));
  }

  ValidityPeriod decoded;
  ASSERT_TRUE(Decoder(wire.data(), wire.size()).decode(decoded));
  EXPECT_EQ(decoded.notBefore, 1542099529);
  EXPECT_EQ(decoded.notAfter, 1602434283);
}

TEST(ValidityPeriod, DecodeBadLength) {
  auto wire = test::fromHex("FD00FD25"
                            "FD00FE0F 323031383131313354303835383439" // 20181113T085849
                            "FD00FF0E 3230323031303131543136333830"   // 20201011T16380
  ); // NotAfter is missing one byte
  ValidityPeriod vp;
  EXPECT_FALSE(Decoder(wire.data(), wire.size()).decode(vp));
}

TEST(ValidityPeriod, DecodeBadValue) {
  auto wire = test::fromHex("FD00FD25"
                            "FD00FE0F 323031383131313341303835383439" // 20181113A085849
                            "FD00FF0E 323032303130313154313633383033" // 20201011T163803
  ); // NotBefore has 'A' instead of 'T'
  ValidityPeriod vp;
  EXPECT_FALSE(Decoder(wire.data(), wire.size()).decode(vp));
}

TEST(ValidityPeriod, Includes) {
  ValidityPeriod vp(1542099529, 1602434283);
  EXPECT_FALSE(vp.includes(1083820612));
  EXPECT_FALSE(vp.includes(1542099528));
  EXPECT_TRUE(vp.includes(1542099529));
  EXPECT_TRUE(vp.includes(1569790373));
  EXPECT_TRUE(vp.includes(1602434283));
  EXPECT_FALSE(vp.includes(1602434284));
  EXPECT_FALSE(vp.includes(1927427784));

  vp = ValidityPeriod();
  EXPECT_FALSE(vp.includes(1083820612));
  EXPECT_FALSE(vp.includes(1569790373));
  EXPECT_FALSE(vp.includes(1927427784));
}

TEST(ValidityPeriod, Intersect) {
  ValidityPeriod vp1(1542099529, 1602434283);
  ValidityPeriod vp2(1543017600, 1609372800);
  EXPECT_EQ((vp1 && vp2).notBefore, 1543017600);
  EXPECT_EQ((vp1 && vp2).notAfter, 1602434283);

  ValidityPeriod vp0 = ValidityPeriod::getMax() && vp1 && vp2;
  EXPECT_EQ(vp0, ValidityPeriod(1543017600, 1602434283));
}

} // namespace
} // namespace ndnph
