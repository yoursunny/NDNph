#include "ndnph/keychain/certificate.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Certificate, Naming)
{
  StaticRegion<1024> region;
  Name subjectName = Name::parse(region, "/s");
  Name keyName = Name::parse(region, "/s/KEY/k");
  Name certName = Name::parse(region, "/s/KEY/k/i/35=%00");

  EXPECT_FALSE(Certificate::isKeyName(subjectName));
  EXPECT_TRUE(Certificate::isKeyName(keyName));
  EXPECT_FALSE(Certificate::isKeyName(certName));
  EXPECT_FALSE(Certificate::isCertName(subjectName));
  EXPECT_FALSE(Certificate::isCertName(keyName));
  EXPECT_TRUE(Certificate::isCertName(certName));

  EXPECT_EQ(Certificate::toSubjectName(region, subjectName), subjectName);
  EXPECT_EQ(Certificate::toSubjectName(region, keyName), subjectName);
  EXPECT_EQ(Certificate::toSubjectName(region, certName), subjectName);

  EXPECT_TRUE(Certificate::isKeyName(Certificate::toKeyName(region, subjectName)));
  EXPECT_EQ(Certificate::toKeyName(region, keyName), keyName);
  EXPECT_EQ(Certificate::toKeyName(region, certName), keyName);

  EXPECT_TRUE(Certificate::isCertName(Certificate::toCertName(region, subjectName)));
  EXPECT_TRUE(Certificate::isCertName(Certificate::toCertName(region, keyName)));
  EXPECT_EQ(Certificate::toCertName(region, certName), certName);
}

} // namespace
} // namespace ndnph
