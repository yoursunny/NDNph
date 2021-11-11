#include "ndnph/keychain/certificate.hpp"

#include "test-common.hpp"

namespace ndnph {
namespace {

TEST(Certificate, Naming)
{
  StaticRegion<1024> region;
  Name subjectName = Name::parse(region, "/s");
  Name keyName = Name::parse(region, "/s/KEY/k");
  Name certName = Name::parse(region, "/s/KEY/k/i/54=%00");
  Component keyId = keyName[-1];
  Component issuerId = certName[-2];
  Component version = certName[-1];

  EXPECT_FALSE(certificate::isKeyName(subjectName));
  EXPECT_TRUE(certificate::isKeyName(keyName));
  EXPECT_FALSE(certificate::isKeyName(certName));
  EXPECT_FALSE(certificate::isCertName(subjectName));
  EXPECT_FALSE(certificate::isCertName(keyName));
  EXPECT_TRUE(certificate::isCertName(certName));

  EXPECT_EQ(certificate::toSubjectName(region, subjectName), subjectName);
  EXPECT_EQ(certificate::toSubjectName(region, keyName), subjectName);
  EXPECT_EQ(certificate::toSubjectName(region, certName), subjectName);

  EXPECT_TRUE(certificate::isKeyName(certificate::toKeyName(region, subjectName)));
  EXPECT_EQ(certificate::toKeyName(region, keyName), keyName);
  EXPECT_EQ(certificate::toKeyName(region, certName), keyName);

  EXPECT_TRUE(certificate::isCertName(certificate::toCertName(region, subjectName)));
  EXPECT_TRUE(certificate::isCertName(certificate::toCertName(region, keyName)));
  EXPECT_EQ(certificate::toCertName(region, certName), certName);

  EXPECT_EQ(certificate::makeKeyName(region, subjectName, keyId), keyName);
  EXPECT_EQ(certificate::makeCertName(region, keyName, issuerId, version), certName);
  EXPECT_TRUE(certificate::isCertName(certificate::makeCertName(region, keyName, issuerId)));
}

} // namespace
} // namespace ndnph
