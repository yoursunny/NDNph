#include "ndnph/app/ndncert/client.hpp"
#include "ndnph/app/ndncert/server.hpp"

#include "mock/bridge-fixture.hpp"
#include "test-common.hpp"

namespace ndnph {
namespace ndncert {
namespace {

class NdncertFixture : public BridgeFixture
{
protected:
  NdncertFixture()
    : sRegion(4096)
    , cRegion(4096)
  {}

  void SetUp() override
  {
    DynamicRegion packetRegion(4096);

    sProfile.prefix = Name::parse(sRegion, "/authority");
    ASSERT_TRUE(sProfile.prefix);
    sProfile.maxValidityPeriod = 86400;
    ASSERT_TRUE(ec::generate(sRegion, sProfile.prefix.getPrefix(-1), sPvt, sPub));
    sProfile.cert = sRegion.create<Data>();
    ASSERT_TRUE(
      sProfile.cert.decodeFrom(sPub.selfSign(packetRegion, ValidityPeriod::getMax(), sPvt)));

    Data profileData = packetRegion.create<Data>();
    ASSERT_TRUE(profileData.decodeFrom(sProfile.toData(packetRegion, sPvt)));
    EXPECT_EQ(test::toString(profileData.getName().getPrefix(3)), "/8=authority/8=CA/8=INFO");
    ASSERT_TRUE(cProfile.fromData(cRegion, profileData));
    EXPECT_EQ(test::toString(cProfile.prefix), "/8=authority");
    EXPECT_EQ(cProfile.maxValidityPeriod, 86400);

    Name cName = Name::parse(cRegion, "/client");
    ASSERT_TRUE(ec::generate(cRegion, cName, cPvt, cPub));
  }

  static void clientCallback(void* ctx, Data cert)
  {
    auto self = reinterpret_cast<NdncertFixture*>(ctx);
    if (!!cert) {
      EXPECT_TRUE(ec::isCertificate(cert));
      self->cIssuedCertName = test::toString(cert.getName());
    } else {
      self->cIssuedCertName = "FAIL";
    }
  }

  void executeWorkflow(server::ChallengeList sChallenges, client::ChallengeList cChallenges)
  {
    server::NopChallenge sNopChallenge;
    Server server(Server::Options{
      .face = faceA,
      .profile = sProfile,
      .challenges = sChallenges,
      .signer = sPvt,
    });

    client::NopChallenge cNopChallenge;
    runInThreads(
      [&] {
        Client::requestCertificate(Client::Options{
          .face = faceB,
          .profile = cProfile,
          .challenges = cChallenges,
          .pub = cPub,
          .pvt = cPvt,
          .cb = clientCallback,
          .ctx = this,
        });
      },
      [=] { return cIssuedCertName.empty(); });
  }

protected:
  DynamicRegion sRegion;
  DynamicRegion cRegion;
  server::CaProfile sProfile;
  EcPrivateKey sPvt;
  EcPublicKey sPub;
  client::CaProfile cProfile;
  EcPrivateKey cPvt;
  EcPublicKey cPub;
  std::string cIssuedCertName;
};

TEST_F(NdncertFixture, WorkflowNop)
{
  server::NopChallenge sNopChallenge;
  client::NopChallenge cNopChallenge;
  executeWorkflow({ &sNopChallenge }, { &cNopChallenge });
  EXPECT_THAT(cIssuedCertName, g::StartsWith(test::toString(cPub.getName())));
}

TEST_F(NdncertFixture, WorkflowPossession)
{
  DynamicRegion oRegion(4095);
  EcPrivateKey oRootPvt;
  EcPublicKey oRootPub;
  ASSERT_TRUE(ec::generate(oRegion, Name::parse(oRegion, "/root"), oRootPvt, oRootPub));
  auto oRootCert = oRegion.create<Data>();
  ASSERT_TRUE(oRootCert.decodeFrom(oRootPub.selfSign(oRegion, ValidityPeriod::getMax(), oRootPvt)));
  EcPrivateKey oUserPvt;
  EcPublicKey oUserPub;
  ASSERT_TRUE(ec::generate(oRegion, Name::parse(oRegion, "/requester"), oUserPvt, oUserPub));
  auto oUserCert = oRegion.create<Data>();
  ASSERT_TRUE(oUserCert.decodeFrom(oUserPub.buildCertificate(
    oRegion, oUserPvt.getName(), ValidityPeriod::secondsFromNow(3600), oRootPvt)));

  server::PossessionChallenge sPossessionChallenge;
  client::PossessionChallenge cPossessionChallenge(oUserCert, oUserPvt);
  executeWorkflow({ &sPossessionChallenge }, { &cPossessionChallenge });
  EXPECT_THAT(cIssuedCertName, g::StartsWith(test::toString(cPub.getName())));
}

} // namespace
} // namespace ndncert
} // namespace ndnph
