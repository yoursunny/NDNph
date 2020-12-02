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

    sProfile.prefix = Name::parse(sRegion, "/authority/CA");
    ASSERT_TRUE(sProfile.prefix);
    sProfile.maxValidityPeriod = 86400;
    ASSERT_TRUE(ec::generate(sRegion, sProfile.prefix.getPrefix(-1), sPvt, sPub));
    sProfile.cert = sRegion.create<Data>();
    ASSERT_TRUE(
      sProfile.cert.decodeFrom(sPub.selfSign(packetRegion, ValidityPeriod::getMax(), sPvt)));

    Data profileData = packetRegion.create<Data>();
    ASSERT_TRUE(profileData.decodeFrom(sProfile.toData(packetRegion, sPvt)));
    ASSERT_TRUE(cProfile.fromData(cRegion, profileData));
    EXPECT_EQ(test::toString(cProfile.prefix), "/8=authority/8=CA");
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

TEST_F(NdncertFixture, Packets)
{
  DynamicRegion packetRegion(4096);

  client::NopChallenge cNopChallenge;
  client::Session cSession(cProfile, { &cNopChallenge });
  server::NopChallenge sNopChallenge;
  server::Session sSession(sProfile, sPvt, { &sNopChallenge });

  EXPECT_EQ(cSession.getState(), client::Session::State::NEW_REQ);
  auto newRequestInterest = packetRegion.create<Interest>();
  ASSERT_TRUE(newRequestInterest.decodeFrom(cSession.makeNewRequest(packetRegion, cPub, cPvt)));

  auto newResponseData = packetRegion.create<Data>();
  ASSERT_TRUE(
    newResponseData.decodeFrom(sSession.handleNewRequest(packetRegion, newRequestInterest)));

  EXPECT_EQ(cSession.getState(), client::Session::State::NEW_RES);
  ASSERT_TRUE(cSession.handleNewResponse(newResponseData));
  packetRegion.reset();

  EXPECT_FALSE(!!cSession.getIssuedCertName());
  EXPECT_FALSE(cSession.waitForChallenge());

  EXPECT_EQ(cSession.getState(), client::Session::State::CHALLENGE_REQ);
  auto challengeRequestInterest = packetRegion.create<Interest>();
  ASSERT_TRUE(challengeRequestInterest.decodeFrom(cSession.makeChallengeRequest(packetRegion)));

  auto challengeResponseData = packetRegion.create<Data>();
  ASSERT_TRUE(challengeResponseData.decodeFrom(
    sSession.handleChallengeRequest(packetRegion, challengeRequestInterest)));

  EXPECT_EQ(cSession.getState(), client::Session::State::CHALLENGE_RES);
  ASSERT_TRUE(cSession.handleChallengeResponse(challengeResponseData));
  packetRegion.reset();

  EXPECT_EQ(cSession.getState(), client::Session::State::SUCCESS);
  EXPECT_FALSE(cSession.waitForChallenge());
  EXPECT_TRUE(!!cSession.getIssuedCertName());
}

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
  time_t now = time(nullptr);
  ASSERT_TRUE(oUserCert.decodeFrom(oUserPub.buildCertificate(
    oRegion, oUserPvt.getName(), ValidityPeriod(now, now + 3600), oRootPvt)));

  server::PossessionChallenge sPossessionChallenge;
  client::PossessionChallenge cPossessionChallenge(oUserCert, oUserPvt);
  executeWorkflow({ &sPossessionChallenge }, { &cPossessionChallenge });
  EXPECT_THAT(cIssuedCertName, g::StartsWith(test::toString(cPub.getName())));
}

} // namespace
} // namespace ndncert
} // namespace ndnph
