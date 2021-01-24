#ifndef NDNPH_APP_NDNCERT_SERVER_HPP
#define NDNPH_APP_NDNCERT_SERVER_HPP
#ifdef NDNPH_HAVE_MBED

#include "../../face/packet-handler.hpp"
#include "an.hpp"
#include "common.hpp"

namespace ndnph {
namespace ndncert {
namespace server {

class ChallengeRequest;
class ChallengeResponse;

struct ChallengeResult
{
  bool success = false;
  bool decrementRetry = false;
  const char* challengeStatus = "";
  packet_struct::ParameterKV params;
};

/**
 * @brief Server side of a challenge.
 *
 * Subclass instance may store internal state in member fields.
 * An instance can only handle one challenge session at a time.
 */
class Challenge
{
public:
  virtual ~Challenge() = default;

  virtual tlv::Value getId() const = 0;
  virtual int getTimeLimit() const = 0;
  virtual int getRetryLimit() const = 0;

  /** @brief Clear state and prepare the challenge for new session. */
  virtual void clear() = 0;

  /**
   * @brief Process a CHALLENGE request packet.
   * @param region memory region, valid during this invocation only.
   * @param request decoded CHALLENGE request packet. @c request.params is valid during this
   *                invocation only; any necessary information should be copied.
   */
  virtual ChallengeResult process(Region& region, const ChallengeRequest& request) = 0;
};

using ChallengeList = std::array<Challenge*, detail::MaxChallenges::value>;

/** @brief CA profile packet. */
class CaProfile : public packet_struct::CaProfile
{
public:
  /**
   * @brief Build CA profile packet.
   * @param signer private key corresponding to @c cert .
   * @return an Encodable object, or a falsy value upon failure.
   */
  Data::Signed toData(Region& region, EcPrivateKey& signer) const
  {
    Encoder encoder(region);
    encoder.prepend([this](Encoder& encoder) { encoder.prependTlv(TT::CaPrefix, prefix); },
                    [](Encoder& encoder) { encoder.prependTlv(TT::CaInfo); },
                    [this](Encoder& encoder) {
                      encoder.prependTlv(TT::MaxValidityPeriod, tlv::NNI(maxValidityPeriod));
                    },
                    [this](Encoder& encoder) { encoder.prependTlv(TT::CaCertificate, cert); });
    encoder.trim();

    Component version = convention::Version::create(region, convention::TimeValue());
    Component segment = convention::Segment::create(region, 0);
    Name name = prefix.append(region, { getCaComponent(), getInfoComponent(), version, segment });

    Data data = region.create<Data>();
    if (!encoder || !version || !segment || !name || !data) {
      return Data::Signed();
    }
    data.setName(name);
    data.setFreshnessPeriod(30000);
    data.setIsFinalBlock(true);
    data.setContent(tlv::Value(encoder));
    return data.sign(signer);
  }
};

/** @brief NEW request packet. */
class NewRequest : public packet_struct::NewRequest
{
public:
  /** @brief Determine whether @p name is a valid NEW request packet name. */
  static bool isName(const CaProfile& profile, const Name& name)
  {
    return name.size() == profile.prefix.size() + 3 && profile.prefix.isPrefixOf(name) &&
           name[-3] == getCaComponent() && name[-2] == getNewComponent() &&
           name[-1].is<convention::ParamsDigest>();
  }

  /**
   * @brief Extract NEW request from Interest packet.
   * @param interest input Interest packet; it can be freed after this operation.
   * @return whether success.
   */
  bool fromInterest(Region& region, const Interest& interest, const CaProfile& profile,
                    detail::ISigPolicy& signingPolicy)
  {
    return isName(profile, interest.getName()) &&
           EvDecoder::decodeValue(interest.getAppParameters().makeDecoder(),
                                  EvDecoder::def<TT::EcdhPub>(&ecdhPub),
                                  EvDecoder::def<TT::CertRequest>([&](const Decoder::Tlv& d) {
                                    certRequest = region.create<Data>();
                                    return !!certRequest && d.vd().decode(certRequest) &&
                                           pub.import(region, certRequest);
                                  })) &&
           interest.verify(pub) && signingPolicy.check(*interest.getSigInfo());
  }

public:
  /** @brief Requester public key. */
  EcPublicKey pub;
};

/** @brief NEW response packet. */
class NewResponse : public packet_struct::NewResponse
{
public:
  /**
   * @brief Build NEW response packet.
   * @param newRequest NEW request packet.
   * @param challenges list of challenges offered by server.
   * @param signer private key corresponding to CA certificate.
   * @return an Encodable object, or a falsy value upon failure.
   */
  Data::Signed toData(Region& region, const Interest& newRequest, const ChallengeList& challenges,
                      const EcPrivateKey& signer) const
  {
    Encoder encoder(region);
    encoder.prepend(
      [this](Encoder& encoder) { encoder.prependTlv(TT::EcdhPub, ecdhPub); },
      [this](Encoder& encoder) { encoder.prependTlv(TT::Salt, tlv::Value(salt, sizeof(salt))); },
      [this](Encoder& encoder) {
        encoder.prependTlv(TT::RequestId, tlv::Value(requestId, sizeof(requestId)));
      },
      [&challenges](Encoder& encoder) {
        for (auto it = challenges.rbegin(); it != challenges.rend(); ++it) {
          const Challenge* ch = *it;
          if (ch != nullptr) {
            encoder.prependTlv(TT::Challenge, ch->getId());
          }
        }
      });
    encoder.trim();

    Data data = region.create<Data>();
    if (!encoder || !data || !newRequest) {
      return Data::Signed();
    }
    data.setName(newRequest.getName());
    data.setFreshnessPeriod(4000);
    data.setContent(tlv::Value(encoder));
    return data.sign(signer);
  }
};

/** @brief CHALLENGE request packet. */
class ChallengeRequest : public packet_struct::ChallengeRequest<Challenge>
{
public:
  /** @brief Determine whether @p name is a valid CHALLENGE request packet name. */
  static bool isName(const CaProfile& profile, const Name& name)
  {
    return name.size() == profile.prefix.size() + 4 && profile.prefix.isPrefixOf(name) &&
           name[-4] == getCaComponent() && name[-3] == getChallengeComponent() &&
           name[-2].type() == TT::GenericNameComponent &&
           name[-2].length() == detail::RequestIdLen::value &&
           name[-1].is<convention::ParamsDigest>();
  }

  /**
   * @brief Extract requestId from Interest name.
   * @return requestId, or nullptr if @p name is not a valid CHALLENGE request packet name.
   */
  static const uint8_t* parseName(const CaProfile& profile, const Name& name)
  {
    return isName(profile, name) ? name[-2].value() : nullptr;
  }

  /**
   * @brief Extract CHALLENGE request from Interest packet.
   * @param interest input Interest packet; it can be freed after this operation.
   * @return whether success.
   */
  bool fromInterest(Region& region, const Interest& interest, const CaProfile& profile,
                    const uint8_t* requestId, detail::SessionKey& sessionKey,
                    const EcPublicKey& verifier, const ChallengeList& challenges,
                    detail::ISigPolicy& signingPolicy)
  {
    const uint8_t* actualRequestId = parseName(profile, interest.getName());
    if (actualRequestId == nullptr ||
        !std::equal(requestId, requestId + detail::RequestIdLen::value, actualRequestId) ||
        !interest.verify(verifier) || !signingPolicy.check(*interest.getSigInfo())) {
      return false;
    }

    auto decrypted = sessionKey.decrypt(region, interest.getAppParameters(), requestId);
    packet_struct::ParameterKV::Parser paramsParser(params);
    return !!decrypted &&
           EvDecoder::decodeValue(
             decrypted.makeDecoder(),
             EvDecoder::def<TT::SelectedChallenge, false, 1>([&](const Decoder::Tlv& d) {
               for (const auto& ch : challenges) {
                 if (ch == nullptr) {
                   continue;
                 }
                 if (ch->getId() == tlv::Value(d.value, d.length)) {
                   challenge = ch;
                   return true;
                 }
               }
               return false;
             }),
             EvDecoder::def<TT::ParameterKey, true, 2>(
               [&](const Decoder::Tlv& d) { return paramsParser.parseKey(d); }),
             EvDecoder::def<TT::ParameterValue, true, 2>(
               [&](const Decoder::Tlv& d) { return paramsParser.parseValue(d); })) &&
           challenge != nullptr;
  }
};

/** @brief CHALLENGE response packet. */
class ChallengeResponse : public packet_struct::ChallengeResponse
{
public:
  /**
   * @brief Build CHALLENGE response packet.
   * @param challengeRequest CHALLENGE request packet.
   * @param signer private key corresponding to CA certificate.
   * @return an Encodable object, or a falsy value upon failure.
   */
  Data::Signed toData(Region& region, const Interest& challengeRequest, const uint8_t* requestId,
                      detail::SessionKey& sessionKey, const EcPrivateKey& signer) const
  {
    Encoder encoder(region);
    switch (status) {
      case Status::FAILURE:
        break;
      case Status::SUCCESS:
        encoder.prependTlv(TT::IssuedCertName, issuedCertName);
        break;
      default:
        encoder.prepend(
          [this](Encoder& encoder) { encoder.prependTlv(TT::ChallengeStatus, challengeStatus); },
          tlv::NniElement<>(TT::RemainingTries, remainingTries),
          [this](Encoder& encoder) {
            uint64_t remainingTime =
              std::max<int>(0, port::Clock::sub(expireTime, port::Clock::now())) / 1000;
            encoder.prependTlv(TT::RemainingTime, tlv::NNI(remainingTime));
          },
          params);
        break;
    }
    encoder.prepend(tlv::NniElement<>(TT::Status, status));
    encoder.trim();
    if (!encoder) {
      return Data::Signed();
    }
    auto encrypted = sessionKey.encrypt(region, tlv::Value(encoder), requestId);

    Data data = region.create<Data>();
    if (!encrypted || !data || !challengeRequest) {
      return Data::Signed();
    }
    data.setName(challengeRequest.getName());
    data.setFreshnessPeriod(4000);
    data.setContent(encrypted);
    return data.sign(signer);
  }
};

inline Data::Signed
makeError(Region& region, const Interest& interest, uint8_t errorCode, const EcPrivateKey& signer)
{
  Encoder encoder(region);
  encoder.prepend(tlv::NniElement<>(TT::ErrorCode, errorCode),
                  [](Encoder& encoder) { encoder.prependTlv(TT::ErrorInfo); });
  encoder.trim();

  Data data = region.create<Data>();
  if (!encoder || !data || !interest) {
    return Data::Signed();
  }
  data.setName(interest.getName());
  data.setFreshnessPeriod(4000);
  data.setContent(tlv::Value(encoder));
  return data.sign(signer);
}

/** @brief Server session logic. */
class Session
{
public:
  explicit Session(const CaProfile& profile, const EcPrivateKey& signer,
                   const ChallengeList& challenges)
    : m_challengeRegion(makeSubRegion(m_region, 512))
    , m_profile(profile)
    , m_signer(signer)
    , m_challenges(challenges)
    , m_signingPolicy(detail::makeISigPolicy())
  {
    assert(m_challengeRegion != nullptr);
    for (Challenge* ch : challenges) {
      if (ch != nullptr) {
        ch->clear();
      }
    }
  }

  Data::Signed handleNewRequest(Region& packetRegion, const Interest& interest)
  {
    if (!m_newRequest.fromInterest(m_region, interest, m_profile, m_signingPolicy)) {
      return makeError(packetRegion, interest, ErrorCode::BadParameterFormat, m_signer);
    }

    // TODO check ValidityPeriod

    mbedtls::Mpi ecdhPvt;
    if (mbedtls_ecdh_gen_public(mbedtls::P256::group(), &ecdhPvt, &m_newResponse.ecdhPub,
                                mbedtls::rng, nullptr) != 0 ||
        !port::RandomSource::generate(m_newResponse.salt, sizeof(m_newResponse.salt)) ||
        !port::RandomSource::generate(m_newResponse.requestId, sizeof(m_newResponse.requestId)) ||
        !m_sessionKey.makeKey(ecdhPvt, m_newRequest.ecdhPub, m_newResponse.salt,
                              m_newResponse.requestId)) {
      return Data::Signed();
    }
    return m_newResponse.toData(packetRegion, interest, m_challenges, m_signer);
  }

  Data::Signed handleChallengeRequest(Region& packetRegion, const Interest& interest)
  {
    m_challengeRegion->reset();
    Challenge* prevChallenge = m_challengeRequest.challenge;
    if (!m_challengeRequest.fromInterest(*m_challengeRegion, interest, m_profile,
                                         m_newResponse.requestId, m_sessionKey, m_newRequest.pub,
                                         m_challenges, m_signingPolicy)) {
      return makeError(packetRegion, interest, ErrorCode::BadParameterFormat, m_signer);
    }

    auto now = port::Clock::now();
    if (prevChallenge == nullptr) {
      m_challengeResponse.status = Status::CHALLENGE;
      m_challengeResponse.remainingTries = m_challengeRequest.challenge->getRetryLimit();
      m_challengeResponse.expireTime =
        port::Clock::add(now, m_challengeRequest.challenge->getTimeLimit());
    } else if (m_challengeRequest.challenge != prevChallenge) {
      return makeError(packetRegion, interest, ErrorCode::OutOfTries, m_signer);
    }

    if (m_challengeResponse.remainingTries == 0) {
      return makeError(packetRegion, interest, ErrorCode::OutOfTries, m_signer);
    }
    if (port::Clock::isBefore(m_challengeResponse.expireTime, now)) {
      return makeError(packetRegion, interest, ErrorCode::OutOfTime, m_signer);
    }

    ChallengeResult result =
      m_challengeRequest.challenge->process(*m_challengeRegion, m_challengeRequest);
    m_challengeResponse.challengeStatus = tlv::Value::fromString(result.challengeStatus);
    m_challengeResponse.params = result.params;
    if (result.success) {
      m_issuedCert = m_region.create<Data>();
      auto validity = certificate::getValidity(m_newRequest.certRequest);
      if (m_issuedCert.decodeFrom(m_newRequest.pub.buildCertificate(
            m_region, m_newRequest.pub.getName(), validity, m_signer)) &&
          !!(m_challengeResponse.issuedCertName = m_issuedCert.getFullName(m_region))) {
        m_challengeResponse.status = Status::SUCCESS;
      } else {
        m_challengeResponse.status = Status::PENDING;
      }
    } else if (result.decrementRetry) {
      --m_challengeResponse.remainingTries;
    }
    return m_challengeResponse.toData(packetRegion, interest, m_newResponse.requestId, m_sessionKey,
                                      m_signer);
  }

  const Name& getIssuedCertName() const
  {
    return m_challengeResponse.issuedCertName;
  }

  const Data& getIssuedCert() const
  {
    return m_issuedCert;
  }

private:
  StaticRegion<2048> m_region;
  Region* m_challengeRegion = nullptr;
  const CaProfile& m_profile;
  const EcPrivateKey& m_signer;
  ChallengeList m_challenges;
  detail::ISigPolicy m_signingPolicy;
  NewRequest m_newRequest;
  NewResponse m_newResponse;
  detail::SessionKey m_sessionKey;
  ChallengeRequest m_challengeRequest;
  ChallengeResponse m_challengeResponse;
  Data m_issuedCert;
};

/** @brief Server application. */
class Server : public PacketHandler
{
public:
  struct Options
  {
    /** @brief Face for communication. */
    Face& face;

    /** @brief CA profile. */
    const CaProfile& profile;

    /** @brief List of offered challenges. */
    const ChallengeList& challenges;

    /** @brief CA private key. */
    const EcPrivateKey& signer;
  };

  explicit Server(const Options& opts)
    : PacketHandler(opts.face)
    , m_profile(opts.profile)
    , m_challenges(opts.challenges)
    , m_signer(opts.signer)
  {}

private:
  bool processInterest(Interest interest) final
  {
    StaticRegion<1024> packetRegion;
    const Name& interestName = interest.getName();
    if (NewRequest::isName(m_profile, interestName)) {
      m_session.reset(new Session(m_profile, m_signer, m_challenges));
      reply(m_session->handleNewRequest(packetRegion, interest));
      return true;
    } else if (m_session != nullptr && ChallengeRequest::isName(m_profile, interestName)) {
      reply(m_session->handleChallengeRequest(packetRegion, interest));
      return true;
    } else if (m_session != nullptr && m_session->getIssuedCertName() == interestName) {
      reply(m_session->getIssuedCert());
      return true;
    }
    return false;
  }

private:
  const CaProfile& m_profile;
  ChallengeList m_challenges;
  const EcPrivateKey& m_signer;
  std::unique_ptr<Session> m_session;
};

/** @brief The "nop" challenge where the server would approve every request. */
class NopChallenge : public Challenge
{
public:
  tlv::Value getId() const override
  {
    return challenge_consts::nop();
  }

  int getTimeLimit() const override
  {
    return 60000;
  }

  int getRetryLimit() const override
  {
    return 1;
  }

  void clear() override {}

  ChallengeResult process(Region&, const ChallengeRequest&) override
  {
    ChallengeResult result;
    result.success = true;
    return result;
  }
};

/** @brief The "possession" challenge where client must present an existing certificate. */
class PossessionChallenge : public Challenge
{
public:
  tlv::Value getId() const override
  {
    return challenge_consts::possession();
  }

  int getTimeLimit() const override
  {
    return 60000;
  }

  int getRetryLimit() const override
  {
    return 1;
  }

  void clear() override
  {
    m_cert = tlv::Value();
  }

  ChallengeResult process(Region&, const ChallengeRequest& request) override
  {
    tlv::Value proof = request.params.get(challenge_consts::proof());
    if (!proof) {
      return process0(request);
    }

    ChallengeResult result;
    result.success = process1(proof);
    result.decrementRetry = !result.success;
    return result;
  }

private:
  ChallengeResult process0(const ChallengeRequest& request)
  {
    m_cert = request.params.get(challenge_consts::issuedcert());

    StaticRegion<2048> temp;
    ndnph::Data data = temp.create<ndnph::Data>();
    assert(!!data);

    m_region.reset();
    if (!(m_cert.makeDecoder().decode(data) && m_pub.import(temp, data) &&
          certificate::getValidity(data).includesUnix())) {
      // don't reveal the error until proof is submitted
      m_pub = EcPublicKey();
    }
    // TODO check certificate revocation
    // TODO check name assignment policy

    ChallengeResult result;
    if (!port::RandomSource::generate(m_nonce, sizeof(m_nonce))) {
      // server error, decrement retry to fail the challenge
      result.decrementRetry = true;
      result.challengeStatus = "server-error";
      return result;
    }

    result.challengeStatus = "need-proof";
    result.params.set(challenge_consts::nonce(), tlv::Value(m_nonce, sizeof(m_nonce)));
    return result;
  }

  bool process1(tlv::Value proof)
  {
    return m_pub.verify({ tlv::Value(m_nonce, sizeof(m_nonce)) }, proof.begin(), proof.size());
  }

private:
  StaticRegion<256> m_region;
  EcPublicKey m_pub;
  tlv::Value m_cert;
  uint8_t m_nonce[16];
};

} // namespace server

using Server = server::Server;

} // namespace ndncert
} // namespace ndnph

#endif // NDNPH_HAVE_MBED
#endif // NDNPH_APP_NDNCERT_SERVER_HPP
