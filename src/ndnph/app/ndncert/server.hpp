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
};

class Challenge
{
public:
  virtual ~Challenge() = default;
  virtual tlv::Value getId() const = 0;
  virtual int getTimeLimit() const = 0;
  virtual int getRetryLimit() const = 0;
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
  detail::SignedDataRef toData(Region& region, EcPrivateKey& signer) const
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
    Name name = prefix.append(region, { getInfoComponent(), version, segment });

    Data data = region.create<Data>();
    if (!encoder || !version || !segment || !name || !data) {
      return detail::SignedDataRef();
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
    return name.size() == profile.prefix.size() + 2 && profile.prefix.isPrefixOf(name) &&
           name[-2] == getNewComponent() && name[-1].is<convention::ParamsDigest>();
  }

  /**
   * @brief Extract NEW request from Interest packet.
   * @param interest input Interest packet; it can be freed after this operation.
   * @return whether success.
   */
  bool fromInterest(Region& region, const Interest& interest, const CaProfile& profile)
  {
    return isName(profile, interest.getName()) &&
           EvDecoder::decodeValue(interest.getAppParameters().makeDecoder(),
                                  EvDecoder::def<TT::EcdhPub>(&ecdhPub),
                                  EvDecoder::def<TT::CertRequest>([&](const Decoder::Tlv& d) {
                                    certRequest = region.create<Data>();
                                    return !!certRequest && d.vd().decode(certRequest) &&
                                           pub.import(region, certRequest);
                                  })) &&
           interest.verify(pub);
    // TODO validate SigNonce and SigTime
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
  detail::SignedDataRef toData(Region& region, const Interest& newRequest,
                               const ChallengeList& challenges, const EcPrivateKey& signer) const
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
      return detail::SignedDataRef();
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
    return name.size() == profile.prefix.size() + 3 && profile.prefix.isPrefixOf(name) &&
           name[-3] == getChallengeComponent() && name[-2].type() == TT::GenericNameComponent &&
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
                    const EcPublicKey& verifier, const ChallengeList& challenges)
  {
    const uint8_t* actualRequestId = parseName(profile, interest.getName());
    if (actualRequestId == nullptr ||
        !std::equal(requestId, requestId + detail::RequestIdLen::value, actualRequestId) ||
        !interest.verify(verifier)) {
      return false;
    }
    // TODO validate SigNonce and SigTime

    auto decrypted = sessionKey.decrypt(region, interest.getAppParameters(), requestId);
    size_t paramIndex = 0;
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
             EvDecoder::def<TT::ParameterKey, true, 2>([&](const Decoder::Tlv& d) {
               if (paramIndex >= detail::MaxChallengeParams::value) {
                 return false;
               }
               params[paramIndex] = std::make_pair(tlv::Value(d.value, d.length), tlv::Value());
               return true;
             }),
             EvDecoder::def<TT::ParameterValue, true, 2>([&](const Decoder::Tlv& d) {
               if (paramIndex >= detail::MaxChallengeParams::value) {
                 return false;
               }
               auto key = params[paramIndex].first;
               params[paramIndex] = std::make_pair(key, tlv::Value(d.value, d.length));
               ++paramIndex;
               return true;
             })) &&
           challenge != nullptr;
  }

  /** @brief Retrieve parameter value by parameter key. */
  tlv::Value get(tlv::Value key) const
  {
    for (const auto& kv : params) {
      if (kv.first == key) {
        return kv.second;
      }
    }
    return tlv::Value();
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
  detail::SignedDataRef toData(Region& region, const Interest& challengeRequest,
                               const uint8_t* requestId, detail::SessionKey& sessionKey,
                               const EcPrivateKey& signer) const
  {
    Encoder encoder(region);
    encoder.prepend(
      [this](Encoder& encoder) { encoder.prependTlv(TT::Status, tlv::NNI(status)); },
      [this](Encoder& encoder) { encoder.prependTlv(TT::ChallengeStatus, challengeStatus); },
      [this](Encoder& encoder) {
        encoder.prependTlv(TT::RemainingTries, tlv::NNI(remainingTries));
      },
      [this](Encoder& encoder) {
        uint64_t remainingTime =
          std::max(0, port::Clock::sub(expireTime, port::Clock::now())) / 1000;
        encoder.prependTlv(TT::RemainingTime, tlv::NNI(remainingTime));
      },
      [&](Encoder& encoder) {
        if (!!issuedCertName) {
          encoder.prependTlv(TT::IssuedCertName, issuedCertName);
        }
      });
    encoder.trim();
    if (!encoder) {
      return detail::SignedDataRef();
    }
    auto encrypted = sessionKey.encrypt(region, tlv::Value(encoder), requestId);

    Data data = region.create<Data>();
    if (!encrypted || !data || !challengeRequest) {
      return detail::SignedDataRef();
    }
    data.setName(challengeRequest.getName());
    data.setFreshnessPeriod(4000);
    data.setContent(encrypted);
    return data.sign(signer);
  }
};

inline detail::SignedDataRef
makeError(Region& region, const Interest& interest, uint8_t errorCode, const EcPrivateKey& signer)
{
  Encoder encoder(region);
  encoder.prepend(
    [errorCode](Encoder& encoder) { encoder.prependTlv(TT::ErrorCode, tlv::NNI(errorCode)); },
    [](Encoder& encoder) { encoder.prependTlv(TT::ErrorInfo, tlv::Value()); });
  encoder.trim();

  Data data = region.create<Data>();
  if (!encoder || !data || !interest) {
    return detail::SignedDataRef();
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
  {
    assert(m_challengeRegion != nullptr);
  }

  detail::SignedDataRef handleNewRequest(Region& packetRegion, const Interest& interest)
  {
    if (!m_newRequest.fromInterest(m_region, interest, m_profile)) {
      return makeError(packetRegion, interest, ErrorCode::BadParameterFormat, m_signer);
    }

    mbedtls::Mpi ecdhPvt;
    if (mbedtls_ecdh_gen_public(mbedtls::P256::group(), &ecdhPvt, &m_newResponse.ecdhPub,
                                mbedtls::rng, nullptr) != 0 ||
        !port::RandomSource::generate(m_newResponse.salt, sizeof(m_newResponse.salt)) ||
        !port::RandomSource::generate(m_newResponse.requestId, sizeof(m_newResponse.requestId)) ||
        !m_sessionKey.makeKey(ecdhPvt, m_newRequest.ecdhPub, m_newResponse.salt,
                              m_newResponse.requestId, detail::SessionKey::Role::ISSUER)) {
      return detail::SignedDataRef();
    }
    return m_newResponse.toData(packetRegion, interest, m_challenges, m_signer);
  }

  detail::SignedDataRef handleChallengeRequest(Region& packetRegion, const Interest& interest)
  {
    m_challengeRegion->reset();
    Challenge* prevChallenge = m_challengeRequest.challenge;
    if (!m_challengeRequest.fromInterest(*m_challengeRegion, interest, m_profile,
                                         m_newResponse.requestId, m_sessionKey, m_newRequest.pub,
                                         m_challenges)) {
      return makeError(packetRegion, interest, ErrorCode::BadParameterFormat, m_signer);
    }
    // TODO check policy on whether the requested name is allowed

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
    if (result.success) {
      m_issuedCert = m_region.create<Data>();
      auto validity = ValidityPeriod::getMax(); // TODO set proper ValidityPeriod
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
      send(m_session->handleNewRequest(packetRegion, interest));
      return true;
    } else if (m_session != nullptr && ChallengeRequest::isName(m_profile, interestName)) {
      send(m_session->handleChallengeRequest(packetRegion, interest));
      return true;
    } else if (m_session != nullptr && m_session->getIssuedCertName() == interestName) {
      send(m_session->getIssuedCert());
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
    static auto id = tlv::Value::fromString("nop");
    return id;
  }

  int getTimeLimit() const override
  {
    return 1000;
  }

  int getRetryLimit() const override
  {
    return 1;
  }

  ChallengeResult process(Region&, const ChallengeRequest&) override
  {
    ChallengeResult result;
    result.success = true;
    result.challengeStatus = "success";
    return result;
  }
};

} // namespace server

using Server = server::Server;

} // namespace ndncert
} // namespace ndnph

#endif // NDNPH_HAVE_MBED
#endif // NDNPH_APP_NDNCERT_SERVER_HPP
