#ifndef NDNPH_APP_NDNCERT_CLIENT_HPP
#define NDNPH_APP_NDNCERT_CLIENT_HPP
#ifdef NDNPH_HAVE_MBED

#include "../../face/packet-handler.hpp"
#include "an.hpp"
#include "common.hpp"

namespace ndnph {
namespace ndncert {
namespace client {

class ChallengeRequest;
class ChallengeResponse;

/**
 * @brief Client side of a challenge.
 *
 * Subclass instance may store internal state in member fields.
 * An instance can only handle one challenge session at a time.
 */
class Challenge
{
public:
  virtual ~Challenge() = default;

  /** @brief Return challenge identifier. */
  virtual tlv::Value getId() const = 0;

  /**
   * @brief Create a message to select and start the challenge.
   *
   * This function should clear any existing state, populate the @c request , and invoke
   * `cb(arg,true)`; in case of error, invoke `cb(arg,false)`.
   */
  virtual void start(Region& region, ChallengeRequest& request, void (*cb)(void*, bool),
                     void* arg) = 0;

  /**
   * @brief Create a message to continue the challenge.
   *
   * This function should clear any existing state, populate the @c request , and invoke
   * `cb(arg,true)`; in case of error, invoke `cb(arg,false)`.
   */
  virtual void next(Region& region, const ChallengeResponse& response, ChallengeRequest& request,
                    void (*cb)(void*, bool), void* arg) = 0;
};

using ChallengeList = std::array<Challenge*, detail::MaxChallenges::value>;

/** @brief CA profile packet. */
class CaProfile : public packet_struct::CaProfile
{
public:
  /** @brief Determine whether @p name is a valid CA profile packet name. */
  static bool isName(const Name& name)
  {
    return name.size() >= 4 && name[-4] == getCaComponent() && name[-3] == getInfoComponent() &&
           name[-2].is<convention::Version>() && name[-1].is<convention::Segment>() &&
           name[-1].as<convention::Segment>() == 0;
  }

  /**
   * @brief Extract CA profile from Data packet.
   * @param data input Data packet; it can be freed after this operation.
   * @return whether success.
   */
  bool fromData(Region& region, const Data& data)
  {
    return isName(data.getName()) &&
           EvDecoder::decodeValue(
             data.getContent().makeDecoder(),
             EvDecoder::def<TT::CaPrefix>([&](const Decoder::Tlv& d) {
               if (!d.vd().decode(prefix) || data.getName().getPrefix(-3) != prefix) {
                 return false;
               }
               prefix = prefix.clone(region);
               return !!prefix;
             }),
             EvDecoder::defIgnore<TT::CaInfo>(), EvDecoder::defIgnore<TT::ParameterKey, true>(),
             EvDecoder::defNni<TT::MaxValidityPeriod>(&maxValidityPeriod),
             EvDecoder::def<TT::CaCertificate>([&](const Decoder::Tlv& d) {
               cert = region.create<Data>();
               return !!cert && d.vd().decode(cert) && pub.import(region, cert);
             })) &&
           data.verify(pub);
  }

public:
  /** @brief CA public key. */
  EcPublicKey pub;
};

/** @brief NEW request packet. */
class NewRequest : public packet_struct::NewRequest
{
public:
  /**
   * @brief Build NEW request packet.
   * @param signer private key corresponding to @c this->certRequest .
   * @return an Encodable object, or a falsy value upon failure.
   */
  Interest::Signed toInterest(Region& region, const CaProfile& profile,
                              detail::ISigPolicy& signingPolicy, const EcPrivateKey& signer) const
  {
    Encoder encoder(region);
    encoder.prepend([this](Encoder& encoder) { encoder.prependTlv(TT::EcdhPub, ecdhPub); },
                    [this](Encoder& encoder) { encoder.prependTlv(TT::CertRequest, certRequest); });
    encoder.trim();

    Name name = profile.prefix.append(region, getNewComponent());
    Interest interest = region.create<Interest>();
    if (!encoder || !name || !interest) {
      return Interest::Signed();
    }
    interest.setName(name);
    interest.setMustBeFresh(true);
    return interest.parameterize(tlv::Value(encoder)).sign(signer, region, signingPolicy);
  }
};

/** @brief NEW response packet. */
class NewResponse : public packet_struct::NewResponse
{
public:
  /**
   * @brief Extract NEW response from Data packet.
   * @param data input Data packet; it can be freed after this operation.
   * @param challenges list of challenges acceptable by client.
   * @return whether success.
   */
  bool fromData(Region&, const Data& data, const CaProfile& profile,
                const ChallengeList& challenges)
  {
    hasChallenge.reset();
    return data.verify(profile.pub) &&
           EvDecoder::decodeValue(
             data.getContent().makeDecoder(), EvDecoder::def<TT::EcdhPub>(&ecdhPub),
             EvDecoder::def<TT::Salt>([this](const Decoder::Tlv& d) {
               if (d.length == sizeof(salt)) {
                 std::copy_n(d.value, d.length, salt);
                 return true;
               }
               return false;
             }),
             EvDecoder::def<TT::RequestId>([this](const Decoder::Tlv& d) {
               if (d.length == sizeof(requestId)) {
                 std::copy_n(d.value, d.length, requestId);
                 return true;
               }
               return false;
             }),
             EvDecoder::def<TT::Challenge, true>([this, &challenges](const Decoder::Tlv& d) {
               for (size_t i = 0; i < challenges.size(); ++i) {
                 const Challenge* ch = challenges[i];
                 if (ch == nullptr) {
                   continue;
                 }
                 if (ch->getId() == tlv::Value(d.value, d.length)) {
                   hasChallenge.set(i);
                   return;
                 }
               }
             }));
  }

public:
  /** @brief List of client challenges offered by server. */
  std::bitset<detail::MaxChallenges::value> hasChallenge;
};

/** @brief CHALLENGE request packet. */
class ChallengeRequest : public packet_struct::ChallengeRequest<Challenge>
{
public:
  /**
   * @brief Build CHALLENGE request packet.
   * @pre @c challenge and parameters are set.
   * @param signer private key corresponding to @c newRequest->certReqest .
   * @return an Encodable object, or a falsy value upon failure.
   */
  Interest::Signed toInterest(Region& region, const CaProfile& profile, const uint8_t* requestId,
                              detail::SessionKey& sessionKey, detail::ISigPolicy& signingPolicy,
                              const EcPrivateKey& signer) const
  {
    assert(challenge != nullptr);
    Encoder encoder(region);
    encoder.prepend(
      [=](Encoder& encoder) { encoder.prependTlv(TT::SelectedChallenge, challenge->getId()); },
      params);
    encoder.trim();
    if (!encoder) {
      return Interest::Signed();
    }
    auto encrypted = sessionKey.encrypt(region, tlv::Value(encoder), requestId);

    Name name = profile.prefix.append(
      region,
      { getChallengeComponent(), Component(region, detail::RequestIdLen::value, requestId) }, true);
    Interest interest = region.create<Interest>();
    if (!encrypted || !name || !interest) {
      return Interest::Signed();
    }
    interest.setName(name);
    interest.setMustBeFresh(true);
    return interest.parameterize(encrypted).sign(signer, region, signingPolicy);
  }
};

/** @brief CHALLENGE response packet. */
class ChallengeResponse : public packet_struct::ChallengeResponse
{
public:
  /**
   * @brief Extract CHALLENGE response from Data packet.
   * @param data input Data packet; it can be freed after this operation.
   * @return whether success.
   */
  bool fromData(Region& region, const Data& data, const CaProfile& profile,
                const uint8_t* requestId, detail::SessionKey& sessionKey)
  {
    if (!data.verify(profile.pub)) {
      return false;
    }

    auto decrypted = sessionKey.decrypt(region, data.getContent(), requestId);
    uint32_t remainingTime = 0;
    packet_struct::ParameterKV::Parser paramsParser(params);
    bool ok =
      !!decrypted && EvDecoder::decodeValue(
                       decrypted.makeDecoder(), EvDecoder::defNni<TT::Status, tlv::NNI, 1>(&status),
                       EvDecoder::def<TT::ChallengeStatus, false, 2>(&challengeStatus),
                       EvDecoder::defNni<TT::RemainingTries, tlv::NNI, 3>(&remainingTries),
                       EvDecoder::defNni<TT::RemainingTime, tlv::NNI, 4>(&remainingTime),
                       EvDecoder::def<TT::ParameterKey, true, 5>(
                         [&](const Decoder::Tlv& d) { return paramsParser.parseKey(d); }),
                       EvDecoder::def<TT::ParameterValue, true, 5>(
                         [&](const Decoder::Tlv& d) { return paramsParser.parseValue(d); }),
                       EvDecoder::def<TT::IssuedCertName, false, 6>(
                         [this](const Decoder::Tlv& d) { return d.vd().decode(issuedCertName); }));
    if (!ok) {
      return false;
    }
    expireTime = port::Clock::add(port::Clock::now(), remainingTime * 1000);
    return true;
  }
};

/** @brief Client session logic. */
class Session
{
public:
  explicit Session(const CaProfile& profile, const ChallengeList& challenges)
    : m_challengeRegion(makeSubRegion(m_region, 512))
    , m_profile(profile)
    , m_challenges(challenges)
    , m_signingPolicy(detail::makeISigPolicy())
  {
    assert(m_challengeRegion != nullptr);
  }

  enum State
  {
    NEW_REQ,        ///< ready to send NEW request
    NEW_RES,        ///< waiting for NEW response
    CHALLENGE_EXEC, ///< waiting for challenge execution
    CHALLENGE_REQ,  ///< ready to send CHALLENGE request
    CHALLENGE_RES,  ///< waiting for CHALLENGE response
    SUCCESS,        ///< certificate issued
    FAILURE,        ///< procedure failed
  };

  State getState() const
  {
    return m_state;
  }

  Interest::Signed makeNewRequest(Region& packetRegion, const EcPublicKey& pub,
                                  const EcPrivateKey& pvt)
  {
    if (m_state != State::NEW_REQ) {
      return setFailure();
    }

    m_pvt = &pvt;

    int res = mbedtls_ecdh_gen_public(mbedtls::P256::group(), &m_ecdhPvt, &m_newRequest.ecdhPub,
                                      mbedtls::rng, nullptr);
    if (res != 0) {
      return setFailure();
    }

    time_t now = time(nullptr);
    ValidityPeriod validity(now, now + 3600);
    // auto validity = ValidityPeriod::getMax(); // TODO set proper ValidityPeriod
    auto cert = pub.selfSign(m_region, validity, pvt);

    m_newRequest.certRequest = m_region.create<Data>();
    if (!m_newRequest.certRequest.decodeFrom(cert)) {
      return setFailure();
    }

    m_state = State::NEW_RES;
    return setFailure(m_newRequest.toInterest(packetRegion, m_profile, m_signingPolicy, pvt));
  }

  bool handleNewResponse(const Data& data)
  {
    if (m_state != State::NEW_RES ||
        !m_newResponse.fromData(m_region, data, m_profile, m_challenges)) {
      return setFailure(false);
    }
    for (size_t i = 0; i < m_newResponse.hasChallenge.size(); ++i) {
      if (m_newResponse.hasChallenge.test(i)) {
        m_challengeRequest.challenge = m_challenges[i];
        break;
      }
    }
    if (m_challengeRequest.challenge == nullptr ||
        !m_sessionKey.makeKey(m_ecdhPvt, m_newResponse.ecdhPub, m_newResponse.salt,
                              m_newResponse.requestId)) {
      return setFailure(false);
    }
    prepareChallengeRequest();
    return true;
  }

  bool waitForChallenge() const
  {
    return m_state == State::CHALLENGE_EXEC;
  }

  Interest::Signed makeChallengeRequest(Region& packetRegion)
  {
    if (m_state != State::CHALLENGE_REQ) {
      return setFailure();
    }
    m_state = State::CHALLENGE_RES;
    return setFailure(m_challengeRequest.toInterest(
      packetRegion, m_profile, m_newResponse.requestId, m_sessionKey, m_signingPolicy, *m_pvt));
  }

  bool handleChallengeResponse(const Data& data)
  {
    m_challengeRegion->reset();
    if (m_state != State::CHALLENGE_RES ||
        !m_challengeResponse.fromData(*m_challengeRegion, data, m_profile, m_newResponse.requestId,
                                      m_sessionKey)) {
      return setFailure(false);
    }
    switch (m_challengeResponse.status) {
      case Status::CHALLENGE:
        prepareChallengeRequest();
        break;
      case Status::SUCCESS:
        m_state = State::SUCCESS;
        break;
      default:
        m_state = State::FAILURE;
        break;
    }
    return true;
  }

  Name getIssuedCertName() const
  {
    return m_challengeResponse.issuedCertName;
  }

private:
  template<typename T = Interest::Signed>
  T setFailure(T&& value = T())
  {
    if (!value) {
      m_state = State::FAILURE;
    }
    return value;
  }

  void prepareChallengeRequest()
  {
    m_state = State::CHALLENGE_EXEC;
    m_challengeRequest.params.clear();
    if (m_challengeResponse.status == Status::BEFORE_CHALLENGE) {
      m_challengeRequest.challenge->start(*m_challengeRegion, m_challengeRequest, challengeCallback,
                                          this);
    } else {
      m_challengeRequest.challenge->next(*m_challengeRegion, m_challengeResponse,
                                         m_challengeRequest, challengeCallback, this);
    }
  }

  static void challengeCallback(void* self, bool ok)
  {
    static_cast<Session*>(self)->m_state = ok ? State::CHALLENGE_REQ : State::FAILURE;
  }

private:
  StaticRegion<2048> m_region;
  Region* m_challengeRegion = nullptr;
  const CaProfile& m_profile;
  ChallengeList m_challenges;
  detail::ISigPolicy m_signingPolicy;
  const EcPrivateKey* m_pvt = nullptr;
  mbedtls::Mpi m_ecdhPvt;
  NewRequest m_newRequest;
  NewResponse m_newResponse;
  detail::SessionKey m_sessionKey;
  ChallengeRequest m_challengeRequest;
  ChallengeResponse m_challengeResponse;
  State m_state = State::NEW_REQ;
};

/** @brief Client application. */
class Client : public PacketHandler
{
public:
  /**
   * @brief Callback to be invoked when a certificate request completes.
   * @param ctx context pointer.
   * @param cert obtained certificate, or a falsy value upon failure.
   */
  using Callback = void (*)(void* ctx, Data cert);

  struct Options
  {
    /** @brief Face for communication. */
    Face& face;

    /** @brief CA profile. */
    const CaProfile& profile;

    /** @brief List of acceptable challenges. */
    const ChallengeList& challenges;

    /** @brief Public key to appear in the certificate. */
    const EcPublicKey& pub;

    /** @brief Corresponding private key. */
    const EcPrivateKey& pvt;

    Callback cb;
    void* ctx;
  };

  /** @brief Request a certificate. */
  static void requestCertificate(const Options& opts)
  {
    new Client(opts);
  }

private:
  explicit Client(const Options& opts)
    : PacketHandler(opts.face)
    , m_profile(opts.profile)
    , m_session(opts.profile, opts.challenges)
    , m_cb(opts.cb)
    , m_cbCtx(opts.ctx)
  {
    StaticRegion<2048> packetRegion;
    sendWithDeadline(m_session.makeNewRequest(packetRegion, opts.pub, opts.pvt));
  }

  void loop() final
  {
    bool timeout = port::Clock::isBefore(m_deadline, port::Clock::now());
    if (m_fetchSent) {
      if (timeout) {
        invokeCallback();
      }
      return;
    }

    // StaticRegion<1024> packetRegion;
    StaticRegion<2048> packetRegion;
    switch (m_session.getState()) {
      case Session::State::NEW_RES:
      case Session::State::CHALLENGE_RES: {
        if (timeout) {
          invokeCallback();
        }
        break;
      }
      case Session::State::CHALLENGE_REQ: {
        sendWithDeadline(m_session.makeChallengeRequest(packetRegion));
        break;
      }
      case Session::State::SUCCESS: {
        auto interest = packetRegion.create<Interest>();
        interest.setName(m_session.getIssuedCertName());
        sendWithDeadline(interest);
        m_fetchSent = true;
        break;
      }
      default:
        break;
    }
  }

  bool processData(Data data) final
  {
    StaticRegion<1024> packetRegion;
    if (m_fetchSent && m_session.getIssuedCertName() == data.getFullName(packetRegion)) {
      invokeCallback(data);
      return true;
    }
    packetRegion.reset();

    if (!m_profile.prefix.isPrefixOf(data.getName())) {
      return false;
    }

    switch (m_session.getState()) {
      case Session::State::NEW_RES: {
        m_session.handleNewResponse(data);
        break;
      }
      case Session::State::CHALLENGE_RES: {
        m_session.handleChallengeResponse(data);
        break;
      }
      default:
        break;
    }
    return false;
  }

  template<typename Pkt>
  void sendWithDeadline(const Pkt& pkt)
  {
    send(pkt);
    m_deadline = port::Clock::add(port::Clock::now(), 4000);
  }

  void invokeCallback(Data cert = Data())
  {
    m_cb(m_cbCtx, cert);
    delete this;
  }

private:
  const CaProfile& m_profile;
  Session m_session;
  Callback m_cb;
  void* m_cbCtx;
  port::Clock::Time m_deadline;
  bool m_fetchSent = false;
};

/** @brief The "nop" challenge where the server would approve every request. */
class NopChallenge : public Challenge
{
public:
  tlv::Value getId() const override
  {
    return challenge_consts::nop();
  }

  void start(Region&, ChallengeRequest&, void (*cb)(void*, bool), void* arg) override
  {
    cb(arg, true);
  }

  void next(Region&, const ChallengeResponse&, ChallengeRequest&, void (*cb)(void*, bool),
            void* arg) override
  {
    cb(arg, false);
  }
};

/** @brief The "possession" challenge where client must present an existing certificate. */
class PossessionChallenge : public Challenge
{
public:
  explicit PossessionChallenge(Data cert, PrivateKey& signer)
    : m_cert(std::move(cert))
    , m_signer(signer)
  {}

  tlv::Value getId() const override
  {
    return challenge_consts::possession();
  }

  void start(Region& region, ChallengeRequest& request, void (*cb)(void*, bool), void* arg) override
  {
    Encoder encoder(region);
    encoder.prepend(m_cert);
    encoder.trim();
    if (!encoder) {
      cb(arg, false);
      return;
    }

    request.params.set(challenge_consts::issuedcert(), tlv::Value(encoder));
    cb(arg, true);
  }

  void next(Region& region, const ChallengeResponse& response, ChallengeRequest& request,
            void (*cb)(void*, bool), void* arg) override
  {
    tlv::Value nonce = response.params.get(challenge_consts::nonce());
    uint8_t* sig = region.alloc(m_signer.getMaxSigLen());
    if (nonce.size() != 16 || sig == nullptr) {
      cb(arg, false);
      return;
    }

    ssize_t sigLen = m_signer.sign({ nonce }, sig);
    if (sigLen < 0) {
      cb(arg, false);
      return;
    }

    request.params.set(challenge_consts::proof(), tlv::Value(sig, sigLen));
    cb(arg, true);
  }

private:
  Data m_cert;
  PrivateKey& m_signer;
};

} // namespace client

using Client = client::Client;

} // namespace ndncert
} // namespace ndnph

#endif // NDNPH_HAVE_MBED
#endif // NDNPH_APP_NDNCERT_CLIENT_HPP
