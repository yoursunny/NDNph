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
class Challenge {
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
class CaProfile : public packet_struct::CaProfile {
public:
  /** @brief Determine whether @p name is a valid CA profile packet name. */
  static bool isName(const Name& name) {
    return name.size() >= 4 && name[-4] == getCaComponent() && name[-3] == getInfoComponent() &&
           name[-2].is<convention::Version>() && name[-1].is<convention::Segment>() &&
           name[-1].as<convention::Segment>() == 0;
  }

  /**
   * @brief Extract CA profile from Data packet.
   * @param data input Data packet; it can be freed after this operation.
   * @return whether success.
   */
  bool fromData(Region& region, const Data& data) {
    return isName(data.getName()) &&
           EvDecoder::decodeValue(
             data.getContent().makeDecoder(),
             EvDecoder::def<TT::CaPrefix>([&](const Decoder::Tlv& d) {
               if (!d.vd().decode(prefix) || data.getName().getPrefix(-4) != prefix) {
                 return false;
               }
               prefix = prefix.clone(region);
               return !!prefix;
             }),
             EvDecoder::defIgnore<TT::CaInfo>(), EvDecoder::defIgnore<TT::ParameterKey, true>(),
             EvDecoder::defNni<TT::MaxValidityPeriod>(&maxValidityPeriod),
             EvDecoder::def<TT::CaCertificate>([&](const Decoder::Tlv& d) {
               cert = region.create<Data>();
               return !!cert && cert.decodeFrom(tlv::Value(d.value, d.length)) // copying
                      && pub.import(region, cert);
             })) &&
           data.verify(pub);
  }

public:
  /** @brief CA public key. */
  EcPublicKey pub;
};

/** @brief NEW request packet. */
class NewRequest : public packet_struct::NewRequest {
public:
  /**
   * @brief Build NEW request packet.
   * @param signer private key corresponding to @c this->certRequest .
   * @return an Encodable object, or a falsy value upon failure.
   */
  Interest::Signed toInterest(Region& region, const CaProfile& profile,
                              detail::ISigPolicy& signingPolicy, const EcPrivateKey& signer) const {
    Encoder encoder(region);
    encoder.prepend([this](Encoder& encoder) { encoder.prependTlv(TT::EcdhPub, ecdhPub); },
                    [this](Encoder& encoder) { encoder.prependTlv(TT::CertRequest, certRequest); });
    encoder.trim();

    Name name = profile.prefix.append(region, getCaComponent(), getNewComponent());
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
class NewResponse : public packet_struct::NewResponse {
public:
  /**
   * @brief Extract NEW response from Data packet.
   * @param data input Data packet; it can be freed after this operation.
   * @param challenges list of challenges acceptable by client.
   * @return whether success.
   */
  bool fromData(Region&, const Data& data, const CaProfile& profile,
                const ChallengeList& challenges) {
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
class ChallengeRequest : public packet_struct::ChallengeRequest<Challenge> {
public:
  /**
   * @brief Build CHALLENGE request packet.
   * @pre @c challenge and parameters are set.
   * @param signer private key corresponding to @c newRequest->certReqest .
   * @return an Encodable object, or a falsy value upon failure.
   */
  Interest::Signed toInterest(Region& region, const CaProfile& profile, const uint8_t* requestId,
                              detail::SessionKey& sessionKey, detail::ISigPolicy& signingPolicy,
                              const EcPrivateKey& signer) const {
    NDNPH_ASSERT(challenge != nullptr);
    Encoder encoder(region);
    encoder.prepend(
      [this](Encoder& encoder) { encoder.prependTlv(TT::SelectedChallenge, challenge->getId()); },
      params);
    encoder.trim();
    if (!encoder) {
      return Interest::Signed();
    }
    auto encrypted = sessionKey.encrypt(region, tlv::Value(encoder), requestId);

    Name name = profile.prefix.append(region, getCaComponent(), getChallengeComponent(),
                                      Component(region, detail::RequestIdLen::value, requestId));
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
class ChallengeResponse : public packet_struct::ChallengeResponse {
public:
  /**
   * @brief Extract CHALLENGE response from Data packet.
   * @param data input Data packet; it can be freed after this operation.
   * @return whether success.
   */
  bool fromData(Region& region, const Data& data, const CaProfile& profile,
                const uint8_t* requestId, detail::SessionKey& sessionKey) {
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
                         [this](const Decoder::Tlv& d) { return d.vd().decode(issuedCertName); }),
                       EvDecoder::def<TT::ForwardingHint, false, 7>([this](const Decoder::Tlv& d) {
                         return detail::decodeFwHint(d, &fwHint);
                       }));
    if (!ok) {
      return false;
    }
    expireTime = port::Clock::add(port::Clock::now(), remainingTime * 1000);
    return true;
  }
};

/** @brief Client application. */
class Client : public PacketHandler {
public:
  /**
   * @brief Callback to be invoked upon completion of a certificate request procedure.
   * @param ctx context pointer.
   * @param cert obtained certificate, or a falsy value upon failure.
   */
  using Callback = void (*)(void* ctx, Data cert);

  struct Options {
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

    /** @brief Completion callback. */
    Callback cb;

    /** @brief Context pointer. */
    void* ctx;
  };

  /** @brief Request a certificate. */
  static void requestCertificate(const Options& opts) {
    new Client(opts);
  }

private:
  enum class State {
    SendNewRequest,
    WaitNewResponse,
    ExecuteChallenge,
    SendChallengeRequest,
    WaitChallengeResponse,
    FetchIssuedCert,
    WaitIssuedCert,
    Success,
    Failure,
  };

  class GotoState {
  public:
    explicit GotoState(Client* client)
      : m_client(client) {}

    bool operator()(State state) {
      NDNPH_NDNCERT_LOG("client state %d => %d", static_cast<int>(m_client->m_state),
                        static_cast<int>(state));
      m_client->m_state = state;
      m_set = true;
      return true;
    }

    ~GotoState() {
      if (!m_set) {
        NDNPH_NDNCERT_LOG("client state %d => %d", static_cast<int>(m_client->m_state),
                          static_cast<int>(State::Failure));
        m_client->m_state = State::Failure;
      }
    }

  private:
    Client* m_client = nullptr;
    bool m_set = false;
  };

  explicit Client(const Options& opts)
    : PacketHandler(opts.face)
    , m_pending(this)
    , m_profile(opts.profile)
    , m_challenges(opts.challenges)
    , m_pvt(opts.pvt)
    , m_cb(opts.cb)
    , m_cbCtx(opts.ctx) {
    sendNewRequest(opts.pub);
  }

  void loop() final {
    switch (m_state) {
      case State::SendChallengeRequest: {
        sendChallengeRequest();
        break;
      }
      case State::FetchIssuedCert: {
        sendFetchInterest();
        break;
      }
      case State::WaitNewResponse:
      case State::WaitChallengeResponse:
      case State::WaitIssuedCert: {
        if (m_pending.expired()) {
          m_state = State::Failure;
        }
        break;
      }
      case State::Success: {
        delete this;
        return;
      }
      case State::Failure: {
        m_cb(m_cbCtx, Data());
        delete this;
        return;
      }
      default:
        break;
    }
  }

  bool processData(Data data) final {
    if (!m_pending.matchPitToken()) {
      return false;
    }

    switch (m_state) {
      case State::WaitNewResponse: {
        return handleNewResponse(data);
      }
      case State::WaitChallengeResponse: {
        return handleChallengeResponse(data);
      }
      case State::WaitIssuedCert: {
        return handleIssuedCert(data);
      }
      default:
        break;
    }
    return false;
  }

  void sendNewRequest(const EcPublicKey& pub) {
    StaticRegion<2048> region;
    GotoState gotoState(this);
    int res = mbedtls_ecdh_gen_public(mbedtls::P256::group(), m_ecdhPvt, m_newRequest.ecdhPub,
                                      mbedtls::rng, nullptr);
    if (res != 0) {
      NDNPH_NDNCERT_LOG("NewRequest ECDH error");
      return;
    }

    auto validity = certificate::getValidity(m_profile.cert)
                      .intersect(ValidityPeriod::secondsFromNow(m_profile.maxValidityPeriod));
    if (!validity.includesUnix()) {
      NDNPH_NDNCERT_LOG("NewRequest validity expired");
      return;
    }

    auto cert = pub.selfSign(m_region, validity, m_pvt);
    m_newRequest.certRequest = m_region.create<Data>();
    if (!m_newRequest.certRequest || !m_newRequest.certRequest.decodeFrom(cert)) {
      NDNPH_NDNCERT_LOG("NewRequest cert request error");
      return;
    }

    m_pending.send(m_newRequest.toInterest(region, m_profile, m_signingPolicy, m_pvt)) &&
      gotoState(State::WaitNewResponse);
  }

  bool handleNewResponse(Data data) {
    bool ok = m_newResponse.fromData(m_region, data, m_profile, m_challenges);
    if (!ok) {
      NDNPH_NDNCERT_LOG("NewResponse parse error");
      return false;
    }

    GotoState gotoState(this);
    for (size_t i = 0; i < m_newResponse.hasChallenge.size(); ++i) {
      if (m_newResponse.hasChallenge.test(i)) {
        m_challengeRequest.challenge = m_challenges[i];
        break;
      }
    }
    if (m_challengeRequest.challenge == nullptr) {
      NDNPH_NDNCERT_LOG("NewResponse no common challenge");
      return true;
    }

    ok = m_sessionKey.makeKey(m_ecdhPvt, m_newResponse.ecdhPub, m_newResponse.salt,
                              m_newResponse.requestId);
    if (!ok) {
      NDNPH_NDNCERT_LOG("NewResponse session key error");
      return true;
    }
    prepareChallengeRequest(gotoState);
    return true;
  }

  static void challengeCallback(void* self, bool ok) {
    static_cast<Client*>(self)->m_state = ok ? State::SendChallengeRequest : State::Failure;
  }

  void prepareChallengeRequest(GotoState& gotoState) {
    gotoState(State::ExecuteChallenge);
    m_challengeRequest.params.clear();
    if (m_challengeResponse.status == Status::BEFORE_CHALLENGE) {
      m_challengeRequest.challenge->start(m_challengeRegion, m_challengeRequest, challengeCallback,
                                          this);
    } else {
      m_challengeRequest.challenge->next(m_challengeRegion, m_challengeResponse, m_challengeRequest,
                                         challengeCallback, this);
    }
  }

  void sendChallengeRequest() {
    StaticRegion<2048> region;
    GotoState gotoState(this);
    m_pending.send(m_challengeRequest.toInterest(region, m_profile, m_newResponse.requestId,
                                                 m_sessionKey, m_signingPolicy, m_pvt)) &&
      gotoState(State::WaitChallengeResponse);
  }

  bool handleChallengeResponse(Data data) {
    m_challengeRegion.reset();
    bool ok = m_challengeResponse.fromData(m_challengeRegion, data, m_profile,
                                           m_newResponse.requestId, m_sessionKey);
    if (!ok) {
      NDNPH_NDNCERT_LOG("ChallengeResponse parse error");
      return false;
    }

    GotoState gotoState(this);
    switch (m_challengeResponse.status) {
      case Status::CHALLENGE:
        prepareChallengeRequest(gotoState);
        break;
      case Status::SUCCESS:
        return gotoState(State::FetchIssuedCert);
      default:
        break;
    }
    return true;
  }

  void sendFetchInterest() {
    ndnph::StaticRegion<2048> region;
    GotoState gotoState(this);
    auto interest = region.create<ndnph::Interest>();
    NDNPH_ASSERT(!!interest);
    interest.setName(m_challengeResponse.issuedCertName);
    interest.setFwHint(m_challengeResponse.fwHint);
    m_pending.send(interest) && gotoState(State::WaitIssuedCert);
  }

  bool handleIssuedCert(Data data) {
    ndnph::StaticRegion<512> region;
    if (data.getFullName(region) != m_challengeResponse.issuedCertName) {
      NDNPH_NDNCERT_LOG("IssuedCert full name mismatch");
      return false;
    }

    GotoState gotoState(this);
    if (!ec::isCertificate(data)) {
      NDNPH_NDNCERT_LOG("IssuedCert parse error");
      return true;
    }
    m_cb(m_cbCtx, data);
    return gotoState(State::Success);
  }

private:
  OutgoingPendingInterest m_pending;
  State m_state = State::SendNewRequest;

  const CaProfile& m_profile;
  ChallengeList m_challenges;
  const EcPrivateKey& m_pvt;
  Callback m_cb;
  void* m_cbCtx;

  StaticRegion<2048> m_region;
  StaticRegion<512> m_challengeRegion;
  detail::ISigPolicy m_signingPolicy;
  mbedtls::Mpi m_ecdhPvt;
  NewRequest m_newRequest;
  NewResponse m_newResponse;
  detail::SessionKey m_sessionKey;
  ChallengeRequest m_challengeRequest;
  ChallengeResponse m_challengeResponse;
};

/** @brief The "nop" challenge where the server would approve every request. */
class NopChallenge : public Challenge {
public:
  tlv::Value getId() const override {
    return challenge_consts::nop();
  }

  void start(Region&, ChallengeRequest&, void (*cb)(void*, bool), void* arg) override {
    cb(arg, true);
  }

  void next(Region&, const ChallengeResponse&, ChallengeRequest&, void (*cb)(void*, bool),
            void* arg) override {
    cb(arg, false);
  }
};

/** @brief The "possession" challenge where client must present an existing certificate. */
class PossessionChallenge : public Challenge {
public:
  explicit PossessionChallenge(Data cert, const PrivateKey& signer)
    : m_cert(std::move(cert))
    , m_signer(signer) {}

  tlv::Value getId() const override {
    return challenge_consts::possession();
  }

  void start(Region& region, ChallengeRequest& request, void (*cb)(void*, bool),
             void* arg) override {
    Encoder encoder(region);
    encoder.prepend(m_cert);
    encoder.trim();
    if (!encoder) {
      NDNPH_NDNCERT_LOG("PossessionChallenge encode error");
      cb(arg, false);
      return;
    }

    request.params.set(challenge_consts::issuedcert(), tlv::Value(encoder));
    cb(arg, true);
  }

  void next(Region& region, const ChallengeResponse& response, ChallengeRequest& request,
            void (*cb)(void*, bool), void* arg) override {
    tlv::Value nonce = response.params.get(challenge_consts::nonce());
    uint8_t* sig = region.alloc(m_signer.getMaxSigLen());
    if (nonce.size() != 16 || sig == nullptr) {
      NDNPH_NDNCERT_LOG("PossessionChallenge bad nonce or sig");
      cb(arg, false);
      return;
    }

    ssize_t sigLen = m_signer.sign({nonce}, sig);
    if (sigLen < 0) {
      NDNPH_NDNCERT_LOG("PossessionChallenge signing error");
      cb(arg, false);
      return;
    }

    request.params.set(challenge_consts::proof(), tlv::Value(sig, sigLen));
    cb(arg, true);
  }

private:
  Data m_cert;
  const PrivateKey& m_signer;
};

} // namespace client

using Client = client::Client;

} // namespace ndncert
} // namespace ndnph

#endif // NDNPH_HAVE_MBED
#endif // NDNPH_APP_NDNCERT_CLIENT_HPP
