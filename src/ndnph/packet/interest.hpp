#ifndef NDNPH_PACKET_INTEREST_HPP
#define NDNPH_PACKET_INTEREST_HPP

#include "../core/in-region.hpp"
#include "../keychain/common.hpp"
#include "sig-info.hpp"

namespace ndnph {
namespace detail {

struct InterestParams
{
  tlv::Value appParameters;
  ISigInfo sigInfo;
  tlv::Value sigValue;
  tlv::Value signedParams;
  tlv::Value allParams;
};

class InterestObj : public detail::InRegion
{
public:
  explicit InterestObj(Region& region)
    : InRegion(region)
  {}

  enum
  {
    DefaultLifetime = 4000,
    MaxHopLimit = 0xFF,
  };

public:
  InterestParams* params = nullptr; // only relevant on a decoded packet
  Name name;
  uint32_t nonce = 0;
  uint16_t lifetime = DefaultLifetime;
  uint8_t hopLimit = MaxHopLimit;
  bool canBePrefix = false;
  bool mustBeFresh = false;
};

class InterestRefBase : public RefRegion<InterestObj>
{
public:
  using RefRegion::RefRegion;

protected:
  ~InterestRefBase() = default;

  void encodeMiddle(Encoder& encoder) const
  {
    encoder.prepend(
      [this](Encoder& encoder) {
        if (obj->canBePrefix) {
          encoder.prependTlv(TT::CanBePrefix);
        }
      },
      [this](Encoder& encoder) {
        if (obj->mustBeFresh) {
          encoder.prependTlv(TT::MustBeFresh);
        }
      },
      [this](Encoder& encoder) {
        encoder.prependTlv(TT::Nonce, tlv::NNI4(obj->nonce));
      },
      [this](Encoder& encoder) {
        if (obj->lifetime != InterestObj::DefaultLifetime) {
          encoder.prependTlv(TT::InterestLifetime, tlv::NNI(obj->lifetime));
        }
      },
      [this](Encoder& encoder) {
        if (obj->hopLimit != InterestObj::MaxHopLimit) {
          encoder.prependTlv(TT::HopLimit, tlv::NNI1(obj->hopLimit));
        }
      });
  }

  static int findParamsDigest(const Name& name)
  {
    int pos = -1;
    for (const auto& comp : name) {
      ++pos;
      if (comp.type() == TT::ParametersSha256DigestComponent) {
        return pos;
      }
    }
    return -1;
  }
};

template<typename Sha256Port, typename Key>
class SignedInterestRef;

template<typename Sha256Port>
class ParameterizedInterestRef : public InterestRefBase
{
public:
  explicit ParameterizedInterestRef(InterestObj* interest,
                                    tlv::Value appParameters)
    : InterestRefBase(interest)
    , m_appParameters(std::move(appParameters))
  {}

  void encodeTo(Encoder& encoder) const
  {
    encodeImpl(encoder,
               [this](Encoder& encoder) { encodeAppParameters(encoder); });
  }

protected:
  ~ParameterizedInterestRef() = default;

  void encodeName(Encoder& encoder, const tlv::Value& params) const
  {
    Sha256Port hash;
    hash.update(params.begin(), params.size());
    uint8_t digestComp[34];
    if (!hash.final(&digestComp[2])) {
      encoder.setError();
      return;
    }
    digestComp[0] = TT::ParametersSha256DigestComponent;
    digestComp[1] = NDNPH_SHA256_LEN;

    tlv::Value prefix, suffix;
    int posParamsDigest = findParamsDigest(obj->name);
    if (posParamsDigest >= 0) {
      auto namePrefix = obj->name.slice(0, posParamsDigest);
      prefix = tlv::Value(namePrefix.value(), namePrefix.length());
      auto nameSuffix = obj->name.slice(posParamsDigest + 1);
      suffix = tlv::Value(nameSuffix.value(), nameSuffix.length());
    } else {
      prefix = tlv::Value(obj->name.value(), obj->name.length());
    }

    encoder.prependTlv(TT::Name, prefix,
                       tlv::Value(digestComp, sizeof(digestComp)), suffix);
  }

  void encodeAppParameters(Encoder& encoder) const
  {
    encoder.prependTlv(TT::AppParameters, m_appParameters);
  }

  template<typename Fn>
  void encodeImpl(Encoder& encoder, const Fn& encodeParams) const
  {
    tlv::Value params;
    encoder.prependTlv(
      TT::Interest,
      [this, &params](Encoder& encoder) { encodeName(encoder, params); },
      [this](Encoder& encoder) { encodeMiddle(encoder); },
      [&encodeParams, &params](Encoder& encoder) {
        const uint8_t* paramsEnd = encoder.begin();
        encodeParams(encoder);
        if (!encoder) {
          return;
        }
        const uint8_t* paramsBegin = encoder.begin();
        params = tlv::Value(paramsBegin, paramsEnd - paramsBegin);
      });
  }

protected:
  tlv::Value m_appParameters;
};

template<typename Sha256Port, typename Key>
class SignedInterestRef : public ParameterizedInterestRef<Sha256Port>
{
public:
  explicit SignedInterestRef(InterestObj* interest, tlv::Value appParameters,
                             const Key& key, ISigInfo sigInfo)
    : ParameterizedInterestRef<Sha256Port>(interest, std::move(appParameters))
    , m_key(key)
    , m_sigInfo(std::move(sigInfo))
  {}

  void encodeTo(Encoder& encoder) const
  {
    tlv::Value signedName;
    int posParamsDigest = this->findParamsDigest(this->obj->name);
    if (posParamsDigest < 0) {
      signedName =
        tlv::Value(this->obj->name.value(), this->obj->name.length());
    } else if (static_cast<size_t>(posParamsDigest) ==
               this->obj->name.size() - 1) {
      auto prefix = this->obj->name.getPrefix(-1);
      signedName = tlv::Value(prefix.value(), prefix.length());
    } else {
      encoder.setError();
      return;
    }

    m_key.updateSigInfo(m_sigInfo);
    uint8_t* after = const_cast<uint8_t*>(encoder.begin());
    uint8_t* sigBuf = encoder.prependRoom(Key::MaxSigLen::value);
    encoder.prepend(
      [this](Encoder& encoder) { this->encodeAppParameters(encoder); },
      m_sigInfo);
    if (!encoder) {
      return;
    }
    const uint8_t* signedPortion = encoder.begin();
    size_t sizeofSignedPortion = sigBuf - signedPortion;

    ssize_t sigLen = m_key.sign(
      { signedName, tlv::Value(signedPortion, sizeofSignedPortion) }, sigBuf);
    if (sigLen < 0) {
      encoder.setError();
      return;
    }
    if (sigLen != Key::MaxSigLen::value) {
      std::copy_backward(sigBuf, sigBuf + sigLen, after);
    }
    encoder.resetFront(after);

    this->encodeImpl(encoder, [this, sigLen](Encoder& encoder) {
      encoder.prepend(
        [this](Encoder& encoder) { this->encodeAppParameters(encoder); },
        m_sigInfo,
        [sigLen](Encoder& encoder) {
          encoder.prependRoom(sigLen); // room contains signature
          encoder.prependTypeLength(TT::ISigValue, sigLen);
        });
    });
  }

private:
  const Key& m_key;
  mutable ISigInfo m_sigInfo;
};

} // namespace detail

/**
 * @class Interest
 * @brief Interest packet.
 */
/**
 * @brief Interest packet.
 * @tparam Sha256Port platform-specific SHA256 implementation.
 * @tparam TimingSafeEqual platform-specific timing safe equal implementation.
 * @note A port is expected to typedef this template as `Interest` type.
 */
template<typename Sha256Port, typename TimingSafeEqual = DefaultTimingSafeEqual>
class BasicInterest : public detail::InterestRefBase
{
public:
  using InterestRefBase::InterestRefBase;

  const Name& getName() const { return obj->name; }
  void setName(const Name& v) { obj->name = v; }

  bool getCanBePrefix() const { return obj->canBePrefix; }
  void setCanBePrefix(bool v) { obj->canBePrefix = v; }

  bool getMustBeFresh() const { return obj->mustBeFresh; }
  void setMustBeFresh(bool v) { obj->mustBeFresh = v; }

  uint32_t getNonce() const { return obj->nonce; }
  void setNonce(uint32_t v) { obj->nonce = v; }

  uint16_t getLifetime() const { return obj->lifetime; }
  void setLifetime(uint16_t v) { obj->lifetime = v; }

  uint8_t getHopLimit() const { return obj->hopLimit; }
  void setHopLimit(uint8_t v) { obj->hopLimit = v; }

  /**
   * @brief Retrieve AppParameters.
   * @pre only available on decoded packet.
   * @note To create Interest packet with AppParameters, use parameterize().
   */
  tlv::Value getAppParameters() const
  {
    if (obj->params == nullptr) {
      return tlv::Value();
    }
    return obj->params->appParameters;
  }

  /**
   * @brief Retrieve SignatureInfo.
   * @pre only available on decoded packet.
   */
  const ISigInfo* getSigInfo() const
  {
    return obj->params == nullptr ? nullptr : &obj->params->sigInfo;
  }

  /** @brief Encode the Interest without AppParameters. */
  void encodeTo(Encoder& encoder) const
  {
    encoder.prependTlv(TT::Interest, obj->name,
                       [this](Encoder& encoder) { encodeMiddle(encoder); });
  }

  class Parameterized : public detail::ParameterizedInterestRef<Sha256Port>
  {
  public:
    using detail::ParameterizedInterestRef<
      Sha256Port>::ParameterizedInterestRef;

    template<typename Key,
             typename R = detail::SignedInterestRef<Sha256Port, Key>>
    R sign(const Key& key, ISigInfo sigInfo = ISigInfo()) const
    {
      return R(obj, this->m_appParameters, key, std::move(sigInfo));
    }
  };

  /**
   * @brief Add AppParameters to the packet.
   * @pre Name contains zero or one ParametersSha256DigestComponent.
   * @return an Encodable object, with an additional `sign(const Key& key)` method to
   *         create a signed Interest. This object is valid only if Interest and
   *         appParameters are kept alive. It's recommended to pass it to Encoder
   *         immediately without saving as variable.
   * @note Unrecognized fields found during decoding are not preserved in encoding output.
   * @note This method does not set sigValue. Packet is not verifiable after this operation.
   */
  Parameterized parameterize(tlv::Value appParameters) const
  {
    return Parameterized(obj, std::move(appParameters));
  }

  /**
   * @brief Sign the packet with a private key.
   * @pre If Name contains ParametersSha256DigestComponent, it is the last component.
   * @tparam Key see requirement in Data::sign().
   * @return an Encodable object. This object is valid only if Interest and Key are kept alive.
   *         It's recommended to pass it to Encoder immediately without saving as variable.
   * @note Unrecognized fields found during decoding are not preserved in encoding output.
   * @note This method does not set sigValue. Packet is not verifiable after this operation.
   *
   * To create a signed Interest with AppParameters, call parameterize() first, then
   * call sign() on its return value.
   */
  template<typename Key,
           typename R = detail::SignedInterestRef<Sha256Port, Key>>
  R sign(const Key& key, ISigInfo sigInfo = ISigInfo()) const
  {
    return R(obj, tlv::Value(), key, std::move(sigInfo));
  }

  /** @brief Decode packet. */
  bool decodeFrom(const Decoder::Tlv& input)
  {
    return EvDecoder::decode(
      input, { TT::Interest }, EvDecoder::def<TT::Name>(&obj->name),
      EvDecoder::def<TT::CanBePrefix>(
        [this](const Decoder::Tlv&) { setCanBePrefix(true); }),
      EvDecoder::def<TT::MustBeFresh>(
        [this](const Decoder::Tlv&) { setMustBeFresh(true); }),
      EvDecoder::defNni<TT::Nonce, tlv::NNI4>(&obj->nonce),
      EvDecoder::defNni<TT::InterestLifetime, tlv::NNI>(&obj->lifetime),
      EvDecoder::defNni<TT::HopLimit, tlv::NNI1>(&obj->hopLimit),
      EvDecoder::def<TT::AppParameters>([this, &input](const Decoder::Tlv& d) {
        obj->params = regionOf(obj).template make<detail::InterestParams>();
        if (obj->params == nullptr) {
          return false;
        }
        obj->params->allParams =
          tlv::Value(d.tlv, input.tlv + input.size - d.tlv);
        return obj->params->appParameters.decodeFrom(d);
      }),
      EvDecoder::def<TT::ISigInfo>([this](const Decoder::Tlv& d) {
        return obj->params != nullptr && obj->params->sigInfo.decodeFrom(d);
      }),
      EvDecoder::def<TT::ISigValue>([this](const Decoder::Tlv& d) {
        if (obj->params == nullptr) {
          return false;
        }
        obj->params->signedParams =
          tlv::Value(obj->params->allParams.begin(),
                     d.tlv - obj->params->allParams.begin());
        return obj->params->sigValue.decodeFrom(d);
      }));
  }

  /**
   * @brief Check ParametersSha256DigestComponent.
   * @return whether the digest is correct.
   *
   * This method only works on decoded packet.
   * It's unnecessary to call this method if you are going to use verify().
   */
  bool checkDigest() const
  {
    if (obj->params == nullptr) {
      return false;
    }
    int posParamsDigest = findParamsDigest(obj->name);
    if (posParamsDigest < 0) {
      return false;
    }
    Component paramsDigest = obj->name[posParamsDigest];

    uint8_t digest[NDNPH_SHA256_LEN];
    Sha256Port hash;
    hash.update(obj->params->allParams.begin(), obj->params->allParams.size());
    return hash.final(digest) &&
           TimingSafeEqual()(digest, sizeof(digest), paramsDigest.value(),
                             paramsDigest.length());
  }

  /**
   * @brief Verify the packet with a public key.
   * @tparam Key see requirement in Data::verify().
   * @return verification result.
   *
   * This method only works on decoded packet. It does not work on packet that
   * has been modified or (re-)signed.
   */
  template<typename Key>
  bool verify(const Key& key)
  {
    if (!checkDigest()) {
      return false;
    }
    int posParamsDigest = findParamsDigest(obj->name);
    if (static_cast<size_t>(posParamsDigest) != obj->name.size() - 1) {
      return false;
    }
    auto signedName = obj->name.getPrefix(-1);
    return key.verify({ tlv::Value(signedName.value(), signedName.length()),
                        obj->params->signedParams },
                      obj->params->sigValue.begin(),
                      obj->params->sigValue.size());
  }
};

} // namespace ndnph

#endif // NDNPH_PACKET_INTEREST_HPP
