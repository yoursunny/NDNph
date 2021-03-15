#ifndef NDNPH_APP_NDNCERT_COMMON_HPP
#define NDNPH_APP_NDNCERT_COMMON_HPP
#ifdef NDNPH_HAVE_MBED

#include "../../keychain/ec.hpp"
#include "../../packet/encrypted-message.hpp"
#include "../../port/clock/port.hpp"
#include "../../port/mbed-common.hpp"
#include <mbedtls/hkdf.h>

namespace ndnph {
namespace ndncert {
namespace detail {
using namespace ndnph::detail;

using MaxChallenges = std::integral_constant<int, 4>;
using MaxChallengeParams = std::integral_constant<int, 2>;

using SaltLen = std::integral_constant<size_t, 32>;
using RequestIdLen = std::integral_constant<size_t, 8>;
using AuthenticationTagLen = std::integral_constant<size_t, 16>;

/** @brief Symmetric key used in CHALLENGE step. */
class SessionKey
{
public:
  /** @brief Derive the key. */
  bool makeKey(const mbedtls::Mpi& ecdhPvt, const mbedtls::EcPoint& ecdhPub, const uint8_t* salt,
               const uint8_t* requestId)
  {
    mbedtls::P256::SharedSecret ikm;
    AesGcm::Key okm;
    return mbedtls::P256::ecdh(ecdhPvt, ecdhPub, ikm) &&
           mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, SaltLen::value,
                        ikm.data(), ikm.size(), requestId, RequestIdLen::value, okm.data(),
                        okm.size()) == 0 &&
           m_aes.import(okm);
  }

  /** @brief Encrypt to encrypted-message. */
  tlv::Value encrypt(Region& region, tlv::Value plaintext, const uint8_t* requestId)
  {
    return m_aes.encrypt<Encrypted>(region, plaintext, requestId, RequestIdLen::value);
  }

  /** @brief Decrypt from encrypted-message. */
  tlv::Value decrypt(Region& region, tlv::Value message, const uint8_t* requestId)
  {
    Encrypted encrypted;
    bool ok = EvDecoder::decodeValue(message.makeDecoder(),
                                     EvDecoder::def<TT::InitializationVector>(&encrypted),
                                     EvDecoder::def<TT::AuthenticationTag>(&encrypted),
                                     EvDecoder::def<TT::EncryptedPayload>(&encrypted));
    if (!ok) {
      return tlv::Value();
    }
    return m_aes.decrypt(region, encrypted, requestId, RequestIdLen::value);
  }

private:
  using AesGcm = mbedtls::AesGcm<128>;
  using Encrypted =
    EncryptedMessage<TT::InitializationVector, AesGcm::IvLen::value, TT::AuthenticationTag,
                     AesGcm::TagLen::value, TT::EncryptedPayload>;
  AesGcm m_aes;
};

using ISigPolicy = isig::Policy<isig::Nonce<>, isig::Time<>>;

inline ISigPolicy
makeISigPolicy()
{
  return isig::makePolicy(isig::Nonce<>(), isig::Time<>());
}

} // namespace detail
namespace packet_struct {

class ParameterKV
{
public:
  class Parser
  {
  public:
    explicit Parser(ParameterKV& target)
      : m_target(target)
    {
      m_target.clear();
    }

    bool parseKey(const Decoder::Tlv& d)
    {
      if (m_pos >= detail::MaxChallengeParams::value) {
        return false;
      }
      m_target.m_kv[m_pos] = std::make_pair(tlv::Value(d.value, d.length), tlv::Value());
      return true;
    }

    bool parseValue(const Decoder::Tlv& d)
    {
      if (m_pos >= detail::MaxChallengeParams::value) {
        return false;
      }
      auto key = m_target.m_kv[m_pos].first;
      m_target.m_kv[m_pos] = std::make_pair(key, tlv::Value(d.value, d.length));
      ++m_pos;
      return true;
    }

  private:
    ParameterKV& m_target;
    size_t m_pos = 0;
  };

  /** @brief Retrieve parameter value by parameter key. */
  tlv::Value get(tlv::Value key) const
  {
    for (const auto& p : m_kv) {
      if (p.first == key) {
        return p.second;
      }
    }
    return tlv::Value();
  }

  /** @brief Set a parameter. */
  bool set(tlv::Value key, tlv::Value value)
  {
    assert(!!key);
    for (auto& p : m_kv) {
      if (!p.first) {
        p = std::make_pair(key, value);
        return true;
      }
    }
    return false;
  }

  /** @brief Clear parameters. */
  void clear()
  {
    m_kv.fill(std::make_pair(tlv::Value(), tlv::Value()));
  }

  /** @brief Prepend ParameterKey-ParameterValue pairs to Encoder. */
  void encodeTo(Encoder& encoder) const
  {
    for (auto it = m_kv.rbegin(); it != m_kv.rend(); ++it) {
      if (!it->first) {
        continue;
      }
      encoder.prependTlv(TT::ParameterValue, it->second);
      encoder.prependTlv(TT::ParameterKey, it->first);
    }
  }

private:
  std::array<std::pair<tlv::Value, tlv::Value>, detail::MaxChallengeParams::value> m_kv;
};

struct CaProfile
{
  /** @brief CA prefix. */
  Name prefix;

  /** @brief Maximum ValidityPeriod duration in seconds. */
  uint32_t maxValidityPeriod = 0;

  /** @brief CA certificate. */
  Data cert;
};

struct NewRequest
{
  /** @brief Client ECDH public key. */
  mbedtls::EcPoint ecdhPub;

  /** @brief Certificate request. */
  Data certRequest;
};

struct NewResponse
{
  /** @brief Server ECDH public key. */
  mbedtls::EcPoint ecdhPub;

  /** @brief ECDH salt. */
  uint8_t salt[detail::SaltLen::value];

  /** @brief Request ID. */
  uint8_t requestId[detail::RequestIdLen::value];
};

template<typename ChallengeT>
struct ChallengeRequest
{
  /** @brief Challenge reference. */
  ChallengeT* challenge = nullptr;

  /** @brief Parameter key-value pairs. */
  ParameterKV params;
};

struct ChallengeResponse
{
  /** @brief Application status code. */
  uint8_t status = Status::BEFORE_CHALLENGE;

  /** @brief Challenge status string. */
  tlv::Value challengeStatus;

  /** @brief Remaining tries. */
  uint16_t remainingTries = 0;

  /** @brief Session expiration time. Calculates remaining time. */
  port::Clock::Time expireTime = {};

  /** @brief Parameter key-value pairs. */
  ParameterKV params;

  /** @brief Issued certificate full name. */
  Name issuedCertName;

  /** @brief Forwarding hint to retrieve issued certificate. */
  Name fwHint;
};

} // namespace packet_struct
} // namespace ndncert
} // namespace ndnph

#endif // NDNPH_HAVE_MBED
#endif // NDNPH_APP_NDNCERT_COMMON_HPP
