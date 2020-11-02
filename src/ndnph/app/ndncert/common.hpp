#ifndef NDNPH_APP_NDNCERT_COMMON_HPP
#define NDNPH_APP_NDNCERT_COMMON_HPP
#ifdef NDNPH_HAVE_MBED

#include "../../keychain/ec.hpp"
#include "../../port/clock/port.hpp"
#include "../../port/mbed-common.hpp"
#include <mbedtls/ecdh.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

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
  explicit SessionKey()
  {
    mbedtls_gcm_init(&m_ctx);
  }

  ~SessionKey()
  {
    mbedtls_gcm_free(&m_ctx);
  }

  SessionKey(const SessionKey&) = delete;
  SessionKey& operator=(const SessionKey&) = delete;

  /** @brief Derive the key. */
  bool makeKey(const mbedtls::Mpi& ecdhPvt, const mbedtls::EcPoint& ecdhPub, const uint8_t* salt,
               const uint8_t* requestId)
  {
    m_ok = false;

    mbedtls::Mpi shared;
    int res = mbedtls_ecdh_compute_shared(mbedtls::P256::group(), &shared, &ecdhPub, &ecdhPvt,
                                          mbedtls::rng, nullptr);
    if (res != 0) {
      return false;
    }

    uint8_t ikm[32];
    res = mbedtls_mpi_write_binary(&shared, ikm, sizeof(ikm));
    if (res != 0) {
      return false;
    }

    uint8_t okm[16];
    res = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, SaltLen::value, ikm,
                       sizeof(ikm), requestId, RequestIdLen::value, okm, sizeof(okm));
    if (res != 0) {
      return false;
    }

    res = mbedtls_gcm_setkey(&m_ctx, MBEDTLS_CIPHER_ID_AES, okm, 128);
    if (res != 0) {
      return false;
    }

    m_ok =
      port::RandomSource::generate(reinterpret_cast<uint8_t*>(&m_ivRandom), sizeof(m_ivRandom));
    return m_ok;
  }

  /** @brief Encrypt to EncryptedPayload. */
  tlv::Value encrypt(Region& region, tlv::Value plaintext, const uint8_t* requestId)
  {
    Encoder encoder(region);
    uint8_t* ciphertext = encoder.prependRoom(plaintext.size());
    encoder.prependTypeLength(TT::EncryptedPayload, plaintext.size());
    uint8_t* tag = encoder.prependRoom(AuthenticationTagLen::value);
    encoder.prependTypeLength(TT::AuthenticationTag, AuthenticationTagLen::value);
    encoder.prepend(tlv::NNI8(m_ivRandom), tlv::NNI4(m_ivCounter));
    const uint8_t* iv = encoder.begin();
    encoder.prependTypeLength(TT::InitializationVector, 12);
    encoder.trim();

    return !!encoder &&
               mbedtls_gcm_crypt_and_tag(&m_ctx, MBEDTLS_GCM_ENCRYPT, plaintext.size(), iv, 12,
                                         requestId, RequestIdLen::value, plaintext.begin(),
                                         ciphertext, AuthenticationTagLen::value, tag) == 0 &&
               advanceIv(plaintext.size())
             ? tlv::Value(encoder)
             : tlv::Value();
  }

  /** @brief Decrypt from EncryptedPayload. */
  tlv::Value decrypt(Region& region, tlv::Value encrypted, const uint8_t* requestId)
  {
    tlv::Value iv, tag, ciphertext;
    bool ok =
      EvDecoder::decodeValue(encrypted.makeDecoder(), EvDecoder::def<TT::InitializationVector>(&iv),
                             EvDecoder::def<TT::AuthenticationTag>(&tag),
                             EvDecoder::def<TT::EncryptedPayload>(&ciphertext));
    if (!(m_ok && ok && iv.size() == 12 && tag.size() == AuthenticationTagLen::value)) {
      return tlv::Value();
    }

    uint8_t* plaintext = region.alloc(ciphertext.size());
    if (plaintext == nullptr) {
      return tlv::Value();
    }
    return mbedtls_gcm_auth_decrypt(&m_ctx, ciphertext.size(), iv.begin(), iv.size(), requestId,
                                    RequestIdLen::value, tag.begin(), tag.size(),
                                    ciphertext.begin(), plaintext) == 0
             ? tlv::Value(plaintext, ciphertext.size())
             : tlv::Value();
  }

private:
  bool advanceIv(size_t size)
  {
    static constexpr size_t blockSize = 16;
    uint64_t nBlocks = (size / blockSize) + static_cast<int>(size % blockSize != 0);
    uint64_t counter = static_cast<uint64_t>(m_ivCounter) + nBlocks;
    if (counter > std::numeric_limits<uint32_t>::max()) {
      m_ok = false;
    }
    m_ivCounter = static_cast<uint32_t>(counter);
    return m_ok;
  }

private:
  mbedtls_gcm_context m_ctx;
  uint64_t m_ivRandom = 0;
  uint32_t m_ivCounter = 0;
  bool m_ok = false;
};

} // namespace detail
namespace packet_struct {

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

  /** @brief Parameter key-value pairs; empty key indicates empty slot. */
  std::array<std::pair<tlv::Value, tlv::Value>, detail::MaxChallengeParams::value> params;
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
  port::Clock::Time expireTime;

  /** @brief Issued certificate full name. */
  Name issuedCertName;
};

} // namespace packet_struct
} // namespace ndncert
} // namespace ndnph

#endif // NDNPH_HAVE_MBED
#endif // NDNPH_APP_NDNCERT_COMMON_HPP
