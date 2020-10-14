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

  enum Role
  {
    REQUESTER = 0,
    ISSUER = 1,
  };

  /** @brief Derive the key. */
  bool makeKey(const mbedtls::Mpi& ecdhPvt, const mbedtls::EcPoint& ecdhPub, const uint8_t* salt,
               const uint8_t* requestId, Role role)
  {
    bool ok = port::RandomSource::generate(m_ivHead, sizeof(m_ivHead));
    if (!ok) {
      return false;
    }
    m_ivHead[0] &= 0x7F;
    m_ivHead[0] |= role << 7;

    int res = mbedtls_mpi_lset(&m_ivTail, 0);
    if (res != 0) {
      return false;
    }

    mbedtls::Mpi shared;
    res = mbedtls_ecdh_compute_shared(mbedtls::P256::group(), &shared, &ecdhPub, &ecdhPvt,
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

    return true;
  }

  /** @brief Encrypt to EncryptedPayload. */
  tlv::Value encrypt(Region& region, tlv::Value plaintext, const uint8_t* requestId)
  {
    Encoder encoder(region);
    uint8_t* ciphertext = encoder.prependRoom(plaintext.size());
    encoder.prependTypeLength(TT::EncryptedPayload, plaintext.size());
    uint8_t* tag = encoder.prependRoom(AuthenticationTagLen::value);
    encoder.prependTypeLength(TT::AuthenticationTag, AuthenticationTagLen::value);
    uint8_t* iv = encoder.prependRoom(12);
    encoder.prependTypeLength(TT::InitializationVector, 12);
    encoder.trim();
    if (!encoder) {
      return tlv::Value();
    }

    std::copy_n(m_ivHead, 8, iv);
    return mbedtls_mpi_write_binary(&m_ivTail, &iv[8], 4) == 0 &&
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
    ok = ok && iv.size() == 12 && tag.size() == AuthenticationTagLen::value;
    if (!ok) {
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
    size_t nBlocks = (size / 8) + static_cast<int>(size % 8 != 0);
    mbedtls_mpi_uint r = 0;
    return mbedtls_mpi_add_int(&m_ivTail, &m_ivTail, nBlocks) == 0 &&
           mbedtls_mpi_mod_int(&r, &m_ivTail, 0xFFFFFFFF) == 0 &&
           mbedtls_mpi_lset(&m_ivTail, r) == 0;
  }

private:
  mbedtls_gcm_context m_ctx;
  uint8_t m_ivHead[8];
  mbedtls::Mpi m_ivTail;
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
