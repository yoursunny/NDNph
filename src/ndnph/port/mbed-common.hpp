#ifndef NDNPH_PORT_MBED_COMMON_HPP
#define NDNPH_PORT_MBED_COMMON_HPP
#ifdef NDNPH_HAVE_MBED

#include "../keychain/iv.hpp"
#include "random/port.hpp"
#include <mbedtls/bignum.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#ifndef MBEDTLS_ECDSA_DETERMINISTIC
#error MBEDTLS_ECDSA_DETERMINISTIC must be declared
#endif

#if MBEDTLS_VERSION_MAJOR >= 3
#define NDNPH_MBEDTLS_RET2(func) func
#else
#define NDNPH_MBEDTLS_RET2(func) func##_ret
#endif

namespace ndnph {
/** @brief Wrappers of Mbed TLS crypto library. */
namespace mbedtls {

/** @brief Random number generator for various Mbed TLS library functions. */
inline int
rng(void*, uint8_t* output, size_t count) {
  bool ok = port::RandomSource::generate(output, count);
  return ok ? 0 : -1;
}

/** @brief SHA256 hash function. */
class Sha256 {
public:
  explicit Sha256() {
    mbedtls_sha256_init(&m_ctx);
    m_ok = NDNPH_MBEDTLS_RET2(mbedtls_sha256_starts)(&m_ctx, 0) == 0;
  }

  ~Sha256() {
    mbedtls_sha256_free(&m_ctx);
  }

  void update(const uint8_t* chunk, size_t size) {
    m_ok = m_ok && NDNPH_MBEDTLS_RET2(mbedtls_sha256_update)(&m_ctx, chunk, size) == 0;
  }

  bool final(uint8_t digest[NDNPH_SHA256_LEN]) {
    m_ok = m_ok && NDNPH_MBEDTLS_RET2(mbedtls_sha256_finish)(&m_ctx, digest) == 0;
    return m_ok;
  }

private:
  mbedtls_sha256_context m_ctx;
  bool m_ok = false;
};

/**
 * @brief HMAC algorithm.
 * @tparam mdType message digest type identifier.
 * @tparam mdSize checksum size.
 */
template<mbedtls_md_type_t mdType, size_t mdSize>
class Hmac {
public:
  /** @brief Start HMAC operation and set key. */
  explicit Hmac(const uint8_t* key, size_t keyLen) {
    mbedtls_md_init(&m_ctx);
    m_ok = mbedtls_md_setup(&m_ctx, mbedtls_md_info_from_type(mdType), 1) == 0 &&
           mbedtls_md_hmac_starts(&m_ctx, key, keyLen) == 0;
  }

  ~Hmac() {
    mbedtls_md_free(&m_ctx);
  }

  /** @brief Append bytes into hash state. */
  void update(const uint8_t* chunk, size_t size) {
    m_ok = m_ok && mbedtls_md_hmac_update(&m_ctx, chunk, size) == 0;
  }

  /**
   * @brief Finalize HMAC operation and obtain HMAC result.
   * @return whether success.
   * @post this object is ready for new HMAC operation with same key.
   */
  bool final(uint8_t result[mdSize]) {
    m_ok =
      m_ok && mbedtls_md_hmac_finish(&m_ctx, result) == 0 && mbedtls_md_hmac_reset(&m_ctx) == 0;
    return m_ok;
  }

private:
  mbedtls_md_context_t m_ctx;
  bool m_ok = false;
};

/** @brief Multi-Precision Integer. */
class Mpi {
public:
  /** @brief Construct zero. */
  explicit Mpi() {
    mbedtls_mpi_init(&m_value);
  }

  /** @brief Construct from MPI. */
  explicit Mpi(const mbedtls_mpi* src)
    : Mpi() {
    mbedtls_mpi_copy(&m_value, src);
  }

  /** @brief Construct from integer. */
  explicit Mpi(mbedtls_mpi_sint src)
    : Mpi() {
    mbedtls_mpi_lset(&m_value, src);
  }

  ~Mpi() {
    mbedtls_mpi_free(&m_value);
  }

  operator mbedtls_mpi*() {
    return &m_value;
  }

  operator const mbedtls_mpi*() const {
    return &m_value;
  }

  /** @brief Copy assignment is disallowed due to lack of error handling. */
  Mpi& operator=(const Mpi&) = delete;

  /**
   * @brief Move assignment.
   * @post @p y is cleared
   */
  Mpi& operator=(Mpi&& y) {
    mbedtls_mpi_swap(&m_value, &y.m_value);
    return *this;
  }

private:
  mbedtls_mpi m_value;
};

/** @brief EC point. */
class EcPoint {
public:
  /** @brief Construct zero. */
  explicit EcPoint() {
    mbedtls_ecp_point_init(&m_value);
  }

  /** @brief Construct from EC point. */
  explicit EcPoint(const mbedtls_ecp_point* q)
    : EcPoint() {
    if (q != nullptr) {
      mbedtls_ecp_copy(&m_value, q);
    }
  }

  ~EcPoint() {
    mbedtls_ecp_point_free(&m_value);
  }

  operator mbedtls_ecp_point*() {
    return &m_value;
  }

  operator const mbedtls_ecp_point*() const {
    return &m_value;
  }

  /** @brief Copy assignment is disallowed due to lack of error handling. */
  EcPoint& operator=(const EcPoint&) = delete;

  bool writeBinary(mbedtls_ecp_group* group, uint8_t* room, size_t length) const {
    size_t actualLength = 0;
    return mbedtls_ecp_point_write_binary(group, *this, MBEDTLS_ECP_PF_UNCOMPRESSED, &actualLength,
                                          room, length) == 0 &&
           actualLength == length;
  }

  void encodeTo(mbedtls_ecp_group* group, Encoder& encoder, size_t length) const {
    uint8_t* room = encoder.prependRoom(length);
    if (room == nullptr) {
      return;
    }

    if (!writeBinary(group, room, length)) {
      encoder.setError();
    }
  }

  bool readBinary(mbedtls_ecp_group* group, const uint8_t* value, size_t length) {
    return mbedtls_ecp_point_read_binary(group, *this, value, length) == 0 &&
           mbedtls_ecp_check_pubkey(group, *this) == 0;
  }

  bool decodeFrom(mbedtls_ecp_group* group, const Decoder::Tlv& d) {
    return readBinary(group, d.value, d.length);
  }

private:
  mbedtls_ecp_point m_value;
};

/** @brief EC point associated with a curve. */
template<typename Curve>
class EcCurvePoint : public EcPoint {
public:
  bool writeBinary(uint8_t room[Curve::PubLen::value]) const {
    return EcPoint::writeBinary(Curve::group(), room, Curve::PubLen::value);
  }

  void encodeTo(Encoder& encoder) const {
    return EcPoint::encodeTo(Curve::group(), encoder, Curve::PubLen::value);
  }

  bool readBinary(const uint8_t* value, size_t length) {
    return EcPoint::readBinary(Curve::group(), value, length);
  }

  bool decodeFrom(const Decoder::Tlv& d) {
    return EcPoint::decodeFrom(Curve::group(), d);
  }
};

/** @brief EC curve P256. */
class P256 {
public:
  using PvtLen = std::integral_constant<size_t, 32>;
  using PubLen = std::integral_constant<size_t, 65>;
  using MaxSigLen = std::integral_constant<size_t, 74>;
  using Point = EcCurvePoint<P256>;

  static mbedtls_ecp_group* group() {
    static struct S {
      S() {
        int res = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
        NDNPH_ASSERT(res == 0);
      }
      mbedtls_ecp_group grp;
    } s;
    return &s.grp;
  };

  /** @brief ECDH shared secret buffer. */
  using SharedSecret = std::array<uint8_t, PvtLen::value>;

  /** @brief Compute ECDH shared secret. */
  static bool ecdh(const mbedtls_mpi* pvt, const mbedtls_ecp_point* pub, SharedSecret& shared) {
    Mpi z;
    return mbedtls_ecdh_compute_shared(group(), z, pub, pvt, rng, nullptr) == 0 &&
           mbedtls_mpi_write_binary(z, shared.data(), shared.size()) == 0;
  }
};

/**
 * @brief AES-GCM secret key.
 * @tparam keyBits AES key size in bits, either 128 or 256.
 *
 * InitializationVector requirements are enforced by @c AesGcmIvHelper .
 * AuthenticationTag is 16 octets. Other sizes are not supported.
 */
template<int keyBits>
class AesGcm {
public:
  static_assert(keyBits == 128 || keyBits == 256, "");
  using Key = std::array<uint8_t, keyBits / 8>;
  using IvLen = AesGcmIvHelper::IvLen;
  using TagLen = std::integral_constant<size_t, 16>;

  explicit AesGcm() {
    mbedtls_gcm_init(&m_ctx);
  }

  ~AesGcm() {
    mbedtls_gcm_free(&m_ctx);
  }

  AesGcm(const AesGcm&) = delete;
  AesGcm& operator=(const AesGcm&) = delete;

  /**
   * @brief Import raw AES key.
   * @return whether success.
   */
  bool import(const Key& key) {
    m_ok = mbedtls_gcm_setkey(&m_ctx, MBEDTLS_CIPHER_ID_AES, key.data(), keyBits) == 0 &&
           m_ivEncrypt.randomize();
    return m_ok;
  }

  /**
   * @brief Encrypt to encrypted-message.
   * @tparam Encrypted a specialization of @c EncryptedMessage .
   * @param region where to allocate memory.
   * @param plaintext input plaintext.
   * @param aad additional associated data.
   * @param aadLen length of @p aad .
   * @return encrypted-message, or a falsy value upon failure.
   * @post internal IV is incremented by number of encrypted blocks.
   */
  template<typename Encrypted>
  tlv::Value encrypt(Region& region, tlv::Value plaintext, const uint8_t* aad = nullptr,
                     size_t aadLen = 0) {
    checkEncryptedMessage<Encrypted>();
    Encoder encoder(region);
    auto place = Encrypted::prependInPlace(encoder, plaintext.size());
    encoder.trim();

    bool ok = m_ok && !!encoder && m_ivEncrypt.write(place.iv) &&
              mbedtls_gcm_crypt_and_tag(&m_ctx, MBEDTLS_GCM_ENCRYPT, plaintext.size(), place.iv,
                                        IvLen::value, aad, aadLen, plaintext.begin(),
                                        place.ciphertext, TagLen::value, place.tag) == 0 &&
              m_ivEncrypt.advance(plaintext.size());
    if (!ok) {
      encoder.discard();
      return tlv::Value();
    }
    return tlv::Value(encoder);
  }

  /**
   * @brief Decrypt from encrypted-message.
   * @tparam Encrypted a specialization of @c EncryptedMessage .
   * @param region where to allocate memory.
   * @param encrypted encrypted-message.
   * @param aad additional associated data.
   * @param aadLen length of @p aad .
   * @return plaintext, or a falsy value upon failure.
   * @post internal IV is incremented by number of ciphertext blocks.
   *
   * This function enforces IV uniqueness. It requires the random number portion to be consistent,
   * and the counter portion to be monotonically increasing. Attempting to decrypt the same message
   * for a second time would result in failure due to duplicate IV. Caller should deduplicate
   * incoming messages, or disable this check by calling @p clearDecryptIvChecker() every time.
   */
  template<typename Encrypted>
  tlv::Value decrypt(Region& region, const Encrypted& encrypted, const uint8_t* aad = nullptr,
                     size_t aadLen = 0) {
    checkEncryptedMessage<Encrypted>();
    uint8_t* plaintext = region.alloc(encrypted.ciphertext.size());
    bool ok =
      m_ok && m_ivDecrypt.check(encrypted.iv.data(), encrypted.ciphertext.size()) &&
      plaintext != nullptr &&
      mbedtls_gcm_auth_decrypt(&m_ctx, encrypted.ciphertext.size(), encrypted.iv.data(),
                               encrypted.iv.size(), aad, aadLen, encrypted.tag.data(),
                               encrypted.tag.size(), encrypted.ciphertext.begin(), plaintext) == 0;
    if (!ok) {
      region.free(plaintext, encrypted.ciphertext.size());
      return tlv::Value();
    }
    return tlv::Value(plaintext, encrypted.ciphertext.size());
  }

  void clearDecryptIvChecker() {
    m_ivDecrypt = AesGcmIvHelper();
  }

private:
  template<typename Encrypted>
  static void checkEncryptedMessage() {
    static_assert(Encrypted::IvLen::value == IvLen::value, "");
    static_assert(Encrypted::TagLen::value == TagLen::value, "");
  }

private:
  mbedtls_gcm_context m_ctx;
  AesGcmIvHelper m_ivEncrypt;
  AesGcmIvHelper m_ivDecrypt;
  bool m_ok = false;
};

} // namespace mbedtls
} // namespace ndnph

#endif // NDNPH_HAVE_MBED
#endif // NDNPH_PORT_MBED_COMMON_HPP
