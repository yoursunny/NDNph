#ifndef NDNPH_PORT_MBED_COMMON_HPP
#define NDNPH_PORT_MBED_COMMON_HPP
#ifdef NDNPH_HAVE_MBED

#include "../tlv/ev-decoder.hpp"
#include "../tlv/value.hpp"
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

namespace ndnph {
/** @brief Wrappers of Mbed TLS crypto library. */
namespace mbedtls {

/** @brief Random number generator for various Mbed TLS library functions. */
inline int
rng(void*, uint8_t* output, size_t count)
{
  bool ok = port::RandomSource::generate(output, count);
  return ok ? 0 : -1;
}

/** @brief SHA256 hash function. */
class Sha256
{
public:
  explicit Sha256()
  {
    mbedtls_sha256_init(&m_ctx);
    m_ok = mbedtls_sha256_starts_ret(&m_ctx, 0) == 0;
  }

  ~Sha256()
  {
    mbedtls_sha256_free(&m_ctx);
  }

  void update(const uint8_t* chunk, size_t size)
  {
    m_ok = m_ok && mbedtls_sha256_update_ret(&m_ctx, chunk, size) == 0;
  }

  bool final(uint8_t digest[NDNPH_SHA256_LEN])
  {
    m_ok = m_ok && mbedtls_sha256_finish_ret(&m_ctx, digest) == 0;
    return m_ok;
  }

private:
  mbedtls_sha256_context m_ctx;
  bool m_ok = false;
};

/** @brief Multi-Precision Integer. */
class Mpi : public mbedtls_mpi
{
public:
  explicit Mpi(const mbedtls_mpi* src = nullptr)
  {
    mbedtls_mpi_init(this);
    if (src != nullptr) {
      mbedtls_mpi_copy(this, src);
    }
  }

  explicit Mpi(const Mpi& src)
    : Mpi(&src)
  {}

  ~Mpi()
  {
    mbedtls_mpi_free(this);
  }

  Mpi& operator=(const Mpi& src)
  {
    mbedtls_mpi_copy(this, &src);
    return *this;
  }
};

/** @brief EC curve P256. */
class P256
{
public:
  using PvtLen = std::integral_constant<size_t, 32>;
  using PubLen = std::integral_constant<size_t, 65>;
  using MaxSigLen = std::integral_constant<size_t, 74>;

  static mbedtls_ecp_group* group()
  {
    static struct S
    {
      S()
      {
        int res = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
        assert(res == 0);
      }
      mbedtls_ecp_group grp;
    } s;
    return &s.grp;
  };

  /** @brief ECDH shared secret buffer. */
  using SharedSecret = std::array<uint8_t, PvtLen::value>;

  /** @brief Compute ECDH shared secret. */
  static bool ecdh(const mbedtls_mpi& pvt, const mbedtls_ecp_point& pub, SharedSecret& shared)
  {
    Mpi z;
    return mbedtls_ecdh_compute_shared(group(), &z, &pub, &pvt, rng, nullptr) == 0 &&
           mbedtls_mpi_write_binary(&z, shared.data(), shared.size()) == 0;
  }
};

/** @brief EC point. */
class EcPoint : public mbedtls_ecp_point
{
public:
  explicit EcPoint(const mbedtls_ecp_point* src = nullptr)
  {
    mbedtls_ecp_point_init(this);
    if (src != nullptr) {
      mbedtls_ecp_copy(this, src);
    }
  }

  EcPoint(const EcPoint& src)
    : EcPoint(&src)
  {}

  ~EcPoint()
  {
    mbedtls_ecp_point_free(this);
  }

  EcPoint& operator=(const EcPoint& src)
  {
    mbedtls_ecp_copy(this, &src);
    return *this;
  }

  void encodeTo(Encoder& encoder) const
  {
    constexpr size_t expectedLength = 65;
    uint8_t* room = encoder.prependRoom(expectedLength);
    if (room == nullptr) {
      encoder.setError();
      return;
    }

    size_t length = 0;
    int res = mbedtls_ecp_point_write_binary(P256::group(), this, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &length, room, expectedLength);
    if (res != 0 || length != expectedLength) {
      encoder.setError();
    }
  }

  bool decodeFrom(const Decoder::Tlv& d)
  {
    return mbedtls_ecp_point_read_binary(P256::group(), this, d.value, d.length) == 0 &&
           mbedtls_ecp_check_pubkey(P256::group(), this) == 0;
  }
};

namespace detail {

class IvHelper
{
public:
  using BlockSize = std::integral_constant<size_t, 16>;

  bool randomize()
  {
    m_ok = port::RandomSource::generate(reinterpret_cast<uint8_t*>(&random), sizeof(random));
    return m_ok;
  }

  bool advance(size_t size)
  {
    uint64_t nBlocks = (size / BlockSize::value) + static_cast<int>(size % BlockSize::value != 0);
    uint64_t cnt = static_cast<uint64_t>(counter) + nBlocks;
    if (counter > std::numeric_limits<uint32_t>::max()) {
      m_ok = false;
    }
    counter = static_cast<uint32_t>(cnt);
    return m_ok;
  }

  bool check(tlv::Value iv, size_t size)
  {
    if (iv.size() != sizeof(random) + sizeof(counter)) {
      return false;
    }

    uint64_t rand = tlv::NNI8::readValue(iv.begin());
    uint32_t cnt = tlv::NNI4::readValue(iv.begin() + sizeof(rand));

    if (counter == 0) {
      random = rand;
    } else if (random != rand) {
      return false;
    }

    if (cnt < counter) {
      return false;
    }
    counter = cnt;
    return advance(size);
  }

public:
  uint64_t random = 0;
  uint32_t counter = 0;
  bool m_ok = true;
};

} // namespace detail

/**
 * @brief AES-GCM secret key.
 * @tparam keyBits AES key size in bits, either 128 or 256.
 * @tparam ttIV TLV-TYPE of initialization-vector element.
 * @tparam ttTag TLV-TYPE of authentication-tag element.
 * @tparam ttEP TLV-TYPE of encrypted-payload element.
 *
 * InitializationVector is 12 octets. Other sizes are not supported. IV is constructed from an
 * 8-octet random number and a 4-octet counter, incremented for every encrypted block.
 * AuthenticationTag is 16 octets. Other sizes are not supported.
 *
 * TLV encoding has the structure:
 *   encrypted-message = initialization-vector authentication-tag encrypted-payload
 * TLV-TYPE numbers are given in template parameters. Other structures are not supported.
 */
template<int keyBits, int ttIV, int ttTag, int ttEP>
class AesGcm
{
public:
  static_assert(keyBits == 128 || keyBits == 256, "");
  using Key = std::array<uint8_t, keyBits / 8>;
  using AuthenticationTagLen = std::integral_constant<size_t, 16>;

  explicit AesGcm()
  {
    mbedtls_gcm_init(&m_ctx);
  }

  ~AesGcm()
  {
    mbedtls_gcm_free(&m_ctx);
  }

  AesGcm(const AesGcm&) = delete;
  AesGcm& operator=(const AesGcm&) = delete;

  /**
   * @brief Import raw AES key.
   * @return whether success.
   */
  bool import(const Key& key)
  {
    m_ok = mbedtls_gcm_setkey(&m_ctx, MBEDTLS_CIPHER_ID_AES, key.data(), keyBits) == 0 &&
           m_ivEncrypt.randomize();
    return m_ok;
  }

  /**
   * @brief Encrypt to encrypted-message.
   * @param region where to allocate memory.
   * @param plaintext input plaintext.
   * @param aad additional associated data.
   * @param aadLen length of @p aad .
   * @return encrypted-message, or a falsy value upon failure.
   * @post internal IV is incremented by number of encrypted blocks.
   */
  tlv::Value encrypt(Region& region, tlv::Value plaintext, const uint8_t* aad = nullptr,
                     size_t aadLen = 0)
  {
    Encoder encoder(region);
    uint8_t* ciphertext = encoder.prependRoom(plaintext.size());
    encoder.prependTypeLength(ttEP, plaintext.size());
    uint8_t* tag = encoder.prependRoom(AuthenticationTagLen::value);
    encoder.prependTypeLength(ttTag, AuthenticationTagLen::value);
    encoder.prepend(tlv::NNI8(m_ivEncrypt.random), tlv::NNI4(m_ivEncrypt.counter));
    const uint8_t* iv = encoder.begin();
    encoder.prependTypeLength(ttIV, 12);
    encoder.trim();

    bool ok = m_ok && !!encoder &&
              mbedtls_gcm_crypt_and_tag(&m_ctx, MBEDTLS_GCM_ENCRYPT, plaintext.size(), iv, 12, aad,
                                        aadLen, plaintext.begin(), ciphertext,
                                        AuthenticationTagLen::value, tag) == 0 &&
              m_ivEncrypt.advance(plaintext.size());
    if (!ok) {
      encoder.discard();
      return tlv::Value();
    }
    return tlv::Value(encoder);
  }

  /**
   * @brief Decrypt from encrypted-message.
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
  tlv::Value decrypt(Region& region, tlv::Value encrypted, const uint8_t* aad = nullptr,
                     size_t aadLen = 0)
  {
    tlv::Value iv, tag, ciphertext;
    bool ok =
      EvDecoder::decodeValue(encrypted.makeDecoder(), EvDecoder::def<ttIV>(&iv),
                             EvDecoder::def<ttTag>(&tag), EvDecoder::def<ttEP>(&ciphertext));
    if (!(m_ok && ok && tag.size() == AuthenticationTagLen::value &&
          m_ivDecrypt.check(iv, ciphertext.size()))) {
      return tlv::Value();
    }

    uint8_t* plaintext = region.alloc(ciphertext.size());
    ok = plaintext != nullptr &&
         mbedtls_gcm_auth_decrypt(&m_ctx, ciphertext.size(), iv.begin(), iv.size(), aad, aadLen,
                                  tag.begin(), tag.size(), ciphertext.begin(), plaintext) == 0;
    if (!ok) {
      region.free(plaintext, ciphertext.size());
      return tlv::Value();
    }
    return tlv::Value(plaintext, ciphertext.size());
  }

  void clearDecryptIvChecker()
  {
    m_ivDecrypt = detail::IvHelper();
  }

private:
  mbedtls_gcm_context m_ctx;
  detail::IvHelper m_ivEncrypt;
  detail::IvHelper m_ivDecrypt;
  bool m_ok = false;
};

} // namespace mbedtls
} // namespace ndnph

#endif // NDNPH_HAVE_MBED
#endif // NDNPH_PORT_MBED_COMMON_HPP
