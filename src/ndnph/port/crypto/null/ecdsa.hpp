#ifndef NDNPH_PORT_CRYPTO_NULL_ECDSA_HPP
#define NDNPH_PORT_CRYPTO_NULL_ECDSA_HPP

#include "../../../core/common.hpp"

namespace ndnph {
namespace port_crypto_null {

/** @brief Stub ECDSA algorithm implementation. */
class Ecdsa
{
public:
  /** @brief Give information about the curve. */
  struct Curve
  {
    /** @brief Private key length. */
    using PvtLen = std::integral_constant<size_t, 32>;

    /** @brief Public key length. */
    using PubLen = std::integral_constant<size_t, 65>;

    /** @brief Maximum signature length. */
    using MaxSigLen = std::integral_constant<size_t, 73>;
  };

  /** @brief Private key. */
  class PrivateKey
  {
  public:
    /**
     * @brief Perform signing on a SHA256 digest.
     * @return signature length, or -1 upon failure.
     */
    ssize_t sign(const uint8_t[NDNPH_SHA256_LEN], uint8_t[Curve::MaxSigLen::value]) const
    {
      return -1;
    }
  };

  /** @brief Public key. */
  class PublicKey
  {
  public:
    /**
     * @brief Perform verification on a SHA256 digest against a given signature.
     * @return verification result.
     */
    bool verify(const uint8_t[NDNPH_SHA256_LEN], const uint8_t*, size_t) const
    {
      return false;
    }
  };

  /**
   * @brief Generate key pair.
   * @return whether success.
   */
  static bool generateKey(PrivateKey&, PublicKey&)
  {
    return false;
  }
};

} // namespace port_mbedtls
} // namespace ndnph

#endif // NDNPH_PORT_CRYPTO_NULL_ECDSA_HPP
