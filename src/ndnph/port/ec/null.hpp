#ifndef NDNPH_PORT_EC_NULL_HPP
#define NDNPH_PORT_EC_NULL_HPP

#include "../../core/common.hpp"

namespace ndnph {
namespace port_ec_null {

/** @brief Stub ECDSA algorithm implementation. */
class Ec
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
     * @brief Import raw key.
     * @return whether success.
     */
    bool import(const uint8_t[Curve::PubLen::value])
    {
      return false;
    }

    /**
     * @brief Perform signing on a SHA256 digest.
     * @return signature length, or -1 upon failure.
     */
    ssize_t sign(const uint8_t digest[NDNPH_SHA256_LEN], uint8_t sig[Curve::MaxSigLen::value]) const
    {
      (void)digest;
      (void)sig;
      return -1;
    }
  };

  /** @brief Public key. */
  class PublicKey
  {
  public:
    /**
     * @brief Import raw key.
     * @return whether success.
     */
    bool import(const uint8_t[Curve::PubLen::value])
    {
      return false;
    }

    /**
     * @brief Perform verification on a SHA256 digest against a given signature.
     * @return verification result.
     */
    bool verify(const uint8_t digest[NDNPH_SHA256_LEN], const uint8_t* sig, size_t sigLen) const
    {
      (void)digest;
      (void)sig;
      (void)sigLen;
      return false;
    }
  };

  /**
   * @brief Generate key pair.
   * @param[out] pvt raw private key.
   * @param[out] pub raw public key.
   * @return whether success.
   */
  static bool generateKey(uint8_t pvt[Curve::PvtLen::value], uint8_t pub[Curve::PubLen::value])
  {
    (void)pvt;
    (void)pub;
    return false;
  }
};

} // namespace port_ec_null

#ifdef NDNPH_PORT_EC_NULL
namespace port {
using Ec = port_ec_null::Ec;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_EC_NULL_HPP
