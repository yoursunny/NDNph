#ifndef NDNPH_PORT_NULL_ECDSA_HPP
#define NDNPH_PORT_NULL_ECDSA_HPP

#include "../../core/common.hpp"

namespace ndnph {
namespace port_null {

class Ecdsa
{
public:
  struct Curve
  {
    using PvtLen = std::integral_constant<size_t, 32>;
    using PubLen = std::integral_constant<size_t, 65>;
    using MaxSigLen = std::integral_constant<size_t, 73>;
  };

  class PrivateKey
  {
  public:
    ssize_t sign(const uint8_t[NDNPH_SHA256_LEN],
                 uint8_t[Curve::MaxSigLen::value]) const
    {
      return -1;
    }
  };

  class PublicKey
  {
  public:
    bool verify(const uint8_t[NDNPH_SHA256_LEN], const uint8_t*, size_t) const
    {
      return false;
    }
  };

  template<typename RandomSrc>
  static bool generateKey(RandomSrc&, PrivateKey&, PublicKey&)
  {
    return false;
  }
};

} // namespace port_mbedtls
} // namespace ndnph

#endif // NDNPH_PORT_NULL_ECDSA_HPP
