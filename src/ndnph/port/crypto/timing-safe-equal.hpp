#ifndef NDNPH_PORT_CRYPTO_TIMING_SAFE_EQUAL_HPP
#define NDNPH_PORT_CRYPTO_TIMING_SAFE_EQUAL_HPP

#include "../../core/common.hpp"

namespace ndnph {
namespace port_crypto_defaultequal {

/**
 * @brief Timing safe equality comparison.
 * @sa https://codahale.com/a-lesson-in-timing-attacks/
 */
class TimingSafeEqual
{
public:
  bool operator()(const uint8_t* a, size_t aLen, const uint8_t* b, size_t bLen) const
  {
    if (aLen != bLen) {
      return false;
    }
    uint8_t result = 0;
    for (size_t i = 0; i < aLen; ++i) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }
};

} // namespace port_crypto_defaultequal

#ifdef NDNPH_PORT_CRYPTOEQUAL_DEFAULT
namespace port {
using TimingSafeEqual = port_crypto_defaultequal::TimingSafeEqual;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_CRYPTO_TIMING_SAFE_EQUAL_HPP
