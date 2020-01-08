#ifndef NDNPH_KEYCHAIN_TIMING_SAFE_EQUAL_HPP
#define NDNPH_KEYCHAIN_TIMING_SAFE_EQUAL_HPP

#include "../core/common.hpp"

namespace ndnph {

/**
 * @brief Timing safe equality comparison.
 * @sa https://codahale.com/a-lesson-in-timing-attacks/
 */
class DefaultTimingSafeEqual
{
public:
  bool operator()(const uint8_t* a, size_t aLen, const uint8_t* b, size_t bLen)
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

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_TIMING_SAFE_EQUAL_HPP
