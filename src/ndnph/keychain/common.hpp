#ifndef NDNPH_KEYCHAIN_COMMON_HPP
#define NDNPH_KEYCHAIN_COMMON_HPP

#include "../tlv/value.hpp"

namespace ndnph {
namespace detail {

template<typename Sha256Port>
inline bool
computeDigest(std::initializer_list<tlv::Value> chunks, uint8_t digest[NDNPH_SHA256_LEN])
{
  Sha256Port hash;
  for (const auto& chunk : chunks) {
    hash.update(chunk.begin(), chunk.size());
  }
  return hash.final(digest);
}

} // namespace detail

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

#endif // NDNPH_KEYCHAIN_COMMON_HPP
