#ifndef NDNPH_KEYCHAIN_HELPER_HPP
#define NDNPH_KEYCHAIN_HELPER_HPP

#include "../port/crypto/port.hpp"
#include "../tlv/value.hpp"

namespace ndnph {
namespace detail {

inline bool
computeDigest(std::initializer_list<tlv::Value> chunks, uint8_t digest[NDNPH_SHA256_LEN])
{
  port::Sha256 hash;
  for (const auto& chunk : chunks) {
    hash.update(chunk.begin(), chunk.size());
  }
  return hash.final(digest);
}

} // namespace detail
} // namespace ndnph

#endif // NDNPH_KEYCHAIN_HELPER_HPP
