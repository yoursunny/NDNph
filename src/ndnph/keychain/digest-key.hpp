#ifndef NDNPH_KEYCHAIN_DIGEST_KEY_HPP
#define NDNPH_KEYCHAIN_DIGEST_KEY_HPP

#include "../packet/sig-info.hpp"
#include "timing-safe-equal.hpp"

namespace ndnph {

/**
 * @brief DigestSha256 signing and verification.
 * @tparam Sha256Port platform-specific SHA256 implementation.
 * @tparam TimingSafeEqual platform-specific timing safe equal implementation.
 */
template<typename Sha256Port, typename TimingSafeEqual = DefaultTimingSafeEqual>
class DigestKey
{
public:
  void updateSigInfo(SigInfo& sigInfo) const
  {
    sigInfo.sigType = SigType::Sha256;
    sigInfo.name = Name();
  }

  using MaxSigLength = std::integral_constant<int, 32>;

  ssize_t sign(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const
  {
    Sha256Port hash;
    for (const auto& chunk : chunks) {
      hash.update(chunk.begin(), chunk.size());
    }
    bool ok = hash.final(sig);
    return ok ? MaxSigLength::value : -1;
  }

  bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig,
              size_t length) const
  {
    uint8_t digest[MaxSigLength::value];
    return length == sizeof(digest) && sign(chunks, digest) == sizeof(digest) &&
           TimingSafeEqual()(digest, sizeof(digest), sig, length);
  }
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_DIGEST_KEY_HPP
