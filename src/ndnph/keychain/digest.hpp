#ifndef NDNPH_KEYCHAIN_DIGEST_HPP
#define NDNPH_KEYCHAIN_DIGEST_HPP

#include "../port/timingsafe/port.hpp"
#include "helper.hpp"
#include "private-key.hpp"
#include "public-key.hpp"

namespace ndnph {

/** @brief DigestSha256 signing and verification. */
class DigestKey
  : public PrivateKey
  , public PublicKey {
public:
  static const DigestKey& get() {
    static DigestKey instance;
    return instance;
  }

  size_t getMaxSigLen() const final {
    return NDNPH_SHA256_LEN;
  }

  void updateSigInfo(SigInfo& sigInfo) const final {
    sigInfo.sigType = SigType::Sha256;
    sigInfo.name = Name();
  }

  ssize_t sign(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const final {
    bool ok = detail::computeDigest(chunks, sig);
    return ok ? NDNPH_SHA256_LEN : -1;
  }

  bool matchSigInfo(const SigInfo& sigInfo) const final {
    return sigInfo.sigType == SigType::Sha256;
  }

  bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig,
              size_t sigLen) const final {
    uint8_t digest[NDNPH_SHA256_LEN];
    return detail::computeDigest(chunks, digest) &&
           port::TimingSafeEqual()(digest, NDNPH_SHA256_LEN, sig, sigLen);
  }
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_DIGEST_HPP
