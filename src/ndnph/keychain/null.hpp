#ifndef NDNPH_KEYCHAIN_NULL_HPP
#define NDNPH_KEYCHAIN_NULL_HPP

#include "private-key.hpp"
#include "public-key.hpp"

namespace ndnph {

/**
 * @brief Null signature: packet is not signed.
 *
 * Signing produces an empty signature.
 * Verification does nothing and accepts any signature type.
 *
 * @note This is intended in testing environments or for experimental purposes.
 * @sa https://redmine.named-data.net/projects/ndn-tlv/wiki/NullSignature
 */
class NullKey
  : public PrivateKey
  , public PublicKey {
public:
  static const NullKey& get() {
    static NullKey instance;
    return instance;
  }

  size_t getMaxSigLen() const final {
    return 0;
  }

  void updateSigInfo(SigInfo& sigInfo) const final {
    sigInfo.sigType = SigType::Null;
    sigInfo.name = Name();
  }

  ssize_t sign(std::initializer_list<tlv::Value>, uint8_t*) const final {
    return 0;
  }

  bool matchSigInfo(const SigInfo&) const final {
    return true;
  }

  bool verify(std::initializer_list<tlv::Value>, const uint8_t*, size_t) const final {
    return true;
  }
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_NULL_HPP
