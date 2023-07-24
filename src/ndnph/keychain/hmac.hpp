#ifndef NDNPH_KEYCHAIN_HMAC_HPP
#define NDNPH_KEYCHAIN_HMAC_HPP

#include "../port/timingsafe/port.hpp"
#include "helper.hpp"
#include "private-key.hpp"
#include "public-key.hpp"

namespace ndnph {

/** @brief HMAC-SHA256 secret key. */
class HmacKey
  : public detail::NamedPublicKey<SigType::HmacWithSha256>
  , public detail::NamedPrivateKey<SigType::HmacWithSha256> {
public:
  /** @brief Determine if this key is non-empty. */
  explicit operator bool() const {
    return m_key != nullptr;
  }

  /**
   * @brief Import raw secret key bits.
   * @param key raw key bits; will be copied if necessary.
   * @param keyLen key length in octets.
   * @return whether success.
   */
  bool import(const uint8_t* key, size_t keyLen) {
    m_key.reset(new port::HmacSha256(key, keyLen));
    return true;
  }

  size_t getMaxSigLen() const final {
    return NDNPH_SHA256_LEN;
  }

  ssize_t sign(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const final {
    bool ok = computeHmac(chunks, sig);
    return ok ? NDNPH_SHA256_LEN : -1;
  }

  bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig,
              size_t sigLen) const final {
    uint8_t result[NDNPH_SHA256_LEN];
    return computeHmac(chunks, result) &&
           port::TimingSafeEqual()(result, NDNPH_SHA256_LEN, sig, sigLen);
  }

private:
  bool computeHmac(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const {
    if (m_key == nullptr) {
      return false;
    }
    for (const auto& chunk : chunks) {
      m_key->update(chunk.begin(), chunk.size());
    }
    return m_key->final(sig);
  }

private:
  mutable std::unique_ptr<port::HmacSha256> m_key;
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_HMAC_HPP
