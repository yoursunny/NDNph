#ifndef NDNPH_KEYCHAIN_ECDSA_PUBLIC_KEY_HPP
#define NDNPH_KEYCHAIN_ECDSA_PUBLIC_KEY_HPP

#include "../packet/sig-info.hpp"
#include "common.hpp"

namespace ndnph {

/** @brief ECDSA public key. */
class EcdsaPublicKey
{
public:
  using KeyLen = port::Ecdsa::Curve::PubLen;

  /**
   * @brief Import a public key from raw key bits.
   * @return whether success.
   */
  static bool import(EcdsaPublicKey& pub, const Name& name, const uint8_t raw[KeyLen::value])
  {
    std::unique_ptr<port::Ecdsa::PublicKey> portKey(new port::Ecdsa::PublicKey());
    if (!portKey->import(raw)) {
      return false;
    }
    pub = EcdsaPublicKey(name, std::move(portKey));
    return true;
  }

  explicit EcdsaPublicKey() = default;

  /** @brief Determine whether packet was signed by corresponding private key. */
  bool matchSigInfo(const SigInfo& sigInfo) const
  {
    return sigInfo.sigType == SigType::Sha256WithEcdsa && sigInfo.name.isPrefixOf(m_name);
  }

  /**
   * @brief Perform verification.
   * @retval true signature is correct.
   * @retval false error or signature is incorrect.
   */
  bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig, size_t sigLen) const
  {
    if (m_key == nullptr) {
      return false;
    }
    uint8_t digest[NDNPH_SHA256_LEN];
    return detail::computeDigest(chunks, digest) && m_key->verify(digest, sig, sigLen);
  }

private:
  explicit EcdsaPublicKey(const Name& name, std::unique_ptr<port::Ecdsa::PublicKey> key)
    : m_name(name)
    , m_key(std::move(key))
  {}

private:
  Name m_name;
  std::unique_ptr<port::Ecdsa::PublicKey> m_key;
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_ECDSA_PUBLIC_KEY_HPP
