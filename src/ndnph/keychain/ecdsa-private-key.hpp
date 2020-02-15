#ifndef NDNPH_KEYCHAIN_ECDSA_PRIVATE_KEY_HPP
#define NDNPH_KEYCHAIN_ECDSA_PRIVATE_KEY_HPP

#include "ecdsa-public-key.hpp"
#include "private-key.hpp"

namespace ndnph {

/** @brief ECDSA private key. */
class EcdsaPrivateKey : public PrivateKey
{
public:
  using KeyLen = port::Ecdsa::Curve::PvtLen;
  using MaxSigLen = port::Ecdsa::Curve::MaxSigLen;

  /**
   * @brief Generate key pair in raw format.
   * @return whether success.
   */
  static bool generateRaw(uint8_t pvt[EcdsaPrivateKey::KeyLen::value],
                          uint8_t pub[EcdsaPublicKey::KeyLen::value])
  {
    return port::Ecdsa::generateKey(pvt, pub);
  }

  /**
   * @brief Generate key pair.
   * @return whether success.
   *
   * This function would not allow storing the key for future use. To access raw key bits,
   * use generateRaw() instead, then import as EcdsaPrivateKey and EcdsaPublicKey.
   */
  static bool generate(const Name& name, EcdsaPrivateKey& pvt, EcdsaPublicKey& pub)
  {
    uint8_t pvtRaw[EcdsaPrivateKey::KeyLen::value];
    uint8_t pubRaw[EcdsaPublicKey::KeyLen::value];
    return generateRaw(pvtRaw, pubRaw) && EcdsaPrivateKey::import(pvt, name, pvtRaw) &&
           EcdsaPublicKey::import(pub, name, pubRaw);
  }

  /**
   * @brief Import a private key from raw key bits.
   * @return whether success.
   */
  static bool import(EcdsaPrivateKey& pvt, const Name& name, const uint8_t raw[KeyLen::value])
  {
    std::unique_ptr<port::Ecdsa::PrivateKey> portKey(new port::Ecdsa::PrivateKey());
    if (!portKey->import(raw)) {
      return false;
    }
    pvt = EcdsaPrivateKey(name, std::move(portKey));
    return true;
  }

  explicit EcdsaPrivateKey() = default;

  size_t getMaxSigLen() const final
  {
    return MaxSigLen::value;
  }

  void updateSigInfo(SigInfo& sigInfo) const final
  {
    sigInfo.sigType = SigType::Sha256WithEcdsa;
    sigInfo.name = m_name;
  }

  ssize_t sign(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const final
  {
    if (m_key == nullptr) {
      return -1;
    }
    uint8_t digest[NDNPH_SHA256_LEN];
    if (!detail::computeDigest(chunks, digest)) {
      return -1;
    }
    return m_key->sign(digest, sig);
  }

private:
  explicit EcdsaPrivateKey(const Name& name, std::unique_ptr<port::Ecdsa::PrivateKey> key)
    : m_name(name)
    , m_key(std::move(key))
  {}

private:
  Name m_name;
  std::unique_ptr<port::Ecdsa::PrivateKey> m_key;
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_ECDSA_PRIVATE_KEY_HPP
