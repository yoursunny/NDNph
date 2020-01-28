#ifndef NDNPH_KEYCHAIN_ECDSA_KEY_HPP
#define NDNPH_KEYCHAIN_ECDSA_KEY_HPP

#include "../packet/sig-info.hpp"
#include "common.hpp"

namespace ndnph {

/** @brief ECDSA public key. */
class EcdsaPublicKey
{
public:
  explicit EcdsaPublicKey() = default;

  explicit EcdsaPublicKey(const Name&, std::unique_ptr<port::Ecdsa::PublicKey> key)
    : m_key(std::move(key))
  {}

  bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig, size_t sigLen) const
  {
    uint8_t digest[NDNPH_SHA256_LEN];
    return m_key != nullptr && detail::computeDigest(chunks, digest) &&
           m_key->verify(digest, sig, sigLen);
  }

private:
  std::unique_ptr<port::Ecdsa::PublicKey> m_key;
};

/** @brief ECDSA private key. */
class EcdsaPrivateKey
{
public:
  static bool generate(const Name& name, EcdsaPrivateKey& pvt, EcdsaPublicKey& pub)
  {
    std::unique_ptr<port::Ecdsa::PrivateKey> portPvt(new port::Ecdsa::PrivateKey());
    std::unique_ptr<port::Ecdsa::PublicKey> portPub(new port::Ecdsa::PublicKey());
    if (!port::Ecdsa::generateKey(*portPvt, *portPub)) {
      return false;
    }
    pvt = EcdsaPrivateKey(name, std::move(portPvt));
    pub = EcdsaPublicKey(name, std::move(portPub));
    return true;
  }

  explicit EcdsaPrivateKey() = default;

  explicit EcdsaPrivateKey(const Name& name, std::unique_ptr<port::Ecdsa::PrivateKey> key)
    : m_name(name)
    , m_key(std::move(key))
  {}

  void updateSigInfo(SigInfo& sigInfo) const
  {
    sigInfo.sigType = SigType::Sha256WithEcdsa;
    sigInfo.name = m_name;
  }

  using MaxSigLen = port::Ecdsa::Curve::MaxSigLen;

  ssize_t sign(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const
  {
    uint8_t digest[NDNPH_SHA256_LEN];
    return m_key == nullptr || !detail::computeDigest(chunks, digest) ? -1
                                                                      : m_key->sign(digest, sig);
  }

private:
  Name m_name;
  std::unique_ptr<port::Ecdsa::PrivateKey> m_key;
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_ECDSA_KEY_HPP
