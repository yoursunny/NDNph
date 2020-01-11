#ifndef NDNPH_KEYCHAIN_ECDSA_KEY_HPP
#define NDNPH_KEYCHAIN_ECDSA_KEY_HPP

#include "../packet/sig-info.hpp"
#include "common.hpp"

namespace ndnph {

/**
 * @brief ECDSA public key.
 * @tparam Sha256Port platform-specific SHA256 implementation.
 * @tparam EcdsaPort platform-specific ECDSA implementation.
 */
template<typename Sha256Port, typename EcdsaPort, typename PubPort = typename EcdsaPort::PublicKey>
class BasicEcdsaPublicKey
{
public:
  explicit BasicEcdsaPublicKey() = default;

  explicit BasicEcdsaPublicKey(const Name&, std::unique_ptr<PubPort> key)
    : m_key(std::move(key))
  {}

  bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig, size_t sigLen) const
  {
    uint8_t digest[NDNPH_SHA256_LEN];
    return m_key != nullptr && detail::computeDigest<Sha256Port>(chunks, digest) &&
           m_key->verify(digest, sig, sigLen);
  }

private:
  std::unique_ptr<PubPort> m_key;
};

/**
 * @brief ECDSA private key.
 * @tparam Sha256Port platform-specific SHA256 implementation.
 * @tparam EcdsaPort platform-specific ECDSA implementation.
 */
template<typename Sha256Port, typename EcdsaPort, typename PvtPort = typename EcdsaPort::PrivateKey>
class BasicEcdsaPrivateKey
{
public:
  template<typename RandomSrc, typename PubPort = typename EcdsaPort::PublicKey>
  static bool generate(RandomSrc& rng, const Name& name,
                       BasicEcdsaPrivateKey<Sha256Port, EcdsaPort>& pvt,
                       BasicEcdsaPublicKey<Sha256Port, EcdsaPort>& pub)
  {
    std::unique_ptr<PvtPort> portPvt(new PvtPort());
    std::unique_ptr<PubPort> portPub(new PubPort());
    if (!EcdsaPort::generateKey(rng, *portPvt, *portPub)) {
      return false;
    }
    pvt = BasicEcdsaPrivateKey<Sha256Port, EcdsaPort>(name, std::move(portPvt));
    pub = BasicEcdsaPublicKey<Sha256Port, EcdsaPort>(name, std::move(portPub));
    return true;
  }

  explicit BasicEcdsaPrivateKey() = default;

  explicit BasicEcdsaPrivateKey(const Name& name, std::unique_ptr<PvtPort> key)
    : m_name(name)
    , m_key(std::move(key))
  {}

  void updateSigInfo(SigInfo& sigInfo) const
  {
    sigInfo.sigType = SigType::Sha256WithEcdsa;
    sigInfo.name = m_name;
  }

  using MaxSigLen = typename EcdsaPort::Curve::MaxSigLen;

  ssize_t sign(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const
  {
    uint8_t digest[NDNPH_SHA256_LEN];
    return m_key == nullptr || !detail::computeDigest<Sha256Port>(chunks, digest)
             ? -1
             : m_key->sign(digest, sig);
  }

private:
  Name m_name;
  std::unique_ptr<PvtPort> m_key;
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_ECDSA_KEY_HPP
