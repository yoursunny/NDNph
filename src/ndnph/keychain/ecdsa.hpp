#ifndef NDNPH_KEYCHAIN_ECDSA_HPP
#define NDNPH_KEYCHAIN_ECDSA_HPP

#include "certificate.hpp"
#include "private-key.hpp"
#include "public-key.hpp"

namespace ndnph {
namespace detail {

/** @brief Return ECDSA P-256 SPKI except the key. */
inline std::pair<const uint8_t*, size_t>
getEcdsaSpkiHeader()
{
  static const uint8_t hdr[] = {
    0x30, 0x59,                                                 // SEQUENCE
    0x30, 0x13,                                                 // . SEQUENCE
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,       // .. OID ecPublicKey
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // .. OID prime256v1
    0x03, 0x42, 0x00                                            // . BIT STRING
  };
  return std::make_pair(hdr, sizeof(hdr));
}

/** @brief Return '1.2.840.10045.2.1 ecPublicKey' OID bytes. */
inline std::pair<const uint8_t*, size_t>
getEcdsaOid()
{
  const uint8_t* hdr = getEcdsaSpkiHeader().first;
  return std::make_pair(&hdr[4], 9);
}

} // namespace detail

/** @brief ECDSA public key. */
class EcdsaPublicKey : public PublicKey
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

  /**
   * @brief Import a public key from certificate.
   * @return whether success.
   * @post key name is copied into @p region ; @p data can be freed.
   */
  static bool import(EcdsaPublicKey& pub, Region& region, const Data& data)
  {
    const uint8_t* raw = extractFromCertificate(data);
    if (raw == nullptr) {
      return false;
    }

    Name name = certificate::toKeyName(region, data.getName());
    if (!name) {
      return false;
    }

    return import(pub, name, raw);
  }

  /**
   * @brief Determine if the Data packet is a certificate that contains an ECDSA public key.
   *
   * It is unnecessary to call this function before extractFromCertificate or importFromCertificate.
   */
  static bool isCertificate(const Data& data)
  {
    return extractFromCertificate(data) != nullptr;
  }

  /**
   * @brief Extract raw public key from a certificate.
   * @return point to the raw key, length is KeyLen::value. nullptr on failure.
   */
  static const uint8_t* extractFromCertificate(const Data& data)
  {
    if (!certificate::isCertificate(data)) {
      return nullptr;
    }

    auto content = data.getContent();
    if (content.size() < KeyLen::value) {
      return nullptr;
    }

    auto oid = detail::getEcdsaOid();
    auto found = std::search(content.begin(), content.end(), oid.first, &oid.first[oid.second]);
    if (found == content.end()) {
      return nullptr;
    }

    return content.end() - KeyLen::value;
  }

  /**
   * @brief Generate certificate containing ECDSA public key.
   * @param name subject name, key name, or certificate name.
   * @param raw raw ECDSA public key.
   * @param validity certificate validity period.
   * @param signer certificate issuer.
   * @return result object supporting explicit conversion to bool and equipped with a
   *         `void encodeTo(Encoder&) const` method. `!result` indicates the operation
   *         has failed. Encodable object is valid only if arguments to this function
   *         are kept alive.
   */
  template<typename Signer>
  static detail::CertificateBuilder<Signer> buildCertificate(Region& region, const Name& name,
                                                             const uint8_t raw[KeyLen::value],
                                                             const ValidityPeriod& validity,
                                                             const Signer& signer)
  {
    return detail::CertificateBuilder<Signer>::create(
      region, name, validity, signer, [&](Data& data) {
        auto spkiHdr = detail::getEcdsaSpkiHeader();
        size_t spkiLen = spkiHdr.second + KeyLen::value;
        uint8_t* spki = region.alloc(spkiLen);
        if (spki == nullptr) {
          return false;
        }

        auto pos = std::copy_n(spkiHdr.first, spkiHdr.second, spki);
        std::copy_n(raw, KeyLen::value, pos);
        data.setContent(tlv::Value(spki, spkiLen));
        return true;
      });
  }

  explicit EcdsaPublicKey() = default;

  /** @brief Determine whether packet was signed by corresponding private key. */
  bool matchSigInfo(const SigInfo& sigInfo) const final
  {
    return sigInfo.sigType == SigType::Sha256WithEcdsa && sigInfo.name.isPrefixOf(m_name);
  }

  /**
   * @brief Perform verification.
   * @retval true signature is correct.
   * @retval false error or signature is incorrect.
   */
  bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig,
              size_t sigLen) const final
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

#endif // NDNPH_KEYCHAIN_ECDSA_HPP
