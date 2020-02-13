#ifndef NDNPH_KEYCHAIN_ECDSA_CERTIFICATE_HPP
#define NDNPH_KEYCHAIN_ECDSA_CERTIFICATE_HPP

#include "certificate.hpp"
#include "ecdsa-public-key.hpp"

namespace ndnph {

/** @brief Functions to interact with a Certificate containing ECDSA public key. */
class EcdsaCertificate : public Certificate
{
public:
  /** @brief Determine if the Data packet is an ECDSA certificate. */
  static bool isCertificate(const Data& data)
  {
    if (!Certificate::isCertificate(data)) {
      return false;
    }

    auto content = data.getContent();
    if (content.size() < EcdsaPublicKey::KeyLen::value) {
      return false;
    }

    // OID 1.2.840.10045.2.1 ecPublicKey
    static const uint8_t spkiOid[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    auto found = std::search(content.begin(), content.end(), spkiOid, spkiOid + sizeof(spkiOid));
    return found != content.end();
  }

  /**
   * @brief Load ECDSA public key from certificate.
   * @post key name is copied into @p region ; @p data can be freed.
   */
  static bool loadKey(Region& region, const Data& data, EcdsaPublicKey& pub)
  {
    if (!isCertificate(data)) {
      return false;
    }

    Name name = toKeyName(region, data.getName());
    if (!name) {
      return false;
    }

    auto content = data.getContent();
    return EcdsaPublicKey::import(pub, name, content.end() - EcdsaPublicKey::KeyLen::value);
  }

  /**
   * @brief Generate certificate containing ECDSA public key.
   * @param name subject name, key name, or certificate name.
   * @param raw raw ECDSA public key.
   * @param validity certificate validity period.
   * @param signer certificate issuer.
   * @return result object with `bool operator!() const` and `void encodeTo(Encoder&) const`
   *         methods. `!result` indicates operation has failed. Encodable object is valid only
   *         if arguments to this function are kept alive.
   */
  template<typename Signer>
  static Builder<Signer> build(Region& region, const Name& name,
                               const uint8_t raw[EcdsaPublicKey::KeyLen::value],
                               const ValidityPeriod& validity, const Signer& signer)
  {
    return buildImpl(region, name, validity, signer, [&](Data& data) {
      static const uint8_t spkiHdr[] = {
        0x30, 0x59,                                                 // SEQUENCE
        0x30, 0x13,                                                 // . SEQUENCE
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,       // .. OID ecPublicKey
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // .. OID prime256v1
        0x03, 0x42, 0x00                                            // . BIT STRING
      };
      size_t spkiLen = sizeof(spkiHdr) + EcdsaPublicKey::KeyLen::value;
      uint8_t* spki = region.alloc(spkiLen);
      if (spki == nullptr) {
        return false;
      }

      auto pos = std::copy_n(spkiHdr, sizeof(spkiHdr), spki);
      std::copy_n(raw, EcdsaPublicKey::KeyLen::value, pos);
      data.setContent(tlv::Value(spki, spkiLen));
      return true;
    });
  }
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_ECDSA_CERTIFICATE_HPP
