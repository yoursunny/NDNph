#ifndef NDNPH_KEYCHAIN_EC_HPP
#define NDNPH_KEYCHAIN_EC_HPP

#include "../port/ec/port.hpp"
#include "certificate.hpp"
#include "keychain.hpp"

namespace ndnph {
namespace ec {
namespace detail {

using namespace ndnph::detail;

using PvtLen = port::Ec::Curve::PvtLen;
using PubLen = port::Ec::Curve::PubLen;

/** @brief Return EC P-256 SPKI except the key. */
inline tlv::Value
getSpkiHeader() {
  static const uint8_t bytes[] = {
    0x30, 0x59,                                                 // SEQUENCE
    0x30, 0x13,                                                 // . SEQUENCE
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,       // .. OID ecPublicKey
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // .. OID prime256v1
    0x03, 0x42, 0x00                                            // . BIT STRING
  };
  static const tlv::Value value(bytes, sizeof(bytes));
  return value;
}

/** @brief Return '1.2.840.10045.2.1 ecPublicKey' OID bytes. */
inline tlv::Value
getOid() {
  static const tlv::Value value(getSpkiHeader().begin() + 4, 9);
  return value;
}

/**
 * @brief Extract raw public key from a certificate.
 * @return pointer to the raw key, or nullptr on failure.
 */
inline const uint8_t*
findPublicKeyInCertificate(const Data& data) {
  if (!certificate::isCertificate(data)) {
    return nullptr;
  }

  auto content = data.getContent();
  if (content.size() < PubLen::value) {
    return nullptr;
  }

  auto oid = getOid();
  auto found = std::search(content.begin(), content.end(), oid.begin(), oid.end());
  if (found == content.end()) {
    return nullptr;
  }

  return content.end() - PubLen::value;
}

} // namespace detail

/** @brief EC public key. */
class EcPublicKey : public detail::NamedPublicKey<SigType::Sha256WithEcdsa> {
public:
  using KeyLen = detail::PubLen;

  /** @brief Determine if this key is non-empty. */
  explicit operator bool() const {
    return m_key != nullptr;
  }

  /**
   * @brief Import from raw key bits.
   * @param name key name; will be referenced.
   * @param raw raw key bits; will be copied.
   * @return whether success.
   */
  bool import(const Name& name, const uint8_t raw[KeyLen::value]) {
    if (!certificate::isKeyName(name)) {
      return false;
    }

    m_key.reset(new port::Ec::PublicKey());
    if (!m_key->import(raw)) {
      m_key.reset();
      return false;
    }

    setName(name);
    std::copy_n(raw, sizeof(m_raw), m_raw);
    return true;
  }

  /**
   * @brief Import a public key from certificate.
   * @param region where to copy key name.
   * @param data certificate; it can be freed after this operation.
   * @return whether success.
   */
  bool import(Region& region, const Data& data) {
    const uint8_t* raw = detail::findPublicKeyInCertificate(data);
    if (raw == nullptr) {
      return false;
    }

    Name name = certificate::toKeyName(region, data.getName());
    if (!name) {
      return false;
    }

    return import(name, raw);
  }

  /**
   * @brief Generate certificate of this public key.
   * @param name key name or certificate name.
   * @param validity certificate validity period.
   * @param signer certificate issuer.
   * @return result object supporting explicit conversion to bool and equipped with a
   *         `void encodeTo(Encoder&) const` method. `!result` indicates the operation
   *         has failed. Encodable object is valid only if arguments to this function
   *         are kept alive.
   */
  template<typename Signer>
  Data::Signed buildCertificate(Region& region, const Name& name, const ValidityPeriod& validity,
                                const Signer& signer) const {
    return detail::buildCertificate(region, name, validity, signer, [&](Data& data) {
      auto spkiHdr = detail::getSpkiHeader();
      size_t spkiLen = spkiHdr.size() + KeyLen::value;
      uint8_t* spki = region.alloc(spkiLen);
      if (spki == nullptr) {
        return false;
      }

      auto pos = std::copy_n(spkiHdr.begin(), spkiHdr.size(), spki);
      std::copy_n(m_raw, KeyLen::value, pos);
      data.setContent(tlv::Value(spki, spkiLen));
      return true;
    });
  }

  /**
   * @brief Generate self-signed certificate of this public key.
   * @param validity certificate validity period.
   * @param signer corresponding private key.
   * @return result object supporting explicit conversion to bool and equipped with a
   *         `void encodeTo(Encoder&) const` method. `!result` indicates the operation
   *         has failed. Encodable object is valid only if arguments to this function
   *         are kept alive.
   */
  template<typename Signer>
  Data::Signed selfSign(Region& region, const ValidityPeriod& validity,
                        const Signer& signer) const {
    Name certName = certificate::makeCertName(region, getName(), certificate::getIssuerSelf());
    return buildCertificate(region, certName, validity, signer);
  }

  /**
   * @brief Perform verification.
   * @retval true signature is correct.
   * @retval false error or signature is incorrect.
   */
  bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig,
              size_t sigLen) const final {
    if (m_key == nullptr) {
      return false;
    }
    uint8_t digest[NDNPH_SHA256_LEN];
    return detail::computeDigest(chunks, digest) && m_key->verify(digest, sig, sigLen);
  }

private:
  std::unique_ptr<port::Ec::PublicKey> m_key;
  uint8_t m_raw[KeyLen::value];
};

/** @brief EC private key. */
class EcPrivateKey : public detail::NamedPrivateKey<SigType::Sha256WithEcdsa> {
public:
  using KeyLen = detail::PvtLen;
  using MaxSigLen = port::Ec::Curve::MaxSigLen;

  /** @brief Determine if this key is non-empty. */
  explicit operator bool() const {
    return m_key != nullptr;
  }

  /**
   * @brief Import a private key from raw key bits.
   * @return whether success.
   */
  bool import(const Name& name, const uint8_t raw[KeyLen::value]) {
    if (!certificate::isKeyName(name)) {
      return false;
    }

    m_key.reset(new port::Ec::PrivateKey());
    if (!m_key->import(raw)) {
      m_key.reset();
      return false;
    }

    setName(name);
    return true;
  }

  size_t getMaxSigLen() const final {
    return MaxSigLen::value;
  }

  ssize_t sign(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const final {
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
  std::unique_ptr<port::Ec::PrivateKey> m_key;
};

/**
 * @brief Generate key pair in raw format.
 * @return whether success.
 */
inline bool
generateRaw(uint8_t pvt[EcPrivateKey::KeyLen::value], uint8_t pub[EcPublicKey::KeyLen::value]) {
  return port::Ec::generateKey(pvt, pub);
}

namespace detail {

/** @brief Key pair stored in KeyChain. */
struct StoredKeyPair {
  uint8_t pvt[PvtLen::value];
  uint8_t pub[PubLen::value];
};

inline bool
generate(Region& region, const Name& name, EcPrivateKey& pvt, EcPublicKey& pub, KeyChain* keyChain,
         const char* id) {
  Name keyName = certificate::toKeyName(region, name, true);
  if (!keyName) {
    return false;
  }

  ScopedEncoder encoder(region);
  encoder.prepend(keyName);
  auto stored = reinterpret_cast<StoredKeyPair*>(encoder.prependRoom(sizeof(StoredKeyPair)));
  bool ok = stored != nullptr && generateRaw(stored->pvt, stored->pub) &&
            pvt.import(keyName, stored->pvt) && pub.import(keyName, stored->pub);

  if (keyChain != nullptr) {
    ok = ok && keyChain->keys.set(id, tlv::Value(encoder));
  }
  return ok;
}

} // namespace detail

/**
 * @brief Generate key pair.
 * @param region where to allocate key name.
 * @param name subject name or key name; can be released afterwards.
 * @param[out] pvt the private key.
 * @param[out] pub the public key.
 * @return whether success.
 */
inline bool
generate(Region& region, const Name& name, EcPrivateKey& pvt, EcPublicKey& pub) {
  return detail::generate(region, name, pvt, pub, nullptr, nullptr);
}

/**
 * @brief Generate key pair and save in KeyChain.
 * @param region where to allocate key name.
 * @param name subject name or key name; can be released afterwards.
 * @param[out] pvt the private key.
 * @param[out] pub the public key.
 * @param keyChain where to save the key pair.
 * @param id id within @p keyChain.
 * @return whether success.
 */
inline bool
generate(Region& region, const Name& name, EcPrivateKey& pvt, EcPublicKey& pub, KeyChain& keyChain,
         const char* id) {
  return detail::generate(region, name, pvt, pub, &keyChain, id);
}

/**
 * @brief Load key pair from KeyChain.
 * @return whether success.
 */
inline bool
load(KeyChain& keyChain, const char* id, Region& region, EcPrivateKey& pvt, EcPublicKey& pub) {
  tlv::Value storedObject = keyChain.keys.get(id, region);
  if (storedObject.size() < sizeof(detail::StoredKeyPair)) {
    return false;
  }
  auto stored = reinterpret_cast<const detail::StoredKeyPair*>(storedObject.begin());
  Name name;
  Decoder decoder(storedObject.begin() + sizeof(detail::StoredKeyPair),
                  storedObject.size() - sizeof(detail::StoredKeyPair));
  return decoder.decode(name) && pvt.import(name, stored->pvt) && pub.import(name, stored->pub);
}

/**
 * @brief Determine if the Data packet is a certificate that contains an EC public key.
 *
 * It is unnecessary to call this function before EcPublicKey::import().
 */
inline bool
isCertificate(const Data& data) {
  return detail::findPublicKeyInCertificate(data) != nullptr;
}

} // namespace ec

using EcPublicKey = ec::EcPublicKey;
using EcPrivateKey = ec::EcPrivateKey;

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_EC_HPP
