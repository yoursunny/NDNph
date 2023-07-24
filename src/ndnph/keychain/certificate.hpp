#ifndef NDNPH_KEYCHAIN_CERTIFICATE_HPP
#define NDNPH_KEYCHAIN_CERTIFICATE_HPP

#include "../packet/data.hpp"
#include "helper.hpp"
#include "validity-period.hpp"

namespace ndnph {
namespace certificate {

/** @brief Return 'KEY' component. */
inline Component
getKeyComponent() {
  static const uint8_t tlv[]{0x08, 0x03, 'K', 'E', 'Y'};
  static const Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/** @brief Return 'NDNph' component as default issuerId. */
inline Component
getIssuerDefault() {
  static const uint8_t tlv[]{0x08, 0x05, 'N', 'D', 'N', 'p', 'h'};
  static const Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/** @brief Return 'self' component as self-signed issuerId. */
inline Component
getIssuerSelf() {
  static const uint8_t tlv[]{0x08, 0x04, 's', 'e', 'l', 'f'};
  static const Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/** @brief Determine if the input is a key name. */
inline bool
isKeyName(const Name& name) {
  return name[-2] == getKeyComponent();
}

/** @brief Determine if the input is a certificate name. */
inline bool
isCertName(const Name& name) {
  return name[-4] == getKeyComponent();
}

/**
 * @brief Convert to subject name.
 * @param region where to allocate memory if needed.
 * @param input subject name, key name, or certificate name.
 * @param mustCopy if true, the returned name is always copied and does not reference input;
 *                 otherwise, the returned name may reference input name.
 * @return subject name, or an empty name upon failure.
 */
inline Name
toSubjectName(Region& region, const Name& input, bool mustCopy = false) {
  Name result;
  if (isKeyName(input)) {
    result = input.getPrefix(-2);
  } else if (isCertName(input)) {
    result = input.getPrefix(-4);
  } else {
    result = input;
  }

  if (mustCopy) {
    return result.clone(region);
  }
  return result;
}

/**
 * @brief Convert to key name.
 * @param region where to allocate memory if needed.
 * @param input subject name, key name, or certificate name.
 * @param mustCopy if true, the returned name is always copied and does not reference input;
 *                 otherwise, the returned name may reference input name.
 * @return key name, or an empty name upon failure.
 *         If @p input does not contain keyId component, it is randomly generated.
 */
inline Name
toKeyName(Region& region, const Name& input, bool mustCopy = false) {
  Name result;
  if (isKeyName(input)) {
    result = input;
  } else if (isCertName(input)) {
    result = input.getPrefix(-2);
  } else {
    return input.append(region, getKeyComponent(), convention::GenericNumber(),
                        convention::RandomValue());
  }

  if (mustCopy) {
    return result.clone(region);
  }
  return result;
}

/**
 * @brief Convert to certificate name.
 * @param region where to allocate memory if needed.
 * @param input subject name, key name, or certificate name.
 * @param mustCopy if true, the returned name is always copied and does not reference input;
 *                 otherwise, the returned name may reference input name.
 * @return certificate name, or an empty name upon failure.
 *         If @p input does not contain keyId component, it is randomly generated.
 *         If @p input does not contain issuerId component, it is set to 'NDNph'.
 *         If @p input does not contain version component, it is set to current timestamp.
 */
inline Name
toCertName(Region& region, const Name& input, bool mustCopy = false) {
  if (isCertName(input)) {
    if (mustCopy) {
      return input.clone(region);
    }
    return input;
  }

  if (isKeyName(input)) {
    return input.append(region, getIssuerDefault(), convention::Version(), convention::TimeValue());
  }

  return input.append(region, getKeyComponent(), convention::GenericNumber(),
                      convention::RandomValue(), getIssuerDefault(), convention::Version(),
                      convention::TimeValue());
}

/**
 * @brief Construct key name with specified keyId.
 * @param region where to allocate memory.
 * @param input subject name, key name, or certificate name; only subject name is taken.
 * @param keyId specified keyId.
 * @return key name, or an empty name upon failure.
 */
inline Name
makeKeyName(Region& region, const Name& input, const Component& keyId) {
  return toSubjectName(region, input).append(region, getKeyComponent(), keyId);
}

/**
 * @brief Construct certificate name with specified issuerId and version.
 * @param region where to allocate memory.
 * @param input subject name, key name, or certificate name; only key name is taken.
 * @param issuerId specified issuerId.
 * @param version specified version.
 * @return certificate name, or an empty name upon failure.
 */
inline Name
makeCertName(Region& region, const Name& input, const Component& issuerId,
             const Component& version) {
  return toKeyName(region, input).append(region, issuerId, version);
}

/**
 * @brief Construct certificate name with specified issuerId and version.
 * @param region where to allocate memory.
 * @param input subject name, key name, or certificate name; only key name is taken.
 * @param issuerId specified issuerId.
 * @param version version number; default is current Unix timestamp or a random number.
 * @return certificate name, or an empty name upon failure.
 */
inline Name
makeCertName(Region& region, const Name& input, const Component& issuerId, uint64_t version = 0) {
  return toKeyName(region, input)
    .append(region, issuerId, convention::Version(), convention::TimeValue(version));
}

/** @brief Determine if the Data packet is a certificate. */
inline bool
isCertificate(const Data& data) {
  return data && data.getContentType() == ContentType::Key && isCertName(data.getName());
}

inline Name
getIssuer(const Data& data) {
  const DSigInfo* sigInfo = data.getSigInfo();
  if (sigInfo != nullptr) {
    return sigInfo->name;
  }
  return Name();
}

inline ValidityPeriod
getValidity(const Data& data) {
  ValidityPeriod vp;

  const DSigInfo* sigInfo = data.getSigInfo();
  if (sigInfo == nullptr) {
    return vp;
  }

  auto decoder = sigInfo->extensions.makeDecoder();
  for (const auto& tlv : decoder) {
    if (vp.decodeFrom(tlv)) {
      return vp;
    }
  }

  return ValidityPeriod();
}

} // namespace certificate
namespace detail {

template<typename Signer, typename Modify>
Data::Signed
buildCertificate(Region& region, const Name& name, const ValidityPeriod& validity,
                 const Signer& signer, const Modify& modify) {
  auto data = region.create<Data>();
  if (!data) {
    return Data::Signed();
  }
  data.setName(certificate::toCertName(region, name));
  data.setContentType(ContentType::Key);
  data.setFreshnessPeriod(3600000);

  DSigInfo si;
  {
    Encoder encoder(region);
    encoder.prepend(validity);
    si.extensions = tlv::Value(encoder);
    encoder.trim();
  }

  if (!modify(data)) {
    return Data::Signed();
  }
  return data.sign(signer, std::move(si));
}

} // namespace detail
} // namespace ndnph

#endif // NDNPH_KEYCHAIN_CERTIFICATE_HPP
