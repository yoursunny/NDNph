#ifndef NDNPH_KEYCHAIN_CERTIFICATE_HPP
#define NDNPH_KEYCHAIN_CERTIFICATE_HPP

#include "../packet/data.hpp"
#include "helper.hpp"
#include "validity-period.hpp"

namespace ndnph {
namespace certificate {

/** @brief Return 'KEY' component. */
inline Component
getKeyComponent()
{
  static const uint8_t tlv[]{ 0x08, 0x03, 0x4B, 0x45, 0x59 };
  static const Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/** @brief Return 'NDNph' component as default issuerId. */
inline Component
getIssuerDefault()
{
  static const uint8_t tlv[]{ 0x08, 0x05, 0x4E, 0x44, 0x4E, 0x70, 0x68 };
  static const Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/** @brief Return 'self' component as self-signed issuerId. */
inline Component
getIssuerSelf()
{
  static const uint8_t tlv[]{ 0x08, 0x04, 0x73, 0x65, 0x6C, 0x66 };
  static const Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/** @brief Determine if the input is a key name. */
inline bool
isKeyName(const Name& name)
{
  return name[-2] == getKeyComponent();
}

/** @brief Determine if the input is a certificate name. */
inline bool
isCertName(const Name& name)
{
  return name[-4] == getKeyComponent();
}

/** @brief Get subject name from subject name, key name, or certificate name. */
inline Name
toSubjectName(Region&, const Name& input)
{
  if (isKeyName(input)) {
    return input.getPrefix(-2);
  }
  if (isCertName(input)) {
    return input.getPrefix(-4);
  }
  return input;
}

/**
 * @brief Get key name from subject name, key name, or certificate name.
 *
 * If the input is a subject name, the keyId component is randomly generated,
 * and the key name is allocated in the region.
 */
inline Name
toKeyName(Region& region, const Name& input)
{
  if (isKeyName(input)) {
    return input;
  }

  if (isCertName(input)) {
    return input.getPrefix(-2);
  }

  auto keyId = detail::makeRandomComponent(region);
  if (!keyId) {
    return Name();
  }
  return input.append(region, { getKeyComponent(), keyId });
}

/**
 * @brief Get key name from subject name, key name, or certificate name.
 *
 * If the input is a subject name, the keyId component is randomly generated.
 * If the input is a key name, the issuerId is set to 'NDNph', and the version component
 * is randomly generated.
 * In both cases, the cert name is allocated in the region.
 */
inline Name
toCertName(Region& region, const Name& input)
{
  if (isCertName(input)) {
    return input;
  }

  if (isKeyName(input)) {
    auto version = detail::makeRandomComponent(region, TT::VersionNameComponent);
    if (!version) {
      return Name();
    }
    return input.append(region, { getIssuerDefault(), version });
  }

  auto keyId = detail::makeRandomComponent(region);
  auto version = detail::makeRandomComponent(region, TT::VersionNameComponent);
  if (!keyId || !version) {
    return Name();
  }
  return input.append(region, { getKeyComponent(), keyId, getIssuerDefault(), version });
}

/** @brief Determine if the Data packet is a certificate. */
inline bool
isCertificate(const Data& data)
{
  return data && data.getContentType() == ContentType::Key && isCertName(data.getName());
}

} // namespace certificate
namespace detail {

template<typename Signer>
class CertificateBuilder
{
public:
  template<typename Modify>
  static CertificateBuilder<Signer> create(Region& region, const Name& name,
                                           const ValidityPeriod& validity, const Signer& signer,
                                           const Modify& modify)
  {
    CertificateBuilder<Signer> builder(region, signer);
    if (!builder) {
      return builder.reset();
    }

    Data& data = builder.m_data;
    data.setName(certificate::toCertName(region, name));
    data.setContentType(ContentType::Key);
    data.setFreshnessPeriod(3600000);
    bool ok = modify(data);
    if (!ok) {
      return builder.reset();
    }

    DSigInfo& si = builder.m_si;
    {
      Encoder encoder(region);
      encoder.prepend(validity);
      si.extensions = tlv::Value(encoder.begin(), encoder.size());
      encoder.trim();
    }
    return builder;
  }

  explicit operator bool() const
  {
    return !!m_data;
  }

  void encodeTo(Encoder& encoder) const
  {
    if (!m_data) {
      encoder.setError();
    } else {
      m_data.sign(m_signer, m_si).encodeTo(encoder);
    }
  }

private:
  explicit CertificateBuilder(Region& region, const Signer& signer)
    : m_data(region.create<Data>())
    , m_signer(signer)
  {}

  CertificateBuilder<Signer>& reset()
  {
    m_data = Data();
    return *this;
  }

private:
  Data m_data;
  DSigInfo m_si;
  const Signer& m_signer;
};

} // namespace detail
} // namespace ndnph

#endif // NDNPH_KEYCHAIN_CERTIFICATE_HPP
