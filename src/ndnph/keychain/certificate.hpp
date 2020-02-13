#ifndef NDNPH_KEYCHAIN_CERTIFICATE_HPP
#define NDNPH_KEYCHAIN_CERTIFICATE_HPP

#include "../packet/data.hpp"
#include "../port/random/port.hpp"
#include "validity-period.hpp"

namespace ndnph {

/** @brief Functions to interact with a Certificate. */
class Certificate
{
public:
  /** @brief Determine if the input is a key name. */
  static bool isKeyName(const Name& name)
  {
    return name[-2] == getKeyComp();
  }

  /** @brief Determine if the input is a certificate name. */
  static bool isCertName(const Name& name)
  {
    return name[-4] == getKeyComp();
  }

  /** @brief Convert subject name, key name, or certificate name into subject name. */
  static Name toSubjectName(Region&, const Name& input)
  {
    if (isKeyName(input)) {
      return input.getPrefix(-2);
    }
    if (isCertName(input)) {
      return input.getPrefix(-4);
    }
    return input;
  }

  /** @brief Convert subject name, key name, or certificate name into key name. */
  static Name toKeyName(Region& region, const Name& input)
  {
    if (isKeyName(input)) {
      return input;
    }

    if (isCertName(input)) {
      return input.getPrefix(-2);
    }

    auto keyId = makeRandomComp(region);
    if (!keyId) {
      return Name();
    }
    return input.append(region, { getKeyComp(), keyId });
  }

  /** @brief Convert subject name, key name, or certificate name into certificate name. */
  static Name toCertName(Region& region, const Name& input)
  {
    if (isCertName(input)) {
      return input;
    }

    if (isKeyName(input)) {
      auto issuerId = makeRandomComp(region);
      auto version = makeRandomComp(region);
      if (!issuerId || !version) {
        return Name();
      }
      return input.append(region, { issuerId, version });
    }

    auto keyId = makeRandomComp(region);
    auto issuerId = makeRandomComp(region);
    auto version = makeRandomComp(region, 0x23);
    if (!keyId || !issuerId || !version) {
      return Name();
    }
    return input.append(region, { getKeyComp(), keyId, issuerId, version });
  }

  /** @brief Determine if the Data packet is a certificate. */
  static bool isCertificate(const Data& data)
  {
    return !!data && data.getContentType() == ContentType::Key && isCertName(data.getName());
  }

  template<typename Signer>
  class Builder
  {
  public:
    bool operator!() const
    {
      return !m_data;
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
    explicit Builder(Region& region, const Signer& signer)
      : m_data(region.create<Data>())
      , m_signer(signer)
    {}

    Builder<Signer>& reset()
    {
      m_data = Data();
      return *this;
    }

  private:
    Data m_data;
    DSigInfo m_si;
    const Signer& m_signer;

    friend Certificate;
  };

protected:
  template<typename Signer, typename Modifier>
  static Builder<Signer> buildImpl(Region& region, const Name& name, const ValidityPeriod& validity,
                                   const Signer& signer, const Modifier& modify)
  {
    Builder<Signer> builder(region, signer);
    if (!builder) {
      return builder.reset();
    }

    Data& data = builder.m_data;
    data.setName(toCertName(region, name));
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

private:
  Certificate() = delete;

  static Component getKeyComp()
  {
    static const Component comp = ([] {
      static const uint8_t buf[]{ 0x08, 0x03, 0x4B, 0x45, 0x59 };
      Component comp;
      Decoder(buf, sizeof(buf)).decode(comp);
      return comp;
    })();
    return comp;
  }

  static Component makeRandomComp(Region& region, uint16_t type = TT::GenericNameComponent)
  {
    uint8_t value[8];
    if (!port::RandomSource::generate(value, sizeof(value))) {
      return Component();
    }
    return Component(region, type, sizeof(value), value);
  }
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_CERTIFICATE_HPP
