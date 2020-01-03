#ifndef NDNPH_PACKET_INTEREST_HPP
#define NDNPH_PACKET_INTEREST_HPP

#include "../core/in-region.hpp"
#include "../tlv/encoder.hpp"
#include "../tlv/nni.hpp"
#include "name.hpp"

namespace ndnph {

class Interest;

namespace detail {

class InterestObj : public detail::InRegion
{
public:
  explicit InterestObj(Region& region)
    : InRegion(region)
  {}

public:
  enum
  {
    DefaultLifetime = 4000,
  };

private:
  Name m_name;
  uint32_t m_nonce = 0;
  uint16_t m_lifetime = DefaultLifetime;
  uint8_t m_hopLimit = 0xFF;
  bool m_canBePrefix = false;
  bool m_mustBeFresh = false;

  friend Interest;
};

} // namespace detail

class Interest : public detail::RefRegion<detail::InterestObj>
{
public:
  using RefRegion::RefRegion;

  const Name& getName() const { return obj->m_name; }
  void setName(const Name& v) { obj->m_name = v; }

  bool getCanBePrefix() const { return obj->m_canBePrefix; }
  void setCanBePrefix(bool v) { obj->m_canBePrefix = v; }

  bool getMustBeFresh() const { return obj->m_mustBeFresh; }
  void setMustBeFresh(bool v) { obj->m_mustBeFresh = v; }

  uint32_t getNonce() const { return obj->m_nonce; }
  void setNonce(uint32_t v) { obj->m_nonce = v; }

  uint16_t getLifetime() const { return obj->m_lifetime; }
  void setLifetime(uint16_t v) { obj->m_lifetime = v; }

  uint8_t getHopLimit() const { return obj->m_hopLimit; }
  void setHopLimit(uint8_t v) { obj->m_hopLimit = v; }

  void encodeTo(Encoder& encoder) const
  {
    encoder.prependTlv(
      TT::Interest, getName(),
      [this](Encoder& encoder) {
        if (getCanBePrefix()) {
          encoder.prependTlv(TT::CanBePrefix);
        }
      },
      [this](Encoder& encoder) {
        if (getMustBeFresh()) {
          encoder.prependTlv(TT::MustBeFresh);
        }
      },
      [this](Encoder& encoder) {
        encoder.prependTlv(TT::Nonce, tlv::NNI4(getNonce()));
      },
      [this](Encoder& encoder) {
        uint16_t lifetime = getLifetime();
        if (lifetime != Interest::DefaultLifetime) {
          encoder.prependTlv(TT::InterestLifetime, tlv::NNI(lifetime));
        }
      },
      [this](Encoder& encoder) {
        uint8_t hopLimit = getHopLimit();
        if (hopLimit != 0xFF) {
          encoder.prependTlv(TT::HopLimit, tlv::NNI1(hopLimit));
        }
      });
  }

public:
  enum
  {
    DefaultLifetime = detail::InterestObj::DefaultLifetime,
  };
};

} // namespace ndnph

#endif // NDNPH_PACKET_INTEREST_HPP
