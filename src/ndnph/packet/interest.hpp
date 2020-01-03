#ifndef NDNPH_PACKET_INTEREST_HPP
#define NDNPH_PACKET_INTEREST_HPP

#include "../core/in-region.hpp"
#include "../tlv/encoder.hpp"
#include "../tlv/nni.hpp"
#include "name.hpp"

namespace ndnph {
namespace detail {

class InterestObj : public detail::InRegion
{
public:
  explicit InterestObj(Region& region)
    : InRegion(region)
  {}

  enum
  {
    DefaultLifetime = 4000,
    MaxHopLimit = 0xFF,
  };

public:
  Name name;
  uint32_t nonce = 0;
  uint16_t lifetime = DefaultLifetime;
  uint8_t hopLimit = MaxHopLimit;
  bool canBePrefix = false;
  bool mustBeFresh = false;
};

} // namespace detail

class Interest : public detail::RefRegion<detail::InterestObj>
{
public:
  using RefRegion::RefRegion;

  const Name& getName() const { return obj->name; }
  void setName(const Name& v) { obj->name = v; }

  bool getCanBePrefix() const { return obj->canBePrefix; }
  void setCanBePrefix(bool v) { obj->canBePrefix = v; }

  bool getMustBeFresh() const { return obj->mustBeFresh; }
  void setMustBeFresh(bool v) { obj->mustBeFresh = v; }

  uint32_t getNonce() const { return obj->nonce; }
  void setNonce(uint32_t v) { obj->nonce = v; }

  uint16_t getLifetime() const { return obj->lifetime; }
  void setLifetime(uint16_t v) { obj->lifetime = v; }

  uint8_t getHopLimit() const { return obj->hopLimit; }
  void setHopLimit(uint8_t v) { obj->hopLimit = v; }

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
        if (getLifetime() != detail::InterestObj::DefaultLifetime) {
          encoder.prependTlv(TT::InterestLifetime, tlv::NNI(getLifetime()));
        }
      },
      [this](Encoder& encoder) {
        if (getHopLimit() != detail::InterestObj::MaxHopLimit) {
          encoder.prependTlv(TT::HopLimit, tlv::NNI1(getHopLimit()));
        }
      });
  }
};

} // namespace ndnph

#endif // NDNPH_PACKET_INTEREST_HPP
