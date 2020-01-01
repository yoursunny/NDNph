#ifndef NDNPH_PACKET_COMPONENT_HPP
#define NDNPH_PACKET_COMPONENT_HPP

#include "../an.hpp"
#include "../core/region.hpp"
#include "../tlv/decoder.hpp"

namespace ndnph {

/**
 * @brief Name component.
 *
 * This type is immutable.
 */
class Component
{
public:
  explicit Component() = default;

  /** @brief Construct from decoder result, keeping reference to TLV. */
  explicit Component(const tlv::Decoder::Tlv& d) { fromDecoded(d); }

  /** @brief Decode, keeping reference to TLV. */
  explicit Component(const uint8_t* tlv, size_t size)
  {
    tlv::Decoder decoder(tlv, size);
    auto it = decoder.begin();
    if (it != decoder.end()) {
      fromDecoded(*it);
    }
  }

  /** @brief Construct from T-L-V, copying TLV-VALUE. */
  explicit Component(Region& region, uint16_t type, uint16_t length,
                     const uint8_t* value)
    : m_type(type)
    , m_length(length)
  {
    size_t sizeofT = tlv::sizeofVarNum(type);
    size_t sizeofL = tlv::sizeofVarNum(length);
    uint8_t* tlv = region.alloc(sizeofT + sizeofL + length);
    if (tlv == nullptr) {
      return;
    }

    tlv::writeVarNum(tlv, type);
    tlv::writeVarNum(&tlv[sizeofT], length);
    std::copy_n(value, length, &tlv[sizeofT + sizeofL]);
    m_tlv = tlv;
    m_value = &tlv[sizeofT + sizeofL];
  }

  /** @brief Construct GenericNameComponent from L-V, copying TLV-VALUE. */
  explicit Component(Region& region, uint16_t length, const uint8_t* value)
    : Component(region, TT::GenericNameComponent, length, value)
  {}

  /** @brief Return true if Component is invalid. */
  bool operator!() const { return m_type == 0; }

  uint16_t type() const { return m_type; }
  size_t length() const { return m_length; }
  const uint8_t* value() const { return m_value; }

  const uint8_t* tlv() const { return m_tlv; }
  size_t size() const { return m_value - m_tlv + m_length; }

private:
  void fromDecoded(const tlv::Decoder::Tlv& d)
  {
    if (d.type > 0 && d.type <= 0xFFFF) {
      m_tlv = d.tlv;
      m_type = d.type;
      m_length = d.length;
      m_value = d.value;
    }
  }

private:
  uint16_t m_type = 0;
  size_t m_length = 0;
  const uint8_t* m_tlv = nullptr;
  const uint8_t* m_value = nullptr;
};

} // namespace ndnph

#endif // NDNPH_PACKET_COMPONENT_HPP
