#ifndef NDNPH_TLV_NNI_HPP
#define NDNPH_TLV_NNI_HPP

#include "decoder.hpp"
#include "encoder.hpp"

namespace ndnph {
namespace tlv {

/** @brief 1-byte number encoding. */
class NNI1
{
public:
  static bool decode(const Decoder::Tlv& d, uint8_t& value)
  {
    if (d.length != sizeof(value)) {
      return false;
    }
    value = d.value[0];
    return true;
  }

  explicit NNI1(uint8_t value)
    : m_value(value)
  {}

  void encodeTo(Encoder& encoder) const
  {
    uint8_t* room = encoder.prependRoom(sizeof(m_value));
    if (room != nullptr) {
      room[0] = m_value;
    }
  }

private:
  uint8_t m_value = 0;
};

/** @brief 4-byte number encoding. */
class NNI4
{
public:
  static bool decode(const Decoder::Tlv& d, uint32_t& value)
  {
    if (d.length != sizeof(value)) {
      return false;
    }
    value = readValue(d);
    return true;
  }

  explicit NNI4(uint32_t value)
    : m_value(value)
  {}

  void encodeTo(Encoder& encoder) const
  {
    uint8_t* room = encoder.prependRoom(sizeof(m_value));
    if (room != nullptr) {
      room[0] = m_value >> 24;
      room[1] = m_value >> 16;
      room[2] = m_value >> 8;
      room[3] = m_value;
    }
  }

private:
  static uint32_t readValue(const Decoder::Tlv& d)
  {
    return (static_cast<uint32_t>(d.value[0]) << 24) | (static_cast<uint32_t>(d.value[1]) << 16) |
           (static_cast<uint32_t>(d.value[2]) << 8) | d.value[3];
  }

  friend class NNI;

private:
  uint32_t m_value = 0;
};

/** @brief 8-byte number encoding. */
class NNI8
{
public:
  static bool decode(const Decoder::Tlv& d, uint64_t& value)
  {
    if (d.length != sizeof(value)) {
      return false;
    }
    value = readValue(d);
    return true;
  }

  explicit NNI8(uint64_t value)
    : m_value(value)
  {}

  void encodeTo(Encoder& encoder) const
  {
    uint8_t* room = encoder.prependRoom(sizeof(m_value));
    if (room != nullptr) {
      room[0] = m_value >> 56;
      room[1] = m_value >> 48;
      room[2] = m_value >> 40;
      room[3] = m_value >> 32;
      room[4] = m_value >> 24;
      room[5] = m_value >> 16;
      room[6] = m_value >> 8;
      room[7] = m_value;
    }
  }

private:
  static uint64_t readValue(const Decoder::Tlv& d)
  {
    return (static_cast<uint64_t>(d.value[0]) << 56) | (static_cast<uint64_t>(d.value[1]) << 48) |
           (static_cast<uint64_t>(d.value[2]) << 40) | (static_cast<uint64_t>(d.value[3]) << 32) |
           (static_cast<uint64_t>(d.value[4]) << 24) | (static_cast<uint64_t>(d.value[5]) << 16) |
           (static_cast<uint64_t>(d.value[6]) << 8) | d.value[7];
  }

  friend class NNI;

private:
  uint64_t m_value = 0;
};

/** @brief NonNegativeInteger encoding. */
class NNI
{
public:
  /**
   * @brief Decode NonNegativeInteger.
   * @tparam I destination integer type, which could be narrower than uint64_t.
   * @param max inclusive maximum value; default is max possible value of I type.
   */
  template<typename I, typename Limit = typename std::enable_if<std::is_integral<I>::value,
                                                                std::numeric_limits<I>>::type>
  static bool decode(const Decoder::Tlv& d, I& value, uint64_t max = Limit::max())
  {
    uint64_t v = 0;
    switch (d.length) {
      case 1:
        v = d.value[0];
        break;
      case 2:
        v = (static_cast<uint16_t>(d.value[0]) << 8) | d.value[1];
        break;
      case 4:
        v = NNI4::readValue(d);
        break;
      case 8:
        v = NNI8::readValue(d);
        break;
      default:
        return false;
    }
    value = v;
    return v <= max;
  }

  explicit NNI(uint64_t value)
    : m_value(value)
  {}

  void encodeTo(Encoder& encoder) const
  {
    if (m_value <= std::numeric_limits<uint8_t>::max()) {
      NNI1(m_value).encodeTo(encoder);
    } else if (m_value <= std::numeric_limits<uint16_t>::max()) {
      uint8_t* room = encoder.prependRoom(sizeof(uint16_t));
      if (room != nullptr) {
        room[0] = m_value >> 8;
        room[1] = m_value;
      }
    } else if (m_value <= std::numeric_limits<uint32_t>::max()) {
      NNI4(m_value).encodeTo(encoder);
    } else {
      NNI8(m_value).encodeTo(encoder);
    }
  }

private:
  uint64_t m_value = 0;
};

} // namespace tlv
} // namespace ndnph

#endif // NDNPH_TLV_NNI_HPP
