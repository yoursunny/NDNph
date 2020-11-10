#ifndef NDNPH_TLV_NNI_HPP
#define NDNPH_TLV_NNI_HPP

#include "decoder.hpp"
#include "encoder.hpp"

namespace ndnph {
namespace tlv {

class NNI;

namespace detail {

template<typename T>
class NNIValue
{
public:
  static bool decode(const Decoder::Tlv& d, T& value)
  {
    if (d.length != sizeof(T)) {
      return false;
    }
    value = readValue(d.value);
    return true;
  }

  explicit NNIValue(T number)
    : m_number(number)
  {}

  void encodeTo(Encoder& encoder) const
  {
    uint8_t* room = encoder.prependRoom(sizeof(m_number));
    if (room != nullptr) {
      writeValue(room, m_number);
    }
  }

private:
  static T readValue(const uint8_t* value);

  static void writeValue(uint8_t* room, T n);

  friend NNI;

private:
  T m_number = 0;
};

template<>
inline uint8_t
NNIValue<uint8_t>::readValue(const uint8_t* value)
{
  return value[0];
}

template<>
inline void
NNIValue<uint8_t>::writeValue(uint8_t* room, uint8_t n)
{
  room[0] = n;
}

template<>
inline uint16_t
NNIValue<uint16_t>::readValue(const uint8_t* value)
{
  return (static_cast<uint16_t>(value[0]) << 8) | static_cast<uint16_t>(value[1]);
}

template<>
inline void
NNIValue<uint16_t>::writeValue(uint8_t* room, uint16_t n)
{
  room[0] = static_cast<uint8_t>(n >> 8);
  room[1] = static_cast<uint8_t>(n);
}

template<>
inline uint32_t
NNIValue<uint32_t>::readValue(const uint8_t* value)
{
  return (static_cast<uint32_t>(value[0]) << 24) | (static_cast<uint32_t>(value[1]) << 16) |
         (static_cast<uint32_t>(value[2]) << 8) | static_cast<uint32_t>(value[3]);
}

template<>
inline void
NNIValue<uint32_t>::writeValue(uint8_t* room, uint32_t n)
{
  room[0] = static_cast<uint8_t>(n >> 24);
  room[1] = static_cast<uint8_t>(n >> 16);
  room[2] = static_cast<uint8_t>(n >> 8);
  room[3] = static_cast<uint8_t>(n);
}

template<>
inline uint64_t
NNIValue<uint64_t>::readValue(const uint8_t* value)
{
  return (static_cast<uint64_t>(value[0]) << 56) | (static_cast<uint64_t>(value[1]) << 48) |
         (static_cast<uint64_t>(value[2]) << 40) | (static_cast<uint64_t>(value[3]) << 32) |
         (static_cast<uint64_t>(value[4]) << 24) | (static_cast<uint64_t>(value[5]) << 16) |
         (static_cast<uint64_t>(value[6]) << 8) | static_cast<uint64_t>(value[7]);
}

template<>
inline void
NNIValue<uint64_t>::writeValue(uint8_t* room, uint64_t n)
{
  room[0] = static_cast<uint8_t>(n >> 56);
  room[1] = static_cast<uint8_t>(n >> 48);
  room[2] = static_cast<uint8_t>(n >> 40);
  room[3] = static_cast<uint8_t>(n >> 32);
  room[4] = static_cast<uint8_t>(n >> 24);
  room[5] = static_cast<uint8_t>(n >> 16);
  room[6] = static_cast<uint8_t>(n >> 8);
  room[7] = static_cast<uint8_t>(n);
}

} // namespace detail

/** @brief 1-byte number encoding. */
using NNI1 = detail::NNIValue<uint8_t>;

/** @brief 2-byte number encoding. */
using NNI2 = detail::NNIValue<uint16_t>;

/** @brief 4-byte number encoding. */
using NNI4 = detail::NNIValue<uint32_t>;

/** @brief 8-byte number encoding. */
using NNI8 = detail::NNIValue<uint64_t>;

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
    uint64_t n = 0;
    switch (d.length) {
      case 1:
        n = NNI1::readValue(d.value);
        break;
      case 2:
        n = NNI2::readValue(d.value);
        break;
      case 4:
        n = NNI4::readValue(d.value);
        break;
      case 8:
        n = NNI8::readValue(d.value);
        break;
      default:
        return false;
    }
    value = n;
    return n <= max;
  }

  explicit NNI(uint64_t number)
    : m_number(number)
  {}

  void encodeTo(Encoder& encoder) const
  {
    if (m_number <= std::numeric_limits<uint8_t>::max()) {
      NNI1(m_number).encodeTo(encoder);
    } else if (m_number <= std::numeric_limits<uint16_t>::max()) {
      NNI2(m_number).encodeTo(encoder);
    } else if (m_number <= std::numeric_limits<uint32_t>::max()) {
      NNI4(m_number).encodeTo(encoder);
    } else {
      NNI8(m_number).encodeTo(encoder);
    }
  }

private:
  uint64_t m_number = 0;
};

template<typename N = NNI>
class NNIElement
{
public:
  template<typename I>
  explicit NNIElement(uint32_t type, I value)
    : m_type(type)
    , m_nni(value)
  {}

  void encodeTo(Encoder& encoder) const
  {
    encoder.prependTlv(m_type, m_nni);
  }

private:
  uint32_t m_type;
  N m_nni;
};

} // namespace tlv
} // namespace ndnph

#endif // NDNPH_TLV_NNI_HPP
