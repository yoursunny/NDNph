#ifndef NDNPH_TLV_NNI_HPP
#define NDNPH_TLV_NNI_HPP

#include "decoder.hpp"
#include "encoder.hpp"

namespace ndnph {
namespace tlv {

class NNI1
{
public:
  static bool decode(const Decoder::Tlv& d, uint8_t& n)
  {
    if (d.length != sizeof(n)) {
      return false;
    }
    n = d.value[0];
    return true;
  }

  explicit NNI1(uint8_t n)
    : m_n(n)
  {}

  void encodeTo(Encoder& encoder) const
  {
    uint8_t* room = encoder.prependRoom(sizeof(m_n));
    if (room == nullptr) {
      return;
    }
    room[0] = m_n;
  }

private:
  uint8_t m_n = 0;
};

class NNI4
{
public:
  static bool decode(const Decoder::Tlv& d, uint32_t& n)
  {
    if (d.length != sizeof(n)) {
      return false;
    }
    n = (static_cast<uint32_t>(d.value[0]) << 24) |
        (static_cast<uint32_t>(d.value[1]) << 16) |
        (static_cast<uint32_t>(d.value[2]) << 8) | d.value[3];
    return true;
  }

  explicit NNI4(uint32_t n)
    : m_n(n)
  {}

  void encodeTo(Encoder& encoder) const
  {
    uint8_t* room = encoder.prependRoom(sizeof(m_n));
    if (room == nullptr) {
      return;
    }
    room[0] = m_n >> 24;
    room[1] = m_n >> 16;
    room[2] = m_n >> 8;
    room[3] = m_n;
  }

private:
  uint32_t m_n = 0;
};

class NNI
{
public:
  template<typename I,
           typename Limit = typename std::enable_if<
             std::is_integral<I>::value, std::numeric_limits<I>>::type>
  static bool decode(const Decoder::Tlv& d, I& n, uint64_t max = Limit::max())
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
        v = (static_cast<uint32_t>(d.value[0]) << 24) |
            (static_cast<uint32_t>(d.value[1]) << 16) |
            (static_cast<uint32_t>(d.value[2]) << 8) | d.value[3];
        break;
      case 8:
        v = (static_cast<uint64_t>(d.value[0]) << 56) |
            (static_cast<uint64_t>(d.value[1]) << 48) |
            (static_cast<uint64_t>(d.value[2]) << 40) |
            (static_cast<uint64_t>(d.value[3]) << 32) |
            (static_cast<uint64_t>(d.value[4]) << 24) |
            (static_cast<uint64_t>(d.value[5]) << 16) |
            (static_cast<uint64_t>(d.value[6]) << 8) | d.value[7];
        break;
      default:
        return false;
    }
    n = v;
    return v <= max;
  }

  explicit NNI(uint64_t n)
    : m_n(n)
  {}

  void encodeTo(Encoder& encoder) const
  {
    if (m_n <= std::numeric_limits<uint8_t>::max()) {
      uint8_t* room = encoder.prependRoom(sizeof(uint8_t));
      if (room != nullptr) {
        room[0] = m_n;
      }
    } else if (m_n <= std::numeric_limits<uint16_t>::max()) {
      uint8_t* room = encoder.prependRoom(sizeof(uint16_t));
      if (room != nullptr) {
        room[0] = m_n >> 8;
        room[1] = m_n;
      }
    } else if (m_n <= std::numeric_limits<uint32_t>::max()) {
      uint8_t* room = encoder.prependRoom(sizeof(uint32_t));
      if (room != nullptr) {
        room[0] = m_n >> 24;
        room[1] = m_n >> 16;
        room[2] = m_n >> 8;
        room[3] = m_n;
      }
    } else {
      uint8_t* room = encoder.prependRoom(sizeof(uint64_t));
      if (room != nullptr) {
        room[0] = m_n >> 56;
        room[1] = m_n >> 48;
        room[2] = m_n >> 40;
        room[3] = m_n >> 32;
        room[4] = m_n >> 24;
        room[5] = m_n >> 16;
        room[6] = m_n >> 8;
        room[7] = m_n;
      }
    }
  }

private:
  uint64_t m_n = 0;
};

} // namespace tlv
} // namespace ndnph

#endif // NDNPH_TLV_NNI_HPP
