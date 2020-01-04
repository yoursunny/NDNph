#ifndef NDNPH_TLV_VALUE_HPP
#define NDNPH_TLV_VALUE_HPP

#include "decoder.hpp"
#include "encoder.hpp"

namespace ndnph {
namespace tlv {

/** @brief A sequence of bytes, usually TLV-VALUE. */
class Value
{
public:
  explicit Value() = default;

  explicit Value(const uint8_t* value, size_t size)
    : m_value(value)
    , m_size(size)
  {}

  const uint8_t* begin() const { return m_value; }
  const uint8_t* end() const { return m_value + m_size; }
  size_t size() const { return m_size; }

  void encodeTo(Encoder& encoder) const
  {
    uint8_t* room = encoder.prependRoom(m_size);
    if (room != nullptr) {
      std::copy_n(m_value, m_size, room);
    }
  }

  bool decodeFrom(const Decoder::Tlv& d)
  {
    m_value = d.value;
    m_size = d.length;
    return true;
  }

private:
  const uint8_t* m_value = nullptr;
  size_t m_size = 0;
};

} // namespace tlv
} // namespace ndnph

#endif // NDNPH_TLV_VALUE_HPP
