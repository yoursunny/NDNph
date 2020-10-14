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
  static Value fromString(const char* str)
  {
    return Value(reinterpret_cast<const uint8_t*>(str), std::strlen(str));
  }

  explicit Value() = default;

  /** @brief Reference a byte range. */
  explicit Value(const uint8_t* value, size_t size)
    : m_value(value)
    , m_size(size)
  {}

  /** @brief Reference a byte range. */
  explicit Value(const uint8_t* first, const uint8_t* last)
    : m_value(first)
    , m_size(last - first)
  {}

  /** @brief Reference encoder output. */
  explicit Value(const Encoder& encoder)
    : Value(encoder.begin(), encoder.size())
  {}

  /** @brief Return true if value is non-empty. */
  explicit operator bool() const
  {
    return size() > 0;
  }

  const uint8_t* begin() const
  {
    return m_value;
  }

  const uint8_t* end() const
  {
    return m_value + m_size;
  }

  size_t size() const
  {
    return m_size;
  }

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

  /** @brief Create a Decoder over this value buffer. */
  Decoder makeDecoder() const
  {
    return Decoder(m_value, m_size);
  }

private:
  const uint8_t* m_value = nullptr;
  size_t m_size = 0;
};

inline bool
operator==(const Value& lhs, const Value& rhs)
{
  return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

NDNPH_DECLARE_NE(Value, inline)

} // namespace tlv
} // namespace ndnph

#endif // NDNPH_TLV_VALUE_HPP
