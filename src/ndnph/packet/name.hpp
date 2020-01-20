#ifndef NDNPH_PACKET_NAME_HPP
#define NDNPH_PACKET_NAME_HPP

#include "../core/input-iterator-pointer-proxy.hpp"
#include "../tlv/value.hpp"
#include "component.hpp"

namespace ndnph {

/**
 * @brief Name.
 *
 * This type is immutable, except `decodeFrom()` method.
 */
class Name
{
public:
  /** @brief Construct referencing TLV-VALUE. */
  explicit Name(const uint8_t* value = nullptr, size_t length = 0)
  {
    decodeValue(value, length);
  }

  /** @brief Construct from TLV-VALUE. */
  template<typename It>
  explicit Name(Region& region, It first, It last)
  {
    static_assert(std::is_base_of<std::forward_iterator_tag,
                                  typename std::iterator_traits<It>::iterator_category>::value,
                  "");
    static_assert(std::is_same<uint8_t, typename std::iterator_traits<It>::value_type>::value, "");
    size_t length = std::distance(first, last);
    uint8_t* value = region.alloc(length);
    if (value != nullptr) {
      std::copy(first, last, value);
      decodeValue(value, length);
    }
  }

  /** @brief Construct from TLV-VALUE. */
  explicit Name(Region& region, std::initializer_list<uint8_t> value)
    : Name(region, value.begin(), value.end())
  {}

  /**
   * @brief Parse from URI.
   * @param region memory region; must have 2*strlen(uri) available room
   * @param uri URI in canonical format; scheme and authority must be omitted;
   *            `8=` prefix of GenericNameComponent may be omitted.
   * @return name; it's valid if !name is false.
   * @note This is a not-so-strict parser. It lets some invalid inputs slip through
   *       in exchange for smaller code size. Not recommended on untrusted input.
   */
  static Name parse(Region& region, const char* uri)
  {
    size_t uriLen = std::strlen(uri);
    size_t bufLen = 2 * uriLen;
    uint8_t* buf = region.alloc(bufLen);
    if (buf == nullptr) {
      return Name();
    }

    size_t nComps = 0;
    ssize_t length = parseUri(buf, bufLen, uri, uriLen, nComps);
    if (length < 0) {
      region.free(buf, bufLen);
      return Name();
    }

    uint8_t* value = buf + bufLen - length;
    if (value != buf) {
      std::copy_backward(buf, buf + length, value + length);
      region.free(buf, bufLen - length);
    }
    return Name(value, length, nComps);
  }

  /** @brief Return true if Name is invalid. */
  bool operator!() const
  {
    return m_value == nullptr;
  }

  size_t length() const
  {
    return m_length;
  }

  const uint8_t* value() const
  {
    return m_value;
  }

  /** @brief Get number of components. */
  size_t size() const
  {
    return m_nComps;
  }

  /** @brief Iterator over name components. */
  class Iterator : public Decoder::Iterator
  {
  public:
    using super = Decoder::Iterator;
    using iterator_category = std::input_iterator_tag;
    using value_type = const Component;
    using difference_type = std::ptrdiff_t;
    using pointer = detail::InputIteratorPointerProxy<value_type>;
    using reference = value_type;

    Iterator() = default;

    explicit Iterator(const super& inner)
      : super(inner)
    {}

    reference operator*()
    {
      Component comp;
      comp.decodeFrom(super::operator*());
      return comp;
    }

    pointer operator->()
    {
      return pointer(this->operator*());
    }
  };

  Iterator begin() const
  {
    return Iterator(Decoder(m_value, m_length).begin());
  }

  Iterator end() const
  {
    return Iterator(Decoder(m_value, m_length).end());
  }

  /** @brief Access i-th component. */
  Component operator[](int i) const
  {
    if (i < 0) {
      i += m_nComps;
    }
    if (isOutOfRange(i)) {
      return Component();
    }
    auto it = begin();
    std::advance(it, i);
    return *it;
  }

  /**
   * @brief Get sub name [first, last).
   * @param first inclusive first component index; if negative, count from end.
   * @param last exclusive last component index; if non-positive, count from end.
   */
  Name slice(int first = 0, int last = 0) const
  {
    if (first < 0) {
      first += m_nComps;
    }
    if (last <= 0) {
      last += m_nComps;
    }
    if (isOutOfRange(first) || isOutOfRange(last, true) || first >= last) {
      return Name();
    }

    auto it = begin();
    std::advance(it, first);
    auto firstComp = *it;
    std::advance(it, last - first - 1);
    auto lastComp = *it; // inclusive last component
    return Name(firstComp.tlv(), lastComp.tlv() + lastComp.size() - firstComp.tlv(), last - first);
  }

  /**
   * @brief Get prefix of n components.
   * @param n number of component; if non-positive, count from end.
   */
  Name getPrefix(int n = 0) const
  {
    return slice(0, n);
  }

  /**
   * @brief Append a sequence of components.
   * @return new Name that copies TLV-VALUE of this name and all components
   *
   * If you need to append multiple components, it's recommended to append them all at once,
   * so that memory is allocated and copied only once.
   */
  Name append(Region& region, std::initializer_list<Component> comps) const
  {
    size_t nComps = m_nComps, length = m_length;
    for (const auto& comp : comps) {
      ++nComps;
      length += comp.size();
    }
    uint8_t* value = region.alloc(length);
    if (value != nullptr) {
      uint8_t* pos = value;
      pos = std::copy_n(m_value, m_length, pos);
      for (const auto& comp : comps) {
        pos = std::copy_n(comp.tlv(), comp.size(), pos);
      }
    }
    return Name(value, length, nComps);
  }

  /** @brief Name compare result. */
  enum CompareResult
  {
    CMP_LT = -2,      ///< lhs is less than, but not a prefix of rhs
    CMP_LPREFIX = -1, ///< lhs is a prefix of rhs
    CMP_EQUAL = 0,    ///< lhs and rhs are equal
    CMP_RPREFIX = +1, ///< rhs is a prefix of lhs
    CMP_GT = +2,      ///< rhs is less than, but not a prefix of lhs
  };

  /** @brief Compare with other name. */
  CompareResult compare(const Name& other) const
  {
    size_t commonLength = std::min(m_length, other.m_length);
    int commonCmp = std::memcmp(m_value, other.m_value, commonLength);
    if (commonCmp < 0) {
      return CMP_LT;
    }
    if (commonCmp > 0) {
      return CMP_GT;
    }
    if (m_length > commonLength) {
      return CMP_RPREFIX;
    }
    if (other.m_length > commonLength) {
      return CMP_LPREFIX;
    }
    return CMP_EQUAL;
  }

  /** @brief Determine if this name is a prefix of other. */
  bool isPrefixOf(const Name& other) const
  {
    auto cmp = compare(other);
    return cmp == CMP_LPREFIX || cmp == CMP_EQUAL;
  }

  void encodeTo(Encoder& encoder) const
  {
    encoder.prependTlv(TT::Name, tlv::Value(m_value, m_length));
  }

  bool decodeFrom(const Decoder::Tlv& d)
  {
    return decodeValue(d.value, d.length);
  }

private:
  explicit Name(const uint8_t* value, size_t length, size_t nComps)
    : m_value(value)
    , m_length(length)
    , m_nComps(nComps)
  {}

  bool decodeValue(const uint8_t* value, size_t length)
  {
    m_value = value;
    if (decodeComps(length)) {
      return true;
    }
    m_value = nullptr;
    m_length = m_nComps = 0;
    return false;
  }

  bool decodeComps(size_t length)
  {
    Decoder decoder(m_value, length);
    auto it = decoder.begin(), end = decoder.end();
    for (; it != end; ++it) {
      Component comp;
      if (!it->decode(comp)) {
        return false;
      }
      m_length += it->size;
      ++m_nComps;
    }
    return !it.hasError();
  }

  bool isOutOfRange(int i, bool acceptPastEnd = false) const
  {
    return i < 0 ||
           (acceptPastEnd ? i > static_cast<int>(m_nComps) : i >= static_cast<int>(m_nComps));
  }

  static ssize_t parseUri(uint8_t* buf, size_t bufLen, const char* uri, size_t uriLen,
                          size_t& nComps)
  {
    nComps = 0;
    if (uriLen <= 1) { // empty Name
      return 0;
    }
    const char* uriEnd = uri + uriLen;
    size_t length = 0;
    while (uri < uriEnd) {
      ++uri; // skip '/'
      const char* compEnd = std::strchr(uri, '/');
      if (compEnd == nullptr) {
        compEnd = uriEnd;
      }

      auto comp = Component::parse(buf + length, bufLen - length, uri, compEnd - uri);
      if (!comp) {
        return -1;
      }
      ++nComps;
      length += comp.size();
      uri = compEnd;
    }
    return length;
  }

private:
  const uint8_t* m_value = nullptr;
  size_t m_length = 0;
  size_t m_nComps = 0;
};

inline bool
operator==(const Name& lhs, const Name& rhs)
{
  return lhs.compare(rhs) == Name::CMP_EQUAL;
}

inline bool
operator<(const Name& lhs, const Name& rhs)
{
  auto cmp = lhs.compare(rhs);
  return cmp == Name::CMP_LT || cmp == Name::CMP_LPREFIX;
}

NDNPH_DECLARE_NE(Name, inline)
NDNPH_DECLARE_GT_LE_GE(Name, inline)

} // namespace ndnph

#endif // NDNPH_PACKET_NAME_HPP
