#ifndef NDNPH_PACKET_COMPONENT_HPP
#define NDNPH_PACKET_COMPONENT_HPP

#include "../an.hpp"
#include "../core/printing.hpp"
#include "../core/region.hpp"
#include "../tlv/decoder.hpp"
#include "../tlv/encoder.hpp"

namespace ndnph {

/**
 * @brief Name component.
 *
 * This type is immutable, except `decodeFrom()` method.
 */
class Component : public detail::Printable
{
public:
  explicit Component() = default;

  /** @brief Construct from T-L-V. */
  explicit Component(Region& region, uint16_t type, size_t length, const uint8_t* value)
    : Component(region.alloc(computeSize(type, length)), computeSize(type, length), type, length,
                value)
  {}

  /** @brief Construct GenericNameComponent from L-V. */
  explicit Component(Region& region, size_t length, const uint8_t* value)
    : Component(region, TT::GenericNameComponent, length, value)
  {}

  /**
   * @brief Construct from T-L-V into provided buffer.
   * @param buf buffer for writing TLV.
   * @param bufLen size of buf; if insufficient, !component will be true.
   * @param type TLV-TYPE
   * @param length TLV-LENGTH
   * @param value TLV-VALUE, may overlap with buf
   * @param writeFromBack write TLV from back of provided buffer instead of from front.
   */
  explicit Component(uint8_t* buf, size_t bufLen, uint16_t type, size_t length,
                     const uint8_t* value, bool writeFromBack = false)
    : m_type(type)
    , m_length(length)
  {
    size_t sizeofTlv = computeSize(type, length);
    if (buf == nullptr || bufLen < sizeofTlv) {
      m_type = 0;
      return;
    }
    if (writeFromBack) {
      buf = buf + bufLen - sizeofTlv;
    }

    size_t sizeofT = tlv::sizeofVarNum(type);
    size_t sizeofL = tlv::sizeofVarNum(length);
    uint8_t* valueBuf = &buf[sizeofT + sizeofL];
    if (value != valueBuf) {
      std::memmove(valueBuf, value, length);
    }
    tlv::writeVarNum(buf, type);
    tlv::writeVarNum(&buf[sizeofT], length);
    m_tlv = buf;
    m_value = valueBuf;
  }

  /** @brief Construct from const TLV buffer. */
  static Component constant(const uint8_t* tlv, size_t size)
  {
    Component comp;
    Decoder(tlv, size).decode(comp);
    return comp;
  }

  /**
   * @brief Construct from TLV-TYPE, and several arguments to be encoded to TLV-VALUE.
   * @tparam Arg any Encodable type.
   */
  template<typename... Arg>
  static Component from(Region& region, uint16_t type, const Arg&... arg)
  {
    Encoder encoder(region);
    Decoder::Tlv d;
    Component comp;
    if (encoder.prependTlv(type, arg...) && Decoder::readTlv(d, encoder.begin(), encoder.end()) &&
        comp.decodeFrom(d)) {
      encoder.trim();
    } else {
      encoder.discard();
    }
    return comp;
  }

  /**
   * @brief Parse from URI.
   * @param region memory region; must have 8 + strlen(uri) available room
   * @param uri URI in canonical format; except that `8=` prefix of GenericNameComponent
   *            may be omitted.
   * @return component; it's valid if !component is false.
   * @note This is a not-so-strict parser. It lets some invalid inputs slip through
   *       in exchange for smaller code size. Not recommended on untrusted input.
   */
  static Component parse(Region& region, const char* uri)
  {
    return parse(region, uri, std::strlen(uri));
  }

  static Component parse(Region& region, const char* uri, size_t uriLen)
  {
    size_t bufLen = 8 + uriLen;
    uint8_t* buf = region.alloc(bufLen);
    if (buf == nullptr) {
      return Component();
    }
    Component comp = parse(buf, bufLen, uri, uriLen, true);
    region.free(buf, !comp ? bufLen : comp.m_tlv - buf);
    return comp;
  }

  /** @brief Parse from URI into provided buffer. */
  static Component parse(uint8_t* buf, size_t bufLen, const char* uri)
  {
    return parse(buf, bufLen, uri, std::strlen(uri));
  }

  static Component parse(uint8_t* buf, size_t bufLen, const char* uri, size_t uriLen,
                         bool writeFromBack = false)
  {
    const char* uriEnd = uri + uriLen;
    const char* posEqual = std::find(uri, uriEnd, '=');
    uint16_t type = TT::GenericNameComponent;
    if (posEqual != uriEnd) {
      type = std::strtoul(uri, nullptr, 10);
      uri = posEqual + 1;
    }

    size_t valueOffset = std::min(bufLen, tlv::sizeofVarNum(type) + tlv::sizeofVarNum(uriLen));
    uint8_t* valueBuf = buf + valueOffset; // write TLV-VALUE in place in most cases
    ssize_t length = parseUriValue(valueBuf, bufLen - valueOffset, uri, uriEnd);
    if (length < 0) {
      return Component();
    }
    return Component(buf, bufLen, type, length, valueBuf, writeFromBack);
  }

  /** @brief Return true if Component is valid. */
  explicit operator bool() const
  {
    return m_type != 0;
  }

  uint16_t type() const
  {
    return m_type;
  }

  size_t length() const
  {
    return m_length;
  }

  const uint8_t* value() const
  {
    return m_value;
  }

  const uint8_t* tlv() const
  {
    return m_tlv;
  }

  size_t size() const
  {
    return m_value - m_tlv + m_length;
  }

  bool decodeFrom(const Decoder::Tlv& d)
  {
    if (d.type == 0 || d.type > 0xFFFF) {
      return false;
    }
    m_tlv = d.tlv;
    m_type = d.type;
    m_length = d.length;
    m_value = d.value;
    return true;
  }

#ifdef NDNPH_PRINT_ARDUINO
  size_t printTo(::Print& p) const final
  {
    size_t count = 0;
    printImpl([&](const char* str) { count += p.print(str); });
    return count;
  }
#endif

  template<typename Convention>
  bool is() const
  {
    return Convention::match(*this);
  }

  template<typename Convention, typename... Arg>
  auto as(Arg&&... arg) const -> decltype(Convention::parse(*this, std::forward<Arg>(arg)...))
  {
    return Convention::parse(*this, std::forward<Arg>(arg)...);
  }

private:
  static constexpr size_t computeSize(uint16_t type, size_t length)
  {
    return tlv::sizeofVarNum(type) + tlv::sizeofVarNum(length) + length;
  }

  static ssize_t parseUriValue(uint8_t* buf, size_t bufLen, const char* uri, const char* uriEnd)
  {
    if (std::count(uri, uriEnd, '.') == uriEnd - uri && uriEnd - uri >= 3) {
      uri += 3;
    }

    for (size_t j = 0; j < bufLen; ++j) {
      if (uri == uriEnd) {
        return j;
      }

      if (*uri == '%' && uri + 3 <= uriEnd) {
        char hex[] = { uri[1], uri[2], 0 };
        buf[j] = std::strtoul(hex, nullptr, 16);
        uri += 3;
      } else {
        buf[j] = *uri++;
      }
    }
    return -1;
  }

  template<typename F>
  void printImpl(const F& output) const
  {
    char buf[7];
    snprintf(buf, sizeof(buf), "%d=", static_cast<int>(m_type));
    output(buf);
    size_t nNonPeriods = 0;
    std::for_each(m_value, m_value + m_length, [&](uint8_t ch) {
      if (strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~", ch) !=
          nullptr) {
        snprintf(buf, sizeof(buf), "%c", static_cast<char>(ch));
      } else {
        snprintf(buf, sizeof(buf), "%%%02X", static_cast<int>(ch));
      }
      output(buf);
      nNonPeriods += ch != '.';
    });
    if (nNonPeriods == 0) {
      output("...");
    }
  }

#ifdef NDNPH_PRINT_OSTREAM
  friend std::ostream& operator<<(std::ostream& os, const Component& comp)
  {
    comp.printImpl([&os](const char* str) { os << str; });
    return os;
  }
#endif

private:
  uint16_t m_type = 0;
  size_t m_length = 0;
  const uint8_t* m_tlv = nullptr;
  const uint8_t* m_value = nullptr;
};

inline bool
operator==(const Component& lhs, const Component& rhs)
{
  return lhs.size() == rhs.size() && std::equal(lhs.tlv(), lhs.tlv() + lhs.size(), rhs.tlv());
}

NDNPH_DECLARE_NE(Component, inline)

} // namespace ndnph

#endif // NDNPH_PACKET_COMPONENT_HPP
