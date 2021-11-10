#ifndef NDNPH_PACKET_CONVENTION_HPP
#define NDNPH_PACKET_CONVENTION_HPP

#include "../port/random/port.hpp"
#include "../port/unixtime/port.hpp"
#include "../tlv/nni.hpp"
#include "component.hpp"

namespace ndnph {
namespace convention {

/** @brief Indicate that TLV-VALUE should be a random number. */
class RandomValue
{
public:
  /**
   * @brief Generate TLV-VALUE.
   * @return whether success and the number.
   */
  std::pair<bool, uint64_t> toNumber() const
  {
    uint64_t value = 0;
    bool ok = port::RandomSource::generate(reinterpret_cast<uint8_t*>(&value), sizeof(value));
    return std::make_pair(ok, value);
  }
};

/** @brief Indicate that TLV-VALUE should be a timestamp. */
class TimeValue
{
public:
  enum Unit
  {
    Seconds = 1000000,
    Milliseconds = 1000,
    Microseconds = 1,
  };

  /**
   * @brief Constructor.
   * @param t timestamp in microseconds, or 0 to use current time.
   * @param unit time unit.
   * @param allowFallback if true, use RandomValue() when clock is unavailable.
   */
  explicit TimeValue(uint64_t t = 0, uint64_t unit = Microseconds, bool allowFallback = false)
    : m_t(t)
    , m_unit(unit)
    , m_allowFallback(allowFallback)
  {}

  /**
   * @brief Generate TLV-VALUE.
   * @return whether success and the number.
   */
  std::pair<bool, uint64_t> toNumber() const
  {
    uint64_t t = m_t;
    if (t == 0) {
      t = port::UnixTime::now();
      if (!port::UnixTime::valid(t)) {
        if (m_allowFallback) {
          return RandomValue().toNumber();
        } else {
          return std::make_pair(false, 0);
        }
      }
    }
    return std::make_pair(true, t / m_unit);
  }

private:
  uint64_t m_t;
  uint64_t m_unit;
  bool m_allowFallback;
};

namespace detail {

template<uint16_t tlvType>
class TypedDigest
{
public:
  static Component create(Region& region, const uint8_t digest[NDNPH_SHA256_LEN])
  {
    return Component(region, tlvType, NDNPH_SHA256_LEN, digest);
  }

  static bool match(const Component& comp)
  {
    return comp.type() == tlvType && comp.length() == NDNPH_SHA256_LEN;
  }

  static const uint8_t* parse(const Component& comp)
  {
    return comp.value();
  }
};

template<uint16_t tlvType>
class TypedString
{
public:
  static Component create(Region& region, const char* s)
  {
    return Component(region, tlvType, std::strlen(s), reinterpret_cast<const uint8_t*>(s));
  }

  static bool match(const Component& comp)
  {
    return comp.type() == tlvType;
  }

  static const char* parse(const Component& comp, Region& region)
  {
    uint8_t* room = region.alloc(comp.length() + 1);
    if (room == nullptr) {
      return nullptr;
    }
    std::copy_n(comp.value(), comp.length(), room)[0] = 0;
    return reinterpret_cast<const char*>(room);
  }
};

template<uint16_t tlvType>
class TypedNumber
{
public:
  /** @brief Create with specified value. */
  static Component create(Region& region, uint64_t value)
  {
    return Component::from(region, tlvType, tlv::NNI(value));
  }

  /**
   * @brief Create with RandomValue or TimeValue.
   * @tparam G RandomValue or TimeValue.
   *
   * In case the value generator fails, returns an invalid component, which would cause packet
   * encoding error. This condition rarely occurs on a correctly integrated system.
   */
  template<typename G>
  static Component create(Region& region, const G& gen, decltype(&G::toNumber) = nullptr)
  {
    bool ok = false;
    uint64_t value = 0;
    std::tie(ok, value) = gen.toNumber();
    if (!ok) {
      return Component();
    }
    return create(region, value);
  }

  static bool match(const Component& comp)
  {
    return parseImpl(comp).first;
  }

  static uint64_t parse(const Component& comp)
  {
    return parseImpl(comp).second;
  }

private:
  static std::pair<bool, uint64_t> parseImpl(const Component& comp)
  {
    Decoder::Tlv d;
    uint64_t value = 0;
    bool ok = comp.type() == tlvType && Decoder::readTlv(d, comp.tlv(), comp.tlv() + comp.size()) &&
              tlv::NNI::decode(d, value);
    return std::make_pair(ok, value);
  }
};

} // namespace detail

/**
 * @brief ImplicitSha256DigestComponent type.
 *
 * Supported operations:
 * @code
 * uint8_t digest[NDNPH_SHA256_LEN];
 * name.append(region, convention::ImplicitDigest(), digest);
 * bool isDigest = component.is<convention::ImplicitDigest>();
 * uint8_t* digest2 = component.as<convention::ImplicitDigest>();
 * @endcode
 */
using ImplicitDigest = detail::TypedDigest<TT::ImplicitSha256DigestComponent>;

/**
 * @brief ParametersSha256DigestComponent type.
 *
 * Supported operations are same as convention::ImplicitDigest.
 */
using ParamsDigest = detail::TypedDigest<TT::ParametersSha256DigestComponent>;

/**
 * @brief KeywordNameComponent convention.
 *
 * Supported operations:
 * @code
 * name.append(region, convention::Keyword(), "hello");
 * bool isKeyword = component.is<convention::Keyword>();
 * const char* keyword = component.as<convention::Keyword>(region);
 * @endcode
 *
 * `component.as<convention::Keyword>(region)` copies TLV-VALUE and appends NUL.
 * It may return incorrect result if TLV-VALUE contains non-printable characters.
 * It's recommended to use `component.value()` but there's no NUL termination.
 */
using Keyword = detail::TypedString<TT::KeywordNameComponent>;

/**
 * @brief GenericNameComponent that contains NNI.
 *
 * Supported operations are same as convention::Timestamp.
 */
using GenericNumber = detail::TypedNumber<TT::GenericNameComponent>;

/**
 * @brief SegmentNameComponent convention.
 *
 * Supported operations:
 * @code
 * name.append(region, convention::Segment(), 700);
 * bool isSegment = component.is<convention::Segment>();
 * uint64_t segment = component.as<convention::Segment>();
 * @endcode
 */
using Segment = detail::TypedNumber<TT::SegmentNameComponent>;

/**
 * @brief ByteOffsetNameComponent convention.
 *
 * Supported operations are same as convention::Segment.
 */
using ByteOffset = detail::TypedNumber<TT::ByteOffsetNameComponent>;

/**
 * @brief VersionNameComponent convention.
 *
 * Supported operations are same as convention::Timestamp.
 */
using Version = detail::TypedNumber<TT::VersionNameComponent>;

/**
 * @brief TimestampNameComponent convention.
 *
 * Supported operations include those in convention::Segment, and:
 * @code
 * name.append(region, convention::Timestamp(), convention::RandomValue());
 * name.append(region, convention::Timestamp(), convention::TimeValue(port::UnixTime::now()));
 * @endcode
 */
using Timestamp = detail::TypedNumber<TT::TimestampNameComponent>;

/**
 * @brief SequenceNumNameComponent convention.
 *
 * Supported operations are same as convention::Segment.
 */
using SequenceNum = detail::TypedNumber<TT::SequenceNumNameComponent>;

} // namespace convention
} // namespace ndnph

#endif // NDNPH_PACKET_CONVENTION_HPP
