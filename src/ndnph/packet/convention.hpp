#ifndef NDNPH_PACKET_CONVENTION_HPP
#define NDNPH_PACKET_CONVENTION_HPP

#include "../port/random/port.hpp"
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
  std::pair<bool, uint64_t>
  toNumber() const
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
  /**
   * @brief Constructor.
   * @param t timestamp, or 0 to use current time.
   * @param unit time unit.
   * @param allowFallback if true, use RandomValue() when clock is unavailable.
   */
  explicit TimeValue(time_t t = 0, uint64_t unit = Microseconds, bool allowFallback = false)
    : m_t(t)
    , m_unit(unit)
    , m_allowFallback(allowFallback)
  {}

  enum Unit
  {
    Seconds = 1,
    Milliseconds = 1000,
    Microseconds = 1000000,
  };

  /**
   * @brief Generate TLV-VALUE.
   * @return whether success and the number.
   */
  std::pair<bool, uint64_t>
  toNumber() const
  {
    time_t t = m_t;
    if (t == 0) {
      time(&t);
      if (t < 540109800) {
        if (m_allowFallback) {
          return RandomValue().toNumber();
        } else {
          return std::make_pair(false, 0);
        }
      }
    }
    return std::make_pair(true, t * m_unit);
  }

private:
  time_t m_t;
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

private:
  TypedDigest() = delete;
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

private:
  TypedString() = delete;
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
   * @warning In case the value generator fails, returns an empty component. This would usually
   *          encode an invalid packet, but it rarely occurs on a correctly integrated system.
   */
  template<typename G>
  static Component create(Region& region, const G& gen, decltype(&G::toNumber) = nullptr)
  {
    bool ok = false;
    uint64_t value = 0;
    std::tie(ok, value) = gen.toNumber();
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
  TypedNumber() = delete;

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
 * name.append<convention::ImplicitDigest>(region, digest);
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
 * name.append<convention::Keyword>(region, "hello");
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
 * name.append<convention::Segment>(region, 700);
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
 * name.append<convention::Timestamp>(region, convention::RandomValue());
 * name.append<convention::Timestamp>(region, convention::TimeValue(now));
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
