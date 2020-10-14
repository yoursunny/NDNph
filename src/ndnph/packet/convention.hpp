#ifndef NDNPH_PACKET_CONVENTION_HPP
#define NDNPH_PACKET_CONVENTION_HPP

#include "../port/random/port.hpp"
#include "../tlv/nni.hpp"
#include "component.hpp"

namespace ndnph {
namespace convention {

/** @brief Indicate that TLV-VALUE should be a random number. */
class RandomValue
{};

/** @brief Indicate that TLV-VALUE should be a timestamp. */
class TimeValue
{
public:
  explicit TimeValue(time_t t = 0, uint64_t multiplier = Microseconds)
    : t(t)
    , multiplier(multiplier)
  {}

  enum Multiplier
  {
    Seconds = 1,
    Milliseconds = 1000,
    Microseconds = 1000000,
  };

public:
  time_t t;
  uint64_t multiplier;
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
   * @brief Create with random value.
   * @warning In case the random number generator fails, returns an empty component.
   *          This would usually lead to encoding an invalid packet.
   *          However, it rarely occurs on a correctly integrated system.
   */
  static Component create(Region& region, const RandomValue&)
  {
    uint8_t value[8];
    if (!port::RandomSource::generate(value, sizeof(value))) {
      return Component();
    }
    size_t length = 8;
    if ((value[0] | value[1] | value[2] | value[3]) == 0x00) {
      length = 4;
      if ((value[4] | value[5]) == 0x00) {
        length = 2;
        if (value[6] == 0x00) {
          length = 1;
        }
      }
    }
    return Component(region, tlvType, length, &value[sizeof(value) - length]);
  }

  /**
   * @brief Create with timestamp.
   * @param timeVal a specified timestamp, or zero to use current time.
   *                In case the clock is unavailable, a random number is used instead.
   */
  static Component create(Region& region, const TimeValue& timeVal)
  {
    time_t t = timeVal.t;
    if (t == 0) {
      time(&t);
      if (t < 540109800) {
        return create(region, RandomValue());
      }
    }
    return create(region, t * timeVal.multiplier);
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
