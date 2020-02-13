#ifndef NDNPH_PACKET_CONVENTION_HPP
#define NDNPH_PACKET_CONVENTION_HPP

#include "../tlv/nni.hpp"
#include "component.hpp"

namespace ndnph {
namespace convention {
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
  static Component create(Region& region, uint64_t value)
  {
    return Component::from(region, tlvType, tlv::NNI(value));
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
using Keyword = detail::TypedString<0x20>;

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
using Segment = detail::TypedNumber<0x21>;

/**
 * @brief ByteOffsetNameComponent convention.
 *
 * Supported operations are same as convention::Segment.
 */
using ByteOffset = detail::TypedNumber<0x22>;

/**
 * @brief VersionNameComponent convention.
 *
 * Supported operations are same as convention::Segment.
 */
using Version = detail::TypedNumber<0x23>;

/**
 * @brief TimestampNameComponent convention.
 *
 * Supported operations are same as convention::Segment.
 */
using Timestamp = detail::TypedNumber<0x24>;

/**
 * @brief SequenceNumNameComponent convention.
 *
 * Supported operations are same as convention::Segment.
 */
using SequenceNum = detail::TypedNumber<0x25>;

} // namespace convention
} // namespace ndnph

#endif // NDNPH_PACKET_CONVENTION_HPP
