#ifndef NDNPH_PACKET_NACK_HPP
#define NDNPH_PACKET_NACK_HPP

#include "interest.hpp"

namespace ndnph {

/**
 * @brief Nack reason.
 *
 * These are internal 3-bit representation, not assigned numbers.
 */
enum class NackReason : uint8_t
{
  None = 0,
  Congestion = 1,
  Duplicate = 2,
  NoRoute = 3,
  Unspecified = 7,
};

/** @brief Nack header field. */
class NackHeader : public detail::RefRegion<detail::InterestObj>
{
public:
  /** @brief Maximum encoded size. */
  using MaxSize = std::integral_constant<size_t, 3 + 1 + 3 + 1 + 1>;

  using RefRegion::RefRegion;

  NackReason getReason() const
  {
    return static_cast<NackReason>(obj->nackReason);
  }

  void setReason(NackReason v)
  {
    obj->nackReason = static_cast<uint8_t>(v);
  }

  void encodeTo(Encoder& encoder) const
  {
    auto reason = getReason();
    encoder.prependTlv(TT::Nack, [reason](Encoder& encoder) {
      if (reason != NackReason::Unspecified) {
        encoder.prependTlv(TT::NackReason, tlv::NNI(encodeNackReason(reason)));
      }
    });
  }

  bool decodeFrom(const Decoder::Tlv& input)
  {
    uint64_t nackReasonV = 0;
    bool ok =
      EvDecoder::decode(input, { TT::Nack }, EvDecoder::defNni<TT::NackReason>(&nackReasonV));
    if (ok) {
      obj->nackReason = static_cast<uint8_t>(decodeNackReason(nackReasonV));
    }
    return ok;
  }

private:
  static uint64_t encodeNackReason(NackReason v)
  {
    return static_cast<uint64_t>(v) * 50;
  }

  static NackReason decodeNackReason(uint64_t v)
  {
    switch (v) {
      case 50:
      case 100:
      case 150:
        return static_cast<NackReason>(v / 50);
      default:
        return NackReason::Unspecified;
    }
  }
};

/** @brief Nack packet. */
class Nack : public detail::RefRegion<detail::InterestObj>
{
public:
  using RefRegion::RefRegion;

  /** @brief Access the Nack header. */
  NackHeader getHeader() const
  {
    return NackHeader(obj);
  }

  NackReason getReason() const
  {
    return getHeader().getReason();
  }

  /** @brief Access the Interest. */
  Interest getInterest() const
  {
    return Interest(obj);
  }

  /**
   * @brief Create a Nack packet in reply to an Interest.
   *
   * @bug Nack should encode the entire original Interest, but this function
   *      only includes Name, CanBePrefix, MustBeFresh, and Nonce in the encoding.
   *      https://redmine.named-data.net/issues/4535#note-16
   */
  static Nack create(Interest interest, NackReason reason)
  {
    Region& region = regionOf(interest);
    Nack nack = region.create<Nack>();
    if (nack) {
      nack.getHeader().setReason(reason);
      auto ni = nack.getInterest();
      ni.setName(interest.getName());
      ni.setCanBePrefix(interest.getCanBePrefix());
      ni.setMustBeFresh(interest.getMustBeFresh());
      ni.setNonce(interest.getNonce());
    }
    return nack;
  }
};

} // namespace ndnph

#endif // NDNPH_PACKET_NACK_HPP
