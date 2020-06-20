#ifndef NDNPH_PACKET_LP_HPP
#define NDNPH_PACKET_LP_HPP

#include "data.hpp"
#include "interest.hpp"
#include "nack.hpp"

namespace ndnph {
namespace detail {

template<typename L3>
class LpEncodable
{
public:
  explicit LpEncodable(L3 l3)
    : l3(std::move(l3))
  {}

  void encodeTo(Encoder& encoder) const
  {
    if (pitToken == 0 && !nack) {
      encoder.prepend(l3);
      return;
    }
    encoder.prependTlv(
      TT::LpPacket,
      [this](Encoder& encoder) {
        if (pitToken != 0) {
          encoder.prependTlv(TT::PitToken, tlv::NNI8(pitToken));
        }
      },
      [this](Encoder& encoder) {
        if (nack) {
          encoder.prepend(nack);
        }
      },
      [this](Encoder& encoder) { encoder.prependTlv(TT::LpPayload, l3); });
  }

public:
  uint64_t pitToken = 0;
  NackHeader nack;
  L3 l3;
};

} // namespace detail
namespace lp {

/**
 * @brief Encode Interest or Data as LpPacket, optionally with PIT token.
 * @tparam L3 Interest, Data, or their signed variants.
 * @return an Encodable object.
 */
template<typename L3, typename R = detail::LpEncodable<L3>>
R
encode(L3 l3, uint64_t pitToken = 0)
{
  R encodable(l3);
  encodable.pitToken = pitToken;
  return encodable;
}

/**
 * @brief Encode Nack as LpPacket, optionally with PIT token.
 * @return an Encodable object.
 */
inline detail::LpEncodable<Interest>
encode(Nack nack, uint64_t pitToken = 0)
{
  auto encodable = encode(nack.getInterest(), pitToken);
  encodable.nack = nack.getHeader();
  return encodable;
}

/** @brief Decode NDNLPv2 packet for classification. */
class PacketClassify
{
public:
  enum Type : uint32_t
  {
    Interest = TT::Interest,
    Data = TT::Data,
    Nack = TT::Nack,
  };

  bool decodeFrom(const Decoder::Tlv& input)
  {
    switch (input.type) {
      case TT::Interest:
      case TT::Data:
        m_type = static_cast<Type>(input.type);
        m_l3 = input;
        return true;
      case TT::LpPacket:
        break;
      default:
        return false;
    }

    bool ok = EvDecoder::decodeEx(
      input, { TT::LpPacket }, EvDecoder::DefaultUnknownCb(),
      [](uint32_t type) { return type < 800 || type > 959 || (type & 0x03) != 0x00; },
      EvDecoder::defNni<TT::PitToken, tlv::NNI8>(&m_pitToken),
      EvDecoder::def<TT::Nack>([this](const Decoder::Tlv& d) {
        m_type = Nack;
        m_nack = d;
      }),
      EvDecoder::def<TT::LpPayload>([this](const Decoder::Tlv& d) {
        for (auto l3 : d.vd()) {
          m_l3 = l3;
          switch (l3.type) {
            case TT::Interest:
              m_type = m_type == Nack ? Nack : Interest;
              return true;
            case TT::Data:
              m_type = Data;
              return true;
            default:
              return false;
          }
        }
        return false;
      }));
    return ok && m_type != static_cast<Type>(0);
  }

  /** @brief Determine L3 packet type. */
  Type getType() const
  {
    return m_type;
  }

  /** @brief Retrieve PIT token. */
  uint64_t getPitToken() const
  {
    return m_pitToken;
  }

  /**
   * @brief Decode payload as Interest.
   * @pre getType() == Interest
   */
  bool decodeInterest(::ndnph::Interest interest) const
  {
    return m_type == Interest && interest.decodeFrom(m_l3);
  }

  /**
   * @brief Decode payload as Data.
   * @pre getType() == Data
   */
  bool decodeData(::ndnph::Data data) const
  {
    return m_type == Data && data.decodeFrom(m_l3);
  }

  /**
   * @brief Decode Nack.
   * @pre getType() == Nack
   */
  bool decodeNack(::ndnph::Nack nack) const
  {
    return m_type == Nack && nack.getHeader().decodeFrom(m_nack) &&
           nack.getInterest().decodeFrom(m_l3);
  }

private:
  Type m_type = static_cast<Type>(0);
  uint64_t m_pitToken = 0;
  Decoder::Tlv m_nack;
  Decoder::Tlv m_l3;
};

} // namespace lp
} // namespace ndnph

#endif // NDNPH_PACKET_LP_HPP
