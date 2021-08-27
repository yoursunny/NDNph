#ifndef NDNPH_PACKET_LP_HPP
#define NDNPH_PACKET_LP_HPP

#include "data.hpp"
#include "interest.hpp"
#include "nack.hpp"

namespace ndnph {
namespace lp {

/** @brief Fragment header fields. */
class FragmentHeader
{
public:
  /** @brief Maximum encoded size. */
  using MaxSize = std::integral_constant<size_t, 1 + 1 + 8 + 1 + 1 + 1 + 1 + 1 + 1>;

  uint64_t getSeqNumBase() const
  {
    return seqNum - fragIndex;
  }

  void encodeTo(Encoder& encoder) const
  {
    encoder.prepend(
      [this](Encoder& encoder) { encoder.prependTlv(TT::LpSeqNum, tlv::NNI8(seqNum)); },
      [this](Encoder& encoder) { encoder.prependTlv(TT::FragIndex, tlv::NNI(fragIndex)); },
      [this](Encoder& encoder) { encoder.prependTlv(TT::FragCount, tlv::NNI(fragCount)); });
  }

public:
  uint64_t seqNum = 0;
  uint8_t fragIndex = 0;
  uint8_t fragCount = 1;
};

/** @brief PIT token field. */
class PitToken
{
public:
  /** @brief Construct 4-octet PIT token from uint32. */
  static PitToken from4(uint32_t n)
  {
    uint8_t room[4];
    tlv::NNI4::writeValue(room, n);
    PitToken token;
    token.set(4, room);
    return token;
  }

  /** @brief Determine whether PIT token exists. */
  explicit operator bool() const
  {
    return m_length > 0;
  }

  size_t length() const
  {
    return m_length;
  }

  const uint8_t* value() const
  {
    return m_value.begin();
  }

  /** @brief Interpret 4-octet PIT token as uint32. */
  uint32_t to4() const
  {
    return m_length == 4 ? tlv::NNI4::readValue(m_value.begin()) : 0;
  }

  /** @brief Assign PIT token length and value. */
  bool set(size_t length, const uint8_t* value)
  {
    if (length > m_value.size()) {
      return false;
    }
    m_length = length;
    std::copy_n(value, length, m_value.begin());
    return true;
  }

  void encodeTo(Encoder& encoder) const
  {
    uint8_t* room = encoder.prependRoom(m_length);
    if (room == nullptr) {
      return;
    }
    std::copy_n(m_value.begin(), m_length, room);
    encoder.prependTypeLength(TT::PitToken, m_length);
  }

  bool decodeFrom(const Decoder::Tlv& d)
  {
    return set(d.length, d.value);
  }

  friend bool operator==(const PitToken& lhs, const PitToken& rhs)
  {
    return lhs.m_length == rhs.m_length &&
           std::equal(lhs.m_value.begin(), lhs.m_value.begin() + lhs.m_length, rhs.m_value.begin());
  }

  NDNPH_DECLARE_NE(PitToken, friend)

private:
  std::array<uint8_t, NDNPH_PITTOKEN_MAX> m_value;
  uint8_t m_length = 0;

  static_assert(NDNPH_PITTOKEN_MAX >= 4, "");
  static_assert(NDNPH_PITTOKEN_MAX <= 32, "");
};

/** @brief Common fields during encoding. */
class EncodableBase
{
public:
  /** @brief Maximum encoded size of L3 headers. */
  using L3MaxSize =
    std::integral_constant<size_t, 1 + 1 + NDNPH_PITTOKEN_MAX + NackHeader::MaxSize::value>;

  void encodeL3Header(Encoder& encoder) const
  {
    encoder.prepend(
      [this](Encoder& encoder) {
        if (pitToken) {
          encoder.prepend(pitToken);
        }
      },
      [this](Encoder& encoder) {
        if (nack) {
          encoder.prepend(nack);
        }
      });
  }

  void copyL3HeaderFrom(const EncodableBase& src)
  {
    pitToken = src.pitToken;
    nack = src.nack;
  }

public:
  FragmentHeader frag;
  PitToken pitToken;
  NackHeader nack;
};

/**
 * @brief Encodable type of an LpPacket.
 * @tparam Payload Encodable type of the payload.
 */
template<typename Payload>
class Encodable : public EncodableBase
{
public:
  explicit Encodable(Payload payload)
    : payload(std::move(payload))
  {}

  void encodeTo(Encoder& encoder) const
  {
    StaticRegion<L3MaxSize::value> l3hRegion;
    Encoder l3h(l3hRegion);
    encodeL3Header(l3h);
    if (!l3h) {
      encoder.setError();
      return;
    }

    if (frag.fragCount <= 1 && l3h.size() == 0) {
      encoder.prepend(payload);
      return;
    }
    encoder.prependTlv(
      TT::LpPacket,
      [this](Encoder& encoder) {
        if (frag.fragCount > 1) {
          encoder.prepend(frag);
        }
      },
      tlv::Value(l3h), [this](Encoder& encoder) { encoder.prependTlv(TT::LpPayload, payload); });
  }

public:
  Payload payload;
};

/**
 * @brief Encode Interest or Data as LpPacket, optionally with PIT token.
 * @tparam L3 Interest, Data, or their signed variants.
 * @return an Encodable object.
 */
template<typename L3, typename R = Encodable<L3>>
R
encode(L3 l3, PitToken pitToken = {})
{
  R encodable(l3);
  encodable.pitToken = pitToken;
  return encodable;
}

/**
 * @brief Encode Nack as LpPacket, optionally with PIT token.
 * @return an Encodable object.
 */
inline Encodable<Interest>
encode(Nack nack, PitToken pitToken = {})
{
  auto encodable = encode(nack.getInterest(), pitToken);
  encodable.nack = nack.getHeader();
  return encodable;
}

/** @brief NDNLPv2 fragmenter. */
class Fragmenter : public WithRegion
{
public:
  /** @brief Singly linked list of encodable fragments. */
  class Fragment : public Encodable<tlv::Value>
  {
  public:
    using Encodable::Encodable;

  public:
    const Fragment* next = nullptr;
  };

  /**
   * @brief Constructor.
   * @param region where to allocate memory for fragment payloads.
   *               This region may be shared with others fragmenters and reassemblers.
   * @param mtu maximum output packet size including NDNLPv2 headers.
   */
  explicit Fragmenter(Region& region, uint16_t mtu)
    : WithRegion(region)
    , m_room(static_cast<int>(mtu) - FragmentOverhead)
  {
    port::RandomSource::generate(reinterpret_cast<uint8_t*>(&m_nextSeqNum), sizeof(m_nextSeqNum));
  }

  /**
   * @brief Fragment an LP packet.
   * @tparam L3 Interest, Data, or their signed variants.
   * @return singly linked list of fragments, or nullptr on failure.
   *
   * Each @c fragment() invocation resets the region passed to the constructor.
   * If the region is shared with a reassembler, @c Reassembler::discard should be invoked to
   * clear the reassembler buffer.
   *
   * When the region is reset by any means, previously returned fragments are invalidated.
   */
  template<typename L3>
  const Fragment* fragment(Encodable<L3> packet)
  {
    region.reset();
    size_t sizeofHeader = 0;
    {
      ScopedEncoder l3h(region);
      packet.encodeL3Header(l3h);
      if (!l3h) {
        return nullptr;
      }
      sizeofHeader = l3h.size();
    }

    Encoder payload(region);
    packet.payload.encodeTo(payload);
    if (!payload) {
      payload.discard();
      return nullptr;
    }
    payload.trim();

    return fragmentImpl(packet, sizeofHeader, tlv::Value(payload));
  }

private:
  const Fragment* fragmentImpl(EncodableBase& input, size_t sizeofHeader, tlv::Value payload)
  {
    int sizeofFirstFragment = m_room - sizeofHeader;
    if (sizeofFirstFragment > static_cast<int>(payload.size())) {
      auto frag = region.make<Fragment>(payload);
      if (frag == nullptr) {
        return nullptr;
      }
      frag->copyL3HeaderFrom(input);
      return frag;
    }
    if (sizeofFirstFragment <= 0) {
      return nullptr;
    }

    auto first = region.make<Fragment>(tlv::Value(payload.begin(), sizeofFirstFragment));
    if (first == nullptr) {
      return nullptr;
    }
    first->copyL3HeaderFrom(input);

    auto prev = first;
    uint8_t fragCount = 1;
    for (size_t nextOffset, offset = sizeofFirstFragment; offset < payload.size();
         offset = nextOffset) {
      nextOffset = std::min(offset + m_room, payload.size());
      auto frag =
        region.make<Fragment>(tlv::Value(payload.begin() + offset, payload.begin() + nextOffset));
      if (frag == nullptr) {
        return nullptr;
      }
      prev->next = frag;
      prev = frag;
      ++fragCount;
    }

    auto frag = first;
    for (uint8_t fragIndex = 0; fragIndex < fragCount; ++fragIndex) {
      frag->frag.seqNum = m_nextSeqNum++;
      frag->frag.fragIndex = fragIndex;
      frag->frag.fragCount = fragCount;
      frag = const_cast<Fragment*>(frag->next);
    }
    return first;
  }

private:
  enum
  {
    FragmentOverhead = 1 + 3 +     // LpPacket TL
                       1 + 1 + 8 + // LpSeqNum
                       1 + 1 + 1 + // FragIndex
                       1 + 1 + 1 + // FragCount
                       1 + 3       // LpPayload TL
  };

  uint64_t m_nextSeqNum = 0;
  int m_room = 0;
};

/** @brief Decoded L3 header fields. */
class L3Header
{
public:
  std::tuple<bool, L3Header> clone(Region& region) const
  {
    L3Header copy;
    copy.pitToken = pitToken;
    if (!nack) {
      return std::make_tuple(true, copy);
    }
    copy.nack = nack.clone(region);
    return std::make_tuple(!!copy.nack, copy);
  }

public:
  PitToken pitToken;
  tlv::Value nack;
};

/** @brief Decoded fragment. */
class Fragment : public FragmentHeader
{
public:
  L3Header l3header;
  tlv::Value payload;
};

/** @brief Decode NDNLPv2 packet for classification. */
class PacketClassify
{
public:
  enum class Type : uint16_t
  {
    None = 0,
    Fragment = TT::FragIndex,
    Interest = TT::Interest,
    Data = TT::Data,
    Nack = TT::Nack,
  };

  explicit PacketClassify() = default;

  explicit PacketClassify(L3Header l3header, tlv::Value payload)
    : m_l3header(l3header)
    , m_payload(payload)
  {
    m_type = classifyType();
  }

  bool decodeFrom(const Decoder::Tlv& input)
  {
    m_type = Type::None;
    m_l3header = L3Header();
    m_frag = FragmentHeader();

    switch (input.type) {
      case TT::Interest:
      case TT::Data:
        m_payload = tlv::Value(input.tlv, input.size);
        m_type = classifyType();
        return m_type != Type::None;
      case TT::LpPacket:
        break;
      default:
        return false;
    }

    bool ok = EvDecoder::decodeEx(
      input, { TT::LpPacket }, EvDecoder::DefaultUnknownCb(),
      [](uint32_t type) { return type < 800 || type > 959 || (type & 0x03) != 0x00; },
      EvDecoder::defNni<TT::LpSeqNum, tlv::NNI8>(&m_frag.seqNum),
      EvDecoder::defNni<TT::FragIndex>(&m_frag.fragIndex),
      EvDecoder::defNni<TT::FragCount>(&m_frag.fragCount),
      EvDecoder::def<TT::PitToken>(&m_l3header.pitToken),
      EvDecoder::def<TT::Nack>([this](const Decoder::Tlv& d) {
        m_type = Type::Nack;
        m_l3header.nack = tlv::Value(d.tlv, d.size);
      }),
      EvDecoder::def<TT::LpPayload>(&m_payload));
    if (!ok) {
      return false;
    }

    m_type = classifyType();
    return m_type != Type::None;
  }

  /** @brief Determine L3 packet type. */
  Type getType() const
  {
    return m_type;
  }

  /** @brief Retrieve PIT token. */
  const PitToken& getPitToken() const
  {
    return m_l3header.pitToken;
  }

  /**
   * @brief Retrieve fragment.
   * @pre getType() == Type::Fragment
   */
  Fragment getFragment() const
  {
    Fragment frag;
    static_cast<FragmentHeader&>(frag) = m_frag;
    frag.l3header = m_l3header;
    frag.payload = m_payload;
    return frag;
  }

  /**
   * @brief Decode payload as Interest.
   * @pre getType() == Type::Interest
   */
  bool decodeInterest(Interest interest) const
  {
    return m_type == Type::Interest && m_payload.makeDecoder().decode(interest);
  }

  /**
   * @brief Decode payload as Data.
   * @pre getType() == Type::Data
   */
  bool decodeData(Data data) const
  {
    return m_type == Type::Data && m_payload.makeDecoder().decode(data);
  }

  /**
   * @brief Decode Nack.
   * @pre getType() == Nack
   */
  bool decodeNack(Nack nack) const
  {
    auto nackHeader = nack.getHeader();
    auto interest = nack.getInterest();
    return m_type == Type::Nack && m_l3header.nack.makeDecoder().decode(nackHeader) &&
           m_payload.makeDecoder().decode(interest);
  }

private:
  Type classifyType() const
  {
    if (m_frag.fragCount > 1) {
      return Type::Fragment;
    }
    for (auto l3 : m_payload.makeDecoder()) {
      switch (l3.type) {
        case TT::Interest:
          return !!m_l3header.nack ? Type::Nack : Type::Interest;
        case TT::Data:
          return Type::Data;
        default:
          return Type::None;
      }
    }
    return Type::None;
  }

private:
  Type m_type = Type::None;
  FragmentHeader m_frag;
  L3Header m_l3header;
  tlv::Value m_payload;
};

/**
 * @brief NDNLPv2 fragmenter.
 */
class Reassembler : public WithRegion
{
public:
  /**
   * @brief Constructor.
   * @param region where to allocate memory for fragment payloads.
   *               This region may be shared with others fragmenters and reassemblers.
   */
  explicit Reassembler(Region& region)
    : WithRegion(region)
  {}

  /**
   * @brief Discard the reassembly buffer.
   *
   * When the region is reset elsewhere (e.g. in another fragmenter or reassembler sharing the
   * region), this function should be invoked to discard the reassembly buffer. Otherwise,
   * undefined behavior may occur.
   */
  void discard()
  {
    m_buffer = nullptr;
  }

  /**
   * @brief Add a fragment.
   *
   * If FragIndex is 0:
   * - Discard the existing reassembly buffer.
   * - Start a new reassembly buffer in the region passed to the constructor.
   * - Return true.
   *
   * If @p frag comes after the previous fragment:
   * - Append to the existing reassembly buffer.
   * - Return true.
   *
   * Otherwise:
   * - Return false.
   */
  bool add(const Fragment& frag)
  {
    if (frag.fragIndex == 0) {
      return begin(frag);
    }
    return append(frag);
  }

  /**
   * @brief Reassemble the packet if it's complete.
   *
   * If the reassembly buffer contains a complete packet, return the reassembled packet.
   * Otherwise, return a @c PacketClassify with @c Type::None .
   */
  PacketClassify reassemble() const
  {
    if (m_nextFragIndex != m_fragCount) {
      return PacketClassify();
    }
    return PacketClassify(m_l3header, tlv::Value(m_buffer, m_size));
  }

private:
  bool begin(const Fragment& frag)
  {
    discard();
    region.reset();

    bool ok = false;
    std::tie(ok, m_l3header) = frag.l3header.clone(region);
    m_capacity = region.available();
    m_buffer = region.alloc(m_capacity);
    if (!ok || m_buffer == nullptr) {
      return false;
    }

    m_size = 0;
    m_seqNumBase = frag.getSeqNumBase();
    m_nextFragIndex = 0;
    m_fragCount = frag.fragCount;
    return append(frag);
  }

  bool append(const Fragment& frag)
  {
    if (m_buffer == nullptr || frag.getSeqNumBase() != m_seqNumBase ||
        frag.fragIndex != m_nextFragIndex || frag.fragCount != m_fragCount ||
        frag.payload.size() > m_capacity - m_size) {
      return false;
    }

    std::copy(frag.payload.begin(), frag.payload.end(), &m_buffer[m_size]);
    m_size += frag.payload.size();
    ++m_nextFragIndex;
    return true;
  }

private:
  L3Header m_l3header;
  uint8_t* m_buffer = nullptr;
  size_t m_capacity = 0;
  size_t m_size = 0;
  uint64_t m_seqNumBase = 0;
  uint8_t m_nextFragIndex = 0;
  uint8_t m_fragCount = 0;
};

} // namespace lp
} // namespace ndnph

#endif // NDNPH_PACKET_LP_HPP
