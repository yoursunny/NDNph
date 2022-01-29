#ifndef NDNPH_PACKET_SIG_INFO_HPP
#define NDNPH_PACKET_SIG_INFO_HPP

#include "../port/random/port.hpp"
#include "../port/unixtime/port.hpp"
#include "../tlv/ev-decoder.hpp"
#include "name.hpp"

namespace ndnph {

/** @brief SignatureInfo. */
class SigInfo
{
public:
  bool decodeFrom(const Decoder::Tlv& input)
  {
    return EvDecoder::decodeEx(
      input, { TT::ISigInfo, TT::DSigInfo },
      [this, &input](const Decoder::Tlv& d, int& currentOrder) {
        if (currentOrder < 1000) {
          extensions = tlv::Value(d.tlv, input.value + input.length);
          currentOrder = 1000;
        }
        return true;
      },
      EvDecoder::DefaultIsCritical(), EvDecoder::defNni<TT::SigType, tlv::NNI, 1>(&sigType),
      EvDecoder::def<TT::KeyLocator, false, 2>([this](const Decoder::Tlv& d) {
        return EvDecoder::decode(d, {}, EvDecoder::def<TT::Name>(&name));
      }));
  }

protected:
  ~SigInfo() = default;

  void encodeImpl(uint32_t type, Encoder& encoder) const
  {
    encoder.prependTlv(
      type, tlv::NniElement<>(TT::SigType, sigType),
      [this](Encoder& encoder) {
        if (name.size() > 0) {
          encoder.prependTlv(TT::KeyLocator, name);
        }
      },
      extensions);
  }

public:
  Name name;
  tlv::Value extensions;
  uint8_t sigType = 0;
};

/** @brief SignatureInfo on Interest. */
class ISigInfo : public SigInfo
{
public:
  void encodeTo(Encoder& encoder) const
  {
    return encodeImpl(TT::ISigInfo, encoder);
  }
};

/** @brief SignatureInfo on Data. */
class DSigInfo : public SigInfo
{
public:
  void encodeTo(Encoder& encoder) const
  {
    return encodeImpl(TT::DSigInfo, encoder);
  }
};

namespace isig {

/** @brief Parsed extension fields from Interest SigInfo. */
class Fields
{
public:
  bool decode(const ISigInfo& si)
  {
    return EvDecoder::decodeValue(si.extensions.makeDecoder(), EvDecoder::def<TT::SigNonce>(&nonce),
                                  EvDecoder::defNni<TT::SigTime>(&timestamp),
                                  EvDecoder::defNni<TT::SigSeqNum>(&seqNum));
  }

public:
  tlv::Value nonce;
  uint64_t timestamp = 0;
  uint64_t seqNum = 0;
};

namespace detail {

template<int order>
class Skip
{
public:
  using Order = std::integral_constant<int, order>;

  class EncodeValue
  {
  public:
    void encodeTo(Encoder&) const {}
  };

  EncodeValue create()
  {
    return EncodeValue();
  }

  bool check(const Fields&) const
  {
    return true;
  }

  void save(const Fields&) {}
};

} // namespace detail

/**
 * @brief Require SigNonce field in Interest SigInfo.
 * @tparam nonceLength expected TLV-LENGTH of SigNonce.
 * @tparam nTrackedNonces how many values to remember.
 */
template<int nonceLength = 8, int nTrackedNonces = 16>
class Nonce
{
public:
  using Order = std::integral_constant<int, 1>;
  static_assert(nonceLength > 0, "");
  static_assert(nTrackedNonces > 0, "");

  class Value : public std::array<uint8_t, nonceLength>
  {
  public:
    Value() = default;

    explicit Value(tlv::Value input)
      : valid(input.size() == nonceLength)
    {
      if (valid) {
        std::copy(input.begin(), input.end(), this->begin());
      }
    }

    void encodeTo(Encoder& encoder) const
    {
      if (!valid) {
        encoder.setError();
        return;
      }
      encoder.prependTlv(TT::SigNonce, tlv::Value(this->data(), this->size()));
    }

    bool operator==(const Value& other) const
    {
      return valid && other.valid && std::equal(this->begin(), this->end(), other.begin());
    }

  public:
    bool valid = false;
  };

  Value create()
  {
    Value value;
    do {
      value.valid = port::RandomSource::generate(value.data(), value.size());
      if (!value.valid) {
        return value;
      }
    } while (exists(value));
    append(value);
    return value;
  }

  bool check(const Fields& f) const
  {
    Value value(f.nonce);
    return !exists(value);
  }

  void save(const Fields& f)
  {
    Value value(f.nonce);
    append(value);
  }

private:
  bool exists(const Value& value) const
  {
    return std::find(m_nonces.begin(), m_nonces.end(), value) != m_nonces.end();
  }

  void append(const Value& value)
  {
    NDNPH_ASSERT(value.valid);
    m_nonces[m_pos] = value;
    if (++m_pos == m_nonces.size()) {
      m_pos = 0;
    }
  }

private:
  std::array<Value, nTrackedNonces> m_nonces = {};
  size_t m_pos = 0;
};

/**
 * @brief Require SigTime field in Interest SigInfo.
 * @tparam maxClockOffset maximum allowed clock offset in milliseconds.
 */
template<int maxClockOffset = 60000>
class Time
{
public:
  using Order = std::integral_constant<int, 2>;

  tlv::NniElement<> create()
  {
    uint64_t timestamp = std::max(now(), m_last + 1);
    m_last = timestamp;
    return tlv::NniElement<>(TT::SigTime, timestamp);
  }

  bool check(const Fields& f) const
  {
    static_assert(maxClockOffset >= 0, "");
    return f.timestamp > m_last &&
           std::abs(static_cast<int64_t>(now() - f.timestamp)) <= maxClockOffset;
  }

  void save(const Fields& f)
  {
    m_last = std::max(m_last, f.timestamp);
  }

private:
  uint64_t now() const
  {
    // SigTime field uses milliseconds
    return port::UnixTime::now() / 1000;
  }

private:
  uint64_t m_last = 0;
};

/** @brief Require SigSeqNum field in Interest SigInfo. */
class SeqNum
{
public:
  using Order = std::integral_constant<int, 3>;

  explicit SeqNum(uint64_t next = 0)
    : m_next(next)
  {}

  tlv::NniElement<> create()
  {
    return tlv::NniElement<>(TT::SigSeqNum, m_next++);
  }

  bool check(const Fields& f) const
  {
    return f.seqNum >= m_next;
  }

  void save(const Fields& f)
  {
    m_next = std::max(m_next, f.seqNum) + 1;
  }

private:
  uint64_t m_next;
};

/**
 * @brief Validation policy for SigInfo fields in signed Interest.
 * @sa makePolicy
 *
 * The Policy instance internally keeps state. Therefore, each Policy instance can be used either
 * for signing outgoing packets, or for verifying incoming packets signed by one public key.
 * Separate Policy instances should be used for different public keys.
 */
template<typename R0, typename R1 = detail::Skip<11>, typename R2 = detail::Skip<12>>
class Policy
{
public:
  explicit Policy(const R0& r0 = R0(), const R1& r1 = R1(), const R2& r2 = R2())
    : m_r0(r0)
    , m_r1(r1)
    , m_r2(r2)
  {}

  /**
   * @brief Assign SigInfo extension fields.
   * @param region where to allocate memory for encoding extension fields.
   * @param si SigInfo to receive extension fields. Existing extensions will be overwritten.
   * @return whether success.
   * @sa Interest::sign(key, region, policy)
   */
  bool create(Region& region, ISigInfo& si)
  {
    Encoder encoder(region);
    if (!encoder.prepend(m_r0.create(), m_r1.create(), m_r2.create())) {
      encoder.discard();
      return false;
    }
    encoder.trim();
    si.extensions = tlv::Value(encoder);
    return true;
  }

  /**
   * @brief Check that SigInfo fields fulfill current policy.
   * @return whether accepted.
   * @post If accepted, state within this Policy instance is updated.
   */
  bool check(const ISigInfo& si)
  {
    Fields f;
    if (f.decode(si) && m_r0.check(f) && m_r1.check(f) && m_r2.check(f)) {
      m_r0.save(f);
      m_r1.save(f);
      m_r2.save(f);
      return true;
    }
    return false;
  }

private:
  R0 m_r0;
  R1 m_r1;
  R2 m_r2;

  static_assert(R0::Order::value < R1::Order::value, "");
  static_assert(R1::Order::value < R2::Order::value, "");
};

/**
 * @brief Create Interest SigInfo validation policy.
 * @param rule zero or one @c Nonce<>() , zero or one @c Time<>() , zero or one @c SeqNum() .
 *             At least one rule is required; multiple rules must appear in the given order.
 */
template<typename... R>
Policy<R...>
makePolicy(R&&... rule)
{
  return Policy<R...>(std::forward<R>(rule)...);
}

} // namespace isig
} // namespace ndnph

#endif // NDNPH_PACKET_SIG_INFO_HPP
