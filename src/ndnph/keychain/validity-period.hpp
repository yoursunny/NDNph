#ifndef NDNPH_KEYCHAIN_VALIDITY_PERIOD_HPP
#define NDNPH_KEYCHAIN_VALIDITY_PERIOD_HPP

#include "../packet/an.hpp"
#include "../port/unixtime/port.hpp"
#include "../tlv/ev-decoder.hpp"
#include "../tlv/value.hpp"

namespace ndnph {
namespace detail {

class UtcTimezone
{
public:
  UtcTimezone()
  {
    const char* tz = getenv("TZ");
    if (tz == nullptr || strlen(tz) >= sizeof(m_tz)) {
      m_tz[0] = '\0';
    } else {
      strncpy(m_tz, tz, sizeof(m_tz));
    }
    setenv("TZ", "UTC", 1);
  }

  ~UtcTimezone()
  {
    if (m_tz[0] != '\0') {
      setenv("TZ", m_tz, 1);
    }
  }

private:
  char m_tz[64];
};

} // namespace detail

/** @brief ValidityPeriod of a certificate. */
class ValidityPeriod
{
public:
  /** @brief Get a very long ValidityPeriod. */
  static ValidityPeriod getMax()
  {
    return ValidityPeriod(540109800, MAX_TIME);
  }

  /** @brief Get a ValidityPeriod from now until @p seconds later. */
  static ValidityPeriod secondsFromNow(uint64_t seconds)
  {
    time_t now = port::UnixTime::now() / 1000000;
    return ValidityPeriod(now, now + seconds);
  }

  /** @brief Get a ValidityPeriod from now until @p days later. */
  static ValidityPeriod daysFromNow(uint64_t days)
  {
    return secondsFromNow(86400 * days);
  }

  ValidityPeriod() = default;

  explicit ValidityPeriod(time_t notBefore, time_t notAfter)
    : notBefore(notBefore)
    , notAfter(notAfter)
  {}

  /** @brief Determine whether the timestamp (in seconds) is within validity period. */
  bool includes(time_t t)
  {
    return notBefore <= t && t <= notAfter;
  }

  /** @brief Determine whether the Unix timestamp (in microseconds) is within validity period. */
  bool includesUnix(uint64_t t = port::UnixTime::now())
  {
    return includes(t / 1000000);
  }

  /** @brief Calculate the intersection of this and @p other ValidityPeriod. */
  ValidityPeriod intersect(const ValidityPeriod& other) const
  {
    return ValidityPeriod(std::max(notBefore, other.notBefore), std::min(notAfter, other.notAfter));
  }

  void encodeTo(Encoder& encoder) const
  {
    encoder.prependTlv(TT::ValidityPeriod, TimestampEncoder(TT::NotBefore, notBefore),
                       TimestampEncoder(TT::NotAfter, notAfter));
  }

  bool decodeFrom(const Decoder::Tlv& input)
  {
    return EvDecoder::decode(input, { TT::ValidityPeriod },
                             EvDecoder::def<TT::NotBefore>([this](const Decoder::Tlv& d) {
                               return decodeTimestamp(d, &notBefore);
                             }),
                             EvDecoder::def<TT::NotAfter>([this](const Decoder::Tlv& d) {
                               return decodeTimestamp(d, &notAfter);
                             }));
  }

private:
  static constexpr time_t MAX_TIME =
    sizeof(time_t) <= 4 ? std::numeric_limits<time_t>::max() : 253402300799;
  static constexpr const char* const TIMESTAMP_FMT = "%04d%02d%02dT%02d%02d%02d";
  static constexpr size_t TIMESTAMP_LEN = 15;

  class TimestampEncoder
  {
  public:
    explicit TimestampEncoder(uint32_t tlvType, time_t t)
      : tlvType(tlvType)
      , t(t)
    {}

    void encodeTo(Encoder& encoder) const
    {
      struct tm* m = gmtime(&t);
      if (m == nullptr) {
        encoder.setError();
        return;
      }

      char buf[TIMESTAMP_LEN + 1];
      snprintf(buf, sizeof(buf), TIMESTAMP_FMT, 1900 + m->tm_year, 1 + m->tm_mon, m->tm_mday,
               m->tm_hour, m->tm_min, m->tm_sec);
      encoder.prependTlv(tlvType, tlv::Value(reinterpret_cast<const uint8_t*>(buf), TIMESTAMP_LEN));
    }

  public:
    uint32_t tlvType = 0;
    time_t t = 0;
  };

  static bool decodeTimestamp(const Decoder::Tlv& d, time_t* v)
  {
    if (d.length != TIMESTAMP_LEN) {
      return false;
    }

    char buf[TIMESTAMP_LEN + 1];
    std::copy_n(d.value, TIMESTAMP_LEN, buf);
    buf[TIMESTAMP_LEN] = '\0';

    tm m{};
    if (sscanf(buf, TIMESTAMP_FMT, &m.tm_year, &m.tm_mon, &m.tm_mday, &m.tm_hour, &m.tm_min,
               &m.tm_sec) != 6) {
      return false;
    }
    m.tm_year -= 1900;
    m.tm_mon -= 1;

    detail::UtcTimezone useUtc;
    *v = mktime(&m);
    if (sizeof(time_t) <= 4 && *v < 0 && (1900 + m.tm_year) >= 2038) {
      *v = MAX_TIME;
    }
    return *v >= 0;
  }

public:
  /** @brief NotBefore field in seconds since Unix epoch. */
  time_t notBefore = 0;

  /** @brief NotAfter field in seconds since Unix epoch. */
  time_t notAfter = 0;
};

inline bool
operator==(const ValidityPeriod& lhs, const ValidityPeriod& rhs)
{
  return lhs.notBefore == rhs.notBefore && lhs.notAfter == rhs.notAfter;
}

NDNPH_DECLARE_NE(ValidityPeriod, inline)

/** @brief Compute the intersection of two ValidityPeriods. */
inline ValidityPeriod
operator&&(const ValidityPeriod& lhs, const ValidityPeriod& rhs)
{
  ValidityPeriod intersection;
  intersection.notBefore = std::max(lhs.notBefore, rhs.notBefore);
  intersection.notAfter = std::min(lhs.notAfter, rhs.notAfter);
  return intersection;
}

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_VALIDITY_PERIOD_HPP
