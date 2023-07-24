#ifndef NDNPH_PORT_UNIXTIME_SYSTIME_HPP
#define NDNPH_PORT_UNIXTIME_SYSTIME_HPP

#include "../../core/common.hpp"

#include <sys/time.h>

namespace ndnph {
namespace port_unixtime_systime {

/** @brief Clock implemented with @c gettimeofday() . */
class UnixTime {
public:
  UnixTime() = delete;

  /**
   * @brief Retrieve current Unix timestamp in microseconds.
   * @return the timestamp. Use @c valid(t) to determine whether it's valid.
   */
  static uint64_t now() {
    ::timeval tv{};
    ::gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * 1000000 + static_cast<uint64_t>(tv.tv_usec);
  }

  /** @brief Determine whether @p t is likely a valid current Unix timestamp. */
  static bool valid(uint64_t t) {
    return t >= 540109800000000;
  }

  /**
   * @brief Attempt to set current Unix timestamp, if allowed on current system.
   * @param t Unix timestamp in microseconds.
   */
  static void set(uint64_t t) {
#ifdef NDNPH_PORT_UNIXTIME_SYSTIME_CANSET
    ::timeval tv{
      .tv_sec = static_cast<decltype(tv.tv_sec)>(t / 1000000),
      .tv_usec = static_cast<decltype(tv.tv_usec)>(t % 1000000),
    };
    ::settimeofday(&tv, nullptr);
#else
    (void)t;
#endif
  }
};

} // namespace port_unixtime_systime

#ifdef NDNPH_PORT_UNIXTIME_SYSTIME
namespace port {
using UnixTime = port_unixtime_systime::UnixTime;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_UNIXTIME_SYSTIME_HPP
