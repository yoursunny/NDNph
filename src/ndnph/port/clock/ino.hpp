#ifndef NDNPH_PORT_CLOCK_INO_HPP
#define NDNPH_PORT_CLOCK_INO_HPP

#include "../../core/common.hpp"
#include "../arduino-include.hpp"

namespace ndnph {
namespace port_clock_ino {

using TimeMillis = decltype(::millis());

/** @brief Clock implemented with Arduino API. */
class Clock {
public:
  Clock() = delete;

  struct Time {
    TimeMillis ms = 0;
  };

  static Time now() {
    Time r;
    r.ms = ::millis();
    return r;
  }

  static Time add(Time t, int ms) {
    Time r;
    r.ms = t.ms + ms;
    return r;
  }

  static int sub(Time a, Time b) {
    if (isBefore(a, b)) {
      auto diff = b.ms - a.ms;
      return -static_cast<int>(diff);
    }
    auto diff = a.ms - b.ms;
    return static_cast<int>(diff);
  }

  static bool isBefore(Time a, Time b) {
    static_assert(std::is_unsigned<TimeMillis>::value, "");
    auto diff = a.ms - b.ms;
    return diff > std::numeric_limits<TimeMillis>::max() / 2;
  }

  static void sleep(int ms) {
    if (ms >= 0) {
      ::delay(ms);
    }
  }
};

} // namespace port_clock_ino

#ifdef NDNPH_PORT_CLOCK_INO
namespace port {
using Clock = port_clock_ino::Clock;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_CLOCK_INO_HPP
