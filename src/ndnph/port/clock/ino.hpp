#ifndef NDNPH_PORT_CLOCK_INO_HPP
#define NDNPH_PORT_CLOCK_INO_HPP

#include "../../core/common.hpp"

#include <Arduino.h>

namespace ndnph {
namespace port_clock_ino {

/** @brief Clock implemented with Arduino API. */
class Clock
{
public:
  Clock() = delete;

  using Time = decltype(::millis());

  static Time now()
  {
    return ::millis();
  }

  static Time add(Time t, int ms)
  {
    return t + ms;
  }

  static int sub(Time a, Time b)
  {
    if (isBefore(a, b)) {
      Time diff = b - a;
      return -static_cast<int>(diff);
    }
    Time diff = a - b;
    return static_cast<int>(diff);
  }

  static bool isBefore(Time a, Time b)
  {
    static_assert(std::is_unsigned<Time>::value, "");
    Time diff = a - b;
    return diff > std::numeric_limits<Time>::max() / 2;
  }

  static void sleep(int ms)
  {
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
