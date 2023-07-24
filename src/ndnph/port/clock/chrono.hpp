#ifndef NDNPH_PORT_CLOCK_CHRONO_HPP
#define NDNPH_PORT_CLOCK_CHRONO_HPP

#include "../../core/common.hpp"

#include <chrono>
#include <thread>

namespace ndnph {
namespace port_clock_chrono {

/** @brief Clock implemented with std::chrono. */
class Clock {
public:
  Clock() = delete;

  using Time = std::chrono::steady_clock::time_point;

  static Time now() {
    return std::chrono::steady_clock::now();
  }

  static Time add(Time t, int ms) {
    return Time(t.time_since_epoch() +
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                  std::chrono::milliseconds(ms)));
  }

  static int sub(Time a, Time b) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(a - b).count();
  }

  static bool isBefore(Time a, Time b) {
    return a < b;
  }

  static void sleep(int ms) {
#ifdef NDNPH_PORT_CHRONO_BUSY_SLEEP
    Time end = add(now(), ms);
    while (isBefore(now(), end)) {
    }
#else
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
#endif
  }
};

} // namespace port_clock_chrono

#ifdef NDNPH_PORT_CLOCK_CHRONO
namespace port {
using Clock = port_clock_chrono::Clock;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_CLOCK_CHRONO_HPP
