#ifndef NDNPH_PORT_RANDOM_URANDOM_HPP
#define NDNPH_PORT_RANDOM_URANDOM_HPP

#include "../../core/common.hpp"

namespace ndnph {
namespace port_random_urandom {

/** @brief Generate random bytes by reading from urandom device. */
class RandomSource {
public:
  RandomSource() = delete;

  /**
   * @brief Fill output[0:count] with random bytes.
   * @return whether success.
   */
  static bool generate(uint8_t* output, size_t count) {
    static FILE* fd = std::fopen("/dev/urandom", "r");
    return fd != nullptr && std::fread(output, 1, count, fd) == count;
  }
};

} // namespace port_random_urandom

#ifdef NDNPH_PORT_RANDOM_URANDOM
namespace port {
using RandomSource = port_random_urandom::RandomSource;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_RANDOM_URANDOM_HPP
