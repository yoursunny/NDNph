#ifndef NDNPH_PORT_RANDOM_NULL_HPP
#define NDNPH_PORT_RANDOM_NULL_HPP

#include "../../core/common.hpp"

namespace ndnph {
namespace port_random_null {

/** @brief Random bytes generator stub. */
class RandomSource {
public:
  RandomSource() = delete;

  /**
   * @brief Fill output[0:count] with random bytes.
   * @return whether success.
   */
  static bool generate(uint8_t* output, size_t count) {
    std::fill_n(output, count, 0);
    return false;
  }
};

} // namespace port_random_null

#ifdef NDNPH_PORT_RANDOM_NULL
namespace port {
using RandomSource = port_random_null::RandomSource;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_RANDOM_NULL_HPP
