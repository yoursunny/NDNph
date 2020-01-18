#ifndef NDNPH_PORT_RANDOM_NULL_HPP
#define NDNPH_PORT_RANDOM_NULL_HPP

#include "../../core/common.hpp"

#include <cstdio>

namespace ndnph {
namespace port_random_null {

/** @brief Random bytes generator stub. */
class RandomSource
{
public:
  /**
   * @brief Fill output[0:count] with random bytes.
   * @return whether success.
   */
  bool fill(uint8_t* output, size_t count)
  {
    std::fill_n(output, count, 0);
    return false;
  }
};

} // namespace port_random_null

#ifdef NDNPH_PORT_RANDOM_NULL
using RandomSource = port_random_null::RandomSource;
#endif

} // namespace ndnph

#endif // NDNPH_PORT_RANDOM_NULL_HPP
