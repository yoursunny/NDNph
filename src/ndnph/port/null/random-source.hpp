#ifndef NDNPH_PORT_NULL_RANDOM_SOURCE_HPP
#define NDNPH_PORT_NULL_RANDOM_SOURCE_HPP

#include "../../core/common.hpp"

#include <cstdio>

namespace ndnph {
namespace port_null {

class RandomSource
{
public:
  bool fill(uint8_t* output, size_t count)
  {
    std::fill_n(output, count, 0);
    return false;
  }
};

} // namespace port_null
} // namespace ndnph

#endif // NDNPH_PORT_NULL_RANDOM_SOURCE_HPP
