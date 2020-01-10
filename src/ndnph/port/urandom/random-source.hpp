#ifndef NDNPH_PORT_URANDOM_RANDOM_SOURCE_HPP
#define NDNPH_PORT_URANDOM_RANDOM_SOURCE_HPP

#include "../../core/common.hpp"

#include <cstdio>

namespace ndnph {
namespace port_urandom {

class RandomSource
{
public:
  explicit RandomSource()
    : m_urandom(fopen("/dev/urandom", "r"))
  {}

  ~RandomSource()
  {
    if (m_urandom != nullptr) {
      fclose(m_urandom);
    }
  }

  bool fill(uint8_t* output, size_t count)
  {
    return m_urandom != nullptr && fread(output, 1, count, m_urandom) == count;
  }

private:
  FILE* m_urandom = nullptr;
};

} // namespace port_urandom
} // namespace ndnph

#endif // NDNPH_PORT_URANDOM_RANDOM_SOURCE_HPP
