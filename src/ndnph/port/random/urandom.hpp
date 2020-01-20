#ifndef NDNPH_PORT_RANDOM_URANDOM_HPP
#define NDNPH_PORT_RANDOM_URANDOM_HPP

#include "../../core/common.hpp"

namespace ndnph {
namespace port_random_urandom {

/** @brief Generate random bytes by reading from urandom device. */
class RandomSource
{
public:
  explicit RandomSource(const char* filename = "/dev/urandom")
    : m_fd(fopen(filename, "r"))
  {}

  ~RandomSource()
  {
    if (m_fd != nullptr) {
      fclose(m_fd);
    }
  }

  bool fill(uint8_t* output, size_t count)
  {
    return m_fd != nullptr && fread(output, 1, count, m_fd) == count;
  }

private:
  FILE* m_fd = nullptr;
};

} // namespace port_random_urandom

#ifdef NDNPH_PORT_RANDOM_URANDOM
using RandomSource = port_random_urandom::RandomSource;
#endif

} // namespace ndnph

#endif // NDNPH_PORT_RANDOM_URANDOM_HPP
