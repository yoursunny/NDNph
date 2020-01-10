#ifndef NDNPH_PORT_MBEDTLS_RNG_HPP
#define NDNPH_PORT_MBEDTLS_RNG_HPP

#include "../../core/common.hpp"

namespace ndnph {
namespace port_mbedtls {
namespace detail {

template<typename RandomSrc>
class Rng
{
public:
  using Self = Rng<RandomSrc>;

  explicit Rng(RandomSrc& rng)
    : m_rng(rng)
  {}

  static int rng(void* self, uint8_t* output, size_t count)
  {
    bool ok = reinterpret_cast<Self*>(self)->m_rng.fill(output, count);
    return ok ? 0 : -1;
  }

private:
  RandomSrc& m_rng;
};

} // namespace detail
} // namespace port_mbedtls
} // namespace ndnph

#endif // NDNPH_PORT_MBEDTLS_RNG_HPP
