#ifndef NDNPH_PORT_NULL_SHA256_HPP
#define NDNPH_PORT_NULL_SHA256_HPP

#include "../../core/common.hpp"

namespace ndnph {
namespace port_null {

class Sha256
{
public:
  void update(const uint8_t*, size_t) {}

  bool final(uint8_t[NDNPH_SHA256_LEN])
  {
    return false;
  }
};

} // namespace port_null
} // namespace ndnph

#endif // NDNPH_PORT_NULL_SHA256_HPP
