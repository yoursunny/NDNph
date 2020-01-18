#ifndef NDNPH_PORT_CRYPTO_NULL_SHA256_HPP
#define NDNPH_PORT_CRYPTO_NULL_SHA256_HPP

#include "../../../core/common.hpp"

namespace ndnph {
namespace port_crypto_null {

/** @brief Stub SHA256 algorithm implementation. */
class Sha256
{
public:
  /** @brief Append bytes into hash state. */
  void update(const uint8_t*, size_t) {}

  /**
   * @brief Finalize hash and obtain digest.
   * @return whether success.
   */
  bool final(uint8_t[NDNPH_SHA256_LEN])
  {
    return false;
  }
};

} // namespace port_crypto_null
} // namespace ndnph

#endif // NDNPH_PORT_CRYPTO_NULL_SHA256_HPP
