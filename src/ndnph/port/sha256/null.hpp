#ifndef NDNPH_PORT_SHA256_NULL_HPP
#define NDNPH_PORT_SHA256_NULL_HPP

#include "../../core/common.hpp"

namespace ndnph {
namespace port_sha256_null {

/** @brief Stub SHA256 algorithm implementation. */
class Sha256 {
public:
  /** @brief Append bytes into hash state. */
  void update(const uint8_t*, size_t) {}

  /**
   * @brief Finalize hash and obtain digest.
   * @return whether success.
   */
  bool final(uint8_t[NDNPH_SHA256_LEN]) {
    return false;
  }
};

/** @brief Stub HMAC-SHA256 algorithm implementation. */
class HmacSha256 {
public:
  /** @brief Start HMAC operation and set key. */
  explicit HmacSha256(const uint8_t* key, size_t keyLen) {
    (void)key;
    (void)keyLen;
  }

  /** @brief Append bytes into hash state. */
  void update(const uint8_t*, size_t) {}

  /**
   * @brief Finalize HMAC operation and obtain HMAC result.
   * @return whether success.
   * @post this object is ready for new HMAC operation with same key.
   */
  bool final(uint8_t result[NDNPH_SHA256_LEN]) {
    (void)result;
    return false;
  }
};

} // namespace port_sha256_null

#ifdef NDNPH_PORT_SHA256_NULL
namespace port {
using Sha256 = port_sha256_null::Sha256;
using HmacSha256 = port_sha256_null::HmacSha256;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_SHA256_NULL_HPP
