#ifndef NDNPH_PORT_MBEDTLS_SHA256_HPP
#define NDNPH_PORT_MBEDTLS_SHA256_HPP

#include "../../core/common.hpp"

#include <mbedtls/sha256.h>

namespace ndnph {
namespace port_mbedtls {

class Sha256
{
public:
  Sha256()
  {
    mbedtls_sha256_init(&m_ctx);
    m_hasError = m_hasError || mbedtls_sha256_starts_ret(&m_ctx, 0) != 0;
  }

  ~Sha256() { mbedtls_sha256_free(&m_ctx); }

  void update(const uint8_t* chunk, size_t size)
  {
    m_hasError =
      m_hasError || mbedtls_sha256_update_ret(&m_ctx, chunk, size) != 0;
  }

  bool final(uint8_t digest[NDNPH_SHA256_LEN])
  {
    m_hasError = m_hasError || mbedtls_sha256_finish_ret(&m_ctx, digest) != 0;
    return !m_hasError;
  }

private:
  mbedtls_sha256_context m_ctx;
  bool m_hasError = false;
};

} // namespace port_mbedtls
} // namespace ndnph

#endif // NDNPH_PORT_MBEDTLS_SHA256_HPP
