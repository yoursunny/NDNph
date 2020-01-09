#ifndef NDNPH_PORT_MBEDTLS_SHA256_HPP
#define NDNPH_PORT_MBEDTLS_SHA256_HPP

#include "../../packet/interest.hpp"

#include <mbedtls/sha256.h>

namespace ndnph {
namespace port {

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

  bool final(uint8_t digest[32])
  {
    m_hasError = m_hasError || mbedtls_sha256_finish_ret(&m_ctx, digest) != 0;
    return !m_hasError;
  }

private:
  mbedtls_sha256_context m_ctx;
  bool m_hasError = false;
};

} // namespace port

using Interest = InterestBase<port::Sha256>;

} // namespace ndnph

#endif // NDNPH_PORT_MBEDTLS_SHA256_HPP
