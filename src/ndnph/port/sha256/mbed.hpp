#ifndef NDNPH_PORT_SHA256_MBED_HPP
#define NDNPH_PORT_SHA256_MBED_HPP

#include "../mbed-common.hpp"

namespace ndnph {
namespace port_sha256_mbed {

using Sha256 = mbedtls::Sha256;
using HmacSha256 = mbedtls::Hmac<MBEDTLS_MD_SHA256, NDNPH_SHA256_LEN>;

} // namespace port_sha256_mbed

#ifdef NDNPH_PORT_SHA256_MBED
namespace port {
using Sha256 = port_sha256_mbed::Sha256;
using HmacSha256 = port_sha256_mbed::HmacSha256;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_SHA256_MBED_HPP
