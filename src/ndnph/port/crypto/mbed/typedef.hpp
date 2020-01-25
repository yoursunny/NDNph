#ifndef NDNPH_PORT_CRYPTO_MBED_TYPEDEF_HPP
#define NDNPH_PORT_CRYPTO_MBED_TYPEDEF_HPP

#include "ecdsa.hpp"
#include "sha256.hpp"

#ifdef NDNPH_PORT_CRYPTO_MBEDTLS
namespace ndnph {
namespace port {
using Sha256 = port_crypto_mbed::Sha256;
using Ecdsa = port_crypto_mbed::Ecdsa<port_crypto_mbed::ec_curve::P256>;
} // namespace port
} // namespace ndnph
#endif

#endif // NDNPH_PORT_CRYPTO_MBED_TYPEDEF_HPP
