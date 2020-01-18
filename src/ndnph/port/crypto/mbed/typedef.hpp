#ifndef NDNPH_PORT_CRYPTO_MBED_TYPEDEF_HPP
#define NDNPH_PORT_CRYPTO_MBED_TYPEDEF_HPP

#include "../typedef-common.hpp"
#include "ecdsa.hpp"
#include "sha256.hpp"

#ifdef NDNPH_PORT_CRYPTO_MBEDTLS
NDNPH_PORT_CRYPTO_DECLARE_TYPES(port_crypto_mbed::Sha256,
                                port_crypto_mbed::Ecdsa<port_crypto_mbed::ec_curve::P256>)
#endif

#endif // NDNPH_PORT_CRYPTO_MBED_TYPEDEF_HPP
