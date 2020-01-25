#ifndef NDNPH_PORT_CRYPTO_PORT_HPP
#define NDNPH_PORT_CRYPTO_PORT_HPP

#if defined(NDNPH_PORT_CRYPTO_CUSTOM)
// using custom crypto port
#elif defined(NDNPH_PORT_CRYPTO_MBEDTLS)
#include "mbed/typedef.hpp"
#else
#define NDNPH_PORT_CRYPTO_NULL
#include "null/typedef.hpp"
#endif

#if defined(NDNPH_PORT_CRYPTOEQUAL_CUSTOM)
// using custom timing safe equal port
#else
#define NDNPH_PORT_CRYPTOEQUAL_DEFAULT
#include "timing-safe-equal.hpp"
#endif

#endif // NDNPH_PORT_CRYPTO_PORT_HPP
