#ifndef NDNPH_PORT_CRYPTO_PORT_HPP
#define NDNPH_PORT_CRYPTO_PORT_HPP

#if defined(NDNPH_PORT_CRYPTO_CUSTOM)
// Custom crypto port will be included later.
#elif defined(NDNPH_PORT_CRYPTO_MBEDTLS)
#include "mbed/typedef.hpp"
#else
#define NDNPH_PORT_CRYPTO_NULL
#include "null/typedef.hpp"
#endif

#endif // NDNPH_PORT_CRYPTO_PORT_HPP
