#ifndef NDNPH_PORT_SHA256_PORT_HPP
#define NDNPH_PORT_SHA256_PORT_HPP

#if defined(NDNPH_PORT_SHA256_CUSTOM)
// using custom sha256 port
#elif defined(NDNPH_HAVE_MBED)
#define NDNPH_PORT_SHA256_MBED
#include "mbed.hpp"
#else
#define NDNPH_PORT_SHA256_NULL
#include "null.hpp"
#endif

#endif // NDNPH_PORT_SHA256_PORT_HPP
