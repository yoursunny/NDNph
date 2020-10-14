#ifndef NDNPH_PORT_EC_PORT_HPP
#define NDNPH_PORT_EC_PORT_HPP

#if defined(NDNPH_PORT_EC_CUSTOM)
// using custom ECDSA ECDH port
#elif defined(NDNPH_HAVE_MBED)
#define NDNPH_PORT_EC_MBED
#include "mbed.hpp"
#else
#define NDNPH_PORT_EC_NULL
#include "null.hpp"
#endif

#endif // NDNPH_PORT_EC_PORT_HPP
