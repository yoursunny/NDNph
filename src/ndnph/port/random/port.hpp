#ifndef NDNPH_PORT_RANDOM_PORT_HPP
#define NDNPH_PORT_RANDOM_PORT_HPP

#if defined(NDNPH_PORT_RANDOM_CUSTOM)
// using custom random port
#elif defined(NDNPH_PORT_RANDOM_URANDOM)
#include "urandom.hpp"
#else
#define NDNPH_PORT_RANDOM_NULL
#include "null.hpp"
#endif

#endif // NDNPH_PORT_RANDOM_PORT_HPP
