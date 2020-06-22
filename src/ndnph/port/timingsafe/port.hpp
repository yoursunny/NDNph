#ifndef NDNPH_PORT_TIMINGSAFE_PORT_HPP
#define NDNPH_PORT_TIMINGSAFE_PORT_HPP

#if defined(NDNPH_PORT_TIMINGSAFE_CUSTOM)
// using custom tse port
#else
#define NDNPH_PORT_TIMINGSAFE_DEFAULT
#include "default.hpp"
#endif

#endif // NDNPH_PORT_TIMINGSAFE_PORT_HPP
