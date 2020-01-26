#ifndef NDNPH_PORT_CLOCK_PORT_HPP
#define NDNPH_PORT_CLOCK_PORT_HPP

#if defined(NDNPH_PORT_CLOCK_CUSTOM)
// using custom clock port
#elif defined(ARDUINO)
#define NDNPH_PORT_CLOCK_INO
#include "ino.hpp"
#else
#define NDNPH_PORT_CLOCK_CHRONO
#include "chrono.hpp"
#endif

#endif // NDNPH_PORT_CLOCK_PORT_HPP
