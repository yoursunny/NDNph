#ifndef NDNPH_PORT_UNIXTIME_PORT_HPP
#define NDNPH_PORT_UNIXTIME_PORT_HPP

#if defined(NDNPH_PORT_UNIXTIME_CUSTOM)
// using custom unixtime port
#else
#define NDNPH_PORT_UNIXTIME_SYSTIME
#include "systime.hpp"
#endif

#endif // NDNPH_PORT_UNIXTIME_PORT_HPP
