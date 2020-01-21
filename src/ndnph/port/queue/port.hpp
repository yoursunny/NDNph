#ifndef NDNPH_PORT_QUEUE_PORT_HPP
#define NDNPH_PORT_QUEUE_PORT_HPP

#if defined(NDNPH_PORT_QUEUE_CUSTOM)
// Custom queue port will be included later.
#elif defined(NDNPH_PORT_QUEUE_BOOSTLF)
#include "boostlf.hpp"
#else
#define NDNPH_PORT_QUEUE_NULL
#include "null.hpp"
#endif

#endif // NDNPH_PORT_QUEUE_PORT_HPP
