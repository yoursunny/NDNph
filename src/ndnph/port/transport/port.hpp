#ifndef NDNPH_PORT_TRANSPORT_PORT_HPP
#define NDNPH_PORT_TRANSPORT_PORT_HPP

#include "null.hpp"

#if defined(NDNPH_PORT_TRANSPORT_CUSTOM)
// Custom transport port will be included later.
#elif defined(NDNPH_PORT_TRANSPORT_SOCKET)
#include "socket/udp-unicast.hpp"
#else
#endif

#endif // NDNPH_PORT_TRANSPORT_PORT_HPP
