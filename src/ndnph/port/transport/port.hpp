#ifndef NDNPH_PORT_TRANSPORT_PORT_HPP
#define NDNPH_PORT_TRANSPORT_PORT_HPP

#ifdef NDNPH_PORT_TRANSPORT_CUSTOM
// Custom transport port will be included later.
#else

#ifdef NDNPH_PORT_TRANSPORT_SOCKET
#include "socket/udp-unicast.hpp"
#endif

#ifdef NDNPH_PORT_TRANSPORT_MEMIF
#include "memif.hpp"
#endif

#endif // NDNPH_PORT_TRANSPORT_CUSTOM

#endif // NDNPH_PORT_TRANSPORT_PORT_HPP
