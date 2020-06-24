#ifndef NDNPH_PORT_FS_PORT_HPP
#define NDNPH_PORT_FS_PORT_HPP

#if defined(NDNPH_PORT_FS_CUSTOM)
// using custom file store port
#elif defined(NDNPH_PORT_FS_LINUX)
#include "linux.hpp"
#else
#define NDNPH_PORT_FS_NULL
#include "null.hpp"
#endif

#endif // NDNPH_PORT_FS_PORT_HPP
