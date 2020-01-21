#ifndef NDNPH_CORE_COMMON_HPP
#define NDNPH_CORE_COMMON_HPP

#include <sys/types.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>

#ifdef ARDUINO
#include <Print.h>
#include <Printable.h>
#define NDNPH_PRINT_ARDUINO
#else
#include <ostream>
#define NDNPH_PRINT_OSTREAM
#endif

#define NDNPH_SHA256_LEN 32

#endif // NDNPH_CORE_COMMON_HPP
