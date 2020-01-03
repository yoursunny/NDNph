#ifndef NDNPH_CORE_COMMON_HPP
#define NDNPH_CORE_COMMON_HPP

#include <sys/types.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <type_traits>
#include <utility>

#ifndef NDNPH_ALIGNMENT
#define NDNPH_ALIGNMENT (sizeof(void*))
#endif

/** @brief Declare operator!= in terms of operator== */
#define NDNPH_DECLARE_NE(T)                                                    \
  inline bool operator!=(const T& lhs, const T& rhs) { return !(lhs == rhs); }

/** @brief Declare operator>, operator<=, operator>= in terms of operator< */
#define NDNPH_DECLARE_GT_LE_GE(T)                                              \
  inline bool operator>(const T& lhs, const T& rhs) { return rhs < lhs; }      \
  inline bool operator<=(const T& lhs, const T& rhs) { return !(lhs > rhs); }  \
  inline bool operator>=(const T& lhs, const T& rhs) { return !(lhs < rhs); }

#endif // NDNPH_CORE_COMMON_HPP
