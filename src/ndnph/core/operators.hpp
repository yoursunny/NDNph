#ifndef NDNPH_CORE_OPERATORS_HPP
#define NDNPH_CORE_OPERATORS_HPP

#include "common.hpp"

/** @brief Declare operator!= in terms of operator== */
#define NDNPH_DECLARE_NE(T, specifier)                                                             \
  specifier bool operator!=(const T& lhs, const T& rhs)                                            \
  {                                                                                                \
    return !(lhs == rhs);                                                                          \
  }

/** @brief Declare operator>, operator<=, operator>= in terms of operator< */
#define NDNPH_DECLARE_GT_LE_GE(T, specifier)                                                       \
  specifier bool operator>(const T& lhs, const T& rhs)                                             \
  {                                                                                                \
    return rhs < lhs;                                                                              \
  }                                                                                                \
  specifier bool operator<=(const T& lhs, const T& rhs)                                            \
  {                                                                                                \
    return !(lhs > rhs);                                                                           \
  }                                                                                                \
  specifier bool operator>=(const T& lhs, const T& rhs)                                            \
  {                                                                                                \
    return !(lhs < rhs);                                                                           \
  }

namespace ndnph {

/**
 * @brief Compute ceil( @p a / @p b ).
 * @param a non-negative integer.
 * @param b non-negative integer.
 */
template<typename I>
inline typename std::enable_if<std::is_integral<I>::value, I>::type
divCeil(const I& a, const I& b)
{
  return (a + b - 1) / b;
}

} // namespace ndnph

#endif // NDNPH_CORE_OPERATORS_HPP
