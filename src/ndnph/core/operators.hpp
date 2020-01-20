#ifndef NDNPH_CORE_OPERATORS_HPP
#define NDNPH_CORE_OPERATORS_HPP

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

#endif // NDNPH_CORE_OPERATORS_HPP
