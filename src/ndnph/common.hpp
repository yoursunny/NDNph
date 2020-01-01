#ifndef NDNPH_COMMON_HPP
#define NDNPH_COMMON_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iterator>
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

namespace ndnph {
namespace detail {

template<typename T>
class InputIteratorPointerProxy
{
public:
  InputIteratorPointerProxy(T&& item)
    : m_item(item)
  {}
  T* operator->() const { return &m_item; }

private:
  T m_item;
};

} // namespace detail
} // namespace ndnph

#endif // NDNPH_COMMON_HPP
