#ifndef NDNPH_CORE_SIMPLE_QUEUE_HPP
#define NDNPH_CORE_SIMPLE_QUEUE_HPP

#include "common.hpp"

namespace ndnph {

/** @brief Generic non-thread-safe queue. */
template<typename T, size_t Capacity>
class SimpleQueue
{
public:
  static_assert(std::is_default_constructible<T>::value, "");
  static_assert(std::is_move_assignable<T>::value, "");
  static_assert(std::is_move_constructible<T>::value, "");

  bool push(T item)
  {
    size_t newTail = nextIndex(m_tail);
    if (newTail == m_head) {
      return false;
    }

    m_arr[m_tail] = std::move(item);
    m_tail = newTail;
    return true;
  }

  std::tuple<T, bool> pop()
  {
    if (m_head == m_tail) {
      return std::make_tuple(T(), false);
    }
    T item = std::move(m_arr[m_head]);
    m_arr[m_head] = T();
    m_head = nextIndex(m_head);
    return std::make_tuple(std::move(item), true);
  }

  size_t size() const
  {
    return (m_tail - m_head + Capacity + 1) % (Capacity + 1);
  }

  bool isFull() const
  {
    return nextIndex(m_tail) == m_head;
  }

private:
  static constexpr size_t nextIndex(size_t i)
  {
    return (i + 1) % (Capacity + 1);
  }

private:
  T m_arr[Capacity + 1];
  size_t m_head = 0;
  size_t m_tail = 0;
};

} // namespace ndnph

#endif // NDNPH_CORE_SIMPLE_QUEUE_HPP
