#ifndef NDNPH_CORE_SIMPLE_QUEUE_HPP
#define NDNPH_CORE_SIMPLE_QUEUE_HPP

#include "common.hpp"

namespace ndnph {

/** @brief Generic non-thread-safe queue. */
template<typename T>
class SimpleQueue {
public:
  static_assert(std::is_default_constructible<T>::value, "");
  static_assert(std::is_move_assignable<T>::value, "");
  static_assert(std::is_move_constructible<T>::value, "");
  using Item = T;

  bool push(Item item) {
    size_t newTail = nextIndex(m_tail);
    if (newTail == m_head) {
      return false;
    }

    m_arr[m_tail] = std::move(item);
    m_tail = newTail;
    return true;
  }

  std::tuple<Item, bool> pop() {
    if (m_head == m_tail) {
      return std::make_tuple(T(), false);
    }
    Item item = std::move(m_arr[m_head]);
    m_arr[m_head] = T();
    m_head = nextIndex(m_head);
    return std::make_tuple(std::move(item), true);
  }

  size_t capacity() const {
    return m_cap1 - 1;
  }

  size_t size() const {
    return (m_tail - m_head + m_cap1) % m_cap1;
  }

  size_t available() const {
    return capacity() - size();
  }

protected:
  /**
   * @brief Constructor.
   * @param arr array of cap+1 items
   * @param cap maximum number of items
   */
  explicit SimpleQueue(Item* arr, size_t cap)
    : m_arr(arr)
    , m_cap1(cap + 1) {}

  Item* getArray() {
    return m_arr;
  }

private:
  size_t nextIndex(size_t i) const {
    return (i + 1) % m_cap1;
  }

private:
  Item* m_arr;
  size_t m_cap1 = 0;
  size_t m_head = 0;
  size_t m_tail = 0;
};

/**
 * @brief SimpleQueue with statically allocated memory.
 * @tparam C capacity.
 */
template<typename T, size_t C>
class StaticSimpleQueue : public SimpleQueue<T> {
public:
  explicit StaticSimpleQueue()
    : SimpleQueue<T>(m_array, C) {}

private:
  T m_array[C + 1];
};

/** @brief SimpleQueue with dynamically allocated memory. */
template<typename T>
class DynamicSimpleQueue : public SimpleQueue<T> {
public:
  explicit DynamicSimpleQueue(size_t capacity)
    : SimpleQueue<T>(new T[capacity + 1], capacity) {}

  ~DynamicSimpleQueue() {
    delete[] this->getArray();
  }
};

} // namespace ndnph

#endif // NDNPH_CORE_SIMPLE_QUEUE_HPP
