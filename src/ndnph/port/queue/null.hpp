#ifndef NDNPH_PORT_QUEUE_NULL_HPP
#define NDNPH_PORT_QUEUE_NULL_HPP

#include "../../core/common.hpp"

namespace ndnph {
namespace port_queue_null {

/** @brief Generic thread-safe queue stub. */
template<typename T, size_t capacity>
class SafeQueue {
public:
  using Item = T;

  bool push(Item) {
    return false;
  }

  std::tuple<Item, bool> pop() {
    return std::make_tuple(T(), false);
  }
};

} // namespace port_queue_null

#ifdef NDNPH_PORT_QUEUE_NULL
namespace port {
template<typename T, size_t capacity>
using SafeQueue = port_queue_null::SafeQueue<T, capacity>;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_QUEUE_NULL_HPP
