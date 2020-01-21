#ifndef NDNPH_PORT_QUEUE_NULL_HPP
#define NDNPH_PORT_QUEUE_NULL_HPP

#include "typedef-common.hpp"

namespace ndnph {
namespace port_queue_null {

/**
 * @brief Generic thread-safe queue stub.
 */
template<typename T, size_t MaxCapacity = 64>
class SafeQueue
{
public:
  using Item = T;

  explicit SafeQueue(size_t capacity) {}

  bool push(T item)
  {
    return false;
  }

  std::tuple<T, bool> pop()
  {
    return std::make_tuple(T(), false);
  }
};

} // namespace port_queue_null
} // namespace ndnph

#ifdef NDNPH_PORT_QUEUE_NULL
NDNPH_PORT_QUEUE_DECLARE_TYPES(port_queue_null::SafeQueue)
#endif

#endif // NDNPH_PORT_QUEUE_NULL_HPP
