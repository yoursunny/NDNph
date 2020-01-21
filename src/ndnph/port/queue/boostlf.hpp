#ifndef NDNPH_PORT_QUEUE_BOOSTLF_HPP
#define NDNPH_PORT_QUEUE_BOOSTLF_HPP

#include "typedef-common.hpp"

#include <boost/lockfree/spsc_queue.hpp>

namespace ndnph {
namespace port_queue_boostlf {

/**
 * @brief Generic thread-safe queue, implemented with Boost Lockfree library.
 * @tparam T item type.
 * @tparam MaxCapacity capacity of underlying data structure; this is necessary because
 *                     boost::lockfree::spsc_queue uses exceptions unless capacity is set.
 */
template<typename T, size_t MaxCapacity = 64>
class SafeQueue
{
public:
  using Item = T;

  explicit SafeQueue(size_t capacity)
  {
    assert(capacity <= MaxCapacity);
  }

  bool push(T item)
  {
    return m_queue.push(item);
  }

  std::tuple<T, bool> pop()
  {
    T item;
    bool ok = m_queue.pop(item);
    return std::make_tuple(std::move(item), ok);
  }

private:
  using Q = typename boost::lockfree::spsc_queue<T, boost::lockfree::capacity<MaxCapacity>>;
  Q m_queue;
};

} // namespace port_queue_boostlf
} // namespace ndnph

#ifdef NDNPH_PORT_QUEUE_BOOSTLF
NDNPH_PORT_QUEUE_DECLARE_TYPES(port_queue_boostlf::SafeQueue)
#endif

#endif // NDNPH_PORT_QUEUE_BOOSTLF_HPP
