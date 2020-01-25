#ifndef NDNPH_PORT_QUEUE_BOOSTLF_HPP
#define NDNPH_PORT_QUEUE_BOOSTLF_HPP

#include "../../core/common.hpp"

#include <boost/lockfree/spsc_queue.hpp>

namespace ndnph {
namespace port_queue_boostlf {

/** @brief Generic thread-safe queue, implemented with Boost Lockfree library. */
template<typename T, size_t capacity>
class SafeQueue
{
public:
  using Item = T;

  bool push(Item item)
  {
    return m_queue.push(item);
  }

  std::tuple<Item, bool> pop()
  {
    Item item;
    bool ok = m_queue.pop(item);
    return std::make_tuple(std::move(item), ok);
  }

private:
  using Q = typename boost::lockfree::spsc_queue<T, boost::lockfree::capacity<capacity>>;
  Q m_queue;
};

} // namespace port_queue_boostlf

#ifdef NDNPH_PORT_QUEUE_BOOSTLF
namespace port {
template<typename T, size_t capacity>
using SafeQueue = port_queue_boostlf::SafeQueue<T, capacity>;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_QUEUE_BOOSTLF_HPP
