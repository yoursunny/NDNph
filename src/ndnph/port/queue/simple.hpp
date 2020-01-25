#ifndef NDNPH_PORT_QUEUE_SIMPLE_HPP
#define NDNPH_PORT_QUEUE_SIMPLE_HPP

#include "../../core/simple-queue.hpp"

namespace ndnph {

#ifdef NDNPH_PORT_QUEUE_SIMPLE
namespace port {
/** @brief Use non-thread-safe queue as thread-safe queue on single-threaded systems. */
template<typename T, size_t capacity>
using SafeQueue = StaticSimpleQueue<T, capacity>;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_QUEUE_SIMPLE_HPP
