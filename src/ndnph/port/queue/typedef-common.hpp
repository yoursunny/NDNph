#ifndef NDNPH_PORT_QUEUE_TYPEDEF_COMMON_HPP
#define NDNPH_PORT_QUEUE_TYPEDEF_COMMON_HPP

#include "../../face/bridge-transport.hpp"

/**
 * @brief Declare types dependent on queue port.
 * @note This is meant to be used by a port in global namespace.
 */
#define NDNPH_PORT_QUEUE_DECLARE_TYPES(SafeQueuePort)                                              \
  namespace ndnph {                                                                                \
  template<typename T>                                                                             \
  using SafeQueue = SafeQueuePort<T>;                                                              \
  using BridgeTransport = BasicBridgeTransport<SafeQueue<transport::RxQueueItem>>;                 \
  }

#endif // NDNPH_PORT_QUEUE_TYPEDEF_COMMON_HPP
