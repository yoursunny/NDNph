#ifndef NDNPH_FACE_TRANSPORT_RXQUEUE_HPP
#define NDNPH_FACE_TRANSPORT_RXQUEUE_HPP

#include "../core/simple-queue.hpp"
#include "transport.hpp"

namespace ndnph {
namespace transport {

struct RxQueueItem
{
  Region* region = nullptr;
  uint64_t endpointId = 0;
  uint8_t* pkt = nullptr;
  ssize_t pktLen = -1;
};

/**
 * @brief Mixin of RX queue in Transport.
 * @tparam Queue a queue of RxQueueItem.
 */
template<typename Queue = DynamicSimpleQueue<RxQueueItem>>
class RxQueueMixin : public virtual Transport
{
protected:
  explicit RxQueueMixin(size_t capacity)
    : m_allocQ(capacity)
    , m_rxQ(capacity)
    , m_cap(capacity)
  {}

  /**
   * @brief Allocate receive buffers during initialization.
   * @tparam F `Region* (*)()`
   */
  template<typename F>
  void initAllocBuffers(const F& makeRegion)
  {
    for (size_t i = 0; i < m_cap; ++i) {
      RxQueueItem item;
      item.region = makeRegion();
      if (item.region == nullptr || !m_allocQ.push(item)) {
        break;
      }
    }
  }

  class RxContext
  {
  public:
    using TransportT = RxQueueMixin<Queue>;

    explicit RxContext(TransportT& transport)
      : m_transport(transport)
    {
      bool ok = false;
      std::tie(m_item, ok) = transport.m_allocQ.pop();
      if (ok) {
        Region& region = *m_item.region;
        region.reset();
        m_bufLen = region.availableA();
        m_item.pkt = region.allocA(m_bufLen);
        m_item.pktLen = -1;
      }
    }

    ~RxContext()
    {
      if (m_item.region == nullptr) {
        return;
      }
      bool ok = false;
      if (m_item.pktLen < 0) {
        ok = m_transport.m_allocQ.push(m_item);
      } else {
        ok = m_transport.m_rxQ.push(m_item);
      }
      assert(ok);
    }

    operator bool() const
    {
      return m_item.pkt != nullptr;
    }

    uint8_t* buf()
    {
      return m_item.pkt;
    }

    size_t bufLen()
    {
      return m_bufLen;
    }

    void operator()(size_t pktLen, uint64_t endpointId = 0)
    {
      m_item.pktLen = pktLen;
      m_item.endpointId = endpointId;
      m_item.region->free(m_item.pkt + pktLen, m_item.pkt + m_bufLen);
    }

  private:
    TransportT& m_transport;
    RxQueueItem m_item;
    size_t m_bufLen;
  };

  /**
   * @brief Receive packets in a loop.
   *
   * @code
   * while (auto r = receiving()) {
   *   if (receiveInto(r.buf(), r.bufLen())) {
   *     r(pktLen);
   *   } else {
   *     break;
   *   }
   * }
   * @endcode
   */
  RxContext receiving()
  {
    return RxContext(*this);
  }

  /**
   * @brief Process periodical events.
   *
   * This delivers received packets to Face.
   * This should be called in `loop()`.
   */
  void loopRxQueue()
  {
    while (true) {
      RxQueueItem item;
      bool ok = false;
      std::tie(item, ok) = m_rxQ.pop();
      if (!ok) {
        break;
      }
      invokeRxCallback(*item.region, item.pkt, item.pktLen, item.endpointId);
      m_allocQ.push(item);
    }
  }

private:
  Queue m_allocQ;
  Queue m_rxQ;
  size_t m_cap = 0;
};

/**
 * @brief Mixin of RX queue in Transport, allocating buffers from DynamicRegion.
 * @tparam Queue a queue of RxQueueItem.
 */
template<typename Queue = DynamicSimpleQueue<RxQueueItem>>
class DynamicRxQueueMixin : public RxQueueMixin<Queue>
{
protected:
  /**
   * @brief Constructor.
   * @param nBuffers number of buffers, also queue capacity.
   * @param bufLen buffer length, typically MTU.
   */
  explicit DynamicRxQueueMixin(size_t nBuffers = 4, size_t bufLen = 1500)
    : RxQueueMixin<Queue>(nBuffers)
    , m_region(sizeofSubRegions(bufLen, nBuffers))
  {
    this->initAllocBuffers([=] { return makeSubRegion(m_region, bufLen); });
  }

private:
  DynamicRegion m_region;
};

} // namespace transport
} // namespace ndnph

#endif // NDNPH_FACE_TRANSPORT_RXQUEUE_HPP
