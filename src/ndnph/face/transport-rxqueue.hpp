#ifndef NDNPH_FACE_TRANSPORT_RXQUEUE_HPP
#define NDNPH_FACE_TRANSPORT_RXQUEUE_HPP

#include "../port/queue/port.hpp"
#include "transport.hpp"

#ifndef NDNPH_TRANSPORT_RXQUEUELEN
#define NDNPH_TRANSPORT_RXQUEUELEN 8
#endif

namespace ndnph {
namespace transport {

struct RxQueueItem
{
  Region* region = nullptr;
  uint64_t endpointId = 0;
  uint8_t* pkt = nullptr;
  ssize_t pktLen = -1;
};

/** @brief Mixin of RX queue in Transport. */
class RxQueueMixin : public virtual Transport
{
protected:
  /**
   * @brief Allocate receive buffers during initialization.
   * @tparam F `Region* (*)()`
   */
  template<typename F>
  void initAllocBuffers(const F& makeRegion)
  {
    for (size_t i = 0; i < NDNPH_TRANSPORT_RXQUEUELEN; ++i) {
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
    explicit RxContext(RxQueueMixin& transport)
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
    RxQueueMixin& m_transport;
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
  port::SafeQueue<RxQueueItem, NDNPH_TRANSPORT_RXQUEUELEN> m_allocQ;
  port::SafeQueue<RxQueueItem, NDNPH_TRANSPORT_RXQUEUELEN> m_rxQ;
};

/**
 * @brief Mixin of RX queue in Transport, allocating buffers from DynamicRegion.
 */
class DynamicRxQueueMixin : public RxQueueMixin
{
public:
  static constexpr size_t DEFAULT_BUFLEN = 1500;

protected:
  /**
   * @brief Constructor.
   * @param bufLen buffer length, typically MTU.
   */
  explicit DynamicRxQueueMixin(size_t bufLen = DEFAULT_BUFLEN)
    : m_region(sizeofSubRegions(bufLen, NDNPH_TRANSPORT_RXQUEUELEN))
  {
    this->initAllocBuffers([=] { return makeSubRegion(m_region, bufLen); });
  }

private:
  DynamicRegion m_region;
};

} // namespace transport
} // namespace ndnph

#endif // NDNPH_FACE_TRANSPORT_RXQUEUE_HPP
