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

template<typename Queue>
class RxQueueMixin : public virtual Transport
{
protected:
  using RxQueueMixinT = RxQueueMixin<Queue>;
  using RxQueueT = Queue;

  template<typename F>
  explicit RxQueueMixin(const F& makeQueue)
    : m_allocQ(makeQueue())
    , m_rxQ(makeQueue())
  {}

  template<typename F>
  void allocBuffers(const F& populate)
  {
    populate(m_allocQ);
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
        m_item.region->reset();
        m_bufLen = m_item.region->available();
        m_item.pkt = m_item.region->alloc(m_bufLen);
        m_item.pktLen = -1;
      }
    }

    ~RxContext()
    {
      if (m_item.region == nullptr) {
        return;
      }
      if (m_item.pktLen < 0) {
        m_transport.m_allocQ.push(m_item);
      } else {
        m_transport.m_rxQ.push(m_item);
      }
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
      m_item.region->reset();
      uint8_t* room = m_item.region->alloc(pktLen);
      std::memmove(room, m_item.pkt, pktLen);
      m_item.pkt = room;
    }

  private:
    TransportT& m_transport;
    RxQueueItem m_item;
    size_t m_bufLen;
  };

  RxContext receiving()
  {
    return RxContext(*this);
  }

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
};

class DynamicRxQueueMixin : public RxQueueMixin<DynamicSimpleQueue<RxQueueItem>>
{
protected:
  explicit DynamicRxQueueMixin(size_t nBuffers = 4, size_t bufLen = 1500)
    : RxQueueMixinT([nBuffers] { return RxQueueT(nBuffers); })
    , m_region(sizeofSubRegions(bufLen, nBuffers))
  {
    allocBuffers([this, bufLen](RxQueueT& allocQ) {
      while (Region* sub = makeSubRegion(m_region, bufLen)) {
        RxQueueItem item;
        item.region = sub;
        allocQ.push(item);
      }
    });
  }

private:
  DynamicRegion m_region;
};

} // namespace transport
} // namespace ndnph

#endif // NDNPH_FACE_TRANSPORT_RXQUEUE_HPP
