#ifndef NDNPH_FACE_TRANSPORT_HPP
#define NDNPH_FACE_TRANSPORT_HPP

#include "../core/region.hpp"

namespace ndnph {
namespace transport {

class Transport
{
public:
  virtual ~Transport() = default;

  virtual bool isUp() const
  {
    return doIsUp();
  }

  virtual void loop()
  {
    doLoop();
  }

  using RxCallback = void (*)(void* ctx, Region& region, const uint8_t* pkt, size_t pktLen,
                              uint64_t endpointId);

  void setRxCallback(RxCallback cb, void* ctx)
  {
    m_rxCb = cb;
    m_rxCtx = ctx;
  }

  bool send(const uint8_t* pkt, size_t pktLen, uint64_t endpointId = 0)
  {
    return doSend(pkt, pktLen, endpointId);
  }

protected:
  void invokeRxCallback(Region& region, const uint8_t* pkt, size_t pktLen, uint64_t endpointId = 0)
  {
    m_rxCb(m_rxCtx, region, pkt, pktLen, endpointId);
  }

private:
  virtual bool doIsUp() const = 0;

  virtual void doLoop() = 0;

  virtual bool doSend(const uint8_t* pkt, size_t pktLen, uint64_t endpointId) = 0;

private:
  RxCallback m_rxCb = nullptr;
  void* m_rxCtx = nullptr;
};

} // namespace transport

using Transport = transport::Transport;

} // namespace ndnph

#endif // NDNPH_FACE_TRANSPORT_HPP
