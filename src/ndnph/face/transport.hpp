#ifndef NDNPH_FACE_TRANSPORT_HPP
#define NDNPH_FACE_TRANSPORT_HPP

#include "../core/region.hpp"

namespace ndnph {

class Transport
{
public:
  virtual ~Transport() = default;

  virtual bool isUp() const = 0;

  virtual void loop() {}

  using RxCallback = void (*)(void* gctx, void* pctx, const uint8_t* pkt, ssize_t pktLen,
                              uint64_t endpointId);

  void setRxCallback(RxCallback cb, void* gctx)
  {
    m_rxCb = cb;
    m_rxCtx = gctx;
  }

  using TxCallback = void (*)(void* gctx, void* pctx, bool ok);

  void setTxCallback(TxCallback cb, void* gctx)
  {
    m_txCb = cb;
    m_txCtx = gctx;
  }

  virtual void asyncReceive(void* pctx, uint8_t* buf, size_t bufLen) = 0;

  virtual void asyncSend(void* pctx, const uint8_t* pkt, size_t pktLen,
                         uint64_t endpointId = 0) = 0;

protected:
  void invokeRxCallback(void* pctx, const uint8_t* pkt, ssize_t pktLen, uint64_t endpointId = 0)
  {
    m_rxCb(m_rxCtx, pctx, pkt, pktLen, endpointId);
  }

  void invokeTxCallback(void* pctx, bool ok)
  {
    m_txCb(m_txCtx, pctx, ok);
  }

private:
  RxCallback m_rxCb = nullptr;
  void* m_rxCtx = nullptr;
  TxCallback m_txCb = nullptr;
  void* m_txCtx = nullptr;
};

} // namespace ndnph

#endif // NDNPH_FACE_TRANSPORT_HPP
