#ifndef NDNPH_FACE_FACE_HPP
#define NDNPH_FACE_FACE_HPP

#include "../tlv/decoder.hpp"
#include "../tlv/encoder.hpp"
#include "transport.hpp"

namespace ndnph {

class Face
{
public:
  explicit Face(Transport& transport, size_t mtu = 1500)
    : m_transport(transport)
    , m_mtu(mtu)
  {
    m_transport.setRxCallback(transportRxCallback, this);
    m_transport.setTxCallback(transportTxCallback, this);
  }

  void loop()
  {
    m_transport.loop();
  }

  using RxSuccessCallback = void (*)(void* gctx, void* pctx, Decoder& decoder, uint64_t endpointId);
  using RxFailureCallback = void (*)(void* gctx, void* pctx);

  void setRxCallback(RxSuccessCallback successCb, RxFailureCallback failureCb, void* gctx)
  {
    m_rxSuccessCb = successCb;
    m_rxFailureCb = failureCb;
    m_rxCtx = gctx;
  }

  using TxCallback = void (*)(void* gctx, void* pctx, bool ok);

  void setTxCallback(TxCallback cb, void* gctx)
  {
    m_txCb = cb;
    m_txCtx = gctx;
  }

  void asyncReceive(void* pctx, Region& region)
  {
    RxCtx* ctx = region.make<RxCtx>();
    if (ctx == nullptr) {
      m_rxFailureCb(m_rxCtx, pctx);
      return;
    }
    ctx->pctx = pctx;
    ctx->region = &region;

    ctx->bufLen = std::min(region.available(), m_mtu);
    ctx->buf = region.alloc(ctx->bufLen);
    if (ctx->buf == nullptr) {
      m_rxFailureCb(m_rxCtx, pctx);
      return;
    }

    m_transport.asyncReceive(ctx, ctx->buf, ctx->bufLen);
  }

  template<typename Packet>
  void asyncSend(void* pctx, const Packet& packet, uint64_t endpointId = 0)
  {
    Region& region = regionOf(packet);
    TxCtx* ctx = region.make<TxCtx>();
    if (ctx == nullptr) {
      m_txCb(m_txCtx, pctx, false);
      return;
    }
    ctx->pctx = pctx;

    Encoder encoder(region);
    if (!encoder.prepend(packet)) {
      encoder.discard();
      m_txCb(m_txCtx, pctx, false);
      return;
    }
    encoder.trim();

    m_transport.asyncSend(ctx, encoder.begin(), encoder.size(), endpointId);
  }

private:
  struct RxCtx
  {
    void* pctx = nullptr;
    Region* region = nullptr;
    uint8_t* buf = nullptr;
    size_t bufLen = 0;
  };

  static void transportRxCallback(void* self0, void* ctx0, const uint8_t* pkt, ssize_t pktLen,
                                  uint64_t endpointId)
  {
    Face& self = *reinterpret_cast<Face*>(self0);
    RxCtx& ctx = *reinterpret_cast<RxCtx*>(ctx0);
    if (pktLen < 0) {
      self.m_rxFailureCb(self.m_rxCtx, ctx.pctx);
      return;
    }

    uint8_t* buf = ctx.buf + ctx.bufLen - pktLen;
    if (buf > pkt) {
      // TODO allocate at front of Region to avoid copying
      std::copy_backward(pkt, pkt + pktLen, buf + pktLen);
      ctx.region->free(ctx.buf, buf - pkt);
      pkt = buf;
    }

    Decoder decoder(pkt, pktLen);
    self.m_rxSuccessCb(self.m_rxCtx, ctx.pctx, decoder, endpointId);
  }

  struct TxCtx
  {
    void* pctx = nullptr;
  };

  static void transportTxCallback(void* self0, void* ctx0, bool ok)
  {
    Face& self = *reinterpret_cast<Face*>(self0);
    TxCtx& ctx = *reinterpret_cast<TxCtx*>(ctx0);
    self.m_txCb(self.m_txCtx, ctx.pctx, ok);
  }

private:
  Transport& m_transport;
  RxSuccessCallback m_rxSuccessCb = nullptr;
  RxFailureCallback m_rxFailureCb = nullptr;
  void* m_rxCtx = nullptr;
  TxCallback m_txCb = nullptr;
  void* m_txCtx = nullptr;
  size_t m_mtu = 0;
};

} // namespace ndnph

#endif // NDNPH_FACE_FACE_HPP
