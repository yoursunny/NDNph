#ifndef NDNPH_FACE_TRANSPORT_HPP
#define NDNPH_FACE_TRANSPORT_HPP

#include "../core/region.hpp"

namespace ndnph {
namespace transport {

/** @brief Base class of low-level transport. */
class Transport {
public:
  virtual ~Transport() = default;

  /** @brief Determine whether transport is connected. */
  bool isUp() const {
    return doIsUp();
  }

  /** @brief Process periodical events, such as receiving packets. */
  void loop() {
    doLoop();
  }

  using RxCallback = void (*)(void* ctx, const uint8_t* pkt, size_t pktLen, uint64_t endpointId);

  /** @brief Set incoming packet callback. */
  void setRxCallback(RxCallback cb, void* ctx) {
    m_rxCb = cb;
    m_rxCtx = ctx;
  }

  /** @brief Synchronously transmit a packet. */
  bool send(const uint8_t* pkt, size_t pktLen, uint64_t endpointId = 0) {
    return doSend(pkt, pktLen, endpointId);
  }

protected:
  /** @brief Invoke incoming packet callback for a received packet. */
  void invokeRxCallback(const uint8_t* pkt, size_t pktLen, uint64_t endpointId = 0) {
    m_rxCb(m_rxCtx, pkt, pktLen, endpointId);
  }

private:
  virtual bool doIsUp() const = 0;

  virtual void doLoop() = 0;

  virtual bool doSend(const uint8_t* pkt, size_t pktLen, uint64_t endpointId) = 0;

private:
  RxCallback m_rxCb = nullptr;
  void* m_rxCtx = nullptr;
};

/**
 * @brief Wrap another transport.
 *
 * This class passes every call to the inner Transport. It should be inherited, and some functions
 * can be overridden to achieve custom behavior.
 */
class TransportWrap : public virtual Transport {
protected:
  explicit TransportWrap(Transport& inner)
    : inner(inner) {
    inner.setRxCallback(&TransportWrap::innerRx, this);
  }

private:
  static void innerRx(void* self, const uint8_t* pkt, size_t pktLen, uint64_t endpointId) {
    reinterpret_cast<TransportWrap*>(self)->handleRx(pkt, pktLen, endpointId);
  }

  virtual void handleRx(const uint8_t* pkt, size_t pktLen, uint64_t endpointId) {
    invokeRxCallback(pkt, pktLen, endpointId);
  }

  bool doIsUp() const override {
    return inner.isUp();
  }

  void doLoop() override {
    inner.loop();
  }

  bool doSend(const uint8_t* pkt, size_t pktLen, uint64_t endpointId) override {
    return inner.send(pkt, pktLen, endpointId);
  }

protected:
  Transport& inner;
};

} // namespace transport

using Transport = transport::Transport;

} // namespace ndnph

#endif // NDNPH_FACE_TRANSPORT_HPP
