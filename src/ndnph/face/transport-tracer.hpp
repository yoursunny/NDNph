#ifndef NDNPH_FACE_TRANSPORT_TRACER_HPP
#define NDNPH_FACE_TRANSPORT_TRACER_HPP

#include "../core/log.hpp"
#include "transport.hpp"

namespace ndnph {
namespace transport {

/** @brief Print trace logs for each incoming and outgoing packet. */
class Tracer : public TransportWrap
{
public:
  explicit Tracer(Transport& inner, const char* category = "transport")
    : TransportWrap(inner)
    , category(category)
  {}

private:
  virtual void log(char direction, const uint8_t* pkt, size_t pktLen, uint64_t endpointId)
  {
    (void)pkt;
    (void)endpointId;
    NDNPH_LOG_LINE("%s", "%c len=%zu", category, direction, pktLen);
  }

  void handleRx(const uint8_t* pkt, size_t pktLen, uint64_t endpointId) override
  {
    log('>', pkt, pktLen, endpointId);
    invokeRxCallback(pkt, pktLen, endpointId);
  }

  bool doSend(const uint8_t* pkt, size_t pktLen, uint64_t endpointId) override
  {
    log('<', pkt, pktLen, endpointId);
    return inner.send(pkt, pktLen, endpointId);
  }

protected:
  const char* category;
};

} // namespace transport
} // namespace ndnph

#endif // NDNPH_FACE_TRANSPORT_TRACER_HPP
