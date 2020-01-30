#ifndef NDNPH_FACE_TRANSPORT_FORCE_ENDPOINTID_HPP
#define NDNPH_FACE_TRANSPORT_FORCE_ENDPOINTID_HPP

#include "transport.hpp"

namespace ndnph {
namespace transport {

/**
 * @brief Wrap another transport, overwriting endpointId of outgoing packets.
 *
 * One use case is to wrap a transport that is capable of both multicast and unicast,
 * and force every outgoing packets to be sent over multicast.
 */
class ForceEndpointId : public virtual Transport
{
public:
  explicit ForceEndpointId(Transport& inner, uint64_t endpointId = 0)
    : m_inner(inner)
    , m_endpointId(endpointId)
  {
    inner.setRxCallback(&ForceEndpointId::innerRx, this);
  }

private:
  static void innerRx(void* self0, Region& region, const uint8_t* pkt, size_t pktLen,
                      uint64_t endpointId)
  {
    ForceEndpointId& self = *reinterpret_cast<ForceEndpointId*>(self0);
    self.invokeRxCallback(region, pkt, pktLen, endpointId);
  }

  bool doIsUp() const final
  {
    return m_inner.isUp();
  }

  void doLoop() final
  {
    m_inner.loop();
  }

  bool doSend(const uint8_t* pkt, size_t pktLen, uint64_t) final
  {
    return m_inner.send(pkt, pktLen, m_endpointId);
  }

private:
  Transport& m_inner;
  uint64_t m_endpointId = 0;
};

} // namespace transport
} // namespace ndnph

#endif // NDNPH_FACE_TRANSPORT_FORCE_ENDPOINTID_HPP
