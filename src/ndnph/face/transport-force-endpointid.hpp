#ifndef NDNPH_FACE_TRANSPORT_FORCE_ENDPOINTID_HPP
#define NDNPH_FACE_TRANSPORT_FORCE_ENDPOINTID_HPP

#include "transport.hpp"

namespace ndnph {
namespace transport {

/**
 * @brief Overwrite endpointId of outgoing packets.
 *
 * One use case is to wrap a transport that is capable of both multicast and unicast,
 * and force every outgoing packet to be sent over multicast.
 */
class ForceEndpointId : public TransportWrap
{
public:
  explicit ForceEndpointId(Transport& inner, uint64_t endpointId = 0)
    : TransportWrap(inner)
    , m_endpointId(endpointId)
  {}

private:
  bool doSend(const uint8_t* pkt, size_t pktLen, uint64_t) final
  {
    return inner.send(pkt, pktLen, m_endpointId);
  }

private:
  uint64_t m_endpointId;
};

} // namespace transport
} // namespace ndnph

#endif // NDNPH_FACE_TRANSPORT_FORCE_ENDPOINTID_HPP
