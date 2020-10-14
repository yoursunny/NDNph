#if defined(NDNPH_FACE_FACE_HPP_END) && defined(NDNPH_FACE_PACKET_HANDLER_HPP_END)
#ifndef NDNPH_FACE_FACE_IMPL_INC
#define NDNPH_FACE_FACE_IMPL_INC

namespace ndnph {

inline bool
Face::addHandler(PacketHandler& h, int8_t prio)
{
  if (h.m_face != nullptr) {
    return false;
  }
  h.m_face = this;
  h.m_prio = prio;

  PacketHandler** next = &m_handler;
  for (; *next != nullptr && (*next)->m_prio < prio; next = &(*next)->m_next) {
  }
  h.m_next = *next;
  *next = &h;
  return true;
}

inline bool
Face::removeHandler(PacketHandler& h)
{
  if (h.m_face != this) {
    return false;
  }
  h.m_face = nullptr;

  for (PacketHandler** cur = &m_handler; *cur != nullptr; cur = &(*cur)->m_next) {
    if (*cur == &h) {
      *cur = h.m_next;
      return true;
    }
  }
  return false;
}

inline void
Face::loop()
{
  m_transport.loop();
  PacketHandler* next = nullptr;
  for (PacketHandler* h = m_handler; h != nullptr; h = next) {
    next = h->m_next;
    h->loop();
  }
}

inline void
Face::transportRx(void* self0, Region& region, const uint8_t* pkt, size_t pktLen,
                  uint64_t endpointId)
{
  Face& self = *reinterpret_cast<Face*>(self0);
  lp::PacketClassify classify;
  if (!Decoder(pkt, pktLen).decode(classify)) {
    return;
  }
  PacketInfo pi;
  pi.endpointId = endpointId;
  pi.pitToken = classify.getPitToken();
  ScopedCurrentPacketInfo piScoped(self, pi);

  switch (classify.getType()) {
    case lp::PacketClassify::Interest: {
      Interest interest = region.create<Interest>();
      if (interest && classify.decodeInterest(interest)) {
        self.process(&PacketHandler::processInterest, interest);
      }
      break;
    }
    case lp::PacketClassify::Data: {
      Data data = region.create<Data>();
      if (data && classify.decodeData(data)) {
        self.process(&PacketHandler::processData, data);
      }
      break;
    }
    case lp::PacketClassify::Nack: {
      Nack nack = region.create<Nack>();
      if (nack && classify.decodeNack(nack)) {
        self.process(&PacketHandler::processNack, nack);
      }
      break;
    }
  }
}

template<typename Packet, typename H>
bool
Face::process(H processPacket, Packet packet)
{
  bool isAccepted = false;
  PacketHandler* next = nullptr;
  for (PacketHandler* h = m_handler; h != nullptr && !isAccepted; h = next) {
    next = h->m_next;
    isAccepted = (h->*processPacket)(packet);
  }
  return isAccepted;
}

} // namespace ndnph

#endif // NDNPH_FACE_FACE_IMPL_INC
#endif // defined(NDNPH_FACE_FACE_HPP_END) && defined(NDNPH_FACE_PACKET_HANDLER_HPP_END)
