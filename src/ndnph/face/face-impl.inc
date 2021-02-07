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

template<typename Packet>
inline bool
Face::send(Region& region, const Packet& packet, PacketInfo pi)
{
  auto lpp = lp::encode(packet, pi.pitToken);
  if (m_frag == nullptr) {
    ScopedEncoder encoder(region);
    return encoder.prepend(lpp) && m_transport.send(encoder.begin(), encoder.size(), pi.endpointId);
  }

  if (m_reass != nullptr && &regionOf(m_reass) == &regionOf(m_frag)) {
    m_reass->discard();
  }
  auto frag = m_frag->fragment(lpp);
  if (frag == nullptr) {
    return false;
  }

  for (; frag != nullptr; frag = frag->next) {
    ScopedEncoder encoder(region);
    bool ok =
      encoder.prepend(*frag) && m_transport.send(encoder.begin(), encoder.size(), pi.endpointId);
    if (!ok) {
      return false;
    }
  }
  return true;
}

inline void
Face::transportRx(const uint8_t* pkt, size_t pktLen, uint64_t endpointId)
{
  region.reset();
  using PT = lp::PacketClassify::Type;

  lp::PacketClassify classify;
  if (!Decoder(pkt, pktLen).decode(classify)) {
    return;
  }

  if (classify.getType() == PT::Fragment && m_reass != nullptr) {
    m_reass->add(classify.getFragment());
    classify = m_reass->reassemble();
  }

  PacketInfo pi;
  pi.endpointId = endpointId;
  pi.pitToken = classify.getPitToken();
  ScopedCurrentPacketInfo piScoped(*this, pi);

  switch (classify.getType()) {
    case PT::Interest: {
      Interest interest = region.create<Interest>();
      if (interest && classify.decodeInterest(interest)) {
        process(&PacketHandler::processInterest, interest);
      }
      break;
    }
    case PT::Data: {
      Data data = region.create<Data>();
      if (data && classify.decodeData(data)) {
        process(&PacketHandler::processData, data);
      }
      break;
    }
    case PT::Nack: {
      Nack nack = region.create<Nack>();
      if (nack && classify.decodeNack(nack)) {
        process(&PacketHandler::processNack, nack);
      }
      break;
    }
    case PT::None:
    case PT::Fragment: {
      // reassembler unavailable or reassembled as invalid packet
      return;
    }
  }

  if (m_reass != nullptr) {
    m_reass->discard();
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
