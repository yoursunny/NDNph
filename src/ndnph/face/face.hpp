#ifndef NDNPH_FACE_FACE_HPP
#define NDNPH_FACE_FACE_HPP

#include "../an.hpp"
#include "../tlv/decoder.hpp"
#include "../tlv/encoder.hpp"
#include "packet-handler.hpp"
#include "transport.hpp"

namespace ndnph {

template<typename PktTypes>
class BasicFace
{
public:
  using Face = BasicFace<PktTypes>;
  using PacketHandler = BasicPacketHandler<PktTypes>;
  using Interest = typename PktTypes::Interest;
  using Data = typename PktTypes::Data;

  explicit BasicFace(Transport& transport)
    : m_transport(transport)
  {
    m_transport.setRxCallback(transportRx, this);
  }

  bool addHandler(PacketHandler& h, int8_t prio = 0)
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

  bool removeHandler(PacketHandler& h)
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

  void loop()
  {
    m_transport.loop();
  }

  /**
   * @brief Synchronously transmit a packet, keeping wire encoding in Encoder.
   * @tparam Packet an Encodable type
   * @return whether success
   */
  template<typename Packet>
  bool send(Encoder& encoder, const Packet& packet, uint64_t endpointId = 0)
  {
    return encoder.prepend(packet) && m_transport.send(encoder.begin(), encoder.size(), endpointId);
  }

  /**
   * @brief Synchronously transmit a packet.
   * @tparam Packet Interest, Data, or their signed variants
   * @return whether success
   */
  template<typename Packet>
  bool send(const Packet& packet, uint64_t endpointId = 0)
  {
    Region& region = regionOf(packet);
    Encoder encoder(region);
    bool ok = send(encoder, packet, endpointId);
    encoder.discard();
    return ok;
  }

private:
  static void transportRx(void* self0, Region& region, const uint8_t* pkt, size_t pktLen,
                          uint64_t endpointId)
  {
    Face& self = *reinterpret_cast<Face*>(self0);
    Decoder::Tlv d;
    if (!Decoder::readTlv(d, pkt, pkt + pktLen)) {
      return;
    }

    switch (d.type) {
      case TT::Interest: {
        Interest interest = region.create<Interest>();
        if (!!interest && interest.decodeFrom(d)) {
          self.process(&PacketHandler::processInterest, interest, endpointId);
        }
        break;
      }
      case TT::Data: {
        Data data = region.create<Data>();
        if (!!data && data.decodeFrom(d)) {
          self.process(&PacketHandler::processData, data, endpointId);
        }
        break;
      }
    }
  }

  template<typename Packet, typename H = bool (PacketHandler::*)(Packet, uint64_t)>
  bool process(H processPacket, Packet packet, uint64_t endpointId)
  {
    bool isAccepted = false;
    for (PacketHandler* h = m_handler; h != nullptr && !isAccepted; h = h->m_next) {
      isAccepted = (h->*processPacket)(packet, endpointId);
    }
    return isAccepted;
  }

private:
  Transport& m_transport;
  PacketHandler* m_handler = nullptr;
};

} // namespace ndnph

#endif // NDNPH_FACE_FACE_HPP
