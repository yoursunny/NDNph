#ifndef NDNPH_FACE_FACE_HPP
#define NDNPH_FACE_FACE_HPP

#include "packet-handler.hpp"
#include "transport.hpp"

namespace ndnph {

/**
 * @class Face
 * @brief Network layer face.
 */
/**
 * @brief Network layer face.
 * @tparam PktTypes declaration of packet types.
 * @note A port is expected to typedef this template as `Face` type.
 */
template<typename PktTypes>
class BasicFace
{
public:
  using Face = BasicFace<PktTypes>;
  using PacketHandler = BasicPacketHandler<PktTypes>;
  using Interest = typename PktTypes::Interest;
  using Data = typename PktTypes::Data;
  using Nack = typename PktTypes::Nack;

  struct PacketInfo
  {
    uint64_t endpointId = 0;
    uint64_t pitToken = 0;
  };

  explicit BasicFace(Transport& transport)
    : m_transport(transport)
  {
    m_transport.setRxCallback(transportRx, this);
  }

  Transport& getTransport() const
  {
    return m_transport;
  }

  /**
   * @brief Add a packet handler.
   * @param prio priority, smaller number means higher priority.
   */
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

  /** @brief Remove a packet handler. */
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

  /**
   * @brief Process periodical events.
   *
   * This must be invoked periodically.
   */
  void loop()
  {
    m_transport.loop();
  }

  const PacketInfo* getCurrentPacketInfo() const
  {
    return m_currentPacketInfo;
  }

private:
  class ScopedCurrentPacketInfo
  {
  public:
    explicit ScopedCurrentPacketInfo(Face& face, PacketInfo& pi)
      : m_face(face)
    {
      m_face.m_currentPacketInfo = &pi;
    }

    ~ScopedCurrentPacketInfo()
    {
      m_face.m_currentPacketInfo = nullptr;
    }

  private:
    Face& m_face;
  };

  static void transportRx(void* self0, Region& region, const uint8_t* pkt, size_t pktLen,
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
        if (!!interest && classify.decodeInterest(interest)) {
          self.process(&PacketHandler::processInterest, interest);
        }
        break;
      }
      case lp::PacketClassify::Data: {
        Data data = region.create<Data>();
        if (!!data && classify.decodeData(data)) {
          self.process(&PacketHandler::processData, data);
        }
        break;
      }
      case lp::PacketClassify::Nack: {
        Nack nack = region.create<Nack>();
        if (!!nack && classify.decodeNack(nack)) {
          self.process(&PacketHandler::processNack, nack);
        }
        break;
      }
    }
  }

  template<typename Packet, typename H = bool (PacketHandler::*)(Packet)>
  bool process(H processPacket, Packet packet)
  {
    bool isAccepted = false;
    for (PacketHandler* h = m_handler; h != nullptr && !isAccepted; h = h->m_next) {
      isAccepted = (h->*processPacket)(packet);
    }
    return isAccepted;
  }

private:
  Transport& m_transport;
  PacketHandler* m_handler = nullptr;
  const PacketInfo* m_currentPacketInfo = nullptr;
};

} // namespace ndnph

#endif // NDNPH_FACE_FACE_HPP
