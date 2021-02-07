#ifndef NDNPH_FACE_FACE_HPP
#define NDNPH_FACE_FACE_HPP

#include "../packet/lp.hpp"
#include "transport.hpp"

namespace ndnph {

class PacketHandler;

/** @brief Network layer face. */
class Face
{
public:
  struct PacketInfo
  {
    uint64_t endpointId = 0;
    uint64_t pitToken = 0;
  };

  explicit Face(Transport& transport)
    : m_transport(transport)
  {
    m_transport.setRxCallback(transportRx, this);
  }

  Transport& getTransport() const
  {
    return m_transport;
  }

  /**
   * @brief Enable NDNLPv2 fragmentation.
   * @param frag fragmenter. It must be kept until face is destructed.
   *
   * If fragmentation is disabled (this function has not been invoked), the face would attempt to
   * transmit each outgoing packet in full. Oversized packets may be rejected by the transport.
   */
  void setFragmenter(lp::Fragmenter& frag)
  {
    m_frag = &frag;
  }

  /**
   * @brief Enable NDNLPv2 reassembly.
   * @param reass reassembler. It must be kept until face is destructed.
   *
   * If reassembly is disabled (this function has not been invoked), the face would drop
   * incoming fragments.
   *
   * @bug @c transportRx() is using a Region provided by the transport and sized to the MTU.
   *      When fragment size is near MTU, creating objects (e.g. @c DataObj ) in the Region would
   *      fail due to insufficient room. A refactoring is needed to have Face own a Region
   *      independent from transport.
   *      This bug could appear without reassembler, but is most prominent with a reassembler
   *      because larger packet sizes are often in use.
   */
  void setReassembler(lp::Reassembler& reass)
  {
    m_reass = &reass;
  }

  /**
   * @brief Add a packet handler.
   * @param prio priority, smaller number means higher priority.
   */
  bool addHandler(PacketHandler& h, int8_t prio = 0);

  /** @brief Remove a packet handler. */
  bool removeHandler(PacketHandler& h);

  /**
   * @brief Process periodical events.
   *
   * This must be invoked periodically.
   */
  void loop();

  const PacketInfo* getCurrentPacketInfo() const
  {
    return m_currentPacketInfo;
  }

  /**
   * @brief Synchronously transmit a packet.
   * @sa PacketHandler::send
   */
  template<typename Packet>
  bool send(Region& region, const Packet& packet, PacketInfo pi);

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

  static void transportRx(void* self, Region& region, const uint8_t* pkt, size_t pktLen,
                          uint64_t endpointId)
  {
    reinterpret_cast<Face*>(self)->transportRx(region, pkt, pktLen, endpointId);
  }

  void transportRx(Region& region, const uint8_t* pkt, size_t pktLen, uint64_t endpointId);

  template<typename Packet, typename H = bool (PacketHandler::*)(Packet)>
  bool process(H processPacket, Packet packet);

private:
  Transport& m_transport;
  lp::Fragmenter* m_frag = nullptr;
  lp::Reassembler* m_reass = nullptr;
  PacketHandler* m_handler = nullptr;
  const PacketInfo* m_currentPacketInfo = nullptr;
};

} // namespace ndnph

#define NDNPH_FACE_FACE_HPP_END
#include "face-impl.inc"
#include "packet-handler.hpp"

#endif // NDNPH_FACE_FACE_HPP
