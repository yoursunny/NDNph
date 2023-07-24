#ifndef NDNPH_FACE_FACE_HPP
#define NDNPH_FACE_FACE_HPP

#include "../packet/lp.hpp"
#include "transport.hpp"

namespace ndnph {

class PacketHandler;

/** @brief Network layer face. */
class Face : public WithRegion {
public:
  struct PacketInfo {
    uint64_t endpointId = 0;
    lp::PitToken pitToken;
  };

  /**
   * @brief Constructor.
   * @param region where to allocate memory for packet objects (e.g. @c DataObj ) during RX.
   *               This region may be shared among multiple faces, but cannot be shared with
   *               the fragmenter or reassembler associated with this face.
   *               Face does not use this region for packet buffers, but it is passed to
   *               @c PacketHandler processing functions. If a packet processing function
   *               creates a new packet in this region and transmits that packet, that packet
   *               would be temporarily encoded in this region during TX.
   * @param transport underlying transport.
   */
  explicit Face(Region& region, Transport& transport)
    : WithRegion(region)
    , m_transport(transport) {
    m_transport.setRxCallback(transportRx, this);
  }

  explicit Face(Transport& transport)
    : Face(*new OwnRegion(), transport) {
    m_ownRegion.reset(static_cast<OwnRegion*>(&region));
  }

  /** @brief Access the underlying transport. */
  Transport& getTransport() const {
    return m_transport;
  }

  /**
   * @brief Enable NDNLPv2 fragmentation.
   * @param frag fragmenter. It must be kept until face is destructed.
   *
   * If fragmentation is disabled (this function has not been invoked), the face would attempt to
   * transmit each outgoing packet in full. Oversized packets may be rejected by the transport.
   */
  void setFragmenter(lp::Fragmenter& frag) {
    m_frag = &frag;
  }

  /**
   * @brief Enable NDNLPv2 reassembly.
   * @param reass reassembler. It must be kept until face is destructed.
   *
   * If reassembly is disabled (this function has not been invoked), the face would drop
   * incoming fragments.
   */
  void setReassembler(lp::Reassembler& reass) {
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

  const PacketInfo* getCurrentPacketInfo() const {
    return m_currentPacketInfo;
  }

  /**
   * @brief Synchronously transmit a packet.
   * @sa PacketHandler::send
   */
  template<typename Packet>
  bool send(Region& region, const Packet& packet, PacketInfo pi);

private:
  class ScopedCurrentPacketInfo {
  public:
    explicit ScopedCurrentPacketInfo(Face& face, PacketInfo& pi)
      : m_face(face) {
      m_face.m_currentPacketInfo = &pi;
    }

    ~ScopedCurrentPacketInfo() {
      m_face.m_currentPacketInfo = nullptr;
    }

  private:
    Face& m_face;
  };

  static void transportRx(void* self, const uint8_t* pkt, size_t pktLen, uint64_t endpointId) {
    reinterpret_cast<Face*>(self)->transportRx(pkt, pktLen, endpointId);
  }

  void transportRx(const uint8_t* pkt, size_t pktLen, uint64_t endpointId);

  template<typename Packet, typename H = bool (PacketHandler::*)(Packet)>
  bool process(H processPacket, Packet packet);

private:
  using OwnRegion = StaticRegion<2048>;
  std::unique_ptr<OwnRegion> m_ownRegion;
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
