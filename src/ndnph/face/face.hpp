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
                          uint64_t endpointId);

  template<typename Packet, typename H = bool (PacketHandler::*)(Packet)>
  bool process(H processPacket, Packet packet);

private:
  Transport& m_transport;
  PacketHandler* m_handler = nullptr;
  const PacketInfo* m_currentPacketInfo = nullptr;
};

} // namespace ndnph

#define NDNPH_FACE_FACE_HPP_END
#include "face-impl.inc"
#include "packet-handler.hpp"

#endif // NDNPH_FACE_FACE_HPP
