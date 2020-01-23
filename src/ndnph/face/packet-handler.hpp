#ifndef NDNPH_FACE_PACKET_HANDLER_HPP
#define NDNPH_FACE_PACKET_HANDLER_HPP

#include "../core/common.hpp"
#include "../packet/lp.hpp"

namespace ndnph {

template<typename PktTypes>
class BasicFace;

/**
 * @class PacketHandler
 * @brief Base class to receive packets from Face.
 */
/**
 * @brief Base class to receive packets from Face.
 * @tparam PktTypes declaration of packet types.
 * @note A port is expected to typedef this template as `PacketHandler` type.
 */
template<typename PktTypes>
class BasicPacketHandler
{
protected:
  using Face = BasicFace<PktTypes>;
  using PacketHandler = BasicPacketHandler<PktTypes>;
  using Interest = typename PktTypes::Interest;
  using Data = typename PktTypes::Data;
  using Nack = typename PktTypes::Nack;
  using PacketInfo = typename Face::PacketInfo;

  /** @brief Construct without adding to Face. */
  explicit BasicPacketHandler() = default;

  /** @brief Construct and add handler to Face. */
  explicit BasicPacketHandler(Face& face, int8_t prio = 0);

  /** @brief Remove handler from Face. */
  virtual ~BasicPacketHandler();

  Face* getFace() const
  {
    return m_face;
  }

  /**
   * @brief Retrieve information about current processing packet.
   * @pre one of processInterest, processData, or processNack is executing.
   */
  PacketInfo* getCurrentPacketInfo() const
  {
    return m_face == nullptr ? nullptr : m_face->getCurrentPacketInfo();
  }

  /**
   * @brief Synchronously transmit a packet.
   * @tparam Packet Interest, Data, their signed variants, or Nack.
   * @return whether success.
   * @post if successful, wire encoding is kept in encoder.
   */
  template<typename Packet>
  bool send(Encoder& encoder, const Packet& packet, PacketInfo pi = {})
  {
    return m_face != nullptr && encoder.prepend(lp::encode(packet, pi.pitToken)) &&
           m_face->getTransport().send(encoder.begin(), encoder.size(), pi.endpointId);
  }

  /** @brief Synchronously transmit a packet. */
  template<typename Packet>
  bool send(const Packet& packet, PacketInfo pi = {})
  {
    Region& region = regionOf(packet);
    Encoder encoder(region);
    bool ok = send(encoder, packet, pi);
    encoder.discard();
    return ok;
  }

  /**
   * @brief Synchronously transmit a packet in reply to current processing packet.
   * @pre one of processInterest, processData, or processNack is executing.
   *
   * Parameters: same as send() except PacketInfo.
   * This is most useful in processInterest, replying a Data or Nack to the same endpointId
   * and copying the PIT token from current processing Interest.
   */
  template<typename... Arg>
  bool reply(Arg&&... arg)
  {
    PacketInfo* pi = getCurrentPacketInfo();
    return pi != nullptr && send(std::forward<Arg>(arg)..., *pi);
  }

private:
  /**
   * @brief Override to receive Interest packets.
   * @retval true packet has been accepted by this handler.
   * @retval false packet is not accepted, and should go to the next handler.
   */
  virtual bool processInterest(Interest)
  {
    return false;
  }

  /**
   * @brief Override to receive Data packets.
   * @retval true packet has been accepted by this handler.
   * @retval false packet is not accepted, and should go to the next handler.
   */
  virtual bool processData(Data)
  {
    return false;
  }

  /**
   * @brief Override to receive Nack packets.
   * @retval true packet has been accepted by this handler.
   * @retval false packet is not accepted, and should go to the next handler.
   */
  virtual bool processNack(Nack)
  {
    return false;
  }

private:
  Face* m_face = nullptr;
  PacketHandler* m_next = nullptr;
  int8_t m_prio = 0;
  friend Face;
};

} // namespace ndnph

#include "face.hpp"

namespace ndnph {

template<typename PktTypes>
BasicPacketHandler<PktTypes>::BasicPacketHandler(Face& face, int8_t prio)
{
  face.addHandler(*this, prio);
}

template<typename PktTypes>
BasicPacketHandler<PktTypes>::~BasicPacketHandler()
{
  if (m_face != nullptr) {
    m_face->removeHandler(*this);
  }
}

} // namespace ndnph

#endif // NDNPH_FACE_PACKET_HANDLER_HPP
