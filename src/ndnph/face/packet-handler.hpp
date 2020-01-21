#ifndef NDNPH_FACE_PACKET_HANDLER_HPP
#define NDNPH_FACE_PACKET_HANDLER_HPP

#include "../core/common.hpp"

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

  /** @brief Transmit a packet. */
  template<typename... Arg>
  bool send(Arg... arg)
  {
    return m_face != nullptr && m_face->send(std::forward<Arg>(arg)...);
  }

private:
  /**
   * @brief Override to receive Interest packets.
   * @retval true packet has been accepted by this handler.
   * @retval false packet is not accepted, and should go to the next handler.
   */
  virtual bool processInterest(Interest interest, uint64_t endpointId)
  {
    (void)interest;
    (void)endpointId;
    return false;
  }

  /**
   * @brief Override to receive Data packets.
   * @retval true packet has been accepted by this handler.
   * @retval false packet is not accepted, and should go to the next handler.
   */
  virtual bool processData(Data data, uint64_t endpointId)
  {
    (void)data;
    (void)endpointId;
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
