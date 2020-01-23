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
public:
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

protected:
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

  /** @brief Set EndpointId of PacketInfo. */
  class WithEndpointId
  {
  public:
    explicit WithEndpointId(uint64_t endpointId)
      : endpointId(endpointId)
    {}

    void operator()(PacketInfo& pi) const
    {
      pi.endpointId = endpointId;
    }

  public:
    uint64_t endpointId = 0;
  };

  /** @brief Set PIT token of PacketInfo. */
  class WithPitToken
  {
  public:
    explicit WithPitToken(uint64_t pitToken)
      : pitToken(pitToken)
    {}

    void operator()(PacketInfo& pi) const
    {
      pi.pitToken = pitToken;
    }

  public:
    uint64_t pitToken = 0;
  };

  /**
   * @brief Synchronously transmit a packet.
   * @tparam PacketInfoModifier WithEndpointId or WithPitToken
   */
  template<typename Packet, typename... PacketInfoModifier>
  bool send(Encoder& encoder, const Packet& packet, const PacketInfoModifier&... pim)
  {
    return send(encoder, packet, PacketInfo(), pim...);
  }

  /**
   * @brief Synchronously transmit a packet.
   * @tparam Arg either a sequence of `PacketInfoModifier` or `PacketInfo`.
   *
   * @code
   * send(interest);
   * send(interest, WithEndpointId(4688));
   * send(interest, WithPitToken(0x013CA61E013F0B7A), WithEndpointId(4688));
   * send(interest, myPacketInfo);
   * @endcode
   */
  template<typename Packet, typename... Arg,
           typename = typename std::enable_if<
             !std::is_same<Encoder, typename std::decay<Packet>::type>::value>::type>
  bool send(const Packet& packet, Arg&&... arg)
  {
    Region& region = regionOf(packet);
    Encoder encoder(region);
    bool ok = send(encoder, packet, std::forward<Arg>(arg)...);
    encoder.discard();
    return ok;
  }

  /**
   * @brief Synchronously transmit a packet in reply to current processing packet.
   * @pre one of processInterest, processData, or processNack is executing.
   * @param arg either `Encoder&, const Packet&` or `const Packet&`.
   *
   * This is most useful in processInterest, replying a Data or Nack carrying the PIT token of
   * current Interest to the endpointId of current Interest.
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

  template<typename Packet, typename PimFirst, typename... PimRest>
  bool send(Encoder& encoder, const Packet& packet, PacketInfo pi, const PimFirst& pimFirst,
            const PimRest&... pimRest)
  {
    pimFirst(pi);
    return send(encoder, packet, pi, pimRest...);
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
