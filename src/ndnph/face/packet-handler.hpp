#ifndef NDNPH_FACE_PACKET_HANDLER_HPP
#define NDNPH_FACE_PACKET_HANDLER_HPP

#include "../port/clock/port.hpp"
#include "face.hpp"

namespace ndnph {

/** @brief Base class to receive packets from Face. */
class PacketHandler
{
public:
  using PacketInfo = Face::PacketInfo;

  /** @brief Construct without adding to Face. */
  explicit PacketHandler() = default;

  /** @brief Construct and add handler to Face. */
  explicit PacketHandler(Face& face, int8_t prio = 0)
  {
    face.addHandler(*this, prio);
  }

protected:
  /** @brief Remove handler from Face. */
  virtual ~PacketHandler()
  {
    if (m_face != nullptr) {
      m_face->removeHandler(*this);
    }
  }

  Face* getFace() const
  {
    return m_face;
  }

  /**
   * @brief Retrieve information about current processing packet.
   * @pre one of processInterest, processData, or processNack is executing.
   */
  const PacketInfo* getCurrentPacketInfo() const
  {
    return m_face == nullptr ? nullptr : m_face->getCurrentPacketInfo();
  }

  /**
   * @brief Synchronously transmit a packet.
   * @tparam Packet Interest, Data, their signed variants, or Nack.
   * @param region where to allocate temporary memory for packet encoding.
   * @return whether success.
   */
  template<typename Packet>
  bool send(Region& region, const Packet& packet, PacketInfo pi = {})
  {
    return m_face != nullptr && m_face->send(region, packet, pi);
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
   * @tparam Packet Interest, Data, their signed variants, or Nack.
   * @tparam PacketInfoModifier WithEndpointId or WithPitToken
   */
  template<typename Packet, typename... PacketInfoModifier>
  bool send(Region& region, const Packet& packet, const PacketInfoModifier&... pim)
  {
    return send(region, packet, PacketInfo(), pim...);
  }

  /**
   * @brief Synchronously transmit a packet.
   * @tparam Packet Interest, Data, their signed variants, or Nack.
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
             !std::is_base_of<Region, typename std::decay<Packet>::type>::value>::type>
  bool send(const Packet& packet, Arg&&... arg)
  {
    return send(regionOf(packet), packet, std::forward<Arg>(arg)...);
  }

  /**
   * @brief Synchronously transmit a packet in reply to current processing packet.
   * @pre one of processInterest, processData, or processNack is executing.
   * @param arg either `Region&, const Packet&` or `const Packet&`.
   *
   * This is most useful in processInterest, replying a Data or Nack carrying the PIT token of
   * current Interest to the endpointId of current Interest.
   */
  template<typename... Arg>
  bool reply(Arg&&... arg)
  {
    const PacketInfo* pi = getCurrentPacketInfo();
    return pi != nullptr && send(std::forward<Arg>(arg)..., *pi);
  }

  /** @brief Helper to keep track an outgoing pending Interest. */
  class OutgoingPendingInterest
  {
  public:
    OutgoingPendingInterest(PacketHandler* ph)
      : m_ph(*ph)
    {
      port::RandomSource::generate(reinterpret_cast<uint8_t*>(&m_pitToken), sizeof(m_pitToken));
      m_expire = port::Clock::now();
    }

    /**
     * @brief Send an Interest.
     * @tparam Packet @c Interest or its parameterized / signed variant.
     * @param interest the Interest.
     * @param timeout timeout in milliseconds. Default is InterestLifetime.
     * @param arg other arguments to @c PacketHandler::send() .
     */
    template<typename Packet, typename... Arg>
    bool send(const Packet& interest, int timeout, Arg&&... arg)
    {
      m_expire = ndnph::port::Clock::add(ndnph::port::Clock::now(), timeout);
      return m_ph.send(interest, WithPitToken(++m_pitToken), std::forward<Arg>(arg)...);
    }

    template<typename Packet>
    bool send(const Packet& interest)
    {
      return send(interest, interest.getLifetime());
    }

    template<typename Packet, typename ArgFirst, typename... Arg,
             typename = typename std::enable_if<!std::is_integral<ArgFirst>::value>::type>
    bool send(const Packet& interest, ArgFirst&& arg1, Arg&&... arg)
    {
      return send(interest, interest.getLifetime(), std::forward<ArgFirst>(arg1),
                  std::forward<Arg>(arg)...);
    }

    /**
     * @brief Compare PIT token of current incoming packet against last outgoing Interest.
     * @pre one of processInterest, processData, or processNack is executing.
     *
     * Comparing PIT token alone is unreliable because PIT token is not guaranteed to be unique.
     * If the application has saved a copy of the outgoing Interest or its name, it's
     * recommended to use @c match() instead.
     */
    bool matchPitToken() const
    {
      auto pi = m_ph.getCurrentPacketInfo();
      return pi != nullptr && pi->pitToken == m_pitToken;
    }

    /**
     * @brief Check Interest-Data match.
     * @pre processData is executing.
     * @param data incoming Data.
     * @param interest saved outgoing Interest.
     */
    bool match(const Data& data, const Interest& interest) const
    {
      return matchPitToken() && interest.match(data);
    }

    /**
     * @brief Check Interest-Data match.
     * @pre processData is executing.
     * @param data incoming Data.
     * @param name saved outgoing Interest name.
     * @param canBePrefix CanBePrefix flag on the Interest.
     */
    bool match(const Data& data, const Name& name, bool canBePrefix = true) const
    {
      StaticRegion<512> region;
      auto interest = region.create<Interest>();
      if (!interest) {
        return false;
      }
      interest.setName(name);
      interest.setCanBePrefix(canBePrefix);
      return match(data, interest);
    }

    /** @brief Determine if the pending Interest has expired / timed out. */
    bool expired() const
    {
      return ndnph::port::Clock::isBefore(m_expire, ndnph::port::Clock::now());
    }

  private:
    PacketHandler& m_ph;
    uint64_t m_pitToken = 0;
    port::Clock::Time m_expire;
  };

private:
  /** @brief Override to be invoked periodically. */
  virtual void loop() {}

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
  bool send(Region& region, const Packet& packet, PacketInfo pi, const PimFirst& pimFirst,
            const PimRest&... pimRest)
  {
    pimFirst(pi);
    return send(region, packet, pi, pimRest...);
  }

private:
  Face* m_face = nullptr;
  PacketHandler* m_next = nullptr;
  int8_t m_prio = 0;
  friend Face;
};

} // namespace ndnph

#define NDNPH_FACE_PACKET_HANDLER_HPP_END
#include "face-impl.inc"

#endif // NDNPH_FACE_PACKET_HANDLER_HPP
