#ifndef NDNPH_PORT_TRANSPORT_SOCKET_IPV6_ENDPOINTID_HPP
#define NDNPH_PORT_TRANSPORT_SOCKET_IPV6_ENDPOINTID_HPP

#include "../../../core/common.hpp"

namespace ndnph {
namespace port_transport_socket {

/**
 * @brief Helper to pack IPv6 endpoint into 64-bit EndpointId.
 * @tparam capacity maximum is 15.
 *
 * IPv6 address+port has 144 bits, longer than the 64-bit EndpointId. This data structure has
 * an internal table to store parts of each full IPv6 endpoint, while the returned EndpointId
 * contains an index into this table and a checksum. This table can track at least @c capacity
 * distinct flows. Overflow may cause failed or incorrect unpacking.
 */
template<int capacity>
class Ipv6EndpointIdHelper
{
public:
  /**
   * @brief Pack IP address+port into EndpointId.
   * @param addr IP address, 4 or 16 bytes.
   * @param addrLen IP address length, either 4 or 16.
   * @param port port number.
   * @return 64-bit EndpointId.
   */
  uint64_t encode(const uint8_t* addr, size_t addrLen, uint16_t port)
  {
    EndpointId ep{};
    ep.port = port;
    if (addrLen == 4) {
      std::copy_n(addr, 4, ep.v4);
      return ep.id;
    }
    if (addrLen != 16) {
      return 0;
    }

    ep.v6a = addr[9];
    ep.v6b = addr[10];
    ep.v6c = addr[13];
    ep.v6d = addr[14];
    ep.v6e = addr[15];
    Intern r{ addr[0], addr[1], addr[2], addr[3],  addr[4], addr[5],
              addr[6], addr[7], addr[8], addr[11], addr[12] };
    ep.v6sum = computeChecksum(r);

    auto found = std::find(m_interns.begin(), m_interns.end(), r);
    if (found != m_interns.end()) {
      ep.v6ref = 1 + std::distance(m_interns.begin(), found);
    } else {
      m_interns[m_internPos] = r;
      ep.v6ref = ++m_internPos;
      if (m_internPos == m_interns.size()) {
        m_internPos = 0;
      }
    }
    return ep.id;
  }

  /**
   * @brief Unpack IP address+port from EndpointId.
   * @param endpointId 64-bit EndpointId.
   * @param [out] addr IP address, 4 or 16 bytes.
   * @param [out] port port number.
   * @return address length; 0 indicates error.
   */
  size_t decode(uint64_t endpointId, uint8_t addr[16], uint16_t* port)
  {
    EndpointId ep{};
    ep.id = endpointId;
    *port = ep.port;
    if (!ep.isV6) {
      std::copy_n(ep.v4, 4, addr);
      return 4;
    }

    if (ep.v6ref == 0 || ep.v6ref > m_interns.size()) {
      return 0;
    }
    auto r = m_interns[ep.v6ref - 1];
    if (computeChecksum(r) != ep.v6sum) {
      return 0;
    }
    std::copy_n(r.begin(), 9, addr);
    addr[9] = ep.v6a;
    addr[10] = ep.v6b;
    addr[11] = r[9];
    addr[12] = r[10];
    addr[13] = ep.v6c;
    addr[14] = ep.v6d;
    addr[15] = ep.v6e;
    return 16;
  }

private:
  union EndpointId
  {
    uint64_t id;
    struct
    {
      uint16_t port;
      uint8_t v4[4];
      uint16_t isV6;
    };
    struct
    {
      // [____:____:____:____:__AA:BB__:__CC:DDEE]:port
      uint16_t port_;
      uint8_t v6a;
      uint8_t v6b;
      uint8_t v6c;
      uint8_t v6d;
      uint8_t v6e;
      uint8_t v6ref : 4;
      uint8_t v6sum : 4;
    };
  };
  static_assert(sizeof(EndpointId) == sizeof(uint64_t), "");
  static_assert(offsetof(EndpointId, port) == offsetof(EndpointId, port_), "");

  // [AABB:CCDD:EEFF:GGHH:II__:__JJ:KK__:____]:____
  using Intern = std::array<uint8_t, 11>;

  // Rationale of choosing which bits go into EndpointId and which bits go into Intern:
  // maximize the possibility of two IPv6 addresses have the same Intern entry.
  // * Within a LAN, /64 network prefix AABB:CCDD:EEFF:GGHH is the same.
  // * When using SLAAC and EUI-64, JJ:KK is always "FF-FE".
  // * II has 6~7 bits of entropy because MAC address I/G bit is always zero.

  uint8_t computeChecksum(const Intern& r)
  {
    uint8_t sum = 0;
    for (uint8_t b : r) {
      sum ^= b;
    }
    return (sum & 0x0F) ^ (sum >> 4);
  }

private:
  static_assert(capacity <= 15, "");
  std::array<Intern, capacity> m_interns;
  uint8_t m_internPos = 0;
};

} // namespace port_transport_socket
} // namespace ndnph

#endif // NDNPH_PORT_TRANSPORT_SOCKET_IPV6_ENDPOINTID_HPP
