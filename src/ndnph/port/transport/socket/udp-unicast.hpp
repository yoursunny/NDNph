#ifndef NDNPH_PORT_TRANSPORT_SOCKET_UDP_UNICAST_HPP
#define NDNPH_PORT_TRANSPORT_SOCKET_UDP_UNICAST_HPP

#include "../../../face/transport-rxqueue.hpp"
#include "ipv6-endpointid.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace ndnph {
namespace port_transport_socket {

/** @brief A transport that communicates over IPv4 unicast UDP tunnel. */
class UdpUnicastTransport
  : public virtual Transport
  , public transport::DynamicRxQueueMixin
{
public:
  explicit UdpUnicastTransport(size_t bufLen = DEFAULT_BUFLEN)
    : DynamicRxQueueMixin(bufLen)
  {}

  ~UdpUnicastTransport() override
  {
    end();
  }

  /**
   * @brief Start listening on given local IPv4 address.
   * @param laddr local IPv4 address and UDP port.
   * @return whether success.
   */
  bool beginListen(const sockaddr_in* laddr)
  {
    return (createSocket(laddr->sin_family) &&
            bindSocket(reinterpret_cast<const sockaddr*>(laddr))) ||
           closeSocketOnError();
  }

  /**
   * @brief Start listening on given local IPv6 address.
   * @param laddr local IPv6 address and UDP port.
   * @param v6only IPV6_V6ONLY socket option: 0=no, 1=yes, -1=unchanged.
   * @return whether success.
   */
  bool beginListen(const sockaddr_in6* laddr, int v6only = -1)
  {
    return (createSocket(laddr->sin6_family) && changeV6Only(v6only) &&
            bindSocket(reinterpret_cast<const sockaddr*>(laddr))) ||
           closeSocketOnError();
  }

  /**
   * @brief Start listening on given local port for both IPv4 and IPv6.
   * @return whether success.
   */
  bool beginListen(uint16_t localPort = 6363)
  {
    sockaddr_in6 laddr{};
    laddr.sin6_family = AF_INET6;
    laddr.sin6_addr = in6addr_any;
    laddr.sin6_port = htons(localPort);
    return beginListen(&laddr, 0);
  }

  /**
   * @brief Connect to given remote IPv4 address.
   * @param raddr remote IPv4 address and UDP port.
   * @return whether success.
   */
  bool beginTunnel(const sockaddr_in* raddr)
  {
    return (createSocket(raddr->sin_family) &&
            connectSocket(reinterpret_cast<const sockaddr*>(raddr))) ||
           closeSocketOnError();
  }

  /**
   * @brief Connect to given remote IPv6 address.
   * @param raddr remote IPv6 address and UDP port.
   * @param v6only IPV6_V6ONLY socket option: 0=no, 1=yes, -1=unchanged.
   * @return whether success.
   */
  bool beginTunnel(const sockaddr_in6* raddr, int v6only = -1)
  {
    return (createSocket(raddr->sin6_family) && changeV6Only(v6only) &&
            connectSocket(reinterpret_cast<const sockaddr*>(raddr))) ||
           closeSocketOnError();
  }

  /**
   * @brief Connect to given remote IP and port.
   * @param remoteHost four octets to represent IPv4 address.
   * @param remotePort port number.
   */
  bool beginTunnel(std::initializer_list<uint8_t> remoteHost, uint16_t remotePort = 6363)
  {
    sockaddr_in raddr{};
    if (remoteHost.size() != sizeof(raddr.sin_addr)) {
      return false;
    }
    raddr.sin_family = AF_INET;
    std::copy(remoteHost.begin(), remoteHost.end(), reinterpret_cast<uint8_t*>(&raddr.sin_addr));
    raddr.sin_port = htons(remotePort);
    return beginTunnel(&raddr);
  }

  /** @brief Stop listening or close connection. */
  bool end()
  {
    if (m_fd < 0) {
      return true;
    }
    int ok = close(m_fd);
    m_fd = -1;
    return ok == 0;
  }

private:
  bool doIsUp() const final
  {
    return m_fd >= 0;
  }

  void doLoop() final
  {
    const auto& p = getAddressFamilyParams(m_af);
    uint8_t raddr[std::max(sizeof(sockaddr_in), sizeof(sockaddr_in6))];
    iovec iov{};
    while (auto r = receiving()) {
      iov.iov_base = r.buf();
      iov.iov_len = r.bufLen();
      msghdr msg{};
      msg.msg_name = raddr;
      msg.msg_namelen = sizeof(raddr);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;

      ssize_t pktLen = recvmsg(m_fd, &msg, 0);
      if (pktLen < 0 || (msg.msg_flags & MSG_TRUNC) != 0 || msg.msg_namelen != p.nameLen) {
        clearSocketError();
        break;
      }

      in_port_t port = *reinterpret_cast<const in_port_t*>(raddr + p.portOff);
      uint64_t endpointId = m_endpoints.encode(raddr + p.ipOff, p.ipLen, port);
      r(pktLen, endpointId);
    }

    loopRxQueue();
  }

  bool doSend(const uint8_t* pkt, size_t pktLen, uint64_t endpointId) final
  {
    const auto& p = getAddressFamilyParams(m_af);
    uint8_t raddr[std::max(sizeof(sockaddr_in), sizeof(sockaddr_in6))];
    const sockaddr* raddrPtr = nullptr;
    socklen_t raddrLen = 0;
    if (endpointId != 0 &&
        m_endpoints.decode(endpointId, raddr + p.ipOff,
                           reinterpret_cast<in_port_t*>(raddr + p.portOff)) == p.ipLen) {
      raddrPtr = reinterpret_cast<const sockaddr*>(raddr);
      raddrLen = p.nameLen;
    }

    ssize_t sentLen = sendto(m_fd, pkt, pktLen, 0, raddrPtr, raddrLen);
    if (sentLen >= 0) {
      return true;
    }
    clearSocketError();
    return false;
  }

private:
  struct AddressFamilyParams
  {
    socklen_t nameLen;
    ptrdiff_t ipOff;
    socklen_t ipLen;
    ptrdiff_t portOff;
    const char* fmtBracketL;
    const char* fmtBracketR;
  };

  static const AddressFamilyParams& getAddressFamilyParams(sa_family_t family)
  {
    static const AddressFamilyParams inet = {
      .nameLen = sizeof(sockaddr_in),
      .ipOff = offsetof(sockaddr_in, sin_addr),
      .ipLen = sizeof(in_addr),
      .portOff = offsetof(sockaddr_in, sin_port),
      .fmtBracketL = "",
      .fmtBracketR = "",
    };
    static const AddressFamilyParams inet6 = {
      .nameLen = sizeof(sockaddr_in6),
      .ipOff = offsetof(sockaddr_in6, sin6_addr),
      .ipLen = sizeof(in6_addr),
      .portOff = offsetof(sockaddr_in6, sin6_port),
      .fmtBracketL = "",
      .fmtBracketR = "",
    };
    switch (family) {
      case AF_INET:
        return inet;
      case AF_INET6:
        return inet6;
      default:
        NDNPH_ASSERT(false);
        return inet;
    }
  }

  bool createSocket(sa_family_t family)
  {
    end();
    m_fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (m_fd < 0) {
#ifdef NDNPH_SOCKET_DEBUG
      perror("UdpUnicastTransport socket()");
#endif
      return false;
    }
    m_af = family;

    const int yes = 1;
    if (setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
#ifdef NDNPH_SOCKET_DEBUG
      perror("UdpUnicastTransport setsockopt(SO_REUSEADDR)");
#endif
      return false;
    }
    return true;
  }

  bool changeV6Only(int v6only)
  {
    if (v6only < 0) {
      return true;
    }
    int value = v6only > 0 ? 1 : 0;
    if (setsockopt(m_fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)) < 0) {
#ifdef NDNPH_SOCKET_DEBUG
      perror("UdpUnicastTransport setsockopt(IPV6_V6ONLY)");
#endif
      return false;
    }
    return true;
  }

  bool bindSocket(const sockaddr* laddr)
  {
    const auto& p = getAddressFamilyParams(laddr->sa_family);
    if (bind(m_fd, laddr, p.nameLen) < 0) {
#ifdef NDNPH_SOCKET_DEBUG
      perror("UdpUnicastTransport bind()");
#endif
      return false;
    }
#ifdef NDNPH_SOCKET_DEBUG
    char addrBuf[std::max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
    inet_ntop(laddr->sa_family, reinterpret_cast<const uint8_t*>(laddr) + p.ipOff, addrBuf,
              sizeof(addrBuf));
    in_port_t port =
      *reinterpret_cast<const in_port_t*>(reinterpret_cast<const uint8_t*>(laddr) + p.portOff);
    fprintf(stderr, "UdpUnicastTransport bind(%s%s%s:%" PRIu16 ")\n", p.fmtBracketL, addrBuf,
            p.fmtBracketR, ntohs(port));
#endif
    return true;
  }

  bool connectSocket(const sockaddr* raddr)
  {
    const auto& p = getAddressFamilyParams(raddr->sa_family);
    if (connect(m_fd, raddr, p.nameLen) < 0) {
#ifdef NDNPH_SOCKET_DEBUG
      perror("UdpUnicastTransport connect()");
#endif
      return false;
    }
#ifdef NDNPH_SOCKET_DEBUG
    char addrBuf[std::max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
    inet_ntop(raddr->sa_family, reinterpret_cast<const uint8_t*>(raddr) + p.ipOff, addrBuf,
              sizeof(addrBuf));
    in_port_t port =
      *reinterpret_cast<const in_port_t*>(reinterpret_cast<const uint8_t*>(raddr) + p.portOff);
    fprintf(stderr, "UdpUnicastTransport connect(%s%s%s:%" PRIu16 ")\n", p.fmtBracketL, addrBuf,
            p.fmtBracketR, ntohs(port));
#endif
    return true;
  }

  bool closeSocketOnError()
  {
    if (m_fd >= 0) {
      close(m_fd);
      m_af = AF_UNSPEC;
      m_fd = -1;
      m_mtu = -1;
    }
    return false;
  }

  void clearSocketError()
  {
    int error = 0;
    socklen_t len = sizeof(error);
    getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &error, &len);
#ifdef NDNPH_SOCKET_DEBUG
    if (error != 0) {
      errno = error;
      perror("UdpUnicastTransport getsockopt(SO_ERROR)");
    }
#endif
  }

private:
  Ipv6EndpointIdHelper<15> m_endpoints;
  int m_fd = -1;
  ssize_t m_mtu = -1;
  sa_family_t m_af = AF_UNSPEC;
};

} // namespace port_transport_socket

using UdpUnicastTransport = port_transport_socket::UdpUnicastTransport;

} // namespace ndnph

#endif // NDNPH_PORT_TRANSPORT_SOCKET_UDP_UNICAST_HPP
