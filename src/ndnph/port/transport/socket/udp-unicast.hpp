#ifndef NDNPH_PORT_TRANSPORT_SOCKET_UDP_UNICAST_HPP
#define NDNPH_PORT_TRANSPORT_SOCKET_UDP_UNICAST_HPP

#include "../../../face/transport.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace ndnph {
namespace port_transport_socket {

class UdpUnicastTransport : public Transport
{
public:
  bool beginListen(const sockaddr_in* laddr)
  {
    return (createSocket() && bindSocket(laddr)) || closeSocketOnError();
  }

  bool beginListen(uint16_t localPort = 6363)
  {
    sockaddr_in laddr;
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = INADDR_ANY;
    laddr.sin_port = htons(localPort);
    return beginListen(&laddr);
  }

  bool beginTunnel(const sockaddr_in* raddr)
  {
    return (createSocket() && connectSocket(raddr)) || closeSocketOnError();
  }

  bool beginTunnel(std::initializer_list<uint8_t> remoteHost, uint16_t remotePort = 6363)
  {
    sockaddr_in raddr;
    if (remoteHost.size() != sizeof(raddr.sin_addr)) {
      return false;
    }
    raddr.sin_family = AF_INET;
    std::copy(remoteHost.begin(), remoteHost.end(), reinterpret_cast<uint8_t*>(&raddr.sin_addr));
    raddr.sin_port = htons(remotePort);
    return beginTunnel(&raddr);
  }

  bool end()
  {
    if (m_fd < 0) {
      return true;
    }
    int ok = close(m_fd);
    m_fd = -1;
    return ok == 0;
  }

  bool isUp() const final
  {
    return m_fd >= 0;
  }

  void asyncReceive(void* pctx, uint8_t* buf, size_t bufLen) final
  {
    sockaddr_in raddr;
    socklen_t raddrLen = sizeof(raddr);
    ssize_t pktLen = recvfrom(m_fd, buf, bufLen, 0, reinterpret_cast<sockaddr*>(&raddr), &raddrLen);
    if (pktLen >= 0) {
      uint64_t endpointId = (static_cast<uint64_t>(raddr.sin_port) << 32) | raddr.sin_addr.s_addr;
      invokeRxCallback(pctx, buf, pktLen, endpointId);
      return;
    }

    clearSocketError();
    invokeRxCallback(pctx, nullptr, -1);
  }

  void asyncSend(void* pctx, const uint8_t* pkt, size_t pktLen, uint64_t endpointId) final
  {
    const sockaddr* raddr = nullptr;
    socklen_t raddrLen = 0;
    sockaddr_in raddrEndpoint;
    if (endpointId != 0) {
      raddrEndpoint.sin_family = AF_INET;
      raddrEndpoint.sin_addr.s_addr = endpointId;
      raddrEndpoint.sin_port = endpointId >> 32;
      raddr = reinterpret_cast<const sockaddr*>(&raddrEndpoint);
      raddrLen = sizeof(raddrEndpoint);
    }
    ssize_t sentLen = sendto(m_fd, pkt, pktLen, 0, raddr, raddrLen);
    if (sentLen >= 0) {
      invokeTxCallback(pctx, true);
      return;
    }

    clearSocketError();
    invokeTxCallback(pctx, false);
  }

private:
  bool createSocket()
  {
    end();
    m_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (m_fd < 0) {
#ifdef NDNPH_SOCKET_PERROR
      perror("UdpUnicastTransport socket()");
#endif
      return false;
    }
    const int yes = 1;
    if (setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
#ifdef NDNPH_SOCKET_PERROR
      perror("UdpUnicastTransport setsockopt(SO_REUSEADDR)");
#endif
      return false;
    }
    return true;
  }

  bool bindSocket(const sockaddr_in* laddr)
  {
    if (bind(m_fd, reinterpret_cast<const sockaddr*>(laddr), sizeof(*laddr)) < 0) {
#ifdef NDNPH_SOCKET_PERROR
      perror("UdpUnicastTransport bind()");
#endif
      return false;
    }
    return true;
  }

  bool connectSocket(const sockaddr_in* raddr)
  {
    if (connect(m_fd, reinterpret_cast<const sockaddr*>(raddr), sizeof(*raddr)) < 0) {
#ifdef NDNPH_SOCKET_PERROR
      perror("UdpUnicastTransport connect()");
#endif
      return false;
    }
    return true;
  }

  bool closeSocketOnError()
  {
    if (m_fd >= 0) {
      close(m_fd);
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
#ifdef NDNPH_SOCKET_PERROR
    if (error != 0) {
      errno = error;
      perror("UdpUnicastTransport getsockopt(SO_ERROR)");
    }
#endif
  }

private:
  int m_fd = -1;
  mutable ssize_t m_mtu = -1;
};

} // namespace port_transport_socket

#ifdef NDNPH_PORT_TRANSPORT_SOCKET
using UdpUnicastTransport = port_transport_socket::UdpUnicastTransport;
#endif

} // namespace ndnph

#endif // NDNPH_PORT_TRANSPORT_SOCKET_UDP_UNICAST_HPP
