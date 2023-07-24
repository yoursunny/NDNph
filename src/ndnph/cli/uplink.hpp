#ifndef NDNPH_CLI_UPLINK_HPP
#define NDNPH_CLI_UPLINK_HPP

#include "../face/face.hpp"
#include "../port/transport/port.hpp"

namespace ndnph {
namespace cli {
namespace detail {

inline Face*
openMemif(const char* socketName, int* mtu) {
#ifdef NDNPH_PORT_TRANSPORT_MEMIF
  static MemifTransport transport;
  uint16_t dataroom = static_cast<uint16_t>(std::max(0, *mtu));
  if (!transport.begin(socketName, 0, dataroom)) {
    return nullptr;
  }
  *mtu = static_cast<int>(transport.getDataroom());
  static Face face(transport);
  return &face;
#else
  (void)socketName;
  (void)mtu;
  return nullptr;
#endif // NDNPH_PORT_TRANSPORT_MEMIF
}

inline Face*
openUdp() {
  int port = 6363;
  const char* env = getenv("NDNPH_UPLINK_UDP_PORT");
  if (env != nullptr) {
    port = atoi(env);
    if (port <= 0 || port > UINT16_MAX) {
      return nullptr;
    }
  }

  static UdpUnicastTransport transport;
  env = getenv("NDNPH_UPLINK_UDP_LISTEN");
  if (env != nullptr && env[0] == '1') {
    transport.beginListen(port);
  } else {
    sockaddr_in raddr4{};
    raddr4.sin_family = AF_INET;
    raddr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    raddr4.sin_port = htons(port);

    sockaddr_in6 raddr6{};
    raddr6.sin6_family = AF_INET6;
    raddr6.sin6_port = raddr4.sin_port;

    bool useV6 = false;

    env = getenv("NDNPH_UPLINK_UDP");
    if (env != nullptr) {
      if (inet_pton(raddr6.sin6_family, env, &raddr6.sin6_addr)) {
        useV6 = true;
      } else if (!inet_pton(raddr4.sin_family, env, &raddr4.sin_addr)) {
        return nullptr;
      }
    }

    if (!(useV6 ? transport.beginTunnel(&raddr6) : transport.beginTunnel(&raddr4))) {
      return nullptr;
    }
  }

  static Face face(transport);
  return &face;
}

inline void
enableFragReass(Face& face, int mtu) {
  static DynamicRegion region(9200);
  static lp::Fragmenter fragmenter(region, mtu);
  static lp::Reassembler reassembler(region);
  face.setFragmenter(fragmenter);
  face.setReassembler(reassembler);
}

} // namespace detail

/** @brief Open uplink face. */
inline Face&
openUplink() {
  static Face* face = nullptr;
  if (face == nullptr) {
    int mtu = -1;
    const char* envMtu = getenv("NDNPH_UPLINK_MTU");
    if (envMtu != nullptr) {
      mtu = atoi(envMtu);
      if (mtu < 64 || mtu > 9000) {
        fprintf(stderr, "ndnph::cli::openUplink invalid or out-of-range NDNPH_UPLINK_MTU\n");
        exit(1);
      }
    }

    const char* envMemif = getenv("NDNPH_UPLINK_MEMIF");
    if (envMemif == nullptr) {
      face = detail::openUdp();
    } else {
      face = detail::openMemif(envMemif, &mtu);
    }

    if (face == nullptr) {
      fprintf(stderr, "ndnph::cli::openUplink error\n");
      exit(1);
    }

    if (mtu >= 0) {
      detail::enableFragReass(*face, mtu);
    }
  }
  return *face;
}

} // namespace cli
} // namespace ndnph

#endif // NDNPH_CLI_UPLINK_HPP
