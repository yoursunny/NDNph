#ifndef NDNPH_CLI_FACE_HPP
#define NDNPH_CLI_FACE_HPP

#include "../face/face.hpp"
#include "../port/transport/port.hpp"

namespace ndnph {
namespace cli {
namespace detail {

inline Face*
openMemif(const char* socketName)
{
#ifdef NDNPH_PORT_TRANSPORT_MEMIF
  static MemifTransport transport;
  if (!transport.begin(socketName, 0)) {
    return nullptr;
  }
  static Face face(transport);
  return &face;
#else
  (void)socketName;
  return nullptr;
#endif // NDNPH_PORT_TRANSPORT_MEMIF
}

inline Face*
openUdp()
{
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
    sockaddr_in raddr = {};
    raddr.sin_family = AF_INET;
    raddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    raddr.sin_port = htons(port);
    env = getenv("NDNPH_UPLINK_UDP");

    if (env != nullptr && inet_aton(env, &raddr.sin_addr) == 0) {
      return nullptr;
    }

    if (!transport.beginTunnel(&raddr)) {
      return nullptr;
    }
  }

  static Face face(transport);
  return &face;
}

inline void
enableFragReass(Face& face)
{
  const char* env = getenv("NDNPH_UPLINK_MTU");
  if (env == nullptr) {
    return;
  }

  int mtu = atoi(env);
  if (mtu <= 0 || mtu >= 9000) {
    fprintf(stderr, "ndnph::cli::openUplink invalid NDNPH_UPLINK_MTU\n");
    exit(1);
  }

  static DynamicRegion region(9200);
  static lp::Fragmenter fragmenter(region, mtu);
  static lp::Reassembler reassembler(region);
  face.setFragmenter(fragmenter);
  face.setReassembler(reassembler);
}

} // namespace detail

/** @brief Open uplink face. */
inline Face&
openUplink()
{
  static Face* face = nullptr;
  if (face == nullptr) {
    const char* envMemif = getenv("NDNPH_UPLINK_MEMIF");
    if (envMemif == nullptr) {
      face = detail::openUdp();
    } else {
      face = detail::openMemif(envMemif);
    }

    if (face == nullptr) {
      fprintf(stderr, "ndnph::cli::openUplink error\n");
      exit(1);
    }

    detail::enableFragReass(*face);
  }
  return *face;
}

} // namespace cli
} // namespace ndnph

#endif // NDNPH_CLI_FACE_HPP
