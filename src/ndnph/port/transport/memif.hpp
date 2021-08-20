#ifndef NDNPH_PORT_TRANSPORT_MEMIF_HPP
#define NDNPH_PORT_TRANSPORT_MEMIF_HPP

#include "../../face/transport-rxqueue.hpp"
extern "C"
{
#include <libmemif.h>
}

#ifndef NDNPH_MEMIF_RXBURST
/** @brief Receive burst size. */
#define NDNPH_MEMIF_RXBURST 256
#endif

namespace ndnph {
namespace port_transport_memif {

#ifdef NDNPH_MEMIF_DEBUG
#define NDNPH_MEMIF_PRINT_ERR(func)                                                                \
  do {                                                                                             \
    fprintf(stderr, "MemifTransport " #func " %d %s\n", err, memif_strerror(err));                 \
  } while (false)
#else
#define NDNPH_MEMIF_PRINT_ERR(func)                                                                \
  do {                                                                                             \
    (void)err;                                                                                     \
  } while (false)
#endif

/**
 * @brief A transport that communicates via libmemif.
 *
 * Current implementation only allows one memif transport per process.
 * It is compatible with NDN-DPDK dataplane, but has no management integration.
 */
class MemifTransport : public virtual Transport
{
public:
  using DefaultDataroom = std::integral_constant<uint16_t, 2048>;

  bool begin(const char* socketName, uint32_t id, uint16_t maxPktLen = DefaultDataroom::value)
  {
    end();
    m_maxPktLen = maxPktLen;

    int err = memif_init(nullptr, const_cast<char*>("NDNph"), nullptr, nullptr, nullptr);
    if (err != MEMIF_ERR_SUCCESS) {
      NDNPH_MEMIF_PRINT_ERR(memif_init);
      return false;
    }
    m_init = true;

    err = memif_create_socket(&m_sock, socketName, nullptr);
    if (err != MEMIF_ERR_SUCCESS) {
      NDNPH_MEMIF_PRINT_ERR(memif_create_socket);
      return false;
    }

    memif_conn_args_t args = {};
    args.socket = m_sock;
    args.interface_id = id;
    for (args.buffer_size = 64; args.buffer_size < m_maxPktLen;) {
      args.buffer_size <<= 1;
      // libmemif internally assumes buffer_size to be power of two
      // https://github.com/FDio/vpp/blob/v21.06/extras/libmemif/src/main.c#L2406
    }
    err = memif_create(&m_conn, &args, MemifTransport::handleConnect,
                       MemifTransport::handleDisconnect, MemifTransport::handleInterrupt, this);
    if (err != MEMIF_ERR_SUCCESS) {
      NDNPH_MEMIF_PRINT_ERR(memif_create);
      return false;
    }

    return true;
  }

  bool end()
  {
    if (m_conn != nullptr) {
      int err = memif_delete(&m_conn);
      if (err != MEMIF_ERR_SUCCESS) {
        NDNPH_MEMIF_PRINT_ERR(memif_delete);
        return false;
      }
    }

    if (m_sock != nullptr) {
      int err = memif_delete_socket(&m_sock);
      if (err != MEMIF_ERR_SUCCESS) {
        NDNPH_MEMIF_PRINT_ERR(memif_delete_socket);
        return false;
      }
    }

    if (m_init) {
      int err = memif_cleanup();
      if (err != MEMIF_ERR_SUCCESS) {
        NDNPH_MEMIF_PRINT_ERR(memif_cleanup);
        return false;
      }
      m_init = false;
    }
    return true;
  }

private:
  bool doIsUp() const final
  {
    return m_isUp;
  }

  void doLoop() final
  {
    if (!m_init) {
      return;
    }

    int err = memif_poll_event(0);
    if (err != MEMIF_ERR_SUCCESS) {
      NDNPH_MEMIF_PRINT_ERR(memif_poll_event);
    }
  }

  bool doSend(const uint8_t* pkt, size_t pktLen, uint64_t) final
  {
    if (!m_isUp) {
#ifdef NDNPH_MEMIF_DEBUG
      fprintf(stderr, "MemifTransport send drop=transport-disconnected\n");
#endif
      return false;
    }

    if (pktLen > m_maxPktLen) {
#ifdef NDNPH_MEMIF_DEBUG
      fprintf(stderr, "MemifTransport send drop=pkt-too-long len=%zu\n", pktLen);
#endif
      return false;
    }

    memif_buffer_t b = {};
    uint16_t nAlloc = 0;
    int err = memif_buffer_alloc(m_conn, 0, &b, 1, &nAlloc, pktLen);
    if (err != MEMIF_ERR_SUCCESS || nAlloc != 1) {
      NDNPH_MEMIF_PRINT_ERR(memif_buffer_alloc);
      return false;
    }

    assert(b.len >= pktLen);
    assert((b.flags & MEMIF_BUFFER_FLAG_NEXT) == 0);
    std::copy_n(pkt, pktLen, static_cast<uint8_t*>(b.data));
    b.len = pktLen;

    uint16_t nTx = 0;
    err = memif_tx_burst(m_conn, 0, &b, 1, &nTx);
    if (err != MEMIF_ERR_SUCCESS || nTx != 1) {
      NDNPH_MEMIF_PRINT_ERR(memif_tx_burst);
      return false;
    }
    return true;
  }

  static int handleConnect(memif_conn_handle_t conn, void* self0)
  {
    MemifTransport* self = reinterpret_cast<MemifTransport*>(self0);
    assert(self->m_conn == conn);
    self->m_isUp = true;
#ifdef NDNPH_MEMIF_DEBUG
    fprintf(stderr, "MemifTransport connected\n");
#endif

    int err = memif_refill_queue(conn, 0, -1, 0);
    if (err != MEMIF_ERR_SUCCESS) {
      NDNPH_MEMIF_PRINT_ERR(memif_refill_queue);
    }
    return 0;
  }

  static int handleDisconnect(memif_conn_handle_t conn, void* self0)
  {
    MemifTransport* self = reinterpret_cast<MemifTransport*>(self0);
    assert(self->m_conn == conn);
    self->m_isUp = false;
#ifdef NDNPH_MEMIF_DEBUG
    fprintf(stderr, "MemifTransport disconnected\n");
#endif
    return 0;
  }

  static int handleInterrupt(memif_conn_handle_t conn, void* self0, uint16_t qid)
  {
    MemifTransport* self = reinterpret_cast<MemifTransport*>(self0);
    assert(self->m_conn == conn);

    std::array<memif_buffer_t, NDNPH_MEMIF_RXBURST> burst;
    uint16_t nRx = 0;
    int err = memif_rx_burst(conn, qid, burst.data(), burst.size(), &nRx);
    if (err != MEMIF_ERR_SUCCESS) {
      NDNPH_MEMIF_PRINT_ERR(memif_rx_burst);
      return 0;
    }

    for (uint16_t i = 0; i < nRx; ++i) {
      const memif_buffer_t& b = burst[i];
      self->invokeRxCallback(static_cast<const uint8_t*>(b.data), b.len);
    }

    err = memif_refill_queue(conn, qid, nRx, 0);
    if (err != MEMIF_ERR_SUCCESS) {
      NDNPH_MEMIF_PRINT_ERR(memif_rx_burst);
    }
    return 0;
  }

private:
  memif_socket_handle_t m_sock = nullptr;
  memif_conn_handle_t m_conn = nullptr;
  uint16_t m_maxPktLen = 0;
  bool m_init = false;
  bool m_isUp = false;
};

#undef NDNPH_MEMIF_PRINT_ERR

} // namespace port_transport_memif

using MemifTransport = port_transport_memif::MemifTransport;

} // namespace ndnph

#endif // NDNPH_PORT_TRANSPORT_MEMIF_HPP
