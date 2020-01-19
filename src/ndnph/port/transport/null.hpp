#ifndef NDNPH_PORT_TRANSPORT_NULL_HPP
#define NDNPH_PORT_TRANSPORT_NULL_HPP

#include "../../face/transport.hpp"

namespace ndnph {

class NullTransport : public Transport
{
public:
  bool isUp() const final
  {
    return false;
  }

  void asyncReceive(void* pctx, uint8_t*, size_t) final
  {
    invokeRxCallback(pctx, nullptr, -1);
  }

  void asyncSend(void* pctx, const uint8_t*, size_t, uint64_t) final
  {
    invokeTxCallback(pctx, false);
  }
};

} // namespace ndnph

#endif // NDNPH_PORT_TRANSPORT_NULL_HPP
