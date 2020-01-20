#ifndef NDNPH_PORT_TRANSPORT_NULL_HPP
#define NDNPH_PORT_TRANSPORT_NULL_HPP

#include "../../face/transport.hpp"

namespace ndnph {

class NullTransport : public Transport
{
private:
  bool doIsUp() const final
  {
    return false;
  }

  // void doAsyncReceive(void* pctx, uint8_t*, size_t) final
  // {
  //   invokeRxCallback(pctx, nullptr, -1);
  // }

  bool doSend(const uint8_t*, size_t, uint64_t) final
  {
    return false;
  }
};

} // namespace ndnph

#endif // NDNPH_PORT_TRANSPORT_NULL_HPP
