#ifndef NDNPH_TEST_MOCK_TRANSPORT_HPP
#define NDNPH_TEST_MOCK_TRANSPORT_HPP

#include "ndnph/face/face.hpp"

#include "test-common.hpp"

namespace ndnph {

class MockTransport : public Transport
{
public:
  MOCK_METHOD(bool, isUp, (), (const, override));

  MOCK_METHOD(void, loop, (), (override));

  MOCK_METHOD((std::tuple<ssize_t, uint64_t>), doReceive, (void*, uint8_t*, size_t), ());

  MOCK_METHOD(bool, doSend, (void*, std::vector<uint8_t>, uint64_t), ());

  void asyncReceive(void* pctx, uint8_t* buf, size_t bufLen) override
  {
    ssize_t pktLen = 0;
    uint64_t endpointId = 0;
    std::tie(pktLen, endpointId) = doReceive(pctx, buf, bufLen);
    invokeRxCallback(pctx, buf, pktLen, endpointId);
  }

  void asyncSend(void* pctx, const uint8_t* pkt, size_t pktLen, uint64_t endpointId) override
  {
    bool ok = doSend(pctx, std::vector<uint8_t>(pkt, pkt + pktLen), endpointId);
    invokeTxCallback(pctx, ok);
  }
};

class MockFaceCallbacks
{
public:
  void hook(Face& face)
  {
    face.setRxCallback(rxSuccessCallback, rxFailureCallback, this);
    face.setTxCallback(txCallback, this);
  }

  MOCK_METHOD(void, rxSuccess, (void*, std::vector<uint8_t>, uint64_t), ());

  MOCK_METHOD(void, rxFailure, (void*), ());

  MOCK_METHOD(void, tx, (void*, bool), ());

  static void rxSuccessCallback(void* self0, void* pctx, Decoder& decoder, uint64_t endpointId)
  {
    MockFaceCallbacks& self = *reinterpret_cast<MockFaceCallbacks*>(self0);
    std::vector<uint8_t> wire;
    for (const auto& d : decoder) {
      std::copy_n(d.tlv, d.size, std::back_inserter(wire));
    }
    self.rxSuccess(pctx, wire, endpointId);
  }

  static void rxFailureCallback(void* self0, void* pctx)
  {
    MockFaceCallbacks& self = *reinterpret_cast<MockFaceCallbacks*>(self0);
    self.rxFailure(pctx);
  }

  static void txCallback(void* self0, void* pctx, bool ok)
  {
    MockFaceCallbacks& self = *reinterpret_cast<MockFaceCallbacks*>(self0);
    self.tx(pctx, ok);
  }
};

} // namespace ndnph

#endif // NDNPH_TEST_MOCK_TRANSPORT_HPP
