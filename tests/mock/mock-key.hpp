#ifndef NDNPH_TEST_MOCK_KEY_HPP
#define NDNPH_TEST_MOCK_KEY_HPP

#include "ndnph/keychain/private-key.hpp"
#include "ndnph/keychain/public-key.hpp"

#include "test-common.hpp"

namespace ndnph {

class NullPrivateKey : public PrivateKey
{
public:
  size_t getMaxSigLen() const final
  {
    return 0;
  }

  void updateSigInfo(SigInfo&) const final {}

  ssize_t sign(std::initializer_list<tlv::Value>, uint8_t*) const final
  {
    return 0;
  }
};

class MockKeyBase
{
protected:
  ~MockKeyBase() = default;

  static std::vector<uint8_t> gather(std::initializer_list<tlv::Value> chunks)
  {
    std::vector<uint8_t> joined;
    for (const auto& chunk : chunks) {
      std::copy(chunk.begin(), chunk.end(), std::back_inserter(joined));
    }
    return joined;
  }
};

template<int L>
class MockPrivateKey
  : public PrivateKey
  , public MockKeyBase
{
public:
  size_t getMaxSigLen() const final
  {
    return L;
  }

  MOCK_METHOD(void, updateSigInfo, (SigInfo&), (const, final));

  ssize_t sign(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const final
  {
    return doSign(gather(chunks), sig);
  }

  MOCK_METHOD(ssize_t, doSign, (std::vector<uint8_t>, uint8_t*), (const));
};

class MockPublicKey
  : public PublicKey
  , public MockKeyBase
{
public:
  MOCK_METHOD(bool, matchSigInfo, (const SigInfo&), (const, final));

  bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig,
              size_t length) const final
  {
    return doVerify(gather(chunks), std::vector<uint8_t>(sig, sig + length));
  }

  MOCK_METHOD(bool, doVerify, (std::vector<uint8_t>, std::vector<uint8_t>), (const));
};

} // namespace ndnph

#endif // NDNPH_TEST_MOCK_KEY_HPP
