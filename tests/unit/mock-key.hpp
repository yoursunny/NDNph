#ifndef NDNPH_TEST_MOCK_KEY_HPP
#define NDNPH_TEST_MOCK_KEY_HPP

#include "ndnph/tlv/value.hpp"

#include "test-common.hpp"

namespace ndnph {

class NullPrivateKey
{
public:
  void updateSigInfo(SigInfo&) const {}

  using MaxSigLength = std::integral_constant<int, 0>;

  ssize_t sign(std::initializer_list<tlv::Value>, uint8_t*) const { return 0; }
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

class MockPrivateKeyBase : public MockKeyBase
{
public:
  MOCK_METHOD(void, updateSigInfo, (SigInfo&), (const));

  ssize_t sign(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const
  {
    return doSign(gather(chunks), sig);
  }

  MOCK_METHOD(ssize_t, doSign, (std::vector<uint8_t>, uint8_t*), (const));

protected:
  ~MockPrivateKeyBase() = default;
};

template<int L>
class MockPrivateKey : public MockPrivateKeyBase
{
public:
  using MaxSigLength = std::integral_constant<int, L>;
};

class MockPublicKey : public MockKeyBase
{
public:
  bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig,
              size_t length) const
  {
    return doVerify(gather(chunks), std::vector<uint8_t>(sig, sig + length));
  }

  MOCK_METHOD(bool, doVerify, (std::vector<uint8_t>, std::vector<uint8_t>),
              (const));
};

} // namespace ndnph

#endif // NDNPH_TEST_MOCK_KEY_HPP
