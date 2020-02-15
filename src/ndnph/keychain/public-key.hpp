#ifndef NDNPH_KEYCHAIN_PUBLIC_KEY_HPP
#define NDNPH_KEYCHAIN_PUBLIC_KEY_HPP

#include "../packet/sig-info.hpp"

namespace ndnph {

/** @brief Public key. */
class PublicKey
{
public:
  virtual ~PublicKey() = default;

  /** @brief Determine whether packet was signed by corresponding private key. */
  virtual bool matchSigInfo(const SigInfo& sigInfo) const = 0;

  /**
   * @brief Perform verification.
   * @retval true signature is correct.
   * @retval false error or signature is incorrect.
   */
  virtual bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig,
                      size_t sigLen) const = 0;
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_PUBLIC_KEY_HPP
