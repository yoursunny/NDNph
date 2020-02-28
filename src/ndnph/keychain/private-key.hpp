#ifndef NDNPH_KEYCHAIN_PRIVATE_KEY_HPP
#define NDNPH_KEYCHAIN_PRIVATE_KEY_HPP

#include "../packet/sig-info.hpp"

namespace ndnph {

/** @brief Private key. */
class PrivateKey
{
public:
  virtual ~PrivateKey() = default;

  virtual size_t getMaxSigLen() const = 0;

  /**
   * @brief Write SigType and KeyLocator.
   * @param[inout] sigInfo SigInfo to update; other fields are unchanged.
   */
  virtual void updateSigInfo(SigInfo& sigInfo) const = 0;

  /**
   * @brief Perform signing.
   * @param chunks signed portion.
   * @param[out] sig signature buffer, with getMaxSigLen() room.
   * @return signature length, or -1 upon failure.
   */
  virtual ssize_t sign(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const = 0;
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_PRIVATE_KEY_HPP
