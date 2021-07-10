#ifndef NDNPH_KEYCHAIN_HELPER_HPP
#define NDNPH_KEYCHAIN_HELPER_HPP

#include "../packet/name.hpp"
#include "../port/random/port.hpp"
#include "../port/sha256/port.hpp"
#include "../tlv/nni.hpp"
#include "private-key.hpp"
#include "public-key.hpp"

namespace ndnph {
namespace detail {

inline bool
computeDigest(std::initializer_list<tlv::Value> chunks, uint8_t digest[NDNPH_SHA256_LEN])
{
  port::Sha256 hash;
  for (const auto& chunk : chunks) {
    hash.update(chunk.begin(), chunk.size());
  }
  return hash.final(digest);
}

inline Component
makeRandomComponent(Region& region, uint16_t type = TT::GenericNameComponent)
{
  uint8_t value[8];
  if (!port::RandomSource::generate(value, sizeof(value))) {
    return Component();
  }
  return Component(region, type, sizeof(value), value);
}

class NamedKey
{
public:
  /** @brief Retrieve KeyLocator name. */
  const Name& getName() const
  {
    return m_name;
  }

  /** @brief Assign KeyLocator name. */
  void setName(const Name& v)
  {
    m_name = v;
  }

protected:
  ~NamedKey() = default;

private:
  Name m_name;
};

template<uint8_t sigType>
class NamedPublicKey
  : public PublicKey
  , public virtual NamedKey
{
public:
  bool matchSigInfo(const SigInfo& sigInfo) const override
  {
    return sigInfo.sigType == sigType && (!getName() || sigInfo.name.isPrefixOf(getName()));
  }
};

template<uint8_t sigType>
class NamedPrivateKey
  : public PrivateKey
  , public virtual NamedKey
{
public:
  void updateSigInfo(SigInfo& sigInfo) const override
  {
    sigInfo.sigType = sigType;
    sigInfo.name = getName();
  }
};

} // namespace detail
} // namespace ndnph

#endif // NDNPH_KEYCHAIN_HELPER_HPP
