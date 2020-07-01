#ifndef NDNPH_KEYCHAIN_HELPER_HPP
#define NDNPH_KEYCHAIN_HELPER_HPP

#include "../packet/component.hpp"
#include "../port/random/port.hpp"
#include "../port/sha256/port.hpp"
#include "../tlv/nni.hpp"
#include "../tlv/value.hpp"

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

inline Component
makeTimeComponent(Region& region, uint16_t type, uint64_t multiplier, time_t t = 0)
{
  if (t == 0) {
    time(&t);
    if (t < 540109800) {
      return makeRandomComponent(region, type);
    }
  }
  uint8_t buffer[8];
  Encoder encoder(buffer, sizeof(buffer));
  encoder.prepend(tlv::NNI(t * multiplier));
  return Component(region, type, encoder.size(), encoder.begin());
}

} // namespace detail
} // namespace ndnph

#endif // NDNPH_KEYCHAIN_HELPER_HPP
