#ifndef NDNPH_STORE_PACKET_HPP
#define NDNPH_STORE_PACKET_HPP

#include "kv.hpp"

namespace ndnph {

/**
 * @brief File based packet store.
 * @tparam T packet type, which must be default-constructible and decodable.
 */
template<typename T>
class PacketStore : public KvStore
{
public:
  using KvStore::KvStore;

  /**
   * @brief Retrieve a packet.
   * @param key non-empty key.
   * @param region where to allocate memory.
   * @return the packet. Empty packet upon error.
   */
  T get(const char* key, Region& region)
  {
    tlv::Value wire = KvStore::get(key, region);
    if (wire.size() == 0) {
      return T();
    }

    T packet = region.create<T>();
    if (!packet || !wire.makeDecoder().decode(packet)) {
      return T();
    }
    return packet;
  }

  /**
   * @brief Store a packet.
   * @param key non-empty key.
   * @param value the packet, which must be encodable.
   * @param region where to allocate scratch memory for encoding the packet.
   * @return whether success.
   */
  template<typename Encodable>
  bool set(const char* key, Encodable value, Region& region)
  {
    Encoder encoder(region);
    if (!encoder.prepend(value)) {
      encoder.discard();
      return false;
    }

    tlv::Value wire(encoder);
    bool ok = KvStore::set(key, wire);
    encoder.discard();
    return ok;
  }
};

} // namespace ndnph

#endif // NDNPH_STORE_PACKET_HPP
