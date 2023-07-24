#ifndef NDNPH_KEYCHAIN_KEYCHAIN_HPP
#define NDNPH_KEYCHAIN_KEYCHAIN_HPP

#include "../packet/data.hpp"
#include "../port/fs/port.hpp"
#include "../store/packet.hpp"

namespace ndnph {

/**
 * @brief File based key pair store.
 *
 * Unencrypted private keys may be stored. It's important to protect the storage directory
 * using Unix permissions or similar mechanisms.
 */
class KeyChainKeys : public KvStore {
public:
  using KvStore::KvStore;
};

/** @brief File based certificate store. */
class KeyChainCerts : public PacketStore<Data> {
public:
  using PacketStore::PacketStore;

  Data get(const char* id, Region& region) {
    Data data = PacketStore::get(id, region);
    if (!data || !certificate::isCertificate(data)) {
      return Data();
    }
    return data;
  }
};

/** @brief File based key and certificate store. */
class KeyChain {
public:
  explicit KeyChain() = default;

  explicit KeyChain(port::FileStore& fs)
    : keys(fs)
    , certs(fs) {}

  /** @brief Open the FileStore backend in both key store and certificate store. */
  template<typename... Arg>
  bool open(Arg&&... arg) {
    return keys.open(std::forward<Arg>(arg)...) && certs.open(std::forward<Arg>(arg)...);
  }

public:
  KeyChainKeys keys;
  KeyChainCerts certs;
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_KEYCHAIN_HPP
