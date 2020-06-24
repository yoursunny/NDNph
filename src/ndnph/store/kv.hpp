#ifndef NDNPH_STORE_KV_HPP
#define NDNPH_STORE_KV_HPP

#include "../port/fs/port.hpp"
#include "../tlv/value.hpp"

namespace ndnph {

/** @brief File based key-value store. */
class KvStore
{
public:
  /** @brief Constructor to use internal FileStore instance. */
  explicit KvStore() = default;

  /** @brief Constructor to use existing FileStore instance. */
  explicit KvStore(port::FileStore& fs)
    : m_fs(&fs)
  {}

  /**
   * @brief Open the FileStore backend.
   * @tparam Arg arguments passed to port::FileStore::open() function.
   */
  template<typename... Arg>
  bool open(Arg&&... arg)
  {
    if (m_fs == nullptr) {
      m_ownFs.reset(new port::FileStore());
      m_fs = m_ownFs.get();
    }
    return m_fs->open(std::forward<Arg>(arg)...);
  }

  /**
   * @brief Retrieve a value.
   * @param key non-empty key, can only contain digits and lower-case letters.
   * @param region where to allocate memory.
   * @return the value. Empty value upon error.
   */
  tlv::Value get(const char* key, Region& region)
  {
    if (m_fs == nullptr || !checkKey(key)) {
      return tlv::Value();
    }
    int size = m_fs->read(key, nullptr, 0);
    if (size <= 0) {
      return tlv::Value();
    }

    uint8_t* buf = region.alloc(size);
    if (buf == nullptr) {
      return tlv::Value();
    }
    int size2 = m_fs->read(key, buf, size);
    if (size2 != size) {
      region.free(buf, size);
      return tlv::Value();
    }
    return tlv::Value(buf, size);
  }

  /**
   * @brief Store a value.
   * @param key non-empty key, can only contain digits and lower-case letters.
   * @param value the value.
   * @return whether success.
   *
   * When multiple KvStores are created over the same FileStore backend (same instance, or
   * different instances but using the directory), it is the caller's responsibility to ensure
   * that keys do not conflict among different KvStores.
   */
  bool set(const char* key, tlv::Value value)
  {
    if (m_fs == nullptr || !checkKey(key)) {
      return false;
    }
    return m_fs->write(key, value.begin(), value.size());
  }

  /**
   * @brief Delete a key.
   * @param key non-empty key, can only contain digits and lower-case letters.
   * @return whether success; deleting a non-existent key is considered successful.
   */
  bool del(const char* key)
  {
    if (m_fs == nullptr || !checkKey(key)) {
      return false;
    }
    return m_fs->unlink(key);
  }

private:
  static bool checkKey(const char* key)
  {
    size_t keyLen = 0;
    if (key == nullptr || (keyLen = strlen(key)) == 0) {
      return false;
    }
    for (size_t i = 0; i < keyLen; ++i) {
      char ch = key[i];
      if (!isdigit(ch) && !islower(ch)) {
        return false;
      }
    }
    return true;
  }

private:
  std::unique_ptr<port::FileStore> m_ownFs;
  port::FileStore* m_fs = nullptr;
};

} // namespace ndnph

#endif // NDNPH_STORE_KV_HPP
