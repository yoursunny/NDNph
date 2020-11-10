#ifndef NDNPH_PORT_FS_NULL_HPP
#define NDNPH_PORT_FS_NULL_HPP

#include "../../core/common.hpp"

namespace ndnph {
namespace port_fs_null {

/** @brief File storage stub. */
class FileStore
{
public:
  /**
   * @brief Open the storage.
   *
   * Each port may have different arguments to this function.
   */
  bool open()
  {
    return false;
  }

  /**
   * @brief Read a file.
   * @param filename file name; directories are not supported.
   * @param buffer destination buffer.
   * @param count buffer size.
   * @return file size, 0 if the file does not exist, or negative for other errors.
   */
  int read(const char* filename, uint8_t* buffer, size_t count)
  {
    (void)filename;
    (void)buffer;
    (void)count;
    return 0;
  }

  /**
   * @brief Write a file.
   * @param filename file name; directories are not supported.
   * @param buffer source buffer.
   * @param count buffer size; file will be truncated to this size.
   * @return whether success.
   */
  bool write(const char* filename, const uint8_t* buffer, size_t count)
  {
    (void)filename;
    (void)buffer;
    (void)count;
    return false;
  }

  /**
   * @brief Delete a file.
   * @param filename file name; directories are not supported.
   * @return whether success; deleting a non-existent file is considered successful.
   */
  bool unlink(const char* filename)
  {
    (void)filename;
    return true;
  }
};

} // namespace port_fs_null

#ifdef NDNPH_PORT_FS_NULL
namespace port {
using FileStore = port_fs_null::FileStore;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_FS_NULL_HPP
