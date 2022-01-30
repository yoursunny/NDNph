#ifndef NDNPH_PORT_FS_LINUX_HPP
#define NDNPH_PORT_FS_LINUX_HPP

#include "../../core/common.hpp"
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ndnph {
namespace port_fs_linux {
namespace detail {

class Mkdirp
{
public:
  bool create(const char* path)
  {
    size_t pathLen = strlen(path);
    if (pathLen <= 1 || pathLen >= sizeof(m_path) - 1 || path[pathLen - 1] == '/') {
      return false;
    }
    return createDir(path, 0);
  }

private:
  bool createDir(const char* path, int up)
  {
    const char* dir = toDirname(path, up);
    if (::stat(dir, &m_stat) == 0) {
      return S_ISDIR(m_stat.st_mode);
    } else if (errno == ENOENT) {
      bool ok = createDir(path, up + 1);
      if (!ok) {
        return false;
      }
    }

    dir = toDirname(path, up);
    return ::mkdir(dir, 0700) == 0;
  }

  const char* toDirname(const char* path, int up)
  {
    strncpy(m_path, path, sizeof(m_path));
    char* dir = m_path;
    for (int i = 0; i < up; ++i) {
      dir = ::dirname(dir);
    }
    return dir;
  }

private:
  char m_path[PATH_MAX];
  struct stat m_stat;
};

class FdCloser
{
public:
  explicit FdCloser(int fd = -1)
    : m_fd(fd)
  {}

  ~FdCloser()
  {
    close();
  }

  FdCloser& operator=(int fd)
  {
    if (fd != m_fd) {
      close();
      m_fd = fd;
    }
    return *this;
  }

  operator int() const
  {
    return m_fd;
  }

  void close()
  {
    if (m_fd >= 0) {
      ::close(m_fd);
      m_fd = -1;
    }
  }

private:
  int m_fd = -1;
};

} // namespace detail

/** @brief File storage on Linux filesystem. */
class FileStore
{
public:
  /**
   * @brief Open @p path directory as FileStore, creating directories as necessary.
   * @return whether success.
   */
  bool open(const char* path)
  {
    if (!detail::Mkdirp().create(path)) {
      return false;
    }

    m_dfd = ::open(path, O_RDONLY | O_DIRECTORY);
    return m_dfd >= 0;
  }

  /**
   * @brief Read content of @p filename file into @p buffer .
   * @return total file size; negative upon error.
   */
  int read(const char* filename, uint8_t* buffer, size_t count)
  {
    detail::FdCloser fd(::openat(m_dfd, filename, O_RDONLY));
    if (fd < 0) {
      if (errno == ENOENT) {
        return 0;
      }
      return -errno;
    }

    ssize_t nRead = ::read(fd, buffer, count);
    if (nRead < 0) {
      return -errno;
    }
    if (static_cast<size_t>(nRead) == count) {
      return ::lseek(fd, 0, SEEK_END);
    }
    return static_cast<int>(nRead);
  }

  /**
   * @brief Write @p buffer into @p filename file.
   * @return whether success.
   */
  bool write(const char* filename, const uint8_t* buffer, size_t count)
  {
    detail::FdCloser fd(::openat(m_dfd, filename, O_WRONLY | O_CREAT, 0600));
    ssize_t nWrite = ::write(fd, buffer, count);
    return static_cast<size_t>(nWrite) == count;
  }

  /**
   * @brief Delete @p filename file.
   * @return whether success.
   */
  bool unlink(const char* filename)
  {
    int res = ::unlinkat(m_dfd, filename, 0);
    return res == 0 || errno == ENOENT;
  }

private:
  detail::FdCloser m_dfd;
};

} // namespace port_fs_linux

#ifdef NDNPH_PORT_FS_LINUX
namespace port {
using FileStore = port_fs_linux::FileStore;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_FS_LINUX_HPP
