#ifndef NDNPH_PORT_FS_LINUX_HPP
#define NDNPH_PORT_FS_LINUX_HPP

#include "../../core/common.hpp"
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ndnph {
namespace port_fs_linux {

/** @brief File storage on Linux filesystem. */
class FileStore
{
public:
  bool open(const char* path)
  {
    m_pathLen = strlen(path);
    if (m_pathLen >= sizeof(m_path) - 2 || path[m_pathLen - 1] == '/') {
      return false;
    }

    struct stat st;
    bool ok = mkdirp(path, &st, 0);
    if (!ok) {
      return false;
    }

    memcpy(m_path, path, m_pathLen);
    m_path[m_pathLen++] = '/';
    m_path[m_pathLen] = '\0';
    return ok;
  }

  int read(const char* filename, uint8_t* buffer, size_t count)
  {
    JoinFilename join(this, filename);
    if (!join) {
      return -ENAMETOOLONG;
    }

    int fd = ::open(m_path, O_RDONLY);
    if (fd < 0) {
      if (errno == ENOENT) {
        return 0;
      }
      return -errno;
    }

    ssize_t nRead = ::read(fd, buffer, count);
    if (nRead < 0) {
      ::close(fd);
      return -errno;
    }

    int fileSize =
      static_cast<size_t>(nRead) == count ? ::lseek(fd, 0, SEEK_END) : static_cast<int>(nRead);
    ::close(fd);
    return fileSize;
  }

  bool write(const char* filename, const uint8_t* buffer, size_t count)
  {
    JoinFilename join(this, filename);
    if (!join) {
      return false;
    }

    int fd = ::open(m_path, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) {
      return false;
    }

    ssize_t nWrite = ::write(fd, buffer, count);
    ::close(fd);

    return static_cast<size_t>(nWrite) == count;
  }

  bool unlink(const char* filename)
  {
    JoinFilename join(this, filename);
    if (!join) {
      return -ENAMETOOLONG;
    }

    int res = ::unlink(m_path);
    return res == 0 || errno == ENOENT;
  }

private:
  class JoinFilename
  {
  public:
    explicit JoinFilename(FileStore* fs, const char* filename)
      : m_fs(fs)
    {
      size_t filenameLen = strlen(filename);
      if (fs->m_pathLen + filenameLen >= sizeof(fs->m_path) - 1) {
        m_fs = nullptr;
        return;
      }
      memcpy(&fs->m_path[fs->m_pathLen], filename, filenameLen + 1);
    }

    ~JoinFilename()
    {
      if (m_fs != nullptr) {
        m_fs->m_path[m_fs->m_pathLen] = '\0';
      }
    }

    explicit operator bool() const
    {
      return m_fs != nullptr;
    }

  private:
    FileStore* m_fs;
  };

  bool mkdirp(const char* path, struct stat* st, int up)
  {
    const char* dir = toDirname(path, up);
    if (::stat(dir, st) == 0) {
      return S_ISDIR(st->st_mode);
    } else if (errno == ENOENT) {
      bool ok = mkdirp(path, st, up + 1);
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
  char m_path[1024];
  size_t m_pathLen = 0;
};

} // namespace port_fs_linux

#ifdef NDNPH_PORT_FS_LINUX
namespace port {
using FileStore = port_fs_linux::FileStore;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_FS_LINUX_HPP
