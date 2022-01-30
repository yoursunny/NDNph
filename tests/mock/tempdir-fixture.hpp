#ifndef NDNPH_TEST_TEMPDIR_FIXTURE_HPP
#define NDNPH_TEST_TEMPDIR_FIXTURE_HPP

#include "test-common.hpp"

namespace ndnph {

class TempDirFixture : public g::Test
{
protected:
  void SetUp() override
  {
    char dir[PATH_MAX] = "/tmp/NDNph-test-XXXXXX";
    tempDir = ::mkdtemp(dir);
  }

  void TearDown() override
  {
    std::string rmrf = "rm -rf " + tempDir;
    ::system(rmrf.data());
  }

protected:
  std::string tempDir;
};

} // namespace ndnph

#endif // NDNPH_TEST_TEMPDIR_FIXTURE_HPP
