#ifndef NDNPH_TEST_COMMON_HPP
#define NDNPH_TEST_COMMON_HPP

#include <atomic>
#include <chrono>
#include <thread>

#include <boost/concept_check.hpp>
#include <boost/lexical_cast.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace g = testing;

namespace ndnph {
namespace test {

template<typename T>
std::string
toString(const T& obj)
{
  std::string s;
  bool ok = boost::conversion::try_lexical_convert(obj, s);
  return ok ? s : "boost::bad_lexical_cast";
}

} // namespace test
} // namespace ndnph

#endif // NDNPH_TEST_COMMON_HPP
