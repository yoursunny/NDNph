#ifndef NDNPH_TEST_COMMON_HPP
#define NDNPH_TEST_COMMON_HPP

#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <boost/concept_check.hpp>
#include <boost/lexical_cast.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace g = testing;

namespace ndnph {
namespace test {

inline std::vector<uint8_t>
fromHex(const std::string& input) {
  std::vector<uint8_t> v;
  v.reserve(input.size() / 2);
  static const char* hexDigits = "0123456789ABCDEF";
  int last = -1;
  for (char ch : input) {
    const char* digit = strchr(hexDigits, ch);
    if (digit == nullptr) {
      continue;
    }
    int nibble = digit - hexDigits;
    if (last < 0) {
      last = nibble;
    } else {
      v.push_back(static_cast<uint8_t>((last << 4) | nibble));
      last = -1;
    }
  }
  return v;
}

template<typename T>
std::string
toString(const T& obj) {
  std::string s;
  bool ok = boost::conversion::try_lexical_convert(obj, s);
  return ok ? s : "boost::bad_lexical_cast";
}

} // namespace test
} // namespace ndnph

#endif // NDNPH_TEST_COMMON_HPP
