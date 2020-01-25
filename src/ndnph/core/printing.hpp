#ifndef NDNPH_CORE_PRINTING_HPP
#define NDNPH_CORE_PRINTING_HPP

#include "common.hpp"

#if defined(ARDUINO_ARCH_ESP32)
#define NDNPH_PRINT_ARDUINO
#include <Stream.h>
#include <StreamString.h>
#elif defined(ARDUINO)
#define NDNPH_PRINT_ARDUINO
#include <Print.h>
#include <Printable.h>
#else
#define NDNPH_PRINT_OSTREAM
#include <ostream>
#endif

namespace ndnph {
namespace detail {

#if defined(ARDUINO_ARCH_ESP32)

// On ESP32, ::Printable type is not trivially destructible because it has a virtual destructor.
// Consequently, it cannot serve as a base class in a type that needs to be allocated from Region.
// This Printable class is a workaround that relies on implicit conversion to ::String.
class Printable
{
public:
  operator String() const
  {
    StreamString ss;
    printTo(ss);
    return ss;
  }

  virtual size_t printTo(::Print& p) const = 0;
};

#elif defined(ARDUINO)

using Printable = ::Printable;

#else

// In non-Arduino environment, declare Printable as an empty class, so that implementers
// do not have to ifdef away the inheritance. It's still necessary to surround printTo function
// with ifdef, because Arduino ::Print class is absent.

class Printable
{
protected:
  ~Printable() = default;
};

#endif

} // namespace detail
} // namespace ndnph

#endif // NDNPH_CORE_PRINTING_HPP
