#ifndef NDNPH_CORE_IN_REGION_HPP
#define NDNPH_CORE_IN_REGION_HPP

#include "region.hpp"

namespace ndnph {
namespace detail {

class InRegion
{
public:
  InRegion(InRegion&&) = default;
  InRegion& operator=(InRegion&&) = default;

protected:
  explicit InRegion(Region& region)
    : region(region)
  {}

  InRegion(const InRegion&) = delete;
  InRegion& operator=(const InRegion&) = delete;

protected:
  Region& region;
};

} // namespace detail
} // namespace ndnph

#endif // NDNPH_CORE_IN_REGION_HPP
