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

  friend Region& regionOf(const InRegion* obj)
  {
    return obj->region;
  }
};

template<typename Obj>
class RefRegion
{
public:
  using ObjType = Obj;

  explicit RefRegion(ObjType* obj = nullptr)
    : obj(obj)
  {}

  explicit operator bool() const
  {
    return obj != nullptr;
  }

protected:
  ~RefRegion() = default;

protected:
  ObjType* obj = nullptr;

  friend Region& regionOf(const RefRegion<Obj>& ref)
  {
    return regionOf(ref.obj);
  }
};

} // namespace detail
} // namespace ndnph

#endif // NDNPH_CORE_IN_REGION_HPP
