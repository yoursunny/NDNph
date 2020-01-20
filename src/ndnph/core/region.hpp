#ifndef NDNPH_CORE_REGION_HPP
#define NDNPH_CORE_REGION_HPP

#include "common.hpp"

namespace ndnph {

/** @brief Region-based memory allocator thats owns memory of NDNph objects. */
class Region
{
public:
  enum
  {
    ALIGNMENT = sizeof(void*),
  };

  static constexpr size_t sizeofAligned(size_t size)
  {
    return size % ALIGNMENT == 0 ? size : (size | (ALIGNMENT - 1)) + 1;
  }

  Region(uint8_t* buf, size_t cap)
    : m_begin(buf)
    , m_end(buf + cap)
  {
    reset();
  }

  /** @brief Allocate a buffer with no alignment requirement. */
  uint8_t* alloc(size_t size)
  {
    if (m_right - m_left < static_cast<ssize_t>(size)) {
      return nullptr;
    }
    m_right -= size;
    return m_right;
  }

  /** @brief Deallocate (front part of) last buffer from alloc(). */
  bool free(const uint8_t* ptr, size_t size)
  {
    if (ptr != m_right || m_end - m_right < static_cast<ssize_t>(size)) {
      return false;
    }
    m_right += size;
    return true;
  }

  /** @brief Allocate a region aligned to multiple of sizeof(void*). */
  uint8_t* allocA(size_t size)
  {
    size = sizeofAligned(size);
    if (m_right - m_left < static_cast<ssize_t>(size)) {
      return nullptr;
    }
    uint8_t* room = m_left;
    m_left += size;
    return room;
  }

  /** @brief Allocate and create an item, and return its pointer. */
  template<typename T, typename... Arg>
  T* make(Arg&&... arg)
  {
    // Region allocator would not `delete` created objects, so it's safe to
    // create trivially destructible objects only.
    static_assert(std::is_trivially_destructible<T>::value, "");

    uint8_t* ptr = this->allocA(sizeof(T));
    if (ptr == nullptr) {
      return nullptr;
    }
    return new (ptr) T(std::forward<Arg>(arg)...);
  }

  /**
   * @brief Allocate and create an object, and return its reference.
   * @tparam RefType a subclass of detail::RefRegion<ObjType>,
   *                 where ObjType is a subclass of detail::InRegion.
   * @return a reference to the created object.
   * @warning If `!ref` is true on the returned reference, it indicates allocation failure.
   *          Using the reference in that case would cause segmentation fault.
   */
  template<typename RefType, typename... Arg>
  RefType create(Arg&&... arg)
  {
    using ObjType = typename RefType::ObjType;
    auto obj = make<ObjType>(*this, std::forward<Arg>(arg)...);
    return obj == nullptr ? RefType() : RefType(obj);
  }

  /**
   * @brief Discard allocated items.
   * @post Allocated items are invalidated.
   */
  void reset()
  {
    m_left = m_begin;
    m_right = m_end;
  }

  /** @brief Compute remaining space. */
  size_t available() const
  {
    return m_right - m_left;
  }

  /** @brief Compute utilized space. */
  size_t size() const
  {
    return m_end - m_begin - available();
  }

protected:
  uint8_t* getArray()
  {
    return m_begin;
  }

private:
  uint8_t* const m_begin;
  uint8_t* const m_end;
  uint8_t* m_left;  ///< [m_begin, m_left) is allocated for aligned items
  uint8_t* m_right; ///< [m_right, m_end) is allocated for unaligned items
};

/**
 * @brief Region with statically allocated memory.
 * @tparam C capacity.
 */
template<int C>
class StaticRegion : public Region
{
public:
  StaticRegion()
    : Region(m_array, sizeof(m_array))
  {}

  ~StaticRegion() = default;

private:
  uint8_t m_array[C];
};

/** @brief Region with dynamically allocated memory. */
class DynamicRegion : public Region
{
public:
  DynamicRegion(size_t capacity)
    : Region(new uint8_t[capacity], capacity)
  {}

  ~DynamicRegion()
  {
    delete[] getArray();
  }
};

/** @brief Compute total size of several sub Regions of given capacity. */
inline size_t
sizeofSubRegions(size_t capacity, size_t count = 1)
{
  return count * (Region::sizeofAligned(capacity) + Region::sizeofAligned(sizeof(Region)));
}

/** @brief Create Region inside a parent Region. */
inline Region*
makeSubRegion(Region& parent, size_t capacity)
{
  uint8_t* room = parent.allocA(capacity);
  if (room == nullptr) {
    return nullptr;
  }
  return parent.make<Region>(room, capacity);
}

} // namespace ndnph

#endif // NDNPH_CORE_REGION_HPP
