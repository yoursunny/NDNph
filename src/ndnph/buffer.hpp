#ifndef NDNPH_BUFFER_HPP
#define NDNPH_BUFFER_HPP

#include "common.hpp"

namespace ndnph {

/**
 * @brief Memory owner of NDN elements.
 */
class Buffer
{
public:
  /** @brief Allocate a buffer with no alignment requirement. */
  uint8_t* alloc(size_t size)
  {
    if (m_right - m_left < static_cast<ssize_t>(size)) {
      return nullptr;
    }
    m_right -= size;
    return m_right;
  }

  /** @brief Duplicate an input string. */
  uint8_t* dup(const uint8_t* input, size_t size)
  {
    uint8_t* copy = alloc(size);
    if (copy != nullptr) {
      std::copy_n(input, size, copy);
    }
    return copy;
  }

  /** @brief Allocate a buffer aligned to multiple of sizeof(void*). */
  uint8_t* allocA(size_t size)
  {
    if (size % NDNPH_ALIGNMENT != 0) {
      size = (size | (NDNPH_ALIGNMENT - 1)) + 1;
    }
    if (m_right - m_left < static_cast<ssize_t>(size)) {
      return nullptr;
    }
    uint8_t* room = m_left;
    m_left += size;
    return room;
  }

  /**
   * @brief Allocate and create an object.
   */
  template<typename ObjType, typename... Arg>
  ObjType* createObj(size_t sizeofObj, const Arg&... arg)
  {
    uint8_t* ptr = this->allocA(sizeofObj);
    if (ptr == nullptr) {
      return nullptr;
    }
    return new (ptr) ObjType(*this, arg...);
  }

  /**
   * @brief Allocate and create an object, and make its reference.
   */
  template<typename RefType, typename ObjType, typename... Arg>
  RefType createRef(size_t sizeofObj, const Arg&... arg)
  {
    ObjType* obj = createObj<ObjType>(sizeofObj, arg...);
    if (obj == nullptr) {
      return RefType{};
    }
    return RefType{ *obj };
  }

  /**
   * @brief Allocate and create an object, and return its reference.
   */
  template<typename RefType, typename... Arg>
  RefType create(const Arg&... arg)
  {
    using ObjType = typename RefType::ObjType;
    static_assert(std::is_same<RefType, typename ObjType::RefType>::value, "");
    return createRef<RefType, ObjType>(sizeof(ObjType), arg...);
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

  /** @brief Compute utilized space. */
  size_t size() const { return (m_left - m_begin) + (m_end - m_right); }

protected:
  Buffer(uint8_t* buf, size_t cap)
    : m_begin(buf)
    , m_end(buf + cap)
  {
    reset();
  }

  ~Buffer() = default;

protected:
  uint8_t* const m_begin;
  uint8_t* const m_end;
  uint8_t* m_left;
  uint8_t* m_right;
};

namespace detail {

class InBuffer
{
public:
  InBuffer(InBuffer&&) = default;
  InBuffer& operator=(InBuffer&&) = default;

protected:
  explicit InBuffer(Buffer& buffer)
    : buffer(buffer)
  {}

  InBuffer(const InBuffer&) = delete;
  InBuffer& operator=(const InBuffer&) = delete;

protected:
  Buffer& buffer;
};

} // namespace detail

/**
 * @brief Statically allocated buffer.
 * @tparam C capacity.
 */
template<int C>
class StaticBuffer : public Buffer
{
public:
  StaticBuffer()
    : Buffer(m_array, sizeof(m_array))
  {}

  ~StaticBuffer() = default;

private:
  uint8_t m_array[C];
};

/**
 * @brief Dynamically allocated buffer.
 */
class DynamicBuffer : public Buffer
{
public:
  DynamicBuffer(size_t capacity)
    : Buffer(new uint8_t[capacity], capacity)
  {}

  ~DynamicBuffer() { delete[] m_begin; }
};

} // namespace ndnph

#endif // NDNPH_BUFFER_HPP
