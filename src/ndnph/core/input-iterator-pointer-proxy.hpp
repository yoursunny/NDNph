#ifndef NDNPH_CORE_INPUT_ITERATOR_POINTER_PROXY_HPP
#define NDNPH_CORE_INPUT_ITERATOR_POINTER_PROXY_HPP

namespace ndnph {
namespace detail {

/** @brief Wrap a value to appear as InputIterator::pointer. */
template<typename T>
class InputIteratorPointerProxy
{
public:
  InputIteratorPointerProxy(T&& item)
    : m_item(item)
  {}

  T* operator->() const { return &m_item; }

private:
  T m_item;
};

} // namespace detail
} // namespace ndnph

#endif // NDNPH_CORE_INPUT_ITERATOR_POINTER_PROXY_HPP
