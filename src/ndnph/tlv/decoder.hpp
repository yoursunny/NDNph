#ifndef NDNPH_TLV_DECODER_HPP
#define NDNPH_TLV_DECODER_HPP

#include "varnum.hpp"

namespace ndnph {

/** @brief TLV decoder. */
class Decoder
{
public:
  /** @brief Decoded TLV. */
  class Tlv
  {
  public:
    /** @brief Whether this TLV is invalid (e.g. dereference from past-end Iterator). */
    bool operator!() const
    {
      return size == 0;
    }

    /**
     * @brief Decode into target object.
     * @tparam class with `bool decodeFrom(const Decoder::Tlv&)` method.
     * @return whether success.
     * @pre target is newly constructed.
     * @post target may contain reference to the decoder's underlying input buffer.
     */
    template<typename T>
    bool decode(T& target) const
    {
      return !!*this && target.decodeFrom(*this);
    }

    /** @brief Create Decoder over TLV-VALUE. */
    Decoder vd() const
    {
      return Decoder(value, length);
    }

  public:
    uint32_t type = 0;
    size_t length = 0;
    const uint8_t* value = nullptr;

    const uint8_t* tlv = nullptr;
    size_t size = 0;
  };

  static bool readTlv(Tlv& d, const uint8_t* input, const uint8_t* end)
  {
    if (input == end) {
      d = Tlv{};
      return true;
    }
    int sizeofT = tlv::readVarNum(input, end - input, d.type);
    if (sizeofT == 0) {
      return false;
    }
    const uint8_t* posL = input + sizeofT;
    uint32_t length;
    int sizeofL = tlv::readVarNum(posL, end - posL, length);
    if (sizeofL == 0) {
      return false;
    }
    d.length = length;
    d.value = posL + sizeofL;
    d.tlv = input;
    d.size = sizeofT + sizeofL + length;
    return end - d.value >= static_cast<ssize_t>(length);
  }

  /** @brief Iterator over TLV elements. */
  class Iterator
  {
  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = const Tlv;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;

    explicit Iterator(const uint8_t* pos, const uint8_t* end)
      : m_pos(pos)
      , m_end(end)
    {
      tryRead();
    }

    /** @brief Whether a decoding error has occurred. */
    bool hasError() const
    {
      return m_pos == nullptr;
    }

    /**
     * @brief Increment to next TLV element.
     *
     * Incrementing past-end iterator is allowed and has no effect.
     */
    Iterator& operator++()
    {
      m_pos = m_tlv.value + m_tlv.length;
      tryRead();
      return *this;
    }

    Iterator operator++(int)
    {
      Iterator copy(*this);
      ++*this;
      return copy;
    }

    /**
     * @brief Obtain Decoder::Tlv.
     *
     * Dereferencing past-end iterator is allowed and returns empty Decoder::Tlv.
     */
    reference operator*()
    {
      return m_tlv;
    }

    pointer operator->()
    {
      return &m_tlv;
    }

    friend bool operator==(const Iterator& lhs, const Iterator& rhs)
    {
      return (lhs.m_end - lhs.m_pos) == (rhs.m_end - rhs.m_pos);
    }

  private:
    void tryRead()
    {
      if (readTlv(m_tlv, m_pos, m_end)) {
        return;
      }
      m_tlv = Tlv{};
      m_pos = m_end = nullptr;
    }

  private:
    const uint8_t* m_pos;
    const uint8_t* m_end;
    Tlv m_tlv;
  };

  explicit Decoder(const uint8_t* input, size_t count)
    : m_begin(input)
    , m_end(input + count)
  {}

  Iterator begin() const
  {
    return Iterator(m_begin, m_end);
  }

  Iterator end() const
  {
    return Iterator(m_end, m_end);
  }

  /**
   * @brief Decode first TLV into target object.
   * @sa Decoder::Tlv::decode
   */
  template<typename T>
  bool decode(T& target) const
  {
    return begin()->decode(target);
  }

private:
  const uint8_t* m_begin;
  const uint8_t* m_end;
};

NDNPH_DECLARE_NE(Decoder::Iterator)

} // namespace ndnph

#endif // NDNPH_TLV_DECODER_HPP
