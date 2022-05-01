#ifndef NDNPH_TLV_EV_DECODER_HPP
#define NDNPH_TLV_EV_DECODER_HPP

#include "nni.hpp"

namespace ndnph {
namespace detail {

template<int type, bool repeatable, int order>
struct EvdElementDefBase
{
  using TT = std::integral_constant<int, type>;
  using Repeatable = std::integral_constant<bool, repeatable>;
  using Order = std::integral_constant<int, order>;
};

template<int type, bool repeatable, int order, typename Fn>
class EvdElementDefVoid : public EvdElementDefBase<type, repeatable, order>
{
public:
  explicit EvdElementDefVoid(const Fn& f)
    : m_f(f)
  {}

  bool operator()(const Decoder::Tlv& d) const
  {
    m_f(d);
    return true;
  }

private:
  const Fn& m_f;
};

template<int type, bool repeatable, int order, typename Fn>
class EvdElementDefBool : public EvdElementDefBase<type, repeatable, order>
{
public:
  explicit EvdElementDefBool(const Fn& f)
    : m_f(f)
  {}

  bool operator()(const Decoder::Tlv& d) const
  {
    return m_f(d);
  }

private:
  const Fn& m_f;
};

template<int type, bool repeatable, int order, typename Fn,
         typename R = typename std::conditional<
           std::is_convertible<decltype(std::declval<Fn>()(Decoder::Tlv())), bool>::value,
           EvdElementDefBool<type, repeatable, order, Fn>,
           EvdElementDefVoid<type, repeatable, order, Fn>>::type>
class EvdElementDefFn : public R
{
public:
  using R::R;
};

template<int type, bool repeatable, int order, typename Decodable>
class EvdElementDefDecodable : public EvdElementDefBase<type, repeatable, order>
{
public:
  explicit EvdElementDefDecodable(Decodable* obj)
    : m_obj(obj)
  {}

  bool operator()(const Decoder::Tlv& d) const
  {
    return m_obj->decodeFrom(d);
  }

private:
  Decodable* m_obj;
};

template<int type, bool repeatable, int order>
struct EvdElementDefIgnore : public EvdElementDefBase<type, repeatable, order>
{
  bool operator()(const Decoder::Tlv&) const
  {
    return true;
  }
};

template<int type, int order, typename NniClass, typename ValueType>
class EvdElementDefNni : public EvdElementDefBase<type, false, order>
{
public:
  explicit EvdElementDefNni(ValueType* value)
    : m_value(value)
  {}

  bool operator()(const Decoder::Tlv& d) const
  {
    return NniClass::decode(d, *m_value);
  }

private:
  ValueType* m_value;
};

} // namespace detail

/** @brief TLV decoder that understands Packet Format v0.3 evolvability guidelines. */
class EvDecoder
{
public:
  class DefaultUnknownCb
  {
  public:
    bool operator()(const Decoder::Tlv&, int&) const
    {
      return false;
    }
  };

  class DefaultIsCritical
  {
  public:
    bool operator()(uint32_t type) const
    {
      return type <= 0x1F || type % 2 == 1;
    }
  };

  /**
   * @brief Decode input TLV with a sequence of element definitions.
   *
   * Compare to decodeEx(), decode() does not allow customizing unknownCb and isCritical.
   */
  template<typename... E>
  static bool decode(const Decoder::Tlv& input, std::initializer_list<uint32_t> topTypes,
                     const E&... defs)
  {
    return decodeEx(input, topTypes, DefaultUnknownCb(), DefaultIsCritical(), defs...);
  }

  /**
   * @brief Decode input TLV-VALUE with a sequence of element definitions.
   *
   * Compare to decodeValueEx(), decodeValue() does not allow customizing unknownCb and isCritical.
   */
  template<typename... E>
  static bool decodeValue(const Decoder& input, const E&... defs)
  {
    return decodeValueEx(input, DefaultUnknownCb(), DefaultIsCritical(), defs...);
  }

  /**
   * @brief Decode input TLV with a sequence of element definitions.
   * @tparam UnknownCallback `bool (*)(const Decoder::Tlv& d, int& currentOrder)`,
   *                         return true to indicate TLV has been accepted.
   * @tparam IsCritical `bool (*)(uint32_t type)`
   * @tparam E ElementDef
   * @param input TLV element from Decoder.
   * @param topTypes a list of acceptable top-level TLV-TYPE numbers;
   *                 if empty, top-level TLV-TYPE is not checked.
   * @param unknownCb callback to handle TLV with TLV-TYPE number not in defs.
   * @param isCritical callback to determine whether an unrecognized TLV-TYPE number
   *                   is 'critical' and should cause a decode error.
   * @param defs a sequence of ElementDef to recognize each sub TLV element.
   */
  template<typename UnknownCallback, typename IsCritical, typename... E>
  static bool decodeEx(const Decoder::Tlv& input, std::initializer_list<uint32_t> topTypes,

                       const UnknownCallback& unknownCb, const IsCritical& isCritical,
                       const E&... defs)
  {
    if (topTypes.size() > 0 &&
        std::find(topTypes.begin(), topTypes.end(), input.type) == topTypes.end()) {
      return false;
    }
    return decodeValueEx(input.vd(), unknownCb, isCritical, defs...);
  }

  /** @brief Decode input TLV-VALUE with a sequence of element definitions. */
  template<typename UnknownCallback, typename IsCritical, typename... E>
  static bool decodeValueEx(const Decoder& input, const UnknownCallback& unknownCb,
                            const IsCritical& isCritical, const E&... defs)
  {
    int currentOrder = 0;
    for (const auto& d : input) {
      bool ok = decodeElement<AUTO_ORDER_SKIP>(d, currentOrder, unknownCb, isCritical, defs...);
      if (!ok) {
        return false;
      }
    }
    return true;
  }

  /**
   * @brief Create an element definition.
   * @tparam type TLV-TYPE number.
   * @tparam repeatable whether the TLV can be repeated.
   * @tparam order customized order number. Elements must appear in the TLV-VALUE
   *               in a certain order. By default, the order of defs passed to
   *               decode() determines the expected order. This parameter allows
   *               overriding the default order.
   * @tparam Fn `bool (*)(const Decoder::Tlv&)` or `void (*)(const Decoder::Tlv&)`
   * @param f function to process TLV element.
   */
  template<int type, bool repeatable = false, int order = 0, typename Fn = void,
           typename R = detail::EvdElementDefFn<type, repeatable, order, Fn>>
  static R def(const Fn& f, decltype(&Fn::operator()) = nullptr)
  {
    return R(f);
  }

  /**
   * @brief Create an element definition.
   * @tparam Decodable class with `bool decodeFrom(const Decoder::Tlv&)` method.
   */
  template<int type, bool repeatable = false, int order = 0, typename Decodable = void,
           typename R = detail::EvdElementDefDecodable<type, repeatable, order, Decodable>>
  static R def(Decodable* decodable, decltype(&Decodable::decodeFrom) = nullptr)
  {
    return R(decodable);
  }

  /** @brief Create an element definition to ignore a field. */
  template<int type, bool repeatable = false, int order = 0,
           typename R = detail::EvdElementDefIgnore<type, repeatable, order>>
  static R defIgnore()
  {
    return R();
  }

  /**
   * @brief Create an element definition for Non-Negative Integer field.
   * @tparam NniClass either tlv::NNI or a fixed-length variant.
   */
  template<int type, typename NniClass = tlv::NNI, int order = 0, typename ValueType = void,
           typename R = detail::EvdElementDefNni<type, order, NniClass, ValueType>>
  static R defNni(ValueType* value)
  {
    return R(value);
  }

private:
  EvDecoder() = delete;

  enum
  {
    AUTO_ORDER_SKIP = 100,
  };

  template<int autoOrder, typename UnknownCallback, typename IsCritical, typename First,
           typename... E>
  static bool decodeElement(const Decoder::Tlv& d, int& currentOrder,
                            const UnknownCallback& unknownCb, const IsCritical& isCritical,
                            const First& first, const E&... defs)
  {
    if (d.type == First::TT::value) {
      return useDef<autoOrder>(d, currentOrder, isCritical, first);
    }
    return decodeElement<autoOrder + AUTO_ORDER_SKIP>(d, currentOrder, unknownCb, isCritical,
                                                      defs...);
  }

  template<int autoOrder, typename UnknownCallback, typename IsCritical>
  static bool decodeElement(const Decoder::Tlv& d, int& currentOrder,
                            const UnknownCallback& unknownCb, const IsCritical& isCritical)
  {
    return unknownCb(d, currentOrder) || handleUnrecognized(d, isCritical);
  }

  template<int autoOrder, typename IsCritical, typename E>
  static bool useDef(const Decoder::Tlv& d, int& currentOrder, const IsCritical& isCritical,
                     const E& def)
  {
    int defOrder = E::Order::value == 0 ? autoOrder : E::Order::value;
    if (currentOrder > defOrder) {
      return handleUnrecognized(d, isCritical); // out of order
    }
    if (currentOrder == defOrder && !E::Repeatable::value) {
      return false; // cannot repeat
    }
    currentOrder = defOrder;
    return def(d);
  }

  template<typename IsCritical>
  static bool handleUnrecognized(const Decoder::Tlv& d, const IsCritical& isCritical)
  {
    return !isCritical(d.type);
  }
};

} // namespace ndnph

#endif // NDNPH_TLV_EV_DECODER_HPP
