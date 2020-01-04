#ifndef NDNPH_TLV_EV_DECODER_HPP
#define NDNPH_TLV_EV_DECODER_HPP

#include "decoder.hpp"

namespace ndnph {

/** @brief TLV-VALUE decoder that understands Packet Format v0.3 evolvability guidelines. */
class EvDecoder
{
public:
  class DefaultUnknownCb
  {
  public:
    bool operator()(const Decoder::Tlv&, int&) const { return false; }
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
   * @brief Decode input with a sequence of element definitions.
   *
   * Compare to decodeEx(), decode() does not allow customizing unknownCb and isCritical.
   */
  template<typename... E>
  static bool decode(const Decoder::Tlv& input,
                     std::initializer_list<uint32_t> topTypes, const E&... defs)
  {
    return decodeEx(input, topTypes, DefaultUnknownCb(), DefaultIsCritical(),
                    defs...);
  }

  /**
   * @brief Decode input with a sequence of element definitions.
   * @tparam UnknownCallback `bool (*)(const Decoder::Tlv& d, int& currentOrder)`,
   *                         return true to indicate TLV has been accepted.
   * @tparam IsCritical `bool (*)(uint32_t type)`
   * @tparam E ElementDef
   * @param input TLV element from Decoder.
   * @param topTypes a list of acceptable top-level TLV-TYPE numbers;
   *                 if empty, top-level TLV-TYPE is not checked.
   * @param unknownCb callback to handle TLV with unrecognized TLV-TYPE number.
   * @param isCritical callback to determine whether an unrecognized TLV-TYPE number
   *                   is 'critical' and should cause a decode error.
   * @param defs a sequence of ElementDef to recognize each sub TLV element.
   */
  template<typename UnknownCallback, typename IsCritical, typename... E>
  static bool decodeEx(const Decoder::Tlv& input,
                       std::initializer_list<uint32_t> topTypes,

                       const UnknownCallback& unknownCb,
                       const IsCritical& isCritical, const E&... defs)
  {
    if (topTypes.size() > 0) {
      bool found = false;
      for (uint32_t type : topTypes) {
        if (input.type == type) {
          found = true;
          break;
        }
      }
      if (!found) {
        return false;
      }
    }

    int currentOrder = 0;
    for (const auto& d : input.vd()) {
      bool ok = decodeElement<AUTO_ORDER_SKIP>(d, currentOrder, unknownCb,
                                               isCritical, defs...);
      if (!ok) {
        return false;
      }
    }
    return true;
  }

  template<int type, bool repeatable, int order, typename F>
  struct ElementDef
  {
    using TT = std::integral_constant<int, type>;
    using Repeatable = std::integral_constant<bool, repeatable>;
    using Order = std::integral_constant<int, order>;
    using ReturnBool = typename std::is_convertible<
      typename std::result_of<F(const Decoder::Tlv&)>::type, bool>::type;
    const F& f;
  };

  /**
   * @brief Create an element definition.
   * @tparam type TLV-TYPE number.
   * @tparam repeatable whether the TLV can be repeated.
   * @tparam order customized order number. Elements must appear in the TLV-VALUE
   *               in a certain order. By default, the order of defs passed to
   *               decode() determines the expected order. This parameter allows
   *               overriding the default order.
   * @tparam F `bool (*)(const Decoder::Tlv&)` or `void (*)(const Decoder::Tlv&)`
   * @param f function to process TLV element.
   */
  template<int type, bool repeatable = false, int order = 0, typename F = void>
  static ElementDef<type, repeatable, order, F> def(const F& f)
  {
    return ElementDef<type, repeatable, order, F>{ f };
  }

private:
  EvDecoder() = delete;

  enum
  {
    AUTO_ORDER_SKIP = 100,
  };

  template<int autoOrder, typename UnknownCallback, typename IsCritical,
           typename First, typename... E>
  static bool decodeElement(const Decoder::Tlv& d, int& currentOrder,
                            const UnknownCallback& unknownCb,
                            const IsCritical& isCritical, const First& first,
                            const E&... defs)
  {
    if (d.type == First::TT::value) {
      return useDef<autoOrder>(d, currentOrder, isCritical, first);
    }
    return decodeElement<autoOrder + AUTO_ORDER_SKIP>(
      d, currentOrder, unknownCb, isCritical, defs...);
  }

  template<int autoOrder, typename UnknownCallback, typename IsCritical>
  static bool decodeElement(const Decoder::Tlv& d, int& currentOrder,
                            const UnknownCallback& unknownCb,
                            const IsCritical& isCritical)
  {
    return unknownCb(d, currentOrder) || handleUnrecognized(d, isCritical);
  }

  template<int autoOrder, typename IsCritical, typename E>
  static bool useDef(const Decoder::Tlv& d, int& currentOrder,
                     const IsCritical& isCritical, const E& def)
  {
    int defOrder = E::Order::value == 0 ? autoOrder : E::Order::value;
    if (currentOrder > defOrder) {
      return handleUnrecognized(d, isCritical); // out of order
    }
    if (currentOrder == defOrder && !E::Repeatable::value) {
      return false; // cannot repeat
    }
    currentOrder = defOrder;
    return invokeDef(def, d);
  }

  template<typename E>
  static bool invokeDef(
    const E& def, const Decoder::Tlv& d,
    const typename std::enable_if<E::ReturnBool::value>::type* = nullptr)
  {
    return def.f(d);
  }

  template<typename E>
  static bool invokeDef(
    const E& def, const Decoder::Tlv& d,
    const typename std::enable_if<!E::ReturnBool::value>::type* = nullptr)
  {
    def.f(d);
    return true;
  }

  template<typename IsCritical>
  static bool handleUnrecognized(const Decoder::Tlv& d,
                                 const IsCritical& isCritical)
  {
    return !isCritical(d.type);
  }
};

} // namespace ndnph

#endif // NDNPH_TLV_EV_DECODER_HPP
