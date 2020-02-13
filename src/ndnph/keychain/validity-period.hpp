#ifndef NDNPH_KEYCHAIN_VALIDITY_PERIOD_HPP
#define NDNPH_KEYCHAIN_VALIDITY_PERIOD_HPP

#include "../tlv/encoder.hpp"

namespace ndnph {

/** @brief ValidityPeriod stub. */
class ValidityPeriod
{
public:
  void encodeTo(Encoder& encoder) const
  {
    const char* stubNotBefore = "20200212T000000";
    const char* stubNotAfter = "20201030T235959";
    encoder.prependTlv(
      TT::ValidityPeriod,
      [=](Encoder& encoder) {
        encoder.prependTlv(TT::NotBefore,
                           tlv::Value(reinterpret_cast<const uint8_t*>(stubNotBefore), 15));
      },
      [=](Encoder& encoder) {
        encoder.prependTlv(TT::NotAfter,
                           tlv::Value(reinterpret_cast<const uint8_t*>(stubNotAfter), 15));
      });
  }
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_VALIDITY_PERIOD_HPP
