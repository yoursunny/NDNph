#ifndef NDNPH_PACKET_SIG_INFO_HPP
#define NDNPH_PACKET_SIG_INFO_HPP

#include "../tlv/ev-decoder.hpp"
#include "../tlv/nni.hpp"
#include "name.hpp"

namespace ndnph {

class SigInfo
{
public:
  bool decodeFrom(const Decoder::Tlv& input)
  {
    return EvDecoder::decodeEx(
      input, { TT::ISigInfo, TT::DSigInfo },
      [this, &input](const Decoder::Tlv& d, int& currentOrder) {
        if (currentOrder < 1000) {
          extensions = tlv::Value(d.tlv, input.value + input.length - d.tlv);
          currentOrder = 1000;
        }
        return true;
      },
      EvDecoder::DefaultIsCritical(),
      EvDecoder::defNni<TT::SigType, tlv::NNI, 1>(&sigType),
      EvDecoder::def<TT::KeyLocator, false, 2>([this](const Decoder::Tlv& d) {
        return EvDecoder::decode(d, {}, EvDecoder::def<TT::Name>(&name));
      }));
  }

protected:
  ~SigInfo() = default;

  void encodeImpl(uint32_t type, Encoder& encoder) const
  {
    encoder.prependTlv(type,
                       [this](Encoder& encoder) {
                         encoder.prependTlv(TT::SigType, tlv::NNI(sigType));
                       },
                       [this](Encoder& encoder) {
                         if (name.size() > 0) {
                           encoder.prependTlv(TT::KeyLocator, name);
                         }
                       },
                       extensions);
  }

public:
  Name name;
  tlv::Value extensions;
  uint8_t sigType = 0;
};

class DSigInfo : public SigInfo
{
public:
  void encodeTo(Encoder& encoder) const
  {
    return encodeImpl(TT::DSigInfo, encoder);
  }
};

} // namespace ndnph

#endif // NDNPH_PACKET_SIG_INFO_HPP
