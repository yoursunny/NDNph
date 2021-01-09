#ifndef NDNPH_PACKET_ENCRYPTED_MESSAGE_HPP
#define NDNPH_PACKET_ENCRYPTED_MESSAGE_HPP

#include "../tlv/value.hpp"

namespace ndnph {

/**
 * @brief Encrypted message structure.
 * @tparam ivType TLV-TYPE of initialization-vector element.
 * @tparam ivLen TLV-LENGTH of initialization-vector element.
 * @tparam tagType TLV-TYPE of authentication-tag element.
 * @tparam tagLen TLV-LENGTH of authentication-tag element.
 * @tparam epType TLV-TYPE of encrypted-payload element.
 *
 * This class encodes and decodes in the following structure:
 *   encrypted-message =
 *     [initialization-vector] ; omitted only if ivLen == 0
 *     [authentication-tag]    ; omitted only if tagLen == 0
 *     encrypted-payload
 * Other structures are not supported.
 */
template<uint32_t ivType, size_t ivLen, uint32_t tagType, size_t tagLen, uint32_t epType>
class EncryptedMessage
{
public:
  using IvLen = std::integral_constant<size_t, ivLen>;
  using TagLen = std::integral_constant<size_t, tagLen>;

  struct InPlace
  {
    uint8_t* iv = nullptr;
    uint8_t* tag = nullptr;
    uint8_t* ciphertext = nullptr;
  };

  static InPlace prependInPlace(Encoder& encoder, size_t ciphertextLen)
  {
    InPlace result;
    result.ciphertext = encoder.prependRoom(ciphertextLen);
    encoder.prependTypeLength(epType, ciphertextLen);
    if (tagLen > 0) {
      result.tag = encoder.prependRoom(tagLen);
      encoder.prependTypeLength(tagType, tagLen);
    }
    if (ivLen > 0) {
      result.iv = encoder.prependRoom(ivLen);
      encoder.prependTypeLength(ivType, ivLen);
    }
    return result;
  }

  void encodeTo(Encoder& encoder) const
  {
    auto place = prependInPlace(encoder, ciphertext.size());
    if (!encoder) {
      return;
    }

    if (ivLen > 0) {
      std::copy(iv.begin(), iv.end(), place.iv);
    }
    if (tagLen > 0) {
      std::copy(tag.begin(), tag.end(), place.tag);
    }
    std::copy(ciphertext.begin(), ciphertext.end(), place.ciphertext);
  }

  bool decodeFrom(const Decoder::Tlv& d)
  {
    switch (d.type) {
      case ivType: {
        if (d.length == ivLen) {
          std::copy_n(d.value, ivLen, iv.begin());
          return true;
        }
        return false;
      }
      case tagType: {
        if (d.length == tagLen) {
          std::copy_n(d.value, tagLen, tag.begin());
          return true;
        }
        return false;
      }
      case epType: {
        ciphertext = tlv::Value(d.value, d.length);
        return true;
      }
    }
    return false;
  }

public:
  std::array<uint8_t, ivLen> iv;
  std::array<uint8_t, tagLen> tag;
  tlv::Value ciphertext;
};

} // namespace ndnph

#endif // NDNPH_PACKET_ENCRYPTED_MESSAGE_HPP
