#ifndef NDNPH_PACKET_DATA_HPP
#define NDNPH_PACKET_DATA_HPP

#include "../core/in-region.hpp"
#include "sig-info.hpp"

namespace ndnph {
namespace detail {

class DataObj : public detail::InRegion
{
public:
  explicit DataObj(Region& region)
    : InRegion(region)
  {}

  enum
  {
    DefaultContentType = 0x00,
    DefaultFreshnessPeriod = 0,
  };

public:
  Name name;
  tlv::Value content;
  DSigInfo sigInfo;
  tlv::Value sigValue;
  tlv::Value signedPortion;
  uint32_t freshnessPeriod = DefaultFreshnessPeriod;
  uint8_t contentType = DefaultContentType;
  bool isFinalBlock = false;
};

template<typename Key>
class SignedDataRef : public RefRegion<DataObj>
{
public:
  explicit SignedDataRef(DataObj* data, const Key& key)
    : RefRegion(data)
    , m_key(key)
  {}

  void encodeTo(Encoder& encoder) const
  {
    m_key.updateSigInfo(obj->sigInfo);
    uint8_t* after = const_cast<uint8_t*>(encoder.begin());
    uint8_t* sigBuf = encoder.prependRoom(Key::MaxSigLength::value);
    encodeSignedPortion(encoder);
    if (!encoder) {
      return;
    }
    const uint8_t* signedPortion = encoder.begin();
    size_t sizeofSignedPortion = sigBuf - signedPortion;

    ssize_t sigLen =
      m_key.sign({ tlv::Value(signedPortion, sizeofSignedPortion) }, sigBuf);
    if (sigLen < 0) {
      encoder.setError();
      return;
    }
    if (sigLen != Key::MaxSigLength::value) {
      std::copy_backward(sigBuf, sigBuf + sigLen, after);
    }
    encoder.resetFront(after);

    encoder.prependTlv(
      TT::Data, [this](Encoder& encoder) { encodeSignedPortion(encoder); },
      [sigLen](Encoder& encoder) {
        encoder.prependRoom(sigLen); // room contains signature
        encoder.prependTypeLength(TT::DSigValue, sigLen);
      });
  }

private:
  void encodeSignedPortion(Encoder& encoder) const
  {
    encoder.prepend(
      obj->name,
      [this](Encoder& encoder) {
        encoder.prependTlv(
          TT::MetaInfo, Encoder::OmitEmpty,
          [this](Encoder& encoder) {
            if (obj->contentType != detail::DataObj::DefaultContentType) {
              encoder.prependTlv(TT::ContentType, tlv::NNI(obj->contentType));
            }
          },
          [this](Encoder& encoder) {
            if (obj->freshnessPeriod !=
                detail::DataObj::DefaultFreshnessPeriod) {
              encoder.prependTlv(TT::FreshnessPeriod,
                                 tlv::NNI(obj->freshnessPeriod));
            }
          },
          [this](Encoder& encoder) {
            if (obj->isFinalBlock) {
              auto comp = obj->name[-1];
              encoder.prependTlv(TT::FinalBlockId,
                                 tlv::Value(comp.tlv(), comp.size()));
            }
          });
      },
      [this](Encoder& encoder) {
        encoder.prependTlv(TT::Content, Encoder::OmitEmpty, obj->content);
      },
      obj->sigInfo);
  }

private:
  const Key& m_key;
};

} // namespace detail

/** @brief Data packet. */
class Data : public detail::RefRegion<detail::DataObj>
{
public:
  using RefRegion::RefRegion;

  const Name& getName() const { return obj->name; }
  void setName(const Name& v) { obj->name = v; }

  uint8_t getContentType() const { return obj->contentType; }
  void setContentType(uint8_t v) { obj->contentType = v; }

  uint32_t getFreshnessPeriod() const { return obj->freshnessPeriod; }
  void setFreshnessPeriod(uint32_t v) { obj->freshnessPeriod = v; }

  bool getIsFinalBlock() const { return obj->isFinalBlock; }
  void setIsFinalBlock(bool v) { obj->isFinalBlock = v; }

  tlv::Value getContent() const { return obj->content; }
  void setContent(tlv::Value v) { obj->content = std::move(v); }

  /**
   * @brief Sign the packet with a private key.
   * @tparam Key class with
   *             `void updateSigInfo(SigInfo& sigInfo) const`
   *             that writes SigType and KeyLocator into SigInfo, and
   *             `using MaxSigLength = std::integral_constant<int, L>`
   *             that indicates maximum possible signature length, and
   *             `ssize_t sign(std::initializer_list<tlv::Value> chunks, uint8_t* sig) const`
   *             that writes signature to sig[] and returns signature length or -1 on error.
   * @return an Encodable object. This object is valid only if Data and Key are kept alive.
   *         It's recommended to pass it to Encoder immediately without saving as variable.
   * @note Unrecognized fields found during decoding are not preserved in encoding output.
   * @note This method does not set sigValue. Packet is not verifiable after this operation.
   */
  template<typename Key, typename R = detail::SignedDataRef<Key>>
  R sign(const Key& key) const
  {
    return R(obj, key);
  }

  /** @brief Decode packet. */
  bool decodeFrom(const Decoder::Tlv& input)
  {
    return EvDecoder::decode(
      input, { TT::Data }, EvDecoder::def<TT::Name>(&obj->name),
      EvDecoder::def<TT::MetaInfo>([this](const Decoder::Tlv& d) {
        return EvDecoder::decode(
          d, {},
          EvDecoder::defNni<TT::ContentType, tlv::NNI>(&obj->contentType),
          EvDecoder::defNni<TT::FreshnessPeriod, tlv::NNI>(
            &obj->freshnessPeriod),
          EvDecoder::def<TT::FinalBlockId>([this](const Decoder::Tlv& d) {
            auto comp = getName()[-1];
            setIsFinalBlock(
              d.length == comp.size() &&
              std::equal(d.value, d.value + d.length, comp.tlv()));
          }));
      }),
      EvDecoder::def<TT::Content>(&obj->content),
      EvDecoder::def<TT::DSigInfo>(&obj->sigInfo),
      EvDecoder::def<TT::DSigValue>([this, &input](const Decoder::Tlv& d) {
        obj->signedPortion = tlv::Value(input.value, d.tlv - input.value);
        return obj->sigValue.decodeFrom(d);
      }));
  }

  /**
   * @brief Verify the packet with a public key.
   * @tparam Key class with
   *             `bool verify(std::initializer_list<tlv::Value> chunks, const uint8_t* sig,
                              size_t length) const`
   *             that performs verification and returns verification result.
   * @return verification result.
   *
   * This method only works on decoded packet. It does not work on packet that
   * has been modified or (re-)signed.
   */
  template<typename Key>
  bool verify(const Key& key) const
  {
    return key.verify({ obj->signedPortion }, obj->sigValue.begin(),
                      obj->sigValue.size());
  }
};

} // namespace ndnph

#endif // NDNPH_PACKET_DATA_HPP
