#ifndef NDNPH_PACKET_DATA_HPP
#define NDNPH_PACKET_DATA_HPP

#include "../keychain/private-key.hpp"
#include "../keychain/public-key.hpp"
#include "../port/sha256/port.hpp"
#include "convention.hpp"

namespace ndnph {
namespace detail {

/** @brief Fields in Data signature. */
struct DataSigned
{
  DSigInfo sigInfo;
  tlv::Value sigValue;
  tlv::Value signedPortion;
  tlv::Value wholePacket;
};

/** @brief Fields in Data. */
class DataObj : public InRegion
{
public:
  explicit DataObj(Region& region)
    : InRegion(region)
  {}

  enum
  {
    DefaultContentType = ContentType::Blob,
    DefaultFreshnessPeriod = 0,
  };

public:
  DataSigned* sig = nullptr;
  Name name;
  tlv::Value content;
  uint32_t freshnessPeriod = DefaultFreshnessPeriod;
  uint8_t contentType = DefaultContentType;
  bool isFinalBlock = false;
};

class SignedDataRef : public RefRegion<DataObj>
{
public:
  explicit SignedDataRef() = default;

  explicit SignedDataRef(DataObj* data, const PrivateKey& key, DSigInfo sigInfo)
    : RefRegion(data)
    , m_key(&key)
  {
    key.updateSigInfo(sigInfo);
    m_sigInfo = std::move(sigInfo);
  }

  void encodeTo(Encoder& encoder) const
  {
    if (m_key == nullptr) {
      encoder.setError();
      return;
    }

    const uint8_t* afterSig = encoder.begin();
    size_t maxSigLen = m_key->getMaxSigLen();
    uint8_t* sigBuf = encoder.prependRoom(maxSigLen);
    encoder.prependTypeLength(TT::DSigValue, maxSigLen);
    const uint8_t* afterSignedPortion = encoder.begin();
    encodeSignedPortion(encoder);
    if (!encoder) {
      return;
    }

    tlv::Value signedPortion(encoder.begin(), afterSignedPortion);
    ssize_t sigLen = m_key->sign({ signedPortion }, sigBuf);
    if (sigLen < 0) {
      encoder.setError();
      return;
    }

    encoder.resetFront(const_cast<uint8_t*>(afterSig));
    encoder.prependTlv(
      TT::Data,
      [=](Encoder& encoder) {
        uint8_t* room = encoder.prependRoom(signedPortion.size());
        assert(room != nullptr);
        if (room != signedPortion.begin()) {
          std::memmove(room, signedPortion.begin(), signedPortion.size());
        }
      },
      [=](Encoder& encoder) {
        uint8_t* room = encoder.prependRoom(sigLen);
        assert(room != nullptr);
        if (room != sigBuf) {
          std::memmove(room, sigBuf, sigLen);
        }
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
            if (obj->contentType != DataObj::DefaultContentType) {
              encoder.prependTlv(TT::ContentType, tlv::NNI(obj->contentType));
            }
          },
          [this](Encoder& encoder) {
            if (obj->freshnessPeriod != DataObj::DefaultFreshnessPeriod) {
              encoder.prependTlv(TT::FreshnessPeriod, tlv::NNI(obj->freshnessPeriod));
            }
          },
          [this](Encoder& encoder) {
            if (obj->isFinalBlock) {
              auto comp = obj->name[-1];
              encoder.prependTlv(TT::FinalBlock, tlv::Value(comp.tlv(), comp.size()));
            }
          });
      },
      [this](Encoder& encoder) {
        encoder.prependTlv(TT::Content, Encoder::OmitEmpty, obj->content);
      },
      m_sigInfo);
  }

private:
  const PrivateKey* m_key = nullptr;
  DSigInfo m_sigInfo;
};

} // namespace detail

/** @brief Data packet. */
class Data
  : public Printable
  , public RefRegion<detail::DataObj>
{
public:
  using RefRegion::RefRegion;

  const Name& getName() const
  {
    return obj->name;
  }

  void setName(const Name& v)
  {
    obj->name = v;
  }

  uint8_t getContentType() const
  {
    return obj->contentType;
  }

  void setContentType(uint8_t v)
  {
    obj->contentType = v;
  }

  uint32_t getFreshnessPeriod() const
  {
    return obj->freshnessPeriod;
  }

  void setFreshnessPeriod(uint32_t v)
  {
    obj->freshnessPeriod = v;
  }

  bool getIsFinalBlock() const
  {
    return obj->isFinalBlock;
  }

  void setIsFinalBlock(bool v)
  {
    obj->isFinalBlock = v;
  }

  tlv::Value getContent() const
  {
    return obj->content;
  }

  void setContent(tlv::Value v)
  {
    obj->content = std::move(v);
  }

  /**
   * @brief Retrieve SignatureInfo.
   * @pre only available on decoded packet.
   */
  const DSigInfo* getSigInfo() const
  {
    return obj->sig == nullptr ? nullptr : &obj->sig->sigInfo;
  }

  /**
   * @brief Prepend the original packet to Encoder.
   * @pre only available on decoded packet.
   */
  void encodeTo(Encoder& encoder) const
  {
    if (obj->sig == nullptr) {
      encoder.setError();
      return;
    }
    obj->sig->wholePacket.encodeTo(encoder);
  }

  /** @brief Decode packet. */
  bool decodeFrom(const Decoder::Tlv& input)
  {
    obj->sig = regionOf(obj).template make<detail::DataSigned>();
    if (obj->sig == nullptr) {
      return false;
    }
    obj->sig->wholePacket = tlv::Value(input.tlv, input.size);
    return EvDecoder::decode(
      input, { TT::Data }, EvDecoder::def<TT::Name>(&obj->name),
      EvDecoder::def<TT::MetaInfo>([this](const Decoder::Tlv& d) {
        return EvDecoder::decode(d, {}, EvDecoder::defNni<TT::ContentType>(&obj->contentType),
                                 EvDecoder::defNni<TT::FreshnessPeriod>(&obj->freshnessPeriod),
                                 EvDecoder::def<TT::FinalBlock>([this](const Decoder::Tlv& d) {
                                   auto comp = getName()[-1];
                                   setIsFinalBlock(
                                     d.length == comp.size() &&
                                     std::equal(d.value, d.value + d.length, comp.tlv()));
                                 }));
      }),
      EvDecoder::def<TT::Content>(&obj->content), EvDecoder::def<TT::DSigInfo>(&obj->sig->sigInfo),
      EvDecoder::def<TT::DSigValue>([this, &input](const Decoder::Tlv& d) {
        obj->sig->signedPortion = tlv::Value(input.value, d.tlv);
        return obj->sig->sigValue.decodeFrom(d);
      }));
  }

  /**
   * @brief Encode then decode as Data packet.
   *
   * This is useful for obtaining a Data packet in decoded state from the result of signing.
   */
  template<typename Encodable>
  bool decodeFrom(Encodable&& encodable)
  {
    if (obj == nullptr) {
      return false;
    }
    Encoder encoder(regionOf(obj));
    if (!encoder.prepend(std::forward<Encodable>(encodable))) {
      encoder.discard();
      return false;
    }
    encoder.trim();
    return Decoder(encoder.begin(), encoder.size()).decode(*this);
  }

  /** @brief Result of Data::sign operation. */
  using Signed = detail::SignedDataRef;

  /**
   * @brief Sign the packet with a private key.
   * @return an Encodable object. This object is valid only if Data and PrivateKey are kept alive.
   *         It's recommended to pass it to Encoder immediately without saving as variable.
   * @note Unrecognized fields found during decoding are not preserved in encoding output.
   */
  Signed sign(const PrivateKey& key, DSigInfo sigInfo = DSigInfo()) const
  {
    return Signed(obj, key, std::move(sigInfo));
  }

  /**
   * @brief Verify the packet with a public key.
   * @pre only available on decoded packet.
   * @return verification result.
   */
  bool verify(const PublicKey& key) const
  {
    return obj->sig != nullptr && key.verify({ obj->sig->signedPortion },
                                             obj->sig->sigValue.begin(), obj->sig->sigValue.size());
  }

  /**
   * @brief Compute implicit digest.
   * @pre Data was decoded, not being constructed.
   * @return whether success.
   */
  bool computeImplicitDigest(uint8_t digest[NDNPH_SHA256_LEN]) const
  {
    if (obj->sig == nullptr) {
      return false;
    }
    port::Sha256 hash;
    hash.update(obj->sig->wholePacket.begin(), obj->sig->wholePacket.size());
    return hash.final(digest);
  }

  /**
   * @brief Obtain full name with implicit digest.
   * @sa @c computeImplicitDigest() .
   * @return full name, or a falsy value upon failure.
   */
  Name getFullName(Region& region) const
  {
    uint8_t digest[NDNPH_SHA256_LEN];
    if (!computeImplicitDigest(digest)) {
      return Name();
    }
    return getName().append(region, convention::ImplicitDigest(), digest);
  }

#ifdef NDNPH_PRINT_ARDUINO
  size_t printTo(::Print& p) const final
  {
    return p.print(getName());
  }
#endif
};

#ifdef NDNPH_PRINT_OSTREAM
inline std::ostream&
operator<<(std::ostream& os, const Data& data)
{
  return os << data.getName();
}
#endif

} // namespace ndnph

#endif // NDNPH_PACKET_DATA_HPP
