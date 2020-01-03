#ifndef NDNPH_PACKET_DATA_HPP
#define NDNPH_PACKET_DATA_HPP

#include "../core/in-region.hpp"
#include "../tlv/encoder.hpp"
#include "../tlv/nni.hpp"
#include "name.hpp"

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
  uint32_t freshnessPeriod = DefaultFreshnessPeriod;
  uint8_t contentType = DefaultContentType;
  bool isFinalBlock = false;
};

} // namespace detail

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

  void encodeTo(Encoder& encoder) const
  {
    encoder.prependTlv(
      TT::Data, getName(),
      [this](Encoder& encoder) {
        encoder.prependTlv(
          TT::MetaInfo, Encoder::OmitEmpty,
          [this](Encoder& encoder) {
            if (getContentType() != detail::DataObj::DefaultContentType) {
              encoder.prependTlv(TT::ContentType, tlv::NNI(getContentType()));
            }
          },
          [this](Encoder& encoder) {
            if (getFreshnessPeriod() !=
                detail::DataObj::DefaultFreshnessPeriod) {
              encoder.prependTlv(TT::FreshnessPeriod,
                                 tlv::NNI(getFreshnessPeriod()));
            }
          },
          [this](Encoder& encoder) {
            if (getIsFinalBlock()) {
              auto comp = getName()[-1];
              encoder.prependTlv(TT::FinalBlockId,
                                 tlv::Value(comp.tlv(), comp.size()));
            }
          });
      },
      [this](Encoder& encoder) {
        encoder.prependTlv(TT::Content, Encoder::OmitEmpty, getContent());
      });
  }
};

} // namespace ndnph

#endif // NDNPH_PACKET_DATA_HPP
