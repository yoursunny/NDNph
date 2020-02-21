#ifndef NDNPH_APP_SEGMENT_PRODUCER_HPP
#define NDNPH_APP_SEGMENT_PRODUCER_HPP

#include "../face/packet-handler.hpp"
#include "../keychain/digest-key.hpp"

namespace ndnph {

class SegmentProducerBase : public PacketHandler
{
public:
  struct Options
  {
    const PrivateKey& signer = DigestKey::get();

    /** @brief Maximum Content TLV-VALUE in each segment. */
    size_t contentLen = 1000;

    uint32_t freshnessPeriod = 1000;

    /**
     * @brief Name discovery setting.
     *
     * @c 0 Interest name must equal Data name, i.e. include the segment number.
     * @c 1 Interest name can have 1 fewer component than Data name.
     *      Suppose Data name ends with version and segment components, Interest name must
     *      specify version component but may omit segment component.
     * @c 2 Interest name can have 2 fewer components than Data name.
     *      Suppose Data name ends with version and segment components, Interest name may
     *      omit these two components, achieving a simple form of version discovery.
     */
    int discovery = 2;
  };

  /**
   * @brief Constructor.
   * @param face face for communication.
   * @param region region for Data encoding; may be shared.
   * @param opts options.
   */
  explicit SegmentProducerBase(Face& face, Region& region, Options opts)
    : PacketHandler(face)
    , m_region(region)
    , m_opts(std::move(opts))
  {}

  explicit SegmentProducerBase(Face& face, Region& region)
    : SegmentProducerBase(face, region, Options())
  {}

  /**
   * @brief Set or change served content.
   * @param prefix name prefix.
   * @param content content pointer.
   * @param size content size.
   * @note All arguments must be kept alive until setContent() is called again.
   */
  void setContent(Name prefix, const uint8_t* content, size_t size)
  {
    m_prefix = prefix;
    m_content = content;
    m_size = size;

    auto d = std::ldiv(size, m_opts.contentLen);
    m_lastSegment = d.quot - static_cast<int>(size > 0 && d.rem == 0);
  }

protected:
  Region& m_region;
  Options m_opts;
  Name m_prefix;
  uint64_t m_lastSegment = 0;
  const uint8_t* m_content = nullptr;
  size_t m_size = 0;
};

/** @brief Producer of segmented object. */
template<typename SegmentConvention = convention::Segment>
class BasicSegmentProducer : public SegmentProducerBase
{
public:
  using SegmentProducerBase::SegmentProducerBase;

private:
  bool processInterest(Interest interest) final
  {
    if (!m_prefix || m_content == nullptr) {
      return false;
    }

    const Name& interestName = interest.getName();
    size_t dataNameSize = m_prefix.size() + 1;
    if (interestName.size() == dataNameSize) {
      auto lastComp = interestName[-1];
      if (!m_prefix.isPrefixOf(interestName) || !lastComp.is<SegmentConvention>()) {
        return false;
      }
      return replySegment(lastComp.as<SegmentConvention>());
    }

    if (interestName.size() >= dataNameSize - m_opts.discovery &&
        interestName.isPrefixOf(m_prefix) && interest.getCanBePrefix()) {
      return replySegment(0);
    }
    return false;
  }

  bool replySegment(uint64_t segment)
  {
    if (segment > m_lastSegment) {
      return false;
    }

    m_region.reset();
    Data data = m_region.create<Data>();
    assert(!!data);
    data.setName(m_prefix.append<SegmentConvention>(m_region, segment));
    data.setFreshnessPeriod(m_opts.freshnessPeriod);
    data.setIsFinalBlock(segment == m_lastSegment);
    data.setContent(
      tlv::Value(m_content + m_opts.contentLen * segment,
                 m_content + std::min<size_t>(m_opts.contentLen * (segment + 1), m_size)));
    reply(data.sign(m_opts.signer));
    return true;
  }
};

using SegmentProducer = BasicSegmentProducer<>;

} // namespace ndnph

#endif // NDNPH_APP_SEGMENT_PRODUCER_HPP
