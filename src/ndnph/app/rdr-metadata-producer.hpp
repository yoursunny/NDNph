#ifndef NDNPH_APP_RDR_METADATA_PRODUCER_HPP
#define NDNPH_APP_RDR_METADATA_PRODUCER_HPP

#include "../face/packet-handler.hpp"
#include "../keychain/digest.hpp"

namespace ndnph {

/**
 * @brief Producer of RDR metadata packet.
 * @sa https://redmine.named-data.net/projects/ndn-tlv/wiki/RDR
 *
 * This is typically used together with SegmentProducer to serve a versioned dataset.
 * When a new version becomes available, application shall invoke @c SegmentProducer::setContent
 * and @c RdrMetadataProducer::setDatasetPrefix with the same prefix.
 */
class RdrMetadataProducer : public PacketHandler
{
public:
  /** @brief Return '32=metadata' keyword component. */
  static Component getMetadataKeywordComponent()
  {
    static const uint8_t tlv[]{ 0x20, 0x08, 0x6D, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61 };
    static Component comp = Component::constant(tlv, sizeof(tlv));
    return comp;
  }

  struct Options
  {
    const PrivateKey& signer = DigestKey::get();
    uint32_t freshnessPeriod = 1;
  };

  /**
   * @brief Constructor.
   * @param rdrPrefix prefix of metadata packets; must end with '32=metadata'.
   * @param face face for communication.
   * @param region region for Data encoding; may be shared.
   * @param opts options.
   */
  explicit RdrMetadataProducer(const Name& rdrPrefix, Face& face, Region& region, Options opts)
    : PacketHandler(face)
    , m_rdrPrefix(rdrPrefix)
    , m_region(region)
    , m_opts(std::move(opts))
  {
    assert(m_rdrPrefix[-1] == getMetadataKeywordComponent());

    port::RandomSource::generate(reinterpret_cast<uint8_t*>(&m_version), sizeof(m_version));
    m_version = m_version & ~0xFFFFFFFF;
  }

  explicit RdrMetadataProducer(const Name& rdrPrefix, Face& face, Region& region)
    : RdrMetadataProducer(rdrPrefix, face, region, Options())
  {}

  /**
   * @brief Set the dataset prefix.
   * @param datasetPrefix the dataset prefix to appear in RDR metadata packet.
   */
  void setDatasetPrefix(Name datasetPrefix)
  {
    m_datasetPrefix = datasetPrefix;
    ++m_version;
  }

private:
  bool processInterest(Interest interest) final
  {
    const Name& interestName = interest.getName();
    if (!m_datasetPrefix || interestName != m_rdrPrefix || !interest.getCanBePrefix() ||
        !interest.getMustBeFresh()) {
      return false;
    }

    m_region.reset();
    Data data = m_region.create<Data>();
    assert(!!data);
    data.setName(m_rdrPrefix.append(m_region, { convention::Version::create(m_region, m_version),
                                                convention::Segment::create(m_region, 0) }));
    data.setFreshnessPeriod(m_opts.freshnessPeriod);
    data.setIsFinalBlock(true);
    data.setContent(prepareRdrContent());

    reply(data.sign(m_opts.signer));
    return true;
  }

  /**
   * @brief Prepare Content of RDR metadata packet.
   *
   * Subclass can override this method to add extensions in the Content.
   */
  virtual tlv::Value prepareRdrContent()
  {
    Encoder contentEncoder(m_region);
    contentEncoder.prepend(m_datasetPrefix);
    contentEncoder.trim();
    return tlv::Value(contentEncoder.begin(), contentEncoder.end());
  }

protected:
  Name m_rdrPrefix;
  Region& m_region;
  Options m_opts;
  uint64_t m_version = 0;
  Name m_datasetPrefix;
};

} // namespace ndnph

#endif // NDNPH_APP_RDR_METADATA_PRODUCER_HPP
