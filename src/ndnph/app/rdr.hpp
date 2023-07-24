#ifndef NDNPH_APP_RDR_HPP
#define NDNPH_APP_RDR_HPP

#include "../face/packet-handler.hpp"
#include "../keychain/digest.hpp"
#include "../keychain/null.hpp"

namespace ndnph {
namespace rdr {

/** @brief Return '32=metadata' component. */
inline Component
getMetadataComponent() {
  static const uint8_t tlv[]{0x20, 0x08, 'm', 'e', 't', 'a', 'd', 'a', 't', 'a'};
  static Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/**
 * @brief Parse RDR metadata packet.
 * @return enclosed versioned name, or a falsy value upon failure.
 */
inline Name
parseMetadata(Data data) {
  if (!data) {
    return Name();
  }

  Name datasetPrefix;
  bool ok = data.getContent().makeDecoder().decode(datasetPrefix);
  if (!ok) {
    return Name();
  }
  return datasetPrefix;
}

namespace detail {

inline Name
stripMetadataComponent(Name rdrPrefix) {
  return rdrPrefix[-1] == getMetadataComponent() ? rdrPrefix.getPrefix(-1) : rdrPrefix;
}

} // namespace detail

/**
 * @brief Producer of RDR metadata packet.
 * @sa https://redmine.named-data.net/projects/ndn-tlv/wiki/RDR
 *
 * This is typically used together with SegmentProducer to serve a versioned dataset.
 * When a new version becomes available, application shall invoke @c SegmentProducer::setContent
 * and @c RdrMetadataProducer::setDatasetPrefix with the same prefix.
 */
class RdrMetadataProducer : public PacketHandler {
public:
  struct Options {
    /**
     * @brief Initial version number.
     *
     * Default is a randomly generated version number.
     */
    uint64_t initialVersion;

    /**
     * @brief Data FreshnessPeriod.
     *
     * Default and minimum is 1.
     */
    uint32_t freshnessPeriod;

    /** @brief Data packet signer. */
    const PrivateKey& signer;
  };

  /**
   * @brief Constructor.
   * @param rdrPrefix prefix of metadata packets; must be kept alive until producer is destructed.
   * @param face face for communication.
   * @param opts options.
   */
  explicit RdrMetadataProducer(const Name& rdrPrefix, Face& face, const Options& opts)
    : PacketHandler(face)
    , m_rdrPrefix(detail::stripMetadataComponent(rdrPrefix))
    , m_signer(opts.signer)
    , m_version(opts.initialVersion)
    , m_freshness(std::max<uint32_t>(opts.freshnessPeriod, 1)) {
    if (m_version + 1 == 0) {
      port::RandomSource::generate(reinterpret_cast<uint8_t*>(&m_version), sizeof(m_version));
      m_version = m_version & ~0xFFFFFFFF;
    }
  }

  explicit RdrMetadataProducer(const Name& rdrPrefix, Face& face)
    : RdrMetadataProducer(rdrPrefix, face,
                          Options{
                            .initialVersion = std::numeric_limits<uint64_t>::max(),
                            .freshnessPeriod = 1,
                            .signer = DigestKey::get(),
                          }) {}

  /**
   * @brief Set the dataset prefix.
   * @param datasetPrefix the dataset prefix to appear in RDR metadata packet.
   */
  void setDatasetPrefix(Name datasetPrefix) {
    m_datasetPrefix = datasetPrefix;
    ++m_version;
  }

private:
  bool processInterest(Interest interest) final {
    const Name& interestName = interest.getName();
    if (!m_datasetPrefix || interestName.getPrefix(-1) != m_rdrPrefix ||
        interestName[-1] != getMetadataComponent() || !interest.getCanBePrefix() ||
        !interest.getMustBeFresh()) {
      return false;
    }

    StaticRegion<1024> region;
    Data data = region.create<Data>();
    NDNPH_ASSERT(!!data);
    data.setName(m_rdrPrefix.append(region, getMetadataComponent(), convention::Version(),
                                    m_version, convention::Segment(), 0));
    data.setFreshnessPeriod(m_freshness);
    data.setIsFinalBlock(true);

    Encoder contentEncoder(region);
    prepareRdrContent(contentEncoder, m_datasetPrefix);
    contentEncoder.trim();
    data.setContent(tlv::Value(contentEncoder));

    reply(data.sign(m_signer));
    return true;
  }

  /**
   * @brief Prepare Content of RDR metadata packet.
   *
   * Subclass can override this method to add extensions in the Content.
   */
  virtual void prepareRdrContent(Encoder& encoder, const Name& datasetPrefix) {
    encoder.prepend(datasetPrefix);
  }

private:
  Name m_rdrPrefix;
  const PrivateKey& m_signer;
  uint64_t m_version = 0;
  uint32_t m_freshness = 1;
  Name m_datasetPrefix;
};

/**
 * @brief Consumer of RDR metadata packet.
 * @sa https://redmine.named-data.net/projects/ndn-tlv/wiki/RDR
 */
class RdrMetadataConsumer : public PacketHandler {
public:
  using Callback = void (*)(void* ctx, Data data);

  struct Options {
    const PublicKey& verifier;
    uint16_t interestLifetime;
  };

  explicit RdrMetadataConsumer(Face& face, const Options& opts)
    : PacketHandler(face, 0x60)
    , m_pending(this)
    , m_verifier(opts.verifier)
    , m_interestLifetime(opts.interestLifetime) {}

  explicit RdrMetadataConsumer(Face& face)
    : RdrMetadataConsumer(face, Options{
                                  .verifier = NullKey::get(),
                                  .interestLifetime = 1000,
                                }) {}

  void start(Name rdrPrefix, Callback cb, void* ctx = nullptr) {
    invokeCallback(Data());

    m_rdrPrefix = detail::stripMetadataComponent(rdrPrefix);
    m_cb = cb;
    m_ctx = ctx;

    StaticRegion<1024> region;
    auto interest = region.create<Interest>();
    NDNPH_ASSERT(!!interest);
    interest.setName(m_rdrPrefix.append(region, getMetadataComponent()));
    interest.setCanBePrefix(true);
    interest.setMustBeFresh(true);
    interest.setLifetime(m_interestLifetime);
    bool ok = m_pending.send(interest);
    if (!ok) {
      invokeCallback(Data());
    }
  }

private:
  void invokeCallback(Data data) {
    if (m_cb != nullptr) {
      m_cb(m_ctx, std::move(data));
      m_cb = nullptr;
    }
  }

  void loop() final {
    if (m_pending.expired()) {
      invokeCallback(Data());
    }
  }

  bool processData(Data data) final {
    if (!m_pending.match(data, m_rdrPrefix) || data.getName().size() != m_rdrPrefix.size() + 3 ||
        data.getName()[m_rdrPrefix.size()] != getMetadataComponent()) {
      return false;
    }

    if (!data.verify(m_verifier)) {
      invokeCallback(Data());
    } else {
      invokeCallback(data);
    }
    return true;
  }

private:
  OutgoingPendingInterest m_pending;
  const PublicKey& m_verifier;
  uint16_t m_interestLifetime = 0;
  Name m_rdrPrefix;
  Callback m_cb = nullptr;
  void* m_ctx = nullptr;
};

} // namespace rdr

using rdr::RdrMetadataConsumer;
using rdr::RdrMetadataProducer;

} // namespace ndnph

#endif // NDNPH_APP_RDR_HPP
