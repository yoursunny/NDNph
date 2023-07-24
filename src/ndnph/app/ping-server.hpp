#ifndef NDNPH_APP_PING_SERVER_HPP
#define NDNPH_APP_PING_SERVER_HPP

#include "../face/packet-handler.hpp"
#include "../keychain/digest.hpp"

namespace ndnph {

/** @brief Respond to every incoming Interest with empty Data. */
class PingServer : public PacketHandler {
public:
  /**
   * @brief Constructor.
   * @param prefix name prefix to serve. It should have 'ping' suffix.
   * @param face face for communication.
   */
  explicit PingServer(Name prefix, Face& face, const PrivateKey& signer = DigestKey::get())
    : PacketHandler(face)
    , m_prefix(std::move(prefix))
    , m_signer(signer) {}

private:
  bool processInterest(Interest interest) final {
    if (!m_prefix.isPrefixOf(interest.getName())) {
      return false;
    }

    StaticRegion<1024> region;
    Data data = region.create<Data>();
    NDNPH_ASSERT(!!data);
    data.setName(interest.getName());
    data.setFreshnessPeriod(1);
    reply(data.sign(m_signer));
    return true;
  }

private:
  Name m_prefix;
  const PrivateKey& m_signer;
};

} // namespace ndnph

#endif // NDNPH_APP_PING_SERVER_HPP
