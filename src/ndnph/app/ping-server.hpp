#ifndef NDNPH_APP_PING_SERVER_HPP
#define NDNPH_APP_PING_SERVER_HPP

#include "../face/packet-handler.hpp"
#include "../keychain/digest-key.hpp"

namespace ndnph {

/** @brief Respond to every incoming Interest with empty Data. */
class PingServer : public PacketHandler
{
public:
  /**
   * @brief Constructor.
   * @param prefix name prefix to serve.
   * @param face face for communication.
   */
  explicit PingServer(Name prefix, Face& face)
    : PacketHandler(face)
    , m_prefix(std::move(prefix))
  {}

private:
  bool processInterest(Interest interest) final
  {
    if (!m_prefix.isPrefixOf(interest.getName())) {
      return false;
    }

    StaticRegion<1024> region;
    Data data = region.create<Data>();
    assert(!!data);
    data.setName(interest.getName());
    data.setFreshnessPeriod(1);
    reply(data.sign(DigestKey()));
    return true;
  }

private:
  Name m_prefix;
};

} // namespace ndnph

#endif // NDNPH_APP_PING_SERVER_HPP
