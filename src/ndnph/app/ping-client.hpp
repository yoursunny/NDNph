#ifndef NDNPH_APP_PING_CLIENT_HPP
#define NDNPH_APP_PING_CLIENT_HPP

#include "../face/packet-handler.hpp"
#include "../port/clock/port.hpp"

namespace ndnph {

/**
 * @brief Periodically transmit Interests to test reachability.
 *
 * This is a simple ping client implementation that can only keep one pending Interest.
 * After sending a probe Interest, responses to previous Interests are no longer accepted.
 * Therefore, interval must be greater than RTT, otherwise this client cannot receive any Data.
 */
class PingClient : public PacketHandler
{
public:
  /**
   * @brief Constructor.
   * @param prefix name prefix to request. It should have 'ping' suffix.
   * @param face face for communication.
   * @param interval Interest interval in milliseconds.
   */
  explicit PingClient(Name prefix, Face& face, int interval = 1000)
    : PacketHandler(face)
    , m_prefix(std::move(prefix))
    , m_interval(interval)
    , m_next(port::Clock::add(port::Clock::now(), interval))
  {
    port::RandomSource::generate(reinterpret_cast<uint8_t*>(&m_seqNum), sizeof(m_seqNum));
  }

  struct Counters
  {
    uint32_t nTxInterests = 0;
    uint32_t nRxData = 0;
  };

  Counters readCounters() const
  {
    return m_cnt;
  }

private:
  void loop() final
  {
    auto now = port::Clock::now();
    if (port::Clock::isBefore(now, m_next)) {
      return;
    }
    sendInterest();
    m_next = port::Clock::add(now, m_interval);
  }

  bool sendInterest()
  {
    StaticRegion<1024> region;
    Component seqNumComp = Component::from(region, TT::GenericNameComponent, tlv::NNI8(++m_seqNum));
    NDNPH_ASSERT(!!seqNumComp);
    Name name = m_prefix.append(region, seqNumComp);
    NDNPH_ASSERT(!!name);

    Interest interest = region.create<Interest>();
    NDNPH_ASSERT(!!interest);
    interest.setName(name);
    interest.setMustBeFresh(true);

    if (!send(interest)) {
      return false;
    }
    ++m_cnt.nTxInterests;
    return true;
  }

  bool processData(Data data) final
  {
    const Name& dataName = data.getName();
    if (!m_prefix.isPrefixOf(dataName) || m_prefix.size() + 1 != dataName.size()) {
      return false;
    }
    Component lastComp = dataName[-1];
    Decoder::Tlv d;
    Decoder::readTlv(d, lastComp.tlv(), lastComp.tlv() + lastComp.size());
    uint64_t seqNum = 0;
    if (!tlv::NNI8::decode(d, seqNum)) {
      return false;
    }

    if (m_seqNum == seqNum) {
      ++m_cnt.nRxData;
    }
    return true;
  }

private:
  Name m_prefix;
  uint64_t m_seqNum = 0;
  int m_interval = 1000;
  port::Clock::Time m_next;
  Counters m_cnt;
};

} // namespace ndnph

#endif // NDNPH_APP_PING_CLIENT_HPP
