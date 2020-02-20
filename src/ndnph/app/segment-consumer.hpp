#ifndef NDNPH_SEGMENT_CONSUMER_HPP
#define NDNPH_SEGMENT_CONSUMER_HPP

#include "../face/packet-handler.hpp"
#include "../keychain/digest-key.hpp"
#include "../port/clock/port.hpp"

namespace ndnph {

class SegmentConsumerBase : public PacketHandler
{
public:
  struct Options
  {
    const PublicKey& verifier = DigestKey::get();

    /** @brief Maximum retransmission of an Interest, not counting initial Interest. */
    int retxLimit = 5;

    /** @brief Delay in milliseconds before retransmission. */
    int retxDelay = 500;
  };

  /**
   * @brief Constructor.
   * @param face face for communication.
   * @param region region for Interest encoding; may be shared.
   * @param opts options.
   */
  explicit SegmentConsumerBase(Face& face, Region& region, Options opts)
    : PacketHandler(face)
    , m_region(region)
    , m_opts(std::move(opts))
  {}

  explicit SegmentConsumerBase(Face& face, Region& region)
    : SegmentConsumerBase(face, region, Options())
  {}

  /**
   * @brief Callback upon segment arrival.
   * @param ctx user specified context.
   * @param segment segment number; they will appear sequentially.
   * @param data the Data packet.
   *
   * If a segment retrieval has failed, the callback will be invoked with invalid Data where
   * @c !data evaluates to true, and no more callbacks will be invoked.
   * If fetching has completed successfully, the callback will be invoked with the last Data
   * where @c data.getIsFinalBlock() evaluates to true, and no more callbacks will be invoked.
   */
  using SegmentCallback = void (*)(void* ctx, uint64_t segment, Data data);

  /**
   * @brief Assign SegmentCallback.
   *
   * This should be invoked before @c start() .
   */
  void setSegmentCallback(SegmentCallback cb, void* ctx)
  {
    m_cb = cb;
    m_cbCtx = ctx;
  }

  /** @brief Destination and context of saving accumulated payload. */
  class SaveDest
  {
  public:
    explicit SaveDest(uint8_t* output, size_t limit)
      : output(output)
      , limit(limit)
    {}

    static void accumulate(void* self0, uint64_t, Data data)
    {
      reinterpret_cast<SaveDest*>(self0)->accumulate(data);
    }

  private:
    void accumulate(Data data)
    {
      if (hasError || !data) {
        hasError = true;
        return;
      }
      auto content = data.getContent();
      if (length + content.size() > limit) {
        hasError = true;
        return;
      }
      std::copy(content.begin(), content.end(), &output[length]);
      length += content.size();
      isCompleted = data.getIsFinalBlock();
    }

  public:
    uint8_t* output = nullptr;
    size_t limit = 0;
    size_t length = 0;
    bool isCompleted = false;
    bool hasError = false;
  };

  /**
   * @brief Save content to destination.
   * @param dest saving destination, must be kept alive while SegmentConsumer is running.
   *
   * This should be invoked before @c start() .
   * This cannot be used together with SegmentCallback.
   */
  void saveTo(SaveDest& dest)
  {
    setSegmentCallback(SaveDest::accumulate, &dest);
  }

  /**
   * @brief Start fetching content under given prefix.
   *
   * If another fetching is in progress, it will be aborted. The callback will not be invoked.
   */
  void start(Name prefix)
  {
    m_prefix = prefix;
    m_running = true;
    m_segment = 0;
    m_retxRemain = m_opts.retxLimit;
    m_nextSend = port::Clock::now();
  }

  /**
   * @brief Stop fetching.
   *
   * The callback will not be invoked.
   */
  void stop()
  {
    m_running = false;
  }

  /** @brief Determine whether fetching is in progress (not completed or failed). */
  bool isRunning() const
  {
    return m_running;
  }

protected:
  void invokeCallback(Data data)
  {
    if (m_cb != nullptr) {
      m_cb(m_cbCtx, m_segment, data);
    }
  }

protected:
  Region& m_region;
  Options m_opts;
  SegmentCallback m_cb = nullptr;
  void* m_cbCtx = nullptr;
  Name m_prefix;
  uint64_t m_segment = 0;
  port::Clock::Time m_nextSend;
  int m_retxRemain = 0;
  bool m_running = false;
};

/** @brief Consumer of segmented object, using a stop-and-wait algorithm. */
template<typename SegmentConvention = convention::Segment>
class BasicSegmentConsumer : public SegmentConsumerBase
{
public:
  using SegmentConsumerBase::SegmentConsumerBase;

private:
  void loop() final
  {
    auto now = port::Clock::now();
    if (!m_running || port::Clock::isBefore(now, m_nextSend)) {
      return;
    }

    if (--m_retxRemain < -1) {
      m_running = false;
      invokeCallback(Data());
      return;
    }

    m_region.reset();
    Interest interest = m_region.create<Interest>();
    assert(!!interest);
    interest.setName(m_prefix.append<SegmentConvention>(m_region, m_segment));
    send(interest);

    m_nextSend = port::Clock::add(now, m_opts.retxDelay);
  }

  bool processData(Data data) final
  {
    const Name& dataName = data.getName();
    auto lastComp = dataName[-1];
    if (!m_prefix || dataName.size() != m_prefix.size() + 1 || !m_prefix.isPrefixOf(dataName) ||
        !lastComp.is<SegmentConvention>() || !data.verify(m_opts.verifier)) {
      return false;
    }
    uint64_t segment = lastComp.as<SegmentConvention>();
    if (segment != m_segment) {
      return false;
    }

    invokeCallback(data);

    if (data.getIsFinalBlock()) {
      m_running = false;
    } else {
      ++m_segment;
      m_retxRemain = m_opts.retxLimit;
      m_nextSend = port::Clock::now();
    }
    return true;
  }
};

using SegmentConsumer = BasicSegmentConsumer<>;

} // namespace ndnph

#endif // NDNPH_SEGMENT_CONSUMER_HPP
