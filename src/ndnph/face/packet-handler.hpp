#ifndef NDNPH_FACE_PACKET_HANDLER_HPP
#define NDNPH_FACE_PACKET_HANDLER_HPP

#include "../core/common.hpp"

namespace ndnph {

template<typename PktTypes>
class BasicFace;

template<typename PktTypes>
class BasicPacketHandler
{
protected:
  using Face = BasicFace<PktTypes>;
  using PacketHandler = BasicPacketHandler<PktTypes>;
  using Interest = typename PktTypes::Interest;
  using Data = typename PktTypes::Data;

  explicit BasicPacketHandler() = default;

  explicit BasicPacketHandler(Face& face, int8_t prio = 0);

  virtual ~BasicPacketHandler();

  Face* getFace() const
  {
    return m_face;
  }

  template<typename... Arg>
  bool send(Arg... arg)
  {
    return m_face != nullptr && m_face->send(std::forward<Arg>(arg)...);
  }

private:
  virtual bool processInterest(Interest interest, uint64_t endpointId)
  {
    (void)interest;
    (void)endpointId;
    return false;
  }

  virtual bool processData(Data data, uint64_t endpointId)
  {
    (void)data;
    (void)endpointId;
    return false;
  }

private:
  Face* m_face = nullptr;
  PacketHandler* m_next = nullptr;
  int8_t m_prio = 0;
  friend Face;
};

} // namespace ndnph

#include "face.hpp"

namespace ndnph {

template<typename PktTypes>
BasicPacketHandler<PktTypes>::BasicPacketHandler(Face& face, int8_t prio)
{
  face.addHandler(*this, prio);
}

template<typename PktTypes>
BasicPacketHandler<PktTypes>::~BasicPacketHandler()
{
  if (m_face != nullptr) {
    m_face->removeHandler(*this);
  }
}

} // namespace ndnph

#endif // NDNPH_FACE_PACKET_HANDLER_HPP
