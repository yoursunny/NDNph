#include "ndnph/face/face.hpp"
#include "ndnph/port/crypto/port.hpp"

#include "../mock-transport.hpp"

namespace ndnph {
namespace {

TEST(Face, Receive)
{
  MockTransport transport;
  Face face(transport);
  MockFaceCallbacks callbacks;
  callbacks.hook(face);

  std::vector<uint8_t> wire({ 0x04, 0x02, 0xA0, 0xA1 });

  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name(region, { 0x08, 0x01, 0x41 }));
  Encoder encoder(region);
  encoder.prepend(interest);
  encoder.trim();

  int ctx = 0;
  {
    g::InSequence seq;
    EXPECT_CALL(transport, doReceive(g::_, g::NotNull(), g::Ge(wire.size())))
      .WillOnce(g::DoAll(g::SetArrayArgument<1>(wire.begin(), wire.end()),
                         g::Return(std::make_tuple(wire.size(), 4946))));
    EXPECT_CALL(callbacks, rxSuccess(&ctx, g::ElementsAreArray(wire), 4946)).Times(1);
  }
  {
    StaticRegion<1024> region1;
    face.asyncReceive(&ctx, region1);
  }

  {
    g::InSequence seq;
    EXPECT_CALL(transport, doReceive(g::_, g::_, g::_)).WillOnce(g::Return(std::make_tuple(-1, 0)));
    EXPECT_CALL(callbacks, rxFailure(&ctx)).Times(1);
  }
  {
    StaticRegion<1024> region2;
    face.asyncReceive(&ctx, region2);
  }
}

TEST(Face, Send)
{
  MockTransport transport;
  Face face(transport);
  MockFaceCallbacks callbacks;
  callbacks.hook(face);

  StaticRegion<1024> region;
  Interest interest = region.create<Interest>();
  ASSERT_FALSE(!interest);
  interest.setName(Name(region, { 0x08, 0x01, 0x41 }));
  Encoder encoder(region);
  encoder.prepend(interest);
  encoder.trim();

  int ctx = 0;
  {
    g::InSequence seq;
    EXPECT_CALL(transport, doSend(g::_, g::ElementsAreArray(encoder.begin(), encoder.end()), 3202))
      .WillOnce(g::Return(true));
    EXPECT_CALL(callbacks, tx(&ctx, true)).Times(1);
  }
  face.asyncSend(&ctx, interest, 3202);
}

} // namespace
} // namespace ndnph
