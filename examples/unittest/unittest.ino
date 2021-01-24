#include <NDNph.h>

#include <Arduino.h>
#include <ArduinoUnit.h>

test(Clock)
{
  using Clock = ndnph::port::Clock;
  using UnixTime = ndnph::port::UnixTime;

  auto u0 = UnixTime::now();
  auto t0 = Clock::now();
  auto t1 = Clock::add(t0, 20);
  Clock::sleep(100);
  auto t2 = Clock::now();
  auto u2 = UnixTime::now();

  assertEqual(Clock::sub(t0, t1), -20);
  assertEqual(Clock::sub(t1, t0), 20);
  assertTrue(Clock::isBefore(t0, t1));
  assertTrue(Clock::isBefore(t0, t2));
  assertTrue(Clock::isBefore(t1, t2));
  assertFalse(Clock::isBefore(t1, t0));
  assertFalse(Clock::isBefore(t2, t0));
  assertFalse(Clock::isBefore(t2, t1));

  if (UnixTime::valid(u0)) {
    auto uDiff = static_cast<int>(u2 - u0);
    auto tDiff = 1000 * Clock::sub(t2, t0);
    assertLess(std::abs(uDiff - tDiff), 10000); // allow 10ms error
  }
}

test(PacketPrint)
{
  ndnph::StaticRegion<1024> region;
  ndnph::Name name(region, { 0x08, 0x00, 0x09, 0x01, 0x41, 0x0A, 0x03, 0x2E, 0x42, 0x2E });

  {
    MockPrint os;
    os.print(name);
    assertEqual(os, "/8=.../9=A/10=.B.");
  }

  auto interest = region.create<ndnph::Interest>();
  assertTrue(!!interest);
  interest.setName(ndnph::Name::parse(region, "/Q"));
  interest.setCanBePrefix(true);
  interest.setMustBeFresh(true);
  {
    MockPrint os;
    os.print(interest);
    assertEqual(os, "/8=Q[P][F]");
  }

  auto data = region.create<ndnph::Data>();
  assertTrue(!!data);
  data.setName(interest.getName());
  {
    MockPrint os;
    os.print(data);
    assertEqual(os, "/8=Q");
  }
}

void
setup()
{
  Serial.begin(115200);
  Serial.println();
}

void
loop()
{
  Test::run();
}
