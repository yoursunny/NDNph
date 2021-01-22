#include <NDNph.h>

#include <Arduino.h>
#include <ArduinoUnit.h>

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
}

void
loop()
{
  Test::run();
}
