#include "cli-common.hpp"

ndnph::Face& face = cli_common::openUplink();

std::unique_ptr<ndnph::PingClient> client;

static bool
parseArgs(int argc, char** argv)
{
  int interval = 1000;

  int c;
  while ((c = getopt(argc, argv, "i:")) != -1) {
    switch (c) {
      case 'i': {
        interval = atoi(optarg);
        if (interval <= 0 || interval > 60000) {
          return false;
        }
        break;
      }
    }
  }

  if (argc - optind != 1) {
    return false;
  }
  const char* prefix = argv[optind];

  static ndnph::StaticRegion<1024> prefixRegion;
  client.reset(new ndnph::PingClient(ndnph::Name::parse(prefixRegion, prefix), face, interval));
  return true;
}

int
main(int argc, char** argv)
{
  if (!parseArgs(argc, argv)) {
    fprintf(stderr, "ndnph-pingclient [-i INTERVAL] PREFIX\n"
                    "  PREFIX should have 'ping' suffix to interact with ndn-tools ndnpingserver\n"
                    "  INTERVAL must be between 1 and 60000 milliseconds\n"
                    "  INTERVAL should be no less than RTT, or all requests will timeout\n"
                    "\n"
                    "Optional environment variable: NDNPH_UPLINK_UDP=192.0.2.1\n");
    return 2;
  }

  for (;;) {
    ndnph::port::Clock::sleep(1);
    face.loop();

    static uint16_t i = 0;
    if (++i % 1024 == 0) {
      auto cnt = client->readCounters();
      printf("%" PRIu32 "I %" PRIu32 "D\n", cnt.nTxInterests, cnt.nRxData);
    }
  }
}
