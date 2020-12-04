#include "cli-common.hpp"

ndnph::StaticRegion<65536> region;
ndnph::Face& face = cli_common::openUplink();

const char* profileFilename = nullptr;
ndnph::Component identitySuffix;

ndnph::ndncert::client::CaProfile profile;
ndnph::EcPrivateKey myPvt;
ndnph::EcPublicKey myPub;
bool running = true;

static bool
parseArgs(int argc, char** argv)
{
  int c;
  while ((c = getopt(argc, argv, "P:s:")) != -1) {
    switch (c) {
      case 'P': {
        profileFilename = optarg;
        break;
      }
      case 's': {
        identitySuffix = ndnph::Component::parse(region, optarg);
        if (!identitySuffix) {
          return false;
        }
        break;
      }
    }
  }

  return argc - optind == 0 && profileFilename != nullptr;
}

static bool
loadCaProfile()
{
  std::ifstream f(profileFilename, std::ios_base::in | std::ios_base::binary);
  if (!f.good()) {
    return false;
  }

  uint8_t buffer[2048];
  f.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
  if (!f.eof()) {
    return false;
  }

  ndnph::StaticRegion<2048> temp;
  ndnph::Data data = temp.create<ndnph::Data>();
  assert(!!data);
  if (!ndnph::Decoder(buffer, f.gcount()).decode(data)) {
    return false;
  }

  return profile.fromData(region, data);
}

static bool
makeMyKeyPair()
{
  ndnph::StaticRegion<2048> temp;
  ndnph::Name identity = profile.prefix.getPrefix(-1);
  if (!!identitySuffix) {
    identity = identity.append(temp, identitySuffix);
  } else {
    identity = identity.append<ndnph::convention::Timestamp>(temp, ndnph::convention::TimeValue());
  }
  assert(!!identity);

  return ndnph::ec::generate(region, identity, myPvt, myPub);
}

static void
clientCallback(void*, ndnph::Data cert)
{
  running = false;
  if (!cert) {
    exit(5);
  }
  std::cout << cert.getName() << std::endl;
}

int
main(int argc, char** argv)
{
  if (!parseArgs(argc, argv)) {
    fprintf(stderr,
            "ndnph-ndncertclient -P CA-PROFILE [-s IDENTITY-SUFFIX]\n"
            "  CA-PROFILE is a CA profile filename\n"
            "  IDENTITY-SUFFIX is the last component of requested identity\n"
            "Note: this program demonstrates protocol operations but cannot persist keys\n");
    return 2;
  }

  if (!loadCaProfile()) {
    return 4;
  }
  std::cout << profile.prefix << std::endl;

  if (!makeMyKeyPair()) {
    return 5;
  }
  std::cout << myPvt.getName() << std::endl;

  ndnph::ndncert::client::NopChallenge nopChallenge;
  ndnph::ndncert::Client::requestCertificate({
    .face = face,
    .profile = profile,
    .challenges = { &nopChallenge },
    .pub = myPub,
    .pvt = myPvt,
    .cb = clientCallback,
    .ctx = nullptr,
  });

  while (running) {
    ndnph::port::Clock::sleep(1);
    face.loop();
  }
  return 0;
}
