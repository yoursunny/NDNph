#define NDNPH_WANT_CLI
#define NDNPH_MEMIF_DEBUG
#define NDNPH_SOCKET_DEBUG
#include <NDNph-config.h>
#include <NDNph.h>

ndnph::StaticRegion<65536> region;
ndnph::Face& face = ndnph::cli::openUplink();
ndnph::KeyChain& keyChain = ndnph::cli::openKeyChain();

const char* profileFilename = nullptr;
std::string identitySlot;
std::string possessionSlot;

ndnph::ndncert::client::CaProfile profile;
ndnph::EcPrivateKey myPvt;
ndnph::EcPublicKey myPub;
ndnph::EcPrivateKey possessionPvt;
bool running = true;

static bool
parseArgs(int argc, char** argv)
{
  int c;
  while ((c = getopt(argc, argv, "P:i:E:")) != -1) {
    switch (c) {
      case 'P': {
        profileFilename = optarg;
        break;
      }
      case 'i': {
        identitySlot = ndnph::cli::checkKeyChainId(optarg);
        break;
      }
      case 'E': {
        possessionSlot = ndnph::cli::checkKeyChainId(optarg);
        break;
      }
    }
  }

  return argc - optind == 0 && profileFilename != nullptr && !identitySlot.empty();
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
  NDNPH_ASSERT(!!data);
  if (!ndnph::Decoder(buffer, f.gcount()).decode(data)) {
    return false;
  }

  return profile.fromData(region, data);
}

static void
clientCallback(void*, ndnph::Data cert)
{
  running = false;
  if (!cert) {
    exit(1);
  }
  ndnph::cli::output(cert);
}

int
main(int argc, char** argv)
{
  if (!parseArgs(argc, argv)) {
    fprintf(stderr, "ndnph-ndncertclient -P CA-PROFILE -i IDENTITY-ID [-E POSSESSION-ID]\n"
                    "  CA-PROFILE is a CA profile filename.\n"
                    "  IDENTITY-ID is a KeyChain slot of the requester keypair.\n"
                    "    Generate a keypair with the 'ndnph-keychain keygen' command.\n"
                    "  -E enables proof of possession challenge.\n"
                    "  POSSESSION-ID is a KeyChain slot for the existing keypair.\n"
                    "\n"
                    "  New certificate from NDNCERT is written to stdout.\n"
                    "    Import to the KeyChain with the 'ndnph-keychain certimport' command.\n");
    return 1;
  }

  if (!loadCaProfile()) {
    fprintf(stderr, "Error loading CA profile\n");
    return 1;
  }
  ndnph::cli::loadKey(region, identitySlot + "_key", myPvt, myPub);

  ndnph::ndncert::client::ChallengeList challenges{};
  ndnph::ndncert::client::NopChallenge nopChallenge;
  challenges[0] = &nopChallenge;
  std::unique_ptr<ndnph::ndncert::client::PossessionChallenge> possessionChallenge;
  if (!possessionSlot.empty()) {
    ndnph::EcPublicKey possessionPub;
    ndnph::cli::loadKey(region, possessionSlot + "_key", possessionPvt, possessionPub);
    auto possessionCert = ndnph::cli::loadCertificate(region, possessionSlot + "_cert");
    possessionChallenge.reset(
      new ndnph::ndncert::client::PossessionChallenge(possessionCert, possessionPvt));
    challenges[1] = possessionChallenge.get();
  }

  ndnph::ndncert::Client::requestCertificate({
    .face = face,
    .profile = profile,
    .challenges = challenges,
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
