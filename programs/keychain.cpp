#define NDNPH_WANT_CLI
#include <NDNph-config.h>
#include <NDNph.h>
#include <iomanip>

ndnph::StaticRegion<65536> region;
ndnph::KeyChain& keyChain = ndnph::cli::openKeyChain();

static bool
keygen(int argc, char** argv)
{
  if (argc != 4) {
    return false;
  }
  std::string id = ndnph::cli::checkKeyChainId(argv[2]);
  auto name = ndnph::Name::parse(region, argv[3]);

  ndnph::EcPrivateKey pvt;
  ndnph::EcPublicKey pub;
  bool ok = ndnph::ec::generate(region, name, pvt, pub, keyChain, (id + "_key").data());
  if (!ok) {
    fprintf(stderr, "EC generate error\n");
    exit(1);
  }

  auto cert = pub.selfSign(region, ndnph::ValidityPeriod::getMax(), pvt);
  if (!keyChain.certs.set((id + "_cert").data(), cert, region)) {
    fprintf(stderr, "Save certificate error\n");
    exit(1);
  }

  ndnph::cli::output(cert);
  return true;
}

static bool
certinfo(int argc, char** argv)
{
  if (argc != 3) {
    return false;
  }
  std::string id = ndnph::cli::checkKeyChainId(argv[2]);
  auto cert = ndnph::cli::loadCertificate(region, id + "_cert");
  auto vp = ndnph::certificate::getValidity(cert);

  std::cout << "Name:     " << cert.getName() << std::endl;
  std::cout << "Issuer:   " << ndnph::certificate::getIssuer(cert) << std::endl;
  std::cout << "Validity: " << std::put_time(gmtime(&vp.notBefore), "%F") << " - "
            << std::put_time(gmtime(&vp.notAfter), "%F") << std::endl;
  return true;
}

static bool
certexport(int argc, char** argv)
{
  if (argc != 3) {
    return false;
  }
  std::string id = ndnph::cli::checkKeyChainId(argv[2]);
  auto cert = ndnph::cli::loadCertificate(region, id + "_cert");
  ndnph::cli::output(cert);
  return true;
}

static bool
certsign(int argc, char** argv)
{
  if (argc != 3) {
    return false;
  }
  std::string id = ndnph::cli::checkKeyChainId(argv[2]);

  ndnph::EcPrivateKey issuerPvt;
  ndnph::EcPublicKey issuerPub;
  ndnph::cli::loadKey(region, id + "_key", issuerPvt, issuerPub);

  ndnph::EcPublicKey pub;
  ndnph::cli::inputCertificate(region, &pub);
  ndnph::ValidityPeriod vp;
  time(&vp.notBefore);
  vp.notAfter = vp.notBefore + 86400 * 90;

  auto cert = pub.buildCertificate(region, pub.getName(), vp, issuerPvt);
  ndnph::cli::output(cert);
  return true;
}

static bool
certimport(int argc, char** argv)
{
  if (argc != 3) {
    return false;
  }
  std::string id(argv[2]);

  auto cert = ndnph::cli::inputCertificate(region, nullptr);
  if (!keyChain.certs.set((id + "_cert").data(), cert, region)) {
    fprintf(stderr, "Save certificate error\n");
    exit(1);
  }
  return true;
}

static bool
execute(int argc, char** argv)
{
  if (argc <= 1) {
    return false;
  }
#define SUBCOMMAND(cmd)                                                                            \
  if (strcmp(argv[1], #cmd) == 0) {                                                                \
    return cmd(argc, argv);                                                                        \
  }

  SUBCOMMAND(keygen)
  SUBCOMMAND(certinfo)
  SUBCOMMAND(certexport)
  SUBCOMMAND(certsign)
  SUBCOMMAND(certimport)

#undef SUBCOMMAND
  return false;
}

static void
usage()
{
  fprintf(stderr, "ndnph-keychain keygen ID NAME > self-signed-cert.data\n"
                  "  Generate a key pair for NAME and save to ID.\n"
                  "\n"
                  "ndnph-keychain certinfo ID\n"
                  "  Show information about the certificate of ID.\n"
                  "\n"
                  "ndnph-keychain certexport ID > self-signed-cert.data\n"
                  "  Export certificate of ID.\n"
                  "\n"
                  "ndnph-keychain certsign ID < self-signed-cert.data > issued-cert.data\n"
                  "  Issue certificate, signing with private key ID.\n"
                  "\n"
                  "ndnph-keychain certimport ID < issued-cert.data \n"
                  "  Install certificate to ID.\n");
}

int
main(int argc, char** argv)
{
  if (!execute(argc, argv)) {
    usage();
    return 1;
  }
  return 0;
}
