#include <NDNph-config.h>
#include <NDNph.h>

#include <cinttypes>
#include <cstdio>
#include <iomanip>
#include <iostream>

ndnph::StaticRegion<65536> region;
ndnph::KeyChain keyChain;

static ndnph::Data
loadCertificate(const std::string& id)
{
  auto cert = keyChain.certs.get(id.data(), region);
  if (!cert) {
    fprintf(stderr, "Certificate not found\n");
    exit(4);
  }
  return cert;
}

static ndnph::Data
inputCertificate(ndnph::EcPublicKey* pub)
{
  const size_t bufferSize = 4096;
  uint8_t* buffer = region.alloc(bufferSize);
  std::cin.read(reinterpret_cast<char*>(buffer), bufferSize);

  auto data = region.create<ndnph::Data>();
  if (!data || !ndnph::Decoder(buffer, std::cin.gcount()).decode(data) ||
      !(pub == nullptr ? ndnph::certificate::isCertificate(data) : pub->import(region, data))) {
    fprintf(stderr, "Input certificate decode error\n");
    exit(4);
  }
  return data;
}

template<typename Encodable>
static void
output(const Encodable& packet)
{
  ndnph::Encoder encoder(region);
  if (!encoder.prepend(packet)) {
    fprintf(stderr, "Encode error\n");
    exit(4);
  }
  encoder.trim();
  std::cout.write(reinterpret_cast<const char*>(encoder.begin()), encoder.size());
}

static bool
keygen(int argc, char** argv)
{
  if (argc != 4) {
    return false;
  }
  auto name = ndnph::Name::parse(region, argv[3]);
  std::string id(argv[2]);

  ndnph::EcPrivateKey pvt;
  ndnph::EcPublicKey pub;
  bool ok = ndnph::ec::generate(region, name, pvt, pub, keyChain, (id + "_key").data());
  if (!ok) {
    fprintf(stderr, "EC generate error\n");
    exit(4);
  }

  auto cert = pub.selfSign(region, ndnph::ValidityPeriod::getMax(), pvt);
  if (!keyChain.certs.set((id + "_cert").data(), cert, region)) {
    fprintf(stderr, "Save certificate error\n");
    exit(4);
  }

  output(cert);
  return true;
}

static bool
certinfo(int argc, char** argv)
{
  if (argc != 3) {
    return false;
  }
  std::string id(argv[2]);
  auto cert = loadCertificate(id + "_cert");
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
  std::string id(argv[2]);
  auto cert = loadCertificate(id + "_cert");
  output(cert);
  return true;
}

static bool
certsign(int argc, char** argv)
{
  if (argc != 3) {
    return false;
  }
  std::string id(argv[2]);

  ndnph::EcPrivateKey issuerPvt;
  ndnph::EcPublicKey issuerPub;
  if (!ndnph::ec::load(keyChain, (id + "_key").data(), region, issuerPvt, issuerPub)) {
    fprintf(stderr, "Issuer key not found\n");
    exit(4);
  }

  ndnph::EcPublicKey pub;
  inputCertificate(&pub);
  ndnph::ValidityPeriod vp;
  time(&vp.notBefore);
  vp.notAfter = vp.notBefore + 86400 * 90;

  auto cert = pub.buildCertificate(region, pub.getName(), vp, issuerPvt);
  output(cert);
  return true;
}

static bool
certimport(int argc, char** argv)
{
  if (argc != 3) {
    return false;
  }
  std::string id(argv[2]);

  auto cert = inputCertificate(nullptr);
  if (!keyChain.certs.set((id + "_cert").data(), cert, region)) {
    fprintf(stderr, "Save certificate error\n");
    exit(4);
  }
  return true;
}

static bool
execute(int argc, char** argv)
{
  if (argc <= 1) {
    return false;
  }
  if (strcmp(argv[1], "keygen") == 0) {
    return keygen(argc, argv);
  }
  if (strcmp(argv[1], "certinfo") == 0) {
    return certinfo(argc, argv);
  }
  if (strcmp(argv[1], "certexport") == 0) {
    return certexport(argc, argv);
  }
  if (strcmp(argv[1], "certsign") == 0) {
    return certsign(argc, argv);
  }
  if (strcmp(argv[1], "certimport") == 0) {
    return certimport(argc, argv);
  }
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
                  "  Install certificate to ID.\n"
                  "\n"
                  "Required environment variable: NDNPH_KEYCHAIN=/path/to/keychain\n"
                  "ID can only have digits and lower case letters.\n");
}

int
main(int argc, char** argv)
{
  const char* keyChainEnv = getenv("NDNPH_KEYCHAIN");
  if (keyChainEnv == nullptr) {
    usage();
    return 2;
  }
  if (!keyChain.open(keyChainEnv)) {
    fprintf(stderr, "KeyChain open error\n");
    return 3;
  }

  if (!execute(argc, argv)) {
    usage();
    return 2;
  }
  return 0;
}
