#ifndef NDNPH_PROGRAMS_CLI_COMMON_HPP
#define NDNPH_PROGRAMS_CLI_COMMON_HPP

#include <NDNph-config.h>
#include <NDNph.h>

#include <cinttypes>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <unistd.h>

namespace cli_common {

/** @brief Open uplink face according to `NDNPH_UPLINK_UDP` environ. */
inline ndnph::Face&
openUplink()
{
  static ndnph::UdpUnicastTransport transport;
  static ndnph::Face face(transport);
  static bool ready = false;
  if (!ready) {
    sockaddr_in raddr = {};
    raddr.sin_family = AF_INET;
    raddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    raddr.sin_port = htons(6363);

    ready = true;
    const char* env = getenv("NDNPH_UPLINK_UDP");
    if (env != nullptr) {
      ready = inet_aton(env, &raddr.sin_addr) != 0;
    }

    ready = ready && transport.beginTunnel(&raddr);
    if (!ready) {
      fprintf(stderr, "Unable to open uplink\n");
      exit(1);
    }
  }
  return face;
}

/** @brief Open KeyChain according to `NDNPH_KEYCHAIN` environ. */
inline ndnph::KeyChain&
openKeyChain()
{
  static ndnph::KeyChain keyChain;
  static bool ready = false;
  if (!ready) {
    const char* env = getenv("NDNPH_KEYCHAIN");
    if (env == nullptr) {
      fprintf(stderr, "NDNPH_KEYCHAIN environment variable missing\n");
      exit(1);
    }

    ready = keyChain.open(env);
    if (!ready) {
      fprintf(stderr, "KeyChain open error\n");
      exit(1);
    }
  }
  return keyChain;
}

/** @brief Check KeyChain object ID has the proper format. */
inline std::string
checkKeyChainId(const std::string& id)
{
  bool ok = std::all_of(id.begin(), id.end(), [](char ch) {
    return static_cast<bool>(std::islower(ch)) || static_cast<bool>(std::isdigit(ch));
  });
  if (id.empty() || !ok) {
    fprintf(
      stderr,
      "Bad KeyChain ID [%s]; must be non-empty and only contain digits and lower-case letters\n",
      id.data());
    exit(1);
  }
  return id;
}

/** @brief Load a certificate from the KeyChain. */
inline ndnph::Data
loadCertificate(ndnph::Region& region, const std::string& id)
{
  auto cert = openKeyChain().certs.get(id.data(), region);
  if (!cert) {
    fprintf(stderr, "Certificate [%s] not found in KeyChain\n", id.data());
    exit(1);
  }
  return cert;
}

/** @brief Load a certificate in binary format from stdin. */
inline ndnph::Data
inputCertificate(ndnph::Region& region, ndnph::EcPublicKey* pub)
{
  const size_t bufferSize = 4096;
  uint8_t* buffer = region.alloc(bufferSize);
  std::cin.read(reinterpret_cast<char*>(buffer), bufferSize);

  auto data = region.create<ndnph::Data>();
  if (!data || !ndnph::Decoder(buffer, std::cin.gcount()).decode(data) ||
      !(pub == nullptr ? ndnph::certificate::isCertificate(data) : pub->import(region, data))) {
    fprintf(stderr, "Input certificate decode error\n");
    exit(1);
  }
  return data;
}

/** @brief Write an object in binary format to stdout. */
template<typename Encodable>
inline void
output(const Encodable& packet)
{
  ndnph::StaticRegion<65536> temp;
  ndnph::Encoder encoder(temp);
  if (!encoder.prepend(packet)) {
    fprintf(stderr, "Encode error\n");
    exit(1);
  }
  std::cout.write(reinterpret_cast<const char*>(encoder.begin()), encoder.size());
}

} // namespace cli_common

#endif // NDNPH_PROGRAMS_CLI_COMMON_HPP
