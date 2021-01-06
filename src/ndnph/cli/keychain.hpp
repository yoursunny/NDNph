#ifndef NDNPH_CLI_KEYCHAIN_HPP
#define NDNPH_CLI_KEYCHAIN_HPP

#include "../keychain/ec.hpp"
#include "../keychain/keychain.hpp"
#include "io.hpp"

namespace ndnph {
namespace cli {

/** @brief Open KeyChain according to `NDNPH_KEYCHAIN` environ. */
inline KeyChain&
openKeyChain()
{
  static KeyChain keyChain;
  static bool ready = false;
  if (!ready) {
    const char* env = getenv("NDNPH_KEYCHAIN");
    if (env == nullptr) {
      fprintf(stderr, "ndnph::cli::openKeyChain missing NDNPH_KEYCHAIN environment variable\n");
      exit(1);
    }

    ready = keyChain.open(env);
    if (!ready) {
      fprintf(stderr, "ndnph::cli::openKeyChain error\n");
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
    fprintf(stderr,
            "ndnph::cli::checkKeyChainId(%s) id must be non-empty and only contain digits and "
            "lower-case letters\n",
            id.data());
    exit(1);
  }
  return id;
}

/** @brief Load a key from the KeyChain. */
inline void
loadKey(Region& region, const std::string& id, EcPrivateKey& pvt, EcPublicKey& pub)
{
  if (!ec::load(openKeyChain(), id.data(), region, pvt, pub)) {
    fprintf(stderr, "ndnph::cli::loadKey(%s) not found in KeyChain\n", id.data());
    exit(1);
  }
}

/** @brief Load a certificate from the KeyChain. */
inline Data
loadCertificate(Region& region, const std::string& id)
{
  auto cert = openKeyChain().certs.get(id.data(), region);
  if (!cert) {
    fprintf(stderr, "ndnph::cli::loadCertificate(%s) not found in KeyChain\n", id.data());
    exit(1);
  }
  return cert;
}

/** @brief Load a certificate in binary format from input stream. */
inline Data
inputCertificate(Region& region, EcPublicKey* pub = nullptr, std::istream& is = std::cin)
{
  auto data = region.create<Data>();
  if (!data || !input(region, data, is) ||
      !(pub == nullptr ? certificate::isCertificate(data) : pub->import(region, data))) {
    fprintf(stderr, "ndnph::cli::inputCertificate parse cert error\n");
    exit(1);
  }
  return data;
}

} // namespace cli
} // namespace ndnph

#endif // NDNPH_CLI_KEYCHAIN_HPP
