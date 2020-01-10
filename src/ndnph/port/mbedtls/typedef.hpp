#ifndef NDNPH_PORT_MBEDTLS_TYPEDEF_HPP
#define NDNPH_PORT_MBEDTLS_TYPEDEF_HPP

#include "../../keychain/digest-key.hpp"
#include "../../keychain/ecdsa-key.hpp"
#include "../../packet/interest.hpp"
#include "ecdsa.hpp"
#include "sha256.hpp"

namespace ndnph {

using Interest = BasicInterest<port_mbedtls::Sha256>;
using DigestKey = BasicDigestKey<port_mbedtls::Sha256>;
using EcdsaPublicKey =
  BasicEcdsaPublicKey<port_mbedtls::Sha256,
                      port_mbedtls::Ecdsa<port_mbedtls::ec_curve::P256>>;
using EcdsaPrivateKey =
  BasicEcdsaPrivateKey<port_mbedtls::Sha256,
                       port_mbedtls::Ecdsa<port_mbedtls::ec_curve::P256>>;

} // namespace ndnph

#endif // NDNPH_PORT_MBEDTLS_TYPEDEF_HPP
