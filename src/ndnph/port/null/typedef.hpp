#ifndef NDNPH_PORT_NULL_TYPEDEF_HPP
#define NDNPH_PORT_NULL_TYPEDEF_HPP

#include "../../keychain/digest-key.hpp"
#include "../../keychain/ecdsa-key.hpp"
#include "../../packet/interest.hpp"
#include "ecdsa.hpp"
#include "sha256.hpp"

namespace ndnph {

using Interest = BasicInterest<port_null::Sha256>;
using DigestKey = BasicDigestKey<port_null::Sha256>;
using EcdsaPublicKey = BasicEcdsaPublicKey<port_null::Sha256, port_null::Ecdsa>;
using EcdsaPrivateKey =
  BasicEcdsaPrivateKey<port_null::Sha256, port_null::Ecdsa>;

} // namespace ndnph

#endif // NDNPH_PORT_NULL_TYPEDEF_HPP
