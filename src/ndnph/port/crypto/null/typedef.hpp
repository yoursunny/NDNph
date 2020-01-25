#ifndef NDNPH_PORT_CRYPTO_NULL_TYPEDEF_HPP
#define NDNPH_PORT_CRYPTO_NULL_TYPEDEF_HPP

#include "ecdsa.hpp"
#include "sha256.hpp"

#ifdef NDNPH_PORT_CRYPTO_NULL
namespace ndnph {
namespace port {
using Sha256 = port_crypto_null::Sha256;
using Ecdsa = port_crypto_null::Ecdsa;
} // namespace port
} // namespace ndnph
#endif

#endif // NDNPH_PORT_CRYPTO_NULL_TYPEDEF_HPP
