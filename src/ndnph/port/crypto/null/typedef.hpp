#ifndef NDNPH_PORT_CRYPTO_NULL_TYPEDEF_HPP
#define NDNPH_PORT_CRYPTO_NULL_TYPEDEF_HPP

#include "../typedef-common.hpp"
#include "ecdsa.hpp"
#include "sha256.hpp"

#ifdef NDNPH_PORT_CRYPTO_NULL
NDNPH_PORT_CRYPTO_DECLARE_TYPES(port_crypto_null::Sha256, port_crypto_null::Ecdsa)
#endif

#endif // NDNPH_PORT_CRYPTO_NULL_TYPEDEF_HPP
