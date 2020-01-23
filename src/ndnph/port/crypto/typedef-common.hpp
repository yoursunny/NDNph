#ifndef NDNPH_PORT_CRYPTO_TYPEDEF_COMMON_HPP
#define NDNPH_PORT_CRYPTO_TYPEDEF_COMMON_HPP

#include "../../face/face.hpp"
#include "../../keychain/digest-key.hpp"
#include "../../keychain/ecdsa-key.hpp"
#include "../../packet/data.hpp"
#include "../../packet/nack.hpp"

/**
 * @brief Declare types dependent on crypto port.
 * @note This is meant to be used by a port in global namespace.
 */
#define NDNPH_PORT_CRYPTO_DECLARE_TYPES(Sha256Port, EcdsaPort)                                     \
  namespace ndnph {                                                                                \
  namespace detail {                                                                               \
  struct PktTypes                                                                                  \
  {                                                                                                \
    using Interest = BasicInterest<Sha256Port>;                                                    \
    using Data = BasicData<Sha256Port>;                                                            \
    using Nack = BasicNack<Interest>;                                                              \
  };                                                                                               \
  }                                                                                                \
  using Interest = detail::PktTypes::Interest;                                                     \
  using Data = detail::PktTypes::Data;                                                             \
  using Nack = detail::PktTypes::Nack;                                                             \
  using Face = BasicFace<detail::PktTypes>;                                                        \
  using PacketHandler = BasicPacketHandler<detail::PktTypes>;                                      \
  using DigestKey = BasicDigestKey<Sha256Port>;                                                    \
  using EcdsaPublicKey = BasicEcdsaPublicKey<Sha256Port, EcdsaPort>;                               \
  using EcdsaPrivateKey = BasicEcdsaPrivateKey<Sha256Port, EcdsaPort>;                             \
  }

#endif // NDNPH_PORT_CRYPTO_TYPEDEF_COMMON_HPP
