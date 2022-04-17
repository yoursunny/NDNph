#ifndef NDNPH_PORT_EC_MBED_HPP
#define NDNPH_PORT_EC_MBED_HPP

#include "../mbed-common.hpp"
#include <mbedtls/ecdsa.h>

namespace ndnph {
namespace port_ec_mbed {

class EcContext
{
public:
  explicit EcContext(const mbedtls_ecp_keypair& key)
  {
    mbedtls_ecdsa_init(&m_ctx);
    m_hasError = mbedtls_ecdsa_from_keypair(&m_ctx, &key) != 0;
  }

  ~EcContext()
  {
    mbedtls_ecdsa_free(&m_ctx);
  }

  mbedtls_ecdsa_context* get()
  {
    return m_hasError ? nullptr : &m_ctx;
  }

private:
  mbedtls_ecdsa_context m_ctx;
  bool m_hasError = false;
};

class EcKeyBase
{
protected:
  EcKeyBase()
  {
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_copy(&keypair.grp, mbedtls::P256::group());
  }

  ~EcKeyBase()
  {
    mbedtls_ecp_keypair_free(&keypair);
  }

private:
  EcKeyBase(EcKeyBase&) = delete;
  EcKeyBase& operator=(EcKeyBase&) = delete;

protected:
  mbedtls_ecp_keypair keypair;
};

class EcPvt : public EcKeyBase
{
public:
  bool import(const uint8_t* bits)
  {
    return mbedtls_mpi_read_binary(&this->keypair.d, bits, mbedtls::P256::PvtLen::value) == 0 &&
           mbedtls_ecp_check_privkey(&this->keypair.grp, &this->keypair.d) == 0;
  }

  ssize_t sign(const uint8_t* digest, uint8_t* sig) const
  {
    EcContext context(this->keypair);
    auto ctx = context.get();
    if (ctx == nullptr) {
      return -1;
    }

    size_t sigLen;
    return mbedtls_ecdsa_write_signature(ctx, MBEDTLS_MD_SHA256, digest, NDNPH_SHA256_LEN, sig,
                                         &sigLen, nullptr, nullptr) == 0
             ? sigLen
             : -1;
  }
};

class EcPub : public EcKeyBase
{
public:
  bool import(const uint8_t* bits)
  {
    return mbedtls_ecp_point_read_binary(&this->keypair.grp, &this->keypair.Q, bits,
                                         mbedtls::P256::PubLen::value) == 0 &&
           mbedtls_ecp_check_pubkey(&this->keypair.grp, &this->keypair.Q) == 0;
  }

  bool verify(const uint8_t* digest, const uint8_t* sig, size_t sigLen) const
  {
    EcContext context(this->keypair);
    auto ctx = context.get();
    if (ctx == nullptr) {
      return -1;
    }

    return mbedtls_ecdsa_read_signature(ctx, digest, NDNPH_SHA256_LEN, sig, sigLen) == 0;
  }
};

class EcKeyGen : public EcKeyBase
{
public:
  bool generate(uint8_t* pvtBits, uint8_t* pubBits)
  {
    size_t pubLen;
    return mbedtls_ecp_gen_keypair(&this->keypair.grp, &this->keypair.d, &this->keypair.Q,
                                   mbedtls::rng, nullptr) == 0 &&
           mbedtls_mpi_write_binary(&this->keypair.d, pvtBits, mbedtls::P256::PvtLen::value) == 0 &&
           mbedtls_ecp_point_write_binary(&this->keypair.grp, &this->keypair.Q,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED, &pubLen, pubBits,
                                          mbedtls::P256::PubLen::value) == 0 &&
           pubLen == mbedtls::P256::PubLen::value;
  }
};

class Ec
{
public:
  using Curve = mbedtls::P256;
  using PrivateKey = EcPvt;
  using PublicKey = EcPub;

  static bool generateKey(uint8_t* pvt, uint8_t* pub)
  {
    return EcKeyGen().generate(pvt, pub);
  }
};

} // namespace port_ec_mbed

#ifdef NDNPH_PORT_EC_MBED
namespace port {
using Ec = port_ec_mbed::Ec;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_EC_MBED_HPP
