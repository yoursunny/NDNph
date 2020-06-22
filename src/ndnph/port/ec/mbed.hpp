#ifndef NDNPH_PORT_EC_MBED_HPP
#define NDNPH_PORT_EC_MBED_HPP

#include "../random/port.hpp"

#include <mbedtls/ecdsa.h>

#ifndef MBEDTLS_ECDSA_DETERMINISTIC
#error MBEDTLS_ECDSA_DETERMINISTIC must be declared
#endif

namespace ndnph {
namespace port_ec_mbed {

namespace detail {

template<mbedtls_ecp_group_id groupId, size_t pvtLen>
class EcCurve
{
public:
  using Group = std::integral_constant<mbedtls_ecp_group_id, groupId>;
  using PvtLen = std::integral_constant<size_t, pvtLen>;
  using PubLen = std::integral_constant<size_t, 1 + 2 * pvtLen>;
  using MaxSigLen = std::integral_constant<size_t, 9 + 2 * pvtLen>;
};

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

template<typename Curve>
class EcKeyBase
{
protected:
  EcKeyBase()
  {
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&keypair.grp, Curve::Group::value);
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

template<typename Curve>
class EcPvt : public EcKeyBase<Curve>
{
public:
  bool import(const uint8_t bits[Curve::PvtLen::value])
  {
    return mbedtls_mpi_read_binary(&this->keypair.d, bits, Curve::PvtLen::value) == 0 &&
           mbedtls_ecp_check_privkey(&this->keypair.grp, &this->keypair.d) == 0;
  }

  ssize_t sign(const uint8_t digest[NDNPH_SHA256_LEN], uint8_t sig[Curve::MaxSigLen::value]) const
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

template<typename Curve>
class EcPub : public EcKeyBase<Curve>
{
public:
  bool import(const uint8_t bits[Curve::PubLen::value])
  {
    return mbedtls_ecp_point_read_binary(&this->keypair.grp, &this->keypair.Q, bits,
                                         Curve::PubLen::value) == 0 &&
           mbedtls_ecp_check_pubkey(&this->keypair.grp, &this->keypair.Q) == 0;
  }

  bool verify(const uint8_t digest[NDNPH_SHA256_LEN], const uint8_t* sig, size_t sigLen) const
  {
    EcContext context(this->keypair);
    auto ctx = context.get();
    if (ctx == nullptr) {
      return -1;
    }

    return mbedtls_ecdsa_read_signature(ctx, digest, NDNPH_SHA256_LEN, sig, sigLen) == 0;
  }
};

template<typename Curve>
class EcKeyGen : public EcKeyBase<Curve>
{
public:
  bool generate(uint8_t pvtBits[Curve::PvtLen::value], uint8_t pubBits[Curve::PubLen::value])
  {
    size_t pubLen;
    return mbedtls_ecp_gen_keypair(&this->keypair.grp, &this->keypair.d, &this->keypair.Q, rng,
                                   nullptr) == 0 &&
           mbedtls_mpi_write_binary(&this->keypair.d, pvtBits, Curve::PvtLen::value) == 0 &&
           mbedtls_ecp_point_write_binary(&this->keypair.grp, &this->keypair.Q,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED, &pubLen, pubBits,
                                          Curve::PubLen::value) == 0 &&
           pubLen == Curve::PubLen::value;
  }

private:
  static int rng(void*, uint8_t* output, size_t count)
  {
    bool ok = port::RandomSource::generate(output, count);
    return ok ? 0 : -1;
  }
};

} // namespace detail

namespace ec_curve {
using P256 = detail::EcCurve<MBEDTLS_ECP_DP_SECP256R1, 32>;
} // namespace ec_curve

template<typename CurveT>
class Ecdsa
{
public:
  using Curve = CurveT;
  using PrivateKey = detail::EcPvt<Curve>;
  using PublicKey = detail::EcPub<Curve>;

  static bool generateKey(uint8_t pvt[Curve::PvtLen::value], uint8_t pub[Curve::PubLen::value])
  {
    detail::EcKeyGen<Curve> gen;
    return gen.generate(pvt, pub);
  }
};

} // namespace port_ec_mbed

#ifdef NDNPH_PORT_EC_MBED
namespace port {
using Ecdsa = port_ec_mbed::Ecdsa<port_ec_mbed::ec_curve::P256>;
} // namespace port
#endif

} // namespace ndnph

#endif // NDNPH_PORT_EC_MBED_HPP
