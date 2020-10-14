#ifndef NDNPH_PORT_MBED_COMMON_HPP
#define NDNPH_PORT_MBED_COMMON_HPP
#ifdef NDNPH_HAVE_MBED

#include "../tlv/decoder.hpp"
#include "../tlv/encoder.hpp"
#include "random/port.hpp"
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

#ifndef MBEDTLS_ECDSA_DETERMINISTIC
#error MBEDTLS_ECDSA_DETERMINISTIC must be declared
#endif

namespace ndnph {
/** @brief Wrappers of Mbed TLS crypto library. */
namespace mbedtls {

/** @brief Random number generator for various Mbed TLS library functions. */
inline int
rng(void*, uint8_t* output, size_t count)
{
  bool ok = port::RandomSource::generate(output, count);
  return ok ? 0 : -1;
}

/** @brief Multi-Precision Integer. */
class Mpi : public mbedtls_mpi
{
public:
  explicit Mpi(const mbedtls_mpi* src = nullptr)
  {
    mbedtls_mpi_init(this);
    if (src != nullptr) {
      mbedtls_mpi_copy(this, src);
    }
  }

  explicit Mpi(const Mpi& src)
    : Mpi(&src)
  {}

  ~Mpi()
  {
    mbedtls_mpi_free(this);
  }

  Mpi& operator=(const Mpi& src)
  {
    mbedtls_mpi_copy(this, &src);
    return *this;
  }
};

/** @brief EC curve P256. */
class P256
{
public:
  using PvtLen = std::integral_constant<size_t, 32>;
  using PubLen = std::integral_constant<size_t, 65>;
  using MaxSigLen = std::integral_constant<size_t, 74>;

  static mbedtls_ecp_group* group()
  {
    static struct S
    {
      S()
      {
        int res = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
        assert(res == 0);
      }
      mbedtls_ecp_group grp;
    } s;
    return &s.grp;
  };
};

/** @brief EC point. */
class EcPoint : public mbedtls_ecp_point
{
public:
  explicit EcPoint(const mbedtls_ecp_point* src = nullptr)
  {
    mbedtls_ecp_point_init(this);
    if (src != nullptr) {
      mbedtls_ecp_copy(this, src);
    }
  }

  EcPoint(const EcPoint& src)
    : EcPoint(&src)
  {}

  ~EcPoint()
  {
    mbedtls_ecp_point_free(this);
  }

  EcPoint& operator=(const EcPoint& src)
  {
    mbedtls_ecp_copy(this, &src);
    return *this;
  }

  void encodeTo(Encoder& encoder) const
  {
    constexpr size_t expectedLength = 65;
    uint8_t* room = encoder.prependRoom(expectedLength);
    if (room == nullptr) {
      encoder.setError();
      return;
    }

    size_t length = 0;
    int res = mbedtls_ecp_point_write_binary(P256::group(), this, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &length, room, expectedLength);
    if (res != 0 || length != expectedLength) {
      encoder.setError();
    }
  }

  bool decodeFrom(const Decoder::Tlv& d)
  {
    return mbedtls_ecp_point_read_binary(P256::group(), this, d.value, d.length) == 0 &&
           mbedtls_ecp_check_pubkey(P256::group(), this) == 0;
  }
};

} // namespace mbedtls
} // namespace ndnph

#endif // NDNPH_HAVE_MBED
#endif // NDNPH_PORT_MBED_COMMON_HPP
