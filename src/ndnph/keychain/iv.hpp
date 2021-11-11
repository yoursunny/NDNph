#ifndef NDNPH_KEYCHAIN_IV_HPP
#define NDNPH_KEYCHAIN_IV_HPP

#include "../port/random/port.hpp"
#include "../tlv/nni.hpp"
#include "../tlv/value.hpp"

namespace ndnph {

/**
 * @brief AES-GCM Initialization Vector generator and checker.
 *
 * IV is 12 octets. Other sizes are not supported.
 * IV is constructed from an 8-octet random number and a 4-octet counter.
 * The random number portion is expected to stay the same.
 * The counter portion is incremented for every encrypted block.
 */
class AesGcmIvHelper
{
public:
  /** @brief IV length. */
  using IvLen = std::integral_constant<size_t, 12>;

  /** @brief AES-GCM block size. */
  using BlockSize = std::integral_constant<size_t, 16>;

  /** @brief Randomize the random number portion. */
  bool randomize()
  {
    m_ok = port::RandomSource::generate(reinterpret_cast<uint8_t*>(&random), sizeof(random));
    return m_ok;
  }

  /** @brief Write IV to @p room . */
  bool write(uint8_t room[12])
  {
    tlv::NNI8::writeValue(room, random);
    tlv::NNI4::writeValue(room + 8, counter);
    return true;
  }

  /**
   * @brief Advance the counter portion.
   * @param size ciphertext size.
   */
  bool advance(size_t size)
  {
    uint64_t nBlocks = divCeil(size, BlockSize::value);
    uint64_t cnt = static_cast<uint64_t>(counter) + nBlocks;
    if (cnt > std::numeric_limits<uint32_t>::max()) {
      m_ok = false;
    }
    counter = static_cast<uint32_t>(cnt);
    return m_ok;
  }

  /**
   * @brief Check received IV.
   * @param iv received IV.
   * @param size ciphertext size.
   * @post counter is advanced.
   */
  bool check(const uint8_t* iv, size_t size)
  {
    uint64_t rand = tlv::NNI8::readValue(iv);
    uint32_t cnt = tlv::NNI4::readValue(iv + sizeof(rand));

    if (counter == 0) {
      random = rand;
    } else if (random != rand) {
      return false;
    }

    if (cnt < counter) {
      return false;
    }
    counter = cnt;
    return advance(size);
  }

public:
  uint64_t random = 0;
  uint32_t counter = 0;

private:
  bool m_ok = true;
};

} // namespace ndnph

#endif // NDNPH_KEYCHAIN_IV_HPP
