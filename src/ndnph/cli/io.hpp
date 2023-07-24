#ifndef NDNPH_CLI_IO_HPP
#define NDNPH_CLI_IO_HPP

#include "../tlv/decoder.hpp"
#include "../tlv/encoder.hpp"
#include <fstream>
#include <iostream>

namespace ndnph {
namespace cli {

/** @brief Read and decode from input stream. */
template<typename T, int bufferSize = 4096>
inline bool
input(Region& region, T& target, std::istream& is = std::cin) {
  uint8_t* buffer = region.alloc(bufferSize);
  if (buffer == nullptr) {
    fprintf(stderr, "ndnph::cli::input alloc error\n");
    exit(1);
  }
  is.read(reinterpret_cast<char*>(buffer), bufferSize);

  if (!Decoder(buffer, is.gcount()).decode(target)) {
    fprintf(stderr, "ndnph::cli::input decode error\n");
    exit(1);
  }
  return true;
}

/** @brief Write an Encodable to output stream. */
template<typename Encodable, int bufferSize = 65536>
inline void
output(const Encodable& packet, std::ostream& os = std::cout) {
  StaticRegion<bufferSize> temp;
  Encoder encoder(temp);
  if (!encoder.prepend(packet)) {
    fprintf(stderr, "ndnph::cli::output encode error\n");
    exit(1);
  }
  os.write(reinterpret_cast<const char*>(encoder.begin()), encoder.size());
}

} // namespace cli
} // namespace ndnph

#endif // NDNPH_CLI_IO_HPP
