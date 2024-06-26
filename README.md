# NDNph: Named Data Networking packet headers

[![GitHub Workflow status](https://img.shields.io/github/actions/workflow/status/yoursunny/NDNph/build.yml?style=flat)](https://github.com/yoursunny/NDNph/actions) [![Coveralls code coverage](https://img.shields.io/coveralls/github/yoursunny/NDNph?style=flat)](https://coveralls.io/github/yoursunny/NDNph) [![GitHub code size](https://img.shields.io/github/languages/code-size/yoursunny/NDNph?style=flat)](https://github.com/yoursunny/NDNph)

**NDNph** provides [Named Data Networking](https://named-data.net) packet encoding and more in a header-only C++11 library.
It is part of [esp8266ndn](https://github.com/yoursunny/esp8266ndn) that supports microcontroller programming in Arduino IDE.
NDNph can also work independently on Linux and other platforms.

* [Doxygen documentation](https://esp8266ndn.ndn.today) together with esp8266ndn
* [#NDNph on Twitter](https://twitter.com/hashtag/NDNph) for announcements
* [GitHub Issues](https://github.com/yoursunny/NDNph) for bug reports and best-effort support

![NDNph logo](docs/logo.svg)

## Features

Packet encoding and decoding

* Interest and Data
  * [v0.3](https://docs.named-data.net/NDN-packet-spec/0.3/) format only
  * TLV evolvability: yes
  * forwarding hint: yes, limited to one name
* [NDNLPv2](https://redmine.named-data.net/projects/nfd/wiki/NDNLPv2)
  * fragmentation and reassembly: yes, requires in-order delivery
  * Nack: partial
  * PIT token: yes
  * congestion mark: no
  * link layer reliability: no
* Signed Interest: [v0.3 format](https://docs.named-data.net/NDN-packet-spec/0.3/signed-interest.html)
* Naming Convention: [rev3 format](https://named-data.net/publications/techreports/ndn-tr-22-3-ndn-memo-naming-conventions/)

Transports

* UDP: IPv4 and IPv6, unicast only
* shared memory packet interface (memif)

KeyChain

* Crypto: using [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) library
  * SHA256: yes
  * ECDSA: P-256 curve only
  * HMAC-SHA256: yes
  * RSA: no
  * Ed25519: no
  * Null: yes
* [NDN certificates](https://docs.named-data.net/NDN-packet-spec/0.3/certificate.html): basic support
* Persistent key and certificate storage: binary files
* Trust schema: no

Application layer services

* [ndnping](https://github.com/named-data/ndn-tools/tree/master/tools/ping) server and client
* segmented object producer and consumer
* [Realtime Data Retrieval (RDR)](https://redmine.named-data.net/projects/ndn-tlv/wiki/RDR) metadata producer and consumer
* [NDNCERT](https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3) server and client
  * supported challenges: "nop" and "possession"

## Installation

For Arduino, see [esp8266ndn](https://github.com/yoursunny/esp8266ndn) instructions.

For Linux,

1. Install dependencies
   * C++ compiler such as GCC, install Ubuntu package `build-essential`
   * [Meson](https://mesonbuild.com/), install pip package `meson`
   * [Ninja build system](https://ninja-build.org/), install Ubuntu package `ninja-build`
   * [Mbed TLS](https://github.com/ARMmbed/mbedtls) 2.16+ or 3.x, install from source or Ubuntu package `libmbedtls-dev`
   * [Boost](https://www.boost.org/) header-only libraries, install Ubuntu package `libboost-dev`
   * [libmemif](https://s3-docs.fd.io/vpp/22.06/interfacing/libmemif/) 4.0, install from VPP 22.06+ source
   * Note: all dependencies are optional, but omitting a dependency may necessitate extra porting work
2. Create build directory: `meson setup build`
3. Enter build directory and execute build: `meson compile -C build`
4. Run unit test (optional): `meson test -C build`
5. Install headers to system: `sudo meson install -C build`
6. Add `#include <NDNph-config.h>` and `#include <NDNph.h>` in your project, and start coding.
7. Check out the [example programs](programs/) for how to use.

To use as a Meson subproject, copy and modify the [sample Wrap file](docs/NDNph.wrap).
