# NDNph: Named Data Networking packet headers

[![Travis build status](https://img.shields.io/travis/com/yoursunny/NDNph?style=flat)](https://travis-ci.com/yoursunny/NDNph) [![Coveralls code coverage](https://img.shields.io/coveralls/github/yoursunny/NDNph?style=flat)](https://coveralls.io/github/yoursunny/NDNph) [![GitHub code size](https://img.shields.io/github/languages/code-size/yoursunny/NDNph?style=flat)](https://github.com/yoursunny/NDNph/)

**NDNph** provides [Named Data Networking](https://named-data.net/) packet encoding and more in a header-only C++11 library. It is part of [esp8266ndn](https://github.com/yoursunny/esp8266ndn) that supports microcontroller programming in Arduino IDE. NDNph can also work independently on Linux and other platforms.

* [Doxygen documentation](https://esp8266ndn.netlify.com/) together with esp8266ndn
* [#NDNph on Twitter](https://twitter.com/hashtag/NDNph) for announcements
* [ndn-lib mailing list](https://www.lists.cs.ucla.edu/mailman/listinfo/ndn-lib) for best-effort support

![NDNph logo](docs/logo.svg)

## Features

Packet encoding and decoding

* Interest and Data
  * [v0.3](https://named-data.net/doc/NDN-packet-spec/0.3/) format only
  * TLV evolvability: yes
  * forwarding hint: no
* [NDNLPv2](https://redmine.named-data.net/projects/nfd/wiki/NDNLPv2)
  * fragmentation and reassembly: no
  * Nack: yes
  * PIT token: yes
  * congestion mark: no
  * link layer reliability: no
* Signed Interest: [v0.3 format](https://named-data.net/doc/NDN-packet-spec/0.3/signed-interest.html)
* Naming Convention: [2019 format](https://named-data.net/publications/techreports/ndn-tr-22-2-ndn-memo-naming-conventions/)

Transports

* UDP: unicast only

KeyChain

* Crypto: using [Mbed Crypto](https://github.com/ARMmbed/mbed-crypto) library
  * SHA256: yes
  * ECDSA: P-256 curve only
  * HMAC-SHA256: no
  * RSA: no
* [NDN certificates](https://named-data.net/doc/ndn-cxx/0.7.0/specs/certificate-format.html): basic support

Application layer services

* [ndnping](https://github.com/named-data/ndn-tools/tree/master/tools/ping) server and client
* segmented object producer and consumer
* [Realtime Data Retrieval (RDR)](https://redmine.named-data.net/projects/ndn-tlv/wiki/RDR) metadata producer

## Installation

For Arduino, see [esp8266ndn](https://github.com/yoursunny/esp8266ndn) instructions.

For Linux,

1. Copy `src/*` into `/usr/local/include`.
2. Have a look at `ndnph/port/*/port.hpp`, select an implementation of each feature, and put the appropriate `#define` lines in `NDNph-defines.hpp` file of your project.
3. Add `#include "NDNph-defines.hpp"` and `#include <NDNph.h>` in your project.
