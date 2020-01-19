#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"/..

(
  cd src/ndnph
  echo '#ifndef NDNPH_H'
  echo '#define NDNPH_H'
  find . -path ./port -prune -o -name '*.hpp' -printf '%P\n' | sed 's|.*|#include "ndnph/\0"|'
  echo '#include "ndnph/port/crypto/port.hpp"'
  echo '#include "ndnph/port/random/port.hpp"'
  echo '#include "ndnph/port/transport/port.hpp"'
  echo '#endif // NDNPH_H'
) > src/NDNph.h

(
  cd tests/unit
  echo 'unittest_files = files('
  find -name '*.cpp' -printf '%P\n' | sed "s|.*|'\0'|" | paste -sd,
  echo ')'
) > tests/unit/meson.build
