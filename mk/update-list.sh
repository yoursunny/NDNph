#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"/..

(
  cd src/ndnph
  echo "#ifndef NDNPH_H"
  echo "#define NDNPH_H"
  find . -path ./port -prune -o -name '*.hpp' -printf '%P\n' | sed 's|.*|#include "ndnph/\0"|'
  echo '#if NDNPH_PORT_MBEDTLS'
  find ./port/mbedtls -name '*.hpp' -printf '%P\n' | sed 's|.*|#include "ndnph/port/mbedtls/\0"|'
  echo '#endif // NDNPH_PORT_MBEDTLS'
  echo "#endif // NDNPH_H"
) > src/NDNph.h

(
  cd tests/unit
  echo "unittest_files = files("
  find -name '*.cpp' -printf '%P\n' | sed "s|.*|'\0'|" | paste -sd,
  echo ')'
) > tests/unit/meson.build
