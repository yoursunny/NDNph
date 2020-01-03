#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"/..

(
  cd src/ndnph
  echo "#ifndef NDNPH_H"
  echo "#define NDNPH_H"
  find -name '*.hpp' -printf '%P\n' | sed 's|.*|#include "ndnph/\0"|'
  echo "#endif // NDNPH_H"
) > src/NDNph.h

(
  cd tests/unit
  echo "unittest_files = files("
  find -name '*.t.cpp' -printf '%P\n' | sed "s|.*|'\0'|" | paste -sd,
  echo ')'
) > tests/unit/meson.build
