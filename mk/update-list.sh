#!/bin/bash
set -e
set -o pipefail
cd "$( dirname "${BASH_SOURCE[0]}" )"/..
export LC_ALL=C

(
  cd src/ndnph
  echo '#ifndef NDNPH_H'
  echo '#define NDNPH_H'
  for P in clock ec fs queue random sha256 timingsafe; do
    echo '#include "ndnph/port/'$P'/port.hpp"'
  done
  find . -path ./port -prune -o -name '*.hpp' -printf '%P\n' | sort | sed 's|.*|#include "ndnph/\0"|'
  echo '#include "ndnph/port/transport/port.hpp"'
  echo '#endif // NDNPH_H'
) > src/NDNph.h

(
  cd tests/unit
  echo 'unittest_files = files('
  find -name '*.cpp' -printf '%P\n' | sort | sed "s|.*|'\0'|" | paste -sd,
  echo ')'
) > tests/unit/meson.build

(
  cd programs
  find -name '*.cpp' -printf '%P\n' | sort | sed "s|\(.*\)\.cpp|executable('ndnph-\1', '\1.cpp', dependencies: [lib_dep])|"
) > programs/meson.build
