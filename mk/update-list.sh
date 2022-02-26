#!/bin/bash
set -eo pipefail
cd "$( dirname "${BASH_SOURCE[0]}" )"/..
export LC_ALL=C

(
  cd src/ndnph
  echo '#ifndef NDNPH_H'
  echo '#define NDNPH_H'
  find port -path port/transport -prune -o -name 'port.hpp' -printf '%P\n' | sort | sed -e 's|.*|#include "ndnph/port/\0"|'
  find . -path ./port -prune -o -path ./cli -prune -o -name '*.hpp' -printf '%P\n' | sort | sed 's|.*|#include "ndnph/\0"|'
  echo '#include "ndnph/port/transport/port.hpp"'
  echo '#ifdef NDNPH_WANT_CLI'
  find cli -name '*.hpp' -printf '%P\n' | sort | sed -e 's|.*|#include "ndnph/cli/\0"|'
  echo '#endif // NDNPH_WANT_CLI'
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
  find -name '*.cpp' -printf '%P\n' | sort | sed "s|\(.*\)\.cpp|executable('ndnph-\1', '\1.cpp', dependencies: [ndnph_dep])|"
) > programs/meson.build
