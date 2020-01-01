#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"/..

(
  cd tests/unit
  echo "unittest_files = files("
  find -name '*.t.cpp' -printf '%P\n' | sed "s/.*/'\0'/" | paste -sd,
  echo ')'
) > tests/unit/meson.build
