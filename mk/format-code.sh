#!/bin/bash
set -eo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"/..

git ls-files '*.hpp' '*.cpp' '*.inc' '*.ino' | \
  xargs clang-format-11 -i -style=file
