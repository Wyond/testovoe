#!/usr/bin/env bash
# Runs the test suite once per confirming engine. Needs RE2, PCRE2 (Homebrew) and
# librure (scripts/build_rure.sh); engines that cannot be built are skipped.
set -euo pipefail
cd "$(dirname "$0")/.."
export CGO_ENABLED=1 PKG_CONFIG_PATH=/opt/homebrew/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}
export CGO_LDFLAGS="-L$PWD/third_party/lib"
TAGS="re2_cgo rure pcre2"
for e in go re2 rure pcre2; do
  echo "== engine $e"
  WAAP_TEST_ENGINE=$e go test -tags "$TAGS" ./... 2>&1 | grep -v 'cre2.cpp\|Wwritable\|^ *[0-9]* |\|^ *|\|^ *\^\|^$\|warning generated'
done
