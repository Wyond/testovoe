#!/usr/bin/env bash
# Builds librure (Rust regex C API) for the optional rure engine. Needs cargo
# (brew install rust). Output: third_party/lib/librure.a
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p third_party/lib
REGEX_COMMIT=72d650cb0a880a01ab6dc2137c0888e8f89740f7 # the version every measurement used
if [ ! -d third_party/regex ]; then
  git init -q third_party/regex
  git -C third_party/regex fetch -q --depth 1 https://github.com/rust-lang/regex "$REGEX_COMMIT"
  git -C third_party/regex checkout -q FETCH_HEAD
fi
[ "$(git -C third_party/regex rev-parse HEAD)" = "$REGEX_COMMIT" ] || { echo "third_party/regex is not at $REGEX_COMMIT" >&2; exit 1; }
cargo build --release --manifest-path third_party/regex/regex-capi/Cargo.toml
cp third_party/regex/target/release/librure.a third_party/lib/
