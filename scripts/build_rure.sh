#!/usr/bin/env bash
# Builds librure (Rust regex C API) for the optional rure engine. Needs cargo
# (brew install rust). Output: third_party/lib/librure.a
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p third_party/lib
[ -d third_party/regex ] || git clone -q --depth 1 https://github.com/rust-lang/regex third_party/regex
cargo build --release --manifest-path third_party/regex/regex-capi/Cargo.toml
cp third_party/regex/target/release/librure.a third_party/lib/
