#!/usr/bin/env bash
# Reproduces every number in README.md.
#
#   scripts/run.sh                                        # data/ is fetched if missing
#   LEGIT=/path/Legitimate MAL=/path/Malicious scripts/run.sh
#   WORKERS="1 2 4 8" REPEATS=3 BASELINE=100000 PAUSE=0 scripts/run.sh
#   ENGINES=go scripts/run.sh                             # skip the native engines
#
# Main configuration: every rule is confirmed by the engine `matcher calibrate` chose for
# it (Go, RE2 or Rust regex, results/backends.json), and the 807 rules Go cannot compile
# run on PCRE2. That needs RE2 and PCRE2 (brew install re2 pcre2 pkg-config) and Rust
# (brew install rust) to build librure. Without them the script measures plain Go only.
# Plain Go is measured in either case, as the dependency-free reference.
#
# Output: results/summary.md, results/metrics.jsonl (one line per run), results/env.txt.
set -euo pipefail
cd "$(dirname "$0")/.."

LEGIT=${LEGIT:-data/legitimate}
MAL=${MAL:-data/malicious}
PROBES=${PROBES:-data/nmap-service-probes}
CORPUS=${CORPUS:-data/corpus}
REPEATS=${REPEATS:-3}
BASELINE=${BASELINE:-100000}
PAUSE=${PAUSE:-0} # seconds before each timed run; a fanless laptop slows down under load
NCPU=$(getconf _NPROCESSORS_ONLN)
if [ -z "${WORKERS:-}" ]; then
  WORKERS=1; w=2
  while [ "$w" -lt "$NCPU" ]; do WORKERS="$WORKERS $w"; w=$((w * 2)); done
  [ "$NCPU" -gt 1 ] && WORKERS="$WORKERS $NCPU"
fi

if [ ! -f "$PROBES" ] || [ ! -d "$LEGIT" ] || [ ! -d "$MAL" ]; then PROBES=$PROBES LEGIT=$LEGIT MAL=$MAL scripts/fetch_data.sh; fi
mkdir -p bin results

# Native engines, if their libraries are there.
export PKG_CONFIG_PATH=/opt/homebrew/lib/pkgconfig:/usr/local/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}
native=no
if [ "${ENGINES:-auto}" != go ] && pkg-config --exists re2 libpcre2-8 2>/dev/null; then
  if [ -f third_party/lib/librure.a ] || { command -v cargo >/dev/null && scripts/build_rure.sh; }; then
    native=yes
  fi
fi
if [ "$native" = yes ]; then
  export CGO_ENABLED=1 CGO_LDFLAGS="-L$PWD/third_party/lib"
  go build -tags 're2_cgo rure pcre2' -o bin/matcher ./cmd/matcher 2>/dev/null
  scripts/test_engines.sh | grep -v 'no test files'
  MAIN="-backends results/backends.json -excluded pcre2"
  MAIN_LABEL=hybrid+pcre2
else
  echo "native engines not available: measuring plain Go only"
  go build -o bin/matcher ./cmd/matcher
  go test ./...
  MAIN=""
  MAIN_LABEL=go
fi

{ date; go version; uname -a; echo "logical CPUs: $NCPU"; echo "main configuration: $MAIN_LABEL ($MAIN)"
  sysctl -n machdep.cpu.brand_string hw.perflevel0.physicalcpu hw.perflevel1.physicalcpu hw.memsize 2>/dev/null || lscpu 2>/dev/null || true
  shasum -a 256 "$PROBES"; } > results/env.txt

# Phase A: JSON -> binary corpus (once; FORCE_PREPARE=1 repeats it). Its time is in the manifest.
if [ ! -f "$CORPUS/manifest.json" ] || [ -n "${FORCE_PREPARE:-}" ]; then
  bin/matcher prepare -out "$CORPUS" "$LEGIT" "$MAL"
fi
C="-corpus $CORPUS -probes $PROBES"

if [ "$native" = yes ] && [ ! -f results/backends.json ]; then
  echo "== calibrate: per-rule engine on 50000 requests disjoint from the baseline sample"
  bin/matcher calibrate $C -engines go,re2,rure -sample 50000 -offset 1 -out results/backends.json | tail -3
fi

M=results/metrics.jsonl
rm -f "$M"
run() { sleep "$PAUSE"; bin/matcher run $C -metrics "$M" "$@" | tail -1; }
# An untimed pass first: a long naive run can push part of the corpus out of the page
# cache, and the next timed run would then measure disk reads (seen as 6000 major faults).
warm() { bin/matcher run $C "$@" -mode fast -workers "$NCPU" -out "" > /dev/null; }

echo "== sanity ($MAIN_LABEL): naive vs fast, 1 vs N workers, mmap vs pread"
bin/matcher check $C $MAIN -sample 20000 -full | grep -E '^(OK|FAIL|engines)' | cut -c1-200

echo "== baseline ($MAIN_LABEL): naive, 1 worker, $BASELINE requests spread over the corpus; then fast on the same requests"
run $MAIN -mode naive -workers 1 -sample "$BASELINE" -label baseline -out results/baseline-naive.jsonl
warm $MAIN
for _ in $(seq "$REPEATS"); do
  run $MAIN -mode fast -workers 1 -sample "$BASELINE" -label baseline -out results/baseline-fast.jsonl
done

echo "== scaling ($MAIN_LABEL), whole corpus, results written to results/out.jsonl"
warm $MAIN
for _ in $(seq "$REPEATS"); do
  for w in $WORKERS; do run $MAIN -mode fast -workers "$w" -label "$MAIN_LABEL" -out results/out.jsonl; done
  if [ "$native" = yes ]; then # dependency-free reference, same conditions
    for w in 1 "$NCPU"; do run -mode fast -workers "$w" -label go -out results/out-go.jsonl; done
  fi
done

bin/matcher summary "$M" "$CORPUS" | tee results/summary.md
