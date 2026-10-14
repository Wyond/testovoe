#!/usr/bin/env bash
# Reproduces every number in README.md: tests, sanity diff, naive baseline, scaling.
#
#   scripts/run.sh                                   # data/ is fetched if missing
#   LEGIT=/path/Legitimate MAL=/path/Malicious scripts/run.sh
#   WORKERS="1 2 4 8" REPEATS=3 BASELINE=100000 scripts/run.sh
#
# Output: results/metrics.jsonl (one line per run), results/summary.md, results/env.txt.
set -euo pipefail
cd "$(dirname "$0")/.."

LEGIT=${LEGIT:-data/legitimate}
MAL=${MAL:-data/malicious}
PROBES=${PROBES:-data/nmap-service-probes}
CORPUS=${CORPUS:-data/corpus}
REPEATS=${REPEATS:-3}
BASELINE=${BASELINE:-100000}
NCPU=$(getconf _NPROCESSORS_ONLN)
if [ -z "${WORKERS:-}" ]; then
  WORKERS=1; w=2
  while [ "$w" -lt "$NCPU" ]; do WORKERS="$WORKERS $w"; w=$((w * 2)); done
  [ "$NCPU" -gt 1 ] && WORKERS="$WORKERS $NCPU"
fi

if [ ! -f "$PROBES" ] || [ ! -d "$LEGIT" ] || [ ! -d "$MAL" ]; then scripts/fetch_data.sh; fi
mkdir -p bin results
go build -o bin/matcher ./cmd/matcher
go test ./...

{ date; go version; uname -a; echo "logical CPUs: $NCPU"
  sysctl -n machdep.cpu.brand_string hw.perflevel0.physicalcpu hw.perflevel1.physicalcpu hw.memsize 2>/dev/null || lscpu 2>/dev/null || true
  shasum -a 256 "$PROBES"; } > results/env.txt

# Phase A: JSON -> binary corpus (once; FORCE_PREPARE=1 repeats it). Its time is in the manifest.
if [ ! -f "$CORPUS/manifest.json" ] || [ -n "${FORCE_PREPARE:-}" ]; then
  bin/matcher prepare -out "$CORPUS" "$LEGIT" "$MAL"
fi

M=results/metrics.jsonl
rm -f "$M"
run() { bin/matcher run -corpus "$CORPUS" -probes "$PROBES" -metrics "$M" "$@" | tail -1; }

echo "== sanity: naive vs fast, 1 vs N workers, mmap vs pread"
bin/matcher check -corpus "$CORPUS" -probes "$PROBES" -sample 20000 -full | grep -v '^  unsupported'

echo "== baseline: naive, 1 worker, $BASELINE requests spread over the corpus; then fast on the same requests"
run -mode naive -workers 1 -sample "$BASELINE" -label baseline -out results/baseline-naive.jsonl
for _ in $(seq "$REPEATS"); do
  run -mode fast -workers 1 -sample "$BASELINE" -label baseline -out results/baseline-fast.jsonl
done

echo "== scaling: fast, whole corpus, results written to results/out.jsonl"
for _ in $(seq "$REPEATS"); do
  for w in $WORKERS; do run -mode fast -workers "$w" -label full -out results/out.jsonl; done
done

bin/matcher summary "$M" "$CORPUS" | tee results/summary.md
