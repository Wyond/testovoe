#!/usr/bin/env bash
# Reproduces every number in README.md.
#
#   scripts/run.sh                                         # data/ is fetched if missing
#   LEGIT=/path/Legitimate MAL=/path/Malicious scripts/run.sh
#   QUICK=1 scripts/run.sh                                 # ~2-3 min smoke run, not for the README
#   WORKERS="1 2 4 8" REPEATS=3 BASELINE=100000 PAUSE=0 scripts/run.sh
#   PARSER=jx scripts/run.sh                               # control run: jx instead of simdjson
#   READERS=1 scripts/run.sh                               # files read one at a time (default 4 in parallel)
#   ORACLE=0 scripts/run.sh                                # nmap-semantics comparison on all requests (~6 min)
#   ENGINES=go PARSER=jx scripts/run.sh                    # no native libraries at all
#
# Two modes are measured and reported separately:
#
#   1. End-to-end streaming (main): every run reads the JSON files again, finds element
#      boundaries, parses each element, normalizes, matches and writes the result.
#   2. Matcher-only: the same requests prepared once into a binary corpus; JSON cost is
#      excluded. This is also where the single-threaded naive baseline runs.
#
# The main demonstration parses JSON with simdjson (SIMD; NEON on Apple Silicon) and
# fails loudly if it is not installed, rather than quietly measuring jx; jx is the
# control (PARSER=jx). Native matcher parts, used when installed (brew install re2 pcre2
# simdjson pkg-config rust): the per-rule engines from results/backends.json and PCRE2
# for the 807 rules Go cannot compile; without them the matcher is Go regexp.
#
# Output: results/summary.md, results/metrics.jsonl (one line per run), results/env.txt.
set -euo pipefail
cd "$(dirname "$0")/.."

LEGIT=${LEGIT:-data/legitimate}
MAL=${MAL:-data/malicious}
PROBES=${PROBES:-data/nmap-service-probes}
CORPUS=${CORPUS:-data/corpus}
NCPU=$(getconf _NPROCESSORS_ONLN)
if [ -n "${QUICK:-}" ]; then
  REPEATS=${REPEATS:-1}; BASELINE=${BASELINE:-10000}; WORKERS=${WORKERS:-"1 $NCPU"}
fi
REPEATS=${REPEATS:-3}
BASELINE=${BASELINE:-100000}
PAUSE=${PAUSE:-0} # seconds before each timed run; a fanless laptop slows down under load
if [ -z "${WORKERS:-}" ]; then
  WORKERS=1; w=2
  while [ "$w" -lt "$NCPU" ]; do WORKERS="$WORKERS $w"; w=$((w * 2)); done
  [ "$NCPU" -gt 1 ] && WORKERS="$WORKERS $NCPU"
fi

if [ ! -f "$PROBES" ] || [ ! -d "$LEGIT" ] || [ ! -d "$MAL" ]; then PROBES=$PROBES LEGIT=$LEGIT MAL=$MAL scripts/fetch_data.sh; fi
mkdir -p bin results results/cache

# --- build: native parts if their libraries are there ---------------------------------
export PKG_CONFIG_PATH=/opt/homebrew/lib/pkgconfig:/usr/local/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}
TAGS=""
if [ "${ENGINES:-auto}" != go ] && pkg-config --exists re2 libpcre2-8 2>/dev/null; then
  if [ -f third_party/lib/librure.a ] || { command -v cargo >/dev/null && scripts/build_rure.sh; }; then
    TAGS="re2_cgo rure pcre2"
  fi
fi
if [ "${ENGINES:-auto}" != go ] && pkg-config --exists simdjson 2>/dev/null; then TAGS="$TAGS simdjson"; fi
if [ -n "$TAGS" ]; then
  export CGO_ENABLED=1 CGO_LDFLAGS="-L$PWD/third_party/lib"
  go build -tags "$TAGS" -o bin/matcher ./cmd/matcher 2>/dev/null
else
  go build -o bin/matcher ./cmd/matcher
fi
case " $TAGS " in *" pcre2 "*) MAIN=(-backends results/backends.json -excluded pcre2); MAIN_LABEL=hybrid+pcre2 ;; *) MAIN=(); MAIN_LABEL=go ;; esac
PARSER=${PARSER:-simdjson}
READERS=${READERS:-4} # files read and split in parallel in the streaming mode
if [ "$PARSER" = simdjson ]; then
  case " $TAGS " in *" simdjson "*) ;; *)
    echo "simdjson is not available (brew install simdjson pkg-config); PARSER=jx scripts/run.sh runs the control instead" >&2
    exit 1 ;;
  esac
fi
echo "build tags: [${TAGS# }]; matcher: $MAIN_LABEL ${MAIN[*]-}; JSON parser: $PARSER"

echo "== tests"
if [ -n "$TAGS" ]; then
  ENGINE_LIST=go
  case " $TAGS " in *" re2_cgo "*) ENGINE_LIST="go re2 rure pcre2" ;; esac
  for e in $ENGINE_LIST; do
    printf '%-6s ' "$e"; WAAP_TEST_ENGINE=$e go test -tags "$TAGS" ./internal/matcher 2>&1 | grep -v 'cre2\|Wwritable\|^ *[0-9]* |\|^ *|\|^ *\^\|^$\|warning generated' | tail -1
  done
else
  go test ./...
fi

{ date; git rev-parse --short HEAD 2>/dev/null || true; go version; uname -a; echo "logical CPUs: $NCPU"
  echo "build tags: [$TAGS]; matcher: $MAIN_LABEL ${MAIN[*]-}; JSON parser: $PARSER"
  sysctl -n machdep.cpu.brand_string hw.perflevel0.physicalcpu hw.perflevel1.physicalcpu hw.memsize 2>/dev/null || lscpu 2>/dev/null || true
  shasum -a 256 "$PROBES"; } > results/env.txt

C=(-probes "$PROBES" ${MAIN[@]+"${MAIN[@]}"}) # bash 3.2 (macOS) rejects "${a[@]}" of an empty array under set -u
INPUT=("$LEGIT" "$MAL")
M=results/metrics.jsonl
rm -f "$M"
stream() { sleep "$PAUSE"; bin/matcher stream "${C[@]}" -readers "$READERS" -metrics "$M" "$@" "${INPUT[@]}" | grep -A1 '^stream' | cut -c1-250; }
run() { sleep "$PAUSE"; bin/matcher run "${C[@]}" -corpus "$CORPUS" -metrics "$M" "$@" | tail -1; }

if [ "${MAIN_LABEL}" != go ] && [ ! -f results/backends.json ]; then
  NEED_CALIBRATION=1
fi

# --- matcher-only preparation (also the reference for the streaming checks) -----------
if [ ! -f "$CORPUS/manifest.json" ] || [ -n "${FORCE_PREPARE:-}" ]; then
  echo "== prepare: JSON -> binary corpus (matcher-only mode)"
  bin/matcher prepare -out "$CORPUS" "${INPUT[@]}" | head -1
fi
if [ -n "${NEED_CALIBRATION:-}" ]; then
  echo "== calibrate: per-rule engine on 50000 requests disjoint from the baseline sample"
  bin/matcher calibrate -probes "$PROBES" -corpus "$CORPUS" -engines go,re2,rure -sample 50000 -offset 1 -out results/backends.json | tail -3
fi

echo "== 1. end-to-end streaming: correctness"
for p in $(bin/matcher stream -h 2>&1 | grep -o 'JSON parser: [a-z, ]*' | sed 's/JSON parser: //; s/,//g'); do
  bin/matcher check-stream -corpus "$CORPUS" -parser "$p" "${INPUT[@]}"
done
bin/matcher run "${C[@]}" -corpus "$CORPUS" -workers "$NCPU" -out results/out-corpus.jsonl > /dev/null
sort results/out-corpus.jsonl > results/out-corpus.sorted
for wk in "1 1" "$NCPU 1" "$NCPU $READERS"; do
  w=${wk% *}; k=${wk#* }
  rm -f results/out-stream.jsonl
  bin/matcher stream "${C[@]}" -parser "$PARSER" -workers "$w" -readers "$k" -out results/out-stream.jsonl "${INPUT[@]}" > /dev/null
  if sort results/out-stream.jsonl | cmp -s - results/out-corpus.sorted; then
    echo "OK   stream ($PARSER, $w workers, $k readers): output identical to the matcher-only run, $(wc -l < results/out-stream.jsonl | tr -d ' ') lines"
  else
    echo "FAIL stream ($PARSER, $w workers, $k readers): output differs from the matcher-only run"; exit 1
  fi
done
rm -f results/out-corpus.sorted results/out-stream.jsonl results/out-corpus.jsonl

echo "== 1. end-to-end streaming: scaling ($PARSER, $MAIN_LABEL), results written to results/out.jsonl"
for _ in $(seq "$REPEATS"); do
  for w in $WORKERS; do stream -parser "$PARSER" -workers "$w" -label "stream-$PARSER" -out results/out.jsonl; done
done
if [ "$PARSER" != jx ]; then
  echo "== 1. end-to-end streaming: parser A/B, same matcher, alternating, 1 and $NCPU workers"
  for _ in $(seq "$REPEATS"); do
    for w in 1 "$NCPU"; do
      stream -parser jx -workers "$w" -label stream-jx -out results/out.jsonl
      stream -parser "$PARSER" -workers "$w" -label "stream-$PARSER" -out results/out.jsonl
    done
  done
fi
echo "== 1. end-to-end streaming: parallel file readers, $PARSER, $NCPU workers"
for _ in $(seq "$REPEATS"); do
  for k in 1 2 3 4; do
    sleep "$PAUSE"; bin/matcher stream "${C[@]}" -parser "$PARSER" -workers "$NCPU" -readers "$k" -label "stream-$PARSER-readers" -metrics "$M" -out results/out.jsonl "${INPUT[@]}" | grep '^stream' | cut -c1-120
  done
done
echo "== 1. end-to-end streaming: reading and element boundaries alone (-split-only)"
for _ in $(seq "$REPEATS"); do
  for k in 1 "$READERS"; do
    sleep "$PAUSE"; bin/matcher stream "${C[@]}" -split-only -workers "$NCPU" -readers "$k" "${INPUT[@]}" | grep '^split-only'
  done
done

echo "== 2. matcher-only: correctness (naive vs fast, 1 vs N workers, mmap vs pread)"
FULL=-full; [ -n "${QUICK:-}" ] && FULL=""
bin/matcher check "${C[@]}" -corpus "$CORPUS" -sample 20000 $FULL | grep -E '^(OK|FAIL)'

if [ "$MAIN_LABEL" != go ]; then
  # Byte-mode PCRE2 on every rule, no prefilter: stands in for nmap's own matching.
  ORACLE=${ORACLE:-50000}; [ -n "${QUICK:-}" ] && ORACLE=5000
  echo "== 2. matcher-only: comparison with nmap semantics (PCRE2 on bytes), $ORACLE requests (0 = all)"
  bin/matcher oracle "${C[@]}" -corpus "$CORPUS" -sample "$ORACLE" | sed -n '/^reference/,$p'
fi

echo "== 2. matcher-only: baseline, naive single-threaded, $BASELINE requests spread over the corpus"
# The naive pass is slow by definition and depends only on the code, the rules, the engine
# configuration and the corpus; it is reused while none of them changes.
KEY=$( { cat internal/matcher/*.go internal/matcher/*.cpp cmd/matcher/*.go go.sum 2>/dev/null; shasum -a 256 "$PROBES" "$CORPUS/corpus.idx";
         echo "$TAGS ${MAIN[*]-} $BASELINE"; [ -f results/backends.json ] && cat results/backends.json;
         pkg-config --modversion re2 libpcre2-8 simdjson 2>/dev/null || true; } | shasum -a 256 | cut -c1-16)
if [ -f "results/cache/baseline-$KEY.jsonl" ] && [ -z "${FORCE_BASELINE:-}" ]; then
  echo "     reusing results/cache/baseline-$KEY (same code, rules, engines, corpus; FORCE_BASELINE=1 recomputes)"
  cat "results/cache/baseline-$KEY.metrics" >> "$M"
  cp "results/cache/baseline-$KEY.jsonl" results/baseline-naive.jsonl
else
  run -mode naive -workers 1 -sample "$BASELINE" -label baseline -out results/baseline-naive.jsonl
  tail -1 "$M" > "results/cache/baseline-$KEY.metrics"
  cp results/baseline-naive.jsonl "results/cache/baseline-$KEY.jsonl"
fi
bin/matcher run "${C[@]}" -corpus "$CORPUS" -mode fast -workers "$NCPU" -out "" > /dev/null # warm the page cache
for _ in $(seq "$REPEATS"); do
  run -mode fast -workers 1 -sample "$BASELINE" -label baseline -out results/baseline-fast.jsonl
done
if sort results/baseline-naive.jsonl | cmp -s - <(sort results/baseline-fast.jsonl); then
  echo "OK   baseline: naive and fast outputs identical on $BASELINE requests"
else
  echo "FAIL baseline: naive and fast outputs differ"; exit 1
fi

echo "== 2. matcher-only: scaling ($MAIN_LABEL)"
for _ in $(seq "$REPEATS"); do
  for w in 1 "$NCPU"; do run -mode fast -workers "$w" -label "matcher-only" -out results/out.jsonl; done
done

bin/matcher summary "$M" "$CORPUS" | tee results/summary.md
