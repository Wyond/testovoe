#!/usr/bin/env bash
# Checks a clean Linux build inside a golang container, the way a reviewer would:
# pure Go build and tests, librure from scripts/build_rure.sh, tests on every engine,
# the race detector, then QUICK=1 scripts/run.sh on a data subset. Timings inside a
# container mean nothing; only the checks count. Results: results/linux-check.log.
#
#   docker run --rm --platform linux/arm64 \
#     -v "$PWD":/repo:ro -v /path/legit-subset:/in/legit:ro -v /path/Malicious:/in/mal:ro \
#     -v "$PWD"/data/nmap-service-probes:/in/nmap-service-probes:ro \
#     -v "$PWD"/scripts/check_linux.sh:/check.sh:ro golang:1.27-trixie bash /check.sh
#
# --platform linux/amd64 runs the same on x86-64 (emulated on Apple Silicon).
set -euo pipefail
echo "== platform: $(uname -sm), $(go version)"
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq pkg-config libre2-dev libpcre2-dev libsimdjson-dev cargo >/dev/null 2>&1
echo "== libraries: re2 $(pkg-config --modversion re2), pcre2 $(pkg-config --modversion libpcre2-8), simdjson $(pkg-config --modversion simdjson 2>/dev/null || echo missing), $(cargo --version)"
git clone -q /repo /work && cd /work && git log --oneline -1
echo "== pure Go (no native libraries)"
CGO_ENABLED=0 go build ./... && echo "build OK"
CGO_ENABLED=0 go test -count=1 ./... 2>&1 | grep -E '^(ok|FAIL|---|panic)'
echo "== Rust regex (scripts/build_rure.sh)"
scripts/build_rure.sh > /tmp/rure.log 2>&1 && echo "librure OK at $(git -C third_party/regex rev-parse --short HEAD)" || { tail -20 /tmp/rure.log; exit 1; }
export CGO_ENABLED=1 CGO_LDFLAGS="-L$PWD/third_party/lib"
TAGS='simdjson re2_cgo rure pcre2'
echo "== all engines: tests per engine"
for e in go re2 rure pcre2; do printf '%-6s ' $e; WAAP_TEST_ENGINE=$e go test -count=1 -tags "$TAGS" ./internal/matcher 2>&1 | grep -E '^(ok|FAIL|---|panic)' | tail -1; done
echo "== race detector, stream and oracle tests"
go test -count=1 -race -tags "$TAGS" ./internal/matcher -run 'Stream|Oracle' 2>&1 | grep -E '^(ok|FAIL|---|panic|WARNING: DATA RACE)' | head -5
go build -tags "$TAGS" -o bin/matcher ./cmd/matcher
bin/matcher stream -h 2>&1 | grep -o 'JSON parser: [a-z, ]*'
echo "== QUICK=1 scripts/run.sh on a data subset (timings in a container mean nothing)"
mkdir -p data && PROBES=/in/nmap-service-probes LEGIT=/in/legit MAL=/in/mal QUICK=1 PAUSE=0 scripts/run.sh 2>&1 | grep -E '^(build tags|==|OK|FAIL|эталон|запросов|совпадений|правил)|parsed by|identical|rror|panic' | cut -c1-200
echo "== done"
