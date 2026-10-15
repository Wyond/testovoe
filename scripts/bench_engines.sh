#!/usr/bin/env bash
# Go regexp vs C++ RE2 (github.com/wasilibs/go-re2, cgo) as the confirming engine
# behind the same prefilter (docs/EXPERIMENTS.md E18). Needs: brew install re2 pkg-config
# Engines alternate and every run starts after a pause: the laptop slows down under load.
set -euo pipefail
cd "$(dirname "$0")/.."
CORPUS=${CORPUS:-data/corpus}
PROBES=${PROBES:-data/nmap-service-probes}
REPEATS=${REPEATS:-3}
PAUSE=${PAUSE:-45}
M=results/engines.jsonl
mkdir -p bin results
CGO_ENABLED=1 go build -tags re2_cgo -o bin/matcher-re2 ./cmd/matcher 2>/dev/null
rm -f "$M"
run() { sleep "$PAUSE"; "$@" -corpus "$CORPUS" -probes "$PROBES" -metrics "$M" | tail -1; }
for e in go re2; do
  run bin/matcher-re2 run -engine $e -mode naive -workers 1 -sample 2000 -label naive-2k -out ""
done
for r in $(seq "$REPEATS"); do
  for e in go re2; do
    for w in 1 10; do run bin/matcher-re2 run -engine $e -mode fast -workers $w -label full -out results/out.jsonl; done
  done
done
python3 -I - "$M" <<'PY'
import json, sys, statistics as st, collections
g = collections.defaultdict(list)
for l in open(sys.argv[1]):
    r = json.loads(l); g[(r["label"], r["engine"], r["mode"], r["workers"])].append(r)
print("| run | engine | workers | runs | median s | min-max s | req/s | regex calls/req | rule init s | max RSS GB |")
print("|---|---|---:|---:|---:|---|---:|---:|---:|---:|")
for (lab, eng, mode, w), rs in sorted(g.items()):
    s = sorted(r["matching_with_output_seconds"] for r in rs)
    print(f"| {lab} {mode} | {eng} | {w} | {len(rs)} | {st.median(s):.3f} | {s[0]:.3f}-{s[-1]:.3f} | "
          f"{rs[0]['requests']/st.median(s):.0f} | {rs[0]['regex_calls_per_request']:.2f} | "
          f"{st.median(r['rule_init_seconds'] for r in rs):.2f} | {max(r['max_rss_raw'] for r in rs)/2**30:.2f} |")
PY
