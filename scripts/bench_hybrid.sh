#!/usr/bin/env bash
# Engine configurations behind the same prefilter (docs/EXPERIMENTS.md E19):
# single engines, the per-rule hybrid from `matcher calibrate`, and PCRE2 for the rules
# Go cannot compile. Each configuration is checked (naive == fast, 1 == N workers) and
# its output compared with plain Go; runs alternate with a pause before each.
set -euo pipefail
cd "$(dirname "$0")/.."
export CGO_ENABLED=1 PKG_CONFIG_PATH=/opt/homebrew/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}
export CGO_LDFLAGS="-L$PWD/third_party/lib"
REPEATS=${REPEATS:-3}
PAUSE=${PAUSE:-30}
B=bin/matcher-all
M=results/hybrid.jsonl
go build -tags 're2_cgo rure pcre2' -o $B ./cmd/matcher 2>/dev/null
[ -f results/backends.json ] || $B calibrate -engines go,re2,rure -sample 50000 -offset 1 -out results/backends.json
rm -f "$M"
configs=(
  "go|-engine go"
  "re2|-engine re2"
  "rure|-engine rure"
  "pcre2|-engine pcre2"
  "hybrid|-engine go -backends results/backends.json"
  "go+excluded|-engine go -excluded pcre2"
  "hybrid+excluded|-engine go -backends results/backends.json -excluded pcre2"
)
echo "== correctness per configuration (naive vs fast on 20000 requests, 1 vs 10 workers)"
for c in "${configs[@]}"; do
  name=${c%%|*}; flags=${c#*|}
  printf '%-16s ' "$name"; $B check $flags -sample 20000 | grep -E '^(OK|FAIL)' | tr '\n' ' '; echo
done
echo "== output compared with plain Go on the whole corpus"
$B run -engine go -workers 10 -out results/out-go.jsonl > /dev/null
sort results/out-go.jsonl > results/out-go.sorted
for c in "${configs[@]:1}"; do
  name=${c%%|*}; flags=${c#*|}
  $B run $flags -workers 10 -out results/out-cmp.jsonl > /dev/null
  printf '%-16s %s requests differ\n' "$name" "$(sort results/out-cmp.jsonl | diff - results/out-go.sorted | grep -c '^<' || true)"
  sort results/out-cmp.jsonl | diff - results/out-go.sorted | grep '^<' | head -3 | cut -c1-150 || true
done
rm -f results/out-cmp.jsonl results/out-go.sorted
echo "== timing (whole corpus, results written to a file)"
for r in $(seq "$REPEATS"); do
  for c in "${configs[@]}"; do
    name=${c%%|*}; flags=${c#*|}
    for w in 1 10; do
      sleep "$PAUSE"
      $B run $flags -mode fast -workers $w -label "$name" -metrics "$M" -out results/out.jsonl | tail -1 | sed "s/^/$name /"
    done
  done
done
python3 -I - "$M" <<'PY'
import json, sys, statistics as st, collections
g = collections.defaultdict(list); order = []
for l in open(sys.argv[1]):
    r = json.loads(l); k = (r["label"], r["workers"])
    if k not in g: order.append(k)
    g[k].append(r)
base = {w: st.median(x["matching_with_output_seconds"] for x in g[("go", w)]) for w in (1, 10) if ("go", w) in g}
print("| configuration | workers | median s | min-max s | req/s | vs go | regex calls/req | inconclusive | rule init s |")
print("|---|---:|---:|---|---:|---:|---:|---:|---:|")
for k in order:
    rs = g[k]; s = sorted(x["matching_with_output_seconds"] for x in rs); m = st.median(s)
    print(f"| {k[0]} | {k[1]} | {m:.3f} | {s[0]:.3f}-{s[-1]:.3f} | {rs[0]['requests']/m:.0f} | {base[k[1]]/m:.2f}x | "
          f"{rs[0]['regex_calls_per_request']:.2f} | {max(x['inconclusive'] for x in rs)} | {st.median(x['rule_init_seconds'] for x in rs):.2f} |")
PY
