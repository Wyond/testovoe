#!/usr/bin/env bash
# encoding/json vs jx for the conversion phase (docs/EXPERIMENTS.md E14).
# Alternates decoders with a pause before every run, because sustained load on a fanless
# laptop slows later runs down. Every produced corpus must be byte-identical.
#
#   LEGIT=/path/Legitimate MAL=/path/Malicious scripts/bench_decoders.sh
set -euo pipefail
cd "$(dirname "$0")/.."
LEGIT=${LEGIT:-data/legitimate}
MAL=${MAL:-data/malicious}
REPEATS=${REPEATS:-3}
PAUSE=${PAUSE:-60}
INFLIGHT=${INFLIGHT:-1024}
OUT=results/decoders.jsonl
mkdir -p bin results
go build -o bin/matcher ./cmd/matcher
rm -f "$OUT"

echo "== single file, single core (go test benchmark)"
for f in browsing_2024_amazon_hl browsing_2024_pcloud_mu; do
  sleep "$PAUSE"
  BENCH_FILE="$LEGIT/$f.json" go test ./internal/matcher -run XXX -bench Normalize -benchtime 3x | grep Benchmark | sed "s/^/$f /"
done

echo "== whole corpus, $(getconf _NPROCESSORS_ONLN) workers, inflight $INFLIGHT MB"
for r in $(seq "$REPEATS"); do
  for d in std jx jxbytes; do
    sleep "$PAUSE"
    /usr/bin/time -l bin/matcher prepare -decoder "$d" -inflight-mb "$INFLIGHT" -out "data/corpus-$d" "$LEGIT" "$MAL" 2> /tmp/waap-time.$$ | grep -v '^conversion'
    rss=$(awk '/maximum resident set size/ {print $1}' /tmp/waap-time.$$)
    user=$(awk '/ user / {print $3}' /tmp/waap-time.$$)
    python3 -I -c "import json,sys; m=json.load(open('data/corpus-$d/manifest.json')); m.pop('files'); m['max_rss_bytes']=int('$rss'); m['user_cpu_seconds']=float('$user'); m['run']=$r; print(json.dumps(m))" >> "$OUT"
    cmp -s "data/corpus-$d/corpus.bin" "data/corpus-std/corpus.bin" || { echo "corpus from $d differs from std"; exit 1; }
  done
done
rm -f /tmp/waap-time.$$
python3 -I - "$OUT" <<'PY'
import json, sys, statistics as st
rows = [json.loads(l) for l in open(sys.argv[1])]
print("| decoder | runs | median s | min-max s | user CPU s | allocations/request | MB allocated | GC cycles | longest file s | peak RSS GB |")
print("|---|---:|---:|---|---:|---:|---:|---:|---:|---:|")
for d in ("std", "jx", "jxbytes"):
    r = [x for x in rows if x["json_decoder"] == d]
    s = sorted(x["conversion_seconds"] for x in r)
    print(f"| {d} | {len(r)} | {st.median(s):.2f} | {s[0]:.2f}-{s[-1]:.2f} | {st.median(x['user_cpu_seconds'] for x in r):.1f} | "
          f"{r[0]['conversion_heap_allocs']/r[0]['request_count']:.1f} | {r[0]['conversion_heap_alloc_bytes']/1e6:.0f} | "
          f"{st.median(x['conversion_gc_cycles'] for x in r):.0f} | {st.median(x['conversion_longest_file_seconds'] for x in r):.2f} | "
          f"{max(x['max_rss_bytes'] for x in r)/2**30:.2f} |")
PY
echo "all corpora byte-identical"
