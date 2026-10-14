#!/usr/bin/env bash
# Downloads whatever input is missing: the rule file (~2.5 MB) and the two corpora
# (~1.2 GB of zip, 7.3 GB unpacked). Honors PROBES, LEGIT and MAL like scripts/run.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
PROBES=${PROBES:-data/nmap-service-probes}
LEGIT=${LEGIT:-data/legitimate}
MAL=${MAL:-data/malicious}
mkdir -p data
# Pinned: nmap's master moves (on 2026-10-12 a ms-wbt-server pattern changed), and the
# numbers in README were measured with this exact file.
NMAP_COMMIT=3b71f8059f722723a038f37ccc08f7c5aac3d084
NMAP_SHA256=bd1bc6b1904632c617d6cf70e1f21877f4b0abefc8db977ceaf1699accdde5ff
if [ ! -f "$PROBES" ]; then
  curl -fL -o "$PROBES" "https://raw.githubusercontent.com/nmap/nmap/$NMAP_COMMIT/nmap-service-probes"
fi
fetch() { # target dir, archive name
  [ -d "$1" ] && return
  curl -fL -o "data/$2.zip" "https://downloads.openappsec.io/waf-comparison-project/$2.zip"
  unzip -q "data/$2.zip" -d "$1"
}
fetch "$LEGIT" legitimate
fetch "$MAL" malicious
got=$(shasum -a 256 "$PROBES" | cut -d' ' -f1)
if [ "$got" != "$NMAP_SHA256" ]; then
  echo "warning: $PROBES has SHA256 $got, README numbers were measured with $NMAP_SHA256" >&2
fi
