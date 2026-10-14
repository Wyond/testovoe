#!/usr/bin/env bash
# Downloads whatever input is missing: the rule file (~2.5 MB) and the two corpora
# (~1.2 GB of zip, 7.3 GB unpacked). Honors PROBES, LEGIT and MAL like scripts/run.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
PROBES=${PROBES:-data/nmap-service-probes}
LEGIT=${LEGIT:-data/legitimate}
MAL=${MAL:-data/malicious}
mkdir -p data
if [ ! -f "$PROBES" ]; then
  curl -fL -o "$PROBES" https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes
fi
fetch() { # target dir, archive name
  [ -d "$1" ] && return
  curl -fL -o "data/$2.zip" "https://downloads.openappsec.io/waf-comparison-project/$2.zip"
  unzip -q "data/$2.zip" -d "$1"
}
fetch "$LEGIT" legitimate
fetch "$MAL" malicious
# The numbers in README were measured with this version of the rule file:
# bd1bc6b1904632c617d6cf70e1f21877f4b0abefc8db977ceaf1699accdde5ff
shasum -a 256 "$PROBES"
