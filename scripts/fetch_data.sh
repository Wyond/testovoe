#!/usr/bin/env bash
# Downloads the rule file and both corpora into data/ (about 1.2 GB of zip, 7.3 GB unpacked).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data
[ -f data/nmap-service-probes ] || curl -fL -o data/nmap-service-probes \
  https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes
for name in legitimate malicious; do
  [ -d "data/$name" ] && continue
  curl -fL -o "data/$name.zip" "https://downloads.openappsec.io/waf-comparison-project/$name.zip"
  unzip -q "data/$name.zip" -d "data/$name"
done
shasum -a 256 data/nmap-service-probes
