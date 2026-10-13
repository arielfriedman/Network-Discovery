#!/usr/bin/env bash
# update-vendors.sh - download the current MAC vendor registry from the IEEE
# (https://standards-oui.ieee.org/oui/oui.csv, the official source) into
# config/ieee-oui.csv. Scans read it before the copies shipped with
# arp-scan / nmap, which can be years old (newer Raspberry Pi prefixes such
# as 88:A2:9E and 2C:CF:67 are missing from them). Safe to re-run; no root.
set -euo pipefail
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
URL="https://standards-oui.ieee.org/oui/oui.csv"
OUT="$BASE_DIR/config/ieee-oui.csv"
tmp="$(mktemp "$OUT.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
echo "downloading $URL ..."
curl -fsSL --max-time 120 --retry 2 -A "SentinelScan vendor update" -o "$tmp" "$URL"
# sanity check before replacing the old copy
head -n1 "$tmp" | grep -q '^Registry,Assignment,Organization Name' || { echo "unexpected file format - kept the old copy" >&2; exit 1; }
n=$(grep -c '^MA-L,' "$tmp" || true)
(( n > 10000 )) || { echo "only $n entries - kept the old copy" >&2; exit 1; }
chmod 644 "$tmp"; mv -f "$tmp" "$OUT"; trap - EXIT
echo "saved $n vendor prefixes to $OUT"
