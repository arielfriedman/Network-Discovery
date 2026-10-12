#!/usr/bin/env bash
# start.sh - start the SentinelScan dashboard on http://127.0.0.1:8765
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/panel" && exec python3 serve.py "$@"
