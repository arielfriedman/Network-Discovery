#!/usr/bin/env bash
# dashboard.sh - inject findings.json into the HTML template.
# The result is one self-contained file: no network requests, no build step.

build_dashboard() {
  local tpl="$BASE_DIR/lib/dashboard.template.html"
  local out="$RUN_DIR/dashboard.html"
  [[ -f "$tpl" ]] || { warn "dashboard template missing - skipping"; return 0; }
  [[ -f "$RUN_DIR/findings.json" ]] || { warn "no findings.json - skipping dashboard"; return 0; }

  step "building dashboard.html"
  python3 - "$tpl" "$RUN_DIR/findings.json" "$out" <<'PYEOF'
import sys, json
tpl_path, data_path, out_path = sys.argv[1:4]
tpl = open(tpl_path, encoding="utf-8").read()
data = json.load(open(data_path, encoding="utf-8"))

# Compact, and neutralise any sequence that could close the <script> block.
blob = json.dumps(data, separators=(",", ":"))
blob = blob.replace("</", "<\\/").replace("<!--", "<\\!--")

marker = "/*__FINDINGS_JSON__*/"
if marker not in tpl:
    sys.exit("template marker missing")
open(out_path, "w", encoding="utf-8").write(tpl.replace(marker, blob))
PYEOF
  ok "dashboard: $out"
}
