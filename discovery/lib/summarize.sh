#!/usr/bin/env bash
# summarize.sh - turn the raw tool output into (a) findings.json for the
# dashboard, (b) a plain-text report, (c) an on-screen summary.

# ---------------------------------------------------------------- JSON
build_json() {
  step "building findings.json"
  RDNS="$RAW/25-rdns.txt" \
  HOSTS="$WORK/hosts.tsv" SERVICES="$WORK/services.tsv" OSFILE="$WORK/os.tsv" \
  MDNS="$RAW/20-mdns.txt" NETBIOS="$RAW/21-netbios.txt" SSDP="$RAW/22-ssdp.txt" \
  LLDP="$RAW/23-lldp.txt" PUBIP="$RAW/34-public-ip.txt" PATHF="$RAW/33-path.txt" \
  CLOUDDIR="$RAW/cloud" AWSOPEN="$WORK/aws-open-sgs.tsv" \
  META_CIDR="$TARGET_CIDR" META_IFACE="$IFACE" META_GW="$GATEWAY" \
  META_START="$RUN_START_ISO" META_ID="$RUN_ID" META_SELF="$SELF_IP" \
  TARGETS="${TARGETS_FILE:+$WORK/targets.tsv}" CREDUSE="$WORK/cred-use.tsv" SSHDIR="$RAW/ssh" VMDIR="$RAW/vms" HOSTSDIR="$RAW/hosts" HTTPJSON="$WORK/http.json" \
  python3 "$BASE_DIR/lib/build_json.py" >"$RUN_DIR/findings.json"
  ok "findings.json written"
}

# ---------------------------------------------------------------- text
build_text_report() {
  local f="$RUN_DIR/summary.txt"
  {
    printf '%s\n' "================================================================"
    printf 'NETWORK DISCOVERY REPORT\n'
    printf '%s\n' "================================================================"
    printf 'Run id      : %s\n' "$RUN_ID"
    printf 'Started     : %s\n' "$RUN_START_ISO"
    printf 'Finished    : %s\n' "$(date -Is)"
    printf 'Duration    : %s\n' "$(fmt_duration $(( SECONDS - RUN_START_SEC )))"
    printf 'Scanned by  : %s@%s (%s)\n' "$USER" "$(hostname)" "$SELF_IP"
    if [[ -n "${TARGETS_FILE:-}" ]]; then
      printf 'Target      : %s listed target(s) from %s, on %s\n' \
        "$(wc -l <"$TARGETS_FILE")" "$(basename "$TARGETS_RAW")" "$IFACE"
    else
      printf 'Target      : %s on %s\n' "$TARGET_CIDR" "$IFACE"
    fi
    printf 'Gateway     : %s\n' "$GATEWAY"
    printf '\n'

    printf -- '---- SUMMARY ---------------------------------------------------\n'
    python3 - "$RUN_DIR/findings.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
s = d["stats"]
print(f"  Live hosts            : {s['hosts']}")
print(f"  Open services         : {s['services']}")
print(f"  Distinct open ports   : {s['distinct_ports']}")
print(f"  Hosts with a hostname : {s['named_hosts']}")
print(f"  Hardware vendors seen : {s['vendors']}")
print(f"  Cloud resources       : {s['cloud_resources']}")
if d.get("notable"):
    print("\n  Worth a look:")
    for n in d["notable"]:
        print(f"    [{n['level'].upper():<4}] {n['text']}")
PYEOF
    printf '\n'

    if [[ -n "${TARGETS_FILE:-}" ]]; then
      printf -- '---- LISTED TARGETS --------------------------------------------\n'
      awk -F'\t' '{printf "  %-5s %-28s %-12s %-16s %s\n", $1, $2, $5, $4, $6}' "$WORK/targets.tsv"
      printf '\n'
    fi

    printf -- '---- HOSTS -----------------------------------------------------\n'
    python3 - "$RUN_DIR/findings.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
if not d["hosts"]:
    print("  (none)")
for h in d["hosts"]:
    ports = ", ".join(f"{p['port']}/{p['service']}" for p in h["ports"][:12])
    if len(h["ports"]) > 12: ports += f" (+{len(h['ports'])-12} more)"
    print(f"\n  {h['ip']:<16} {h.get('hostname') or '-'}")
    if h.get("mac"):    print(f"    mac      {h['mac']}  {h.get('vendor') or ''}".rstrip())
    if h.get("os"):     print(f"    os       {h['os']}" + (f"  (from {h['os_source']})" if h.get("os_source") else ""))
    for a in h.get("apps", [])[:12]:
        print(f"    app      {a['name']} on {a['port']}  [{a['evidence']}]")
    sy = h.get("system") or {}
    for k in ("os_release", "kernel", "model", "cpu", "memory"):
        if sy.get(k): print(f"    {k:<8} {sy[k]}")
    if sy.get("docker"):
        print(f"    docker   {len(sy['docker'])} container(s): " + ", ".join(f"{c['name']} ({c['image']}, {c['status'].split(' ')[0]})" for c in sy["docker"][:8]))
    if sy.get("kubernetes"): print(f"    k8s      {' '.join(sy['kubernetes'])}")
    if sy.get("services"): print(f"    services {len(sy['services'])} running: " + ", ".join(sy["services"][:15]) + (" ..." if len(sy["services"]) > 15 else ""))
    if h.get("device_type"):
        print(f"    type     {h['device_type']}" + (f" - {h['device_model']}" if h.get("device_model") else "")
              + f" ({h['device_confidence']}: {'; '.join(h['device_evidence'])[:120]})")
    if ports:           print(f"    ports    {ports}")
    for k in ("mdns", "netbios", "ssdp"):
        if h.get(k):    print(f"    {k:<8} {h[k][:100]}")
PYEOF
    printf '\n'

    printf -- '---- PORT SUMMARY ----------------------------------------------\n'
    if [[ -s "$WORK/services.tsv" ]]; then
      awk -F'\t' '{split($2,a,"/"); c[a[1]"/"a[2]" "$3]++}
        END{for(k in c) printf "  %-28s %d host(s)\n", k, c[k]}' "$WORK/services.tsv" \
        | sort -k2 -rn -t' ' | head -n 30
    else
      printf '  (no service data - deep scan skipped or found nothing)\n'
    fi
    printf '\n'

    if [[ -s "$RAW/23-lldp.txt" ]] && grep -q 'Interface:' "$RAW/23-lldp.txt" 2>/dev/null; then
      printf -- '---- SWITCH NEIGHBOURS (LLDP) ----------------------------------\n'
      grep -E 'Interface:|SysName:|PortDescr:|MgmtIP:' "$RAW/23-lldp.txt" | sed 's/^/  /'
      printf '\n'
    fi

    if [[ -s "$RAW/34-public-ip.txt" ]]; then
      printf -- '---- INTERNET FACING -------------------------------------------\n'
      grep -v '^###' "$RAW/34-public-ip.txt" | sed '/^$/d;s/^/  /'
      printf '\n'
    fi

    if [[ -d "$RAW/cloud" ]] && compgen -G "$RAW/cloud/*" >/dev/null; then
      printf -- '---- CLOUD ------------------------------------------------------\n'
      python3 - "$RUN_DIR/findings.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
c = d.get("cloud", {})
if not c: print("  (nothing collected)")
for prov, items in c.items():
    print(f"  {prov}:")
    for kind, n in items.items():
        print(f"    {kind:<22} {n}")
PYEOF
      printf '\n'
    fi

    printf -- '---- WHERE THE DETAIL IS ---------------------------------------\n'
    printf '  Full run folder : %s\n' "$RUN_DIR"
    printf '  Raw tool output : %s\n' "$RAW"
    printf '  Machine-readable: %s\n' "$RUN_DIR/findings.json"
    printf '  Dashboard       : %s\n' "$RUN_DIR/dashboard.html"
    printf '\n'
    printf 'No credentials are stored in this report.\n'
  } >"$f"
  ok "text report written"
}

# ---------------------------------------------------------------- outputs
publish_outputs() {
  section "Output"

  # 1. the copy on the Desktop
  mkdir -p "$DESKTOP_DIR"
  local desk="$DESKTOP_DIR/network-scan-$RUN_ID.txt"
  cp "$RUN_DIR/summary.txt" "$desk"
  ok "Desktop report : $desk"

  # a stable "latest" pointer, plus the dashboard
  ln -sfn "$(basename "$RUN_DIR")" "$BASE_DIR/reports/latest"  # relative, survives moving the folder
  if [[ -f "$RUN_DIR/dashboard.html" ]]; then
    cp "$RUN_DIR/dashboard.html" "$DESKTOP_DIR/network-scan-$RUN_ID.html"
    ok "Desktop dashboard: $DESKTOP_DIR/network-scan-$RUN_ID.html"
  fi

  # 2. on-screen
  echo
  cat "$RUN_DIR/summary.txt"
}

prune_old_runs() {
  [[ "${KEEP_RUNS:-0}" -gt 0 ]] || return 0
  local -a old
  mapfile -t old < <(ls -1dt "$BASE_DIR"/reports/*/ 2>/dev/null | tail -n +$((KEEP_RUNS+1)))
  (( ${#old[@]} )) || return 0
  rm -rf -- "${old[@]}" && step "pruned ${#old[@]} old run(s)"
}

fmt_duration() {
  local s=$1
  printf '%dm %02ds' $(( s / 60 )) $(( s % 60 ))
}
