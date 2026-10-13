#!/usr/bin/env bash
# discover.sh - in-depth discovery of the local network and any connected
# cloud accounts. Writes a report to the Desktop, prints a summary to the
# screen, and builds an offline HTML dashboard.
#
# Usage: ./discover.sh [options]
#   --target CIDR     scan this range instead of the auto-detected one
#   --targets FILE    scan only the IPs / ranges / MACs / hostnames in FILE
#                     (one per line; see docs/SCAN_BUILDER.md)
#   --pn              with --targets: scan listed hosts even if they ignore ping
#   --quick           discovery + passive only; no per-host deep scan
#   --deep            scan all 65535 ports instead of the top 1000 (slow)
#   --auth            enable SNMP/SSH collection (asks for credentials)
#   --vault           unlock the credential vault up front
#   --vuln            run nmap vulnerability scripts (slow, noisy)
#   --no-install      never install packages
#   --no-cloud        skip the cloud inventory
#   --cloud-only      run only the cloud inventory (no LAN scanning)
#   --no-passive      skip mDNS/SSDP/NetBIOS/LLDP
#   --no-wan          skip gateway/traceroute/public-IP checks
#   --allow-public    permit a target outside private address space
#   --out DIR         write the run somewhere other than ./reports
#   -y, --yes         accept the safe defaults, do not prompt
#   -h, --help        this text

set -uo pipefail

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$BASE_DIR/config/settings.conf"
source "$BASE_DIR/lib/common.sh"
source "$BASE_DIR/lib/vault.sh"
source "$BASE_DIR/lib/preflight.sh"
source "$BASE_DIR/lib/scan_local.sh"
source "$BASE_DIR/lib/scan_auth.sh"
source "$BASE_DIR/lib/scan_cloud.sh"
source "$BASE_DIR/lib/summarize.sh"
source "$BASE_DIR/lib/creds.sh"
source "$BASE_DIR/lib/dashboard.sh"

 usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

ALLOW_PUBLIC=0
ASSUME_YES=0
OUT_BASE="$BASE_DIR/reports"

while (( $# )); do
  case "$1" in
    --target)       TARGET_CIDR="${2:?--target needs a CIDR}"; shift 2 ;;
    --targets)      TARGETS_RAW="${2:?--targets needs a file}"; shift 2 ;;
    --pn)           TARGETS_PN=1; shift ;;
    --quick)        DO_DEEP=0; shift ;;
    --deep)         NMAP_PORTS="-p-"; shift ;;
    --auth)         DO_AUTH=1; shift ;;
    --vault)        USE_VAULT=1; shift ;;
    --vuln)         DO_VULN=1; shift ;;
    --no-install)   DO_INSTALL=0; shift ;;
    --no-cloud)     DO_CLOUD=0; shift ;;
    --cloud-only)   DO_DISCOVER=0; DO_PASSIVE=0; DO_DEEP=0; DO_WAN=0; DO_AUTH=0; DO_CLOUD=1; shift ;;
    --no-passive)   DO_PASSIVE=0; shift ;;
    --no-wan)       DO_WAN=0; shift ;;
    --allow-public) ALLOW_PUBLIC=1; shift ;;
    --out)          OUT_BASE="${2:?--out needs a directory}"; shift 2 ;;
    -y|--yes)       ASSUME_YES=1; shift ;;
    -h|--help)      usage 0 ;;
    *) err "unknown option: $1"; usage 1 ;;
  esac
done

trap 'sudo_keepalive_stop; cleanup' EXIT INT
# On TERM (the panel stopped or died) also stop nmap & co. When we lead our own
# process group (as the panel starts us) take the whole group down with us.
on_term() {
  trap - TERM
  sudo_keepalive_stop; cleanup
  [[ "$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')" == "$$" ]] && kill -TERM -- "-$$" 2>/dev/null
  exit 143
}
trap on_term TERM

# Started by the panel: if the panel dies, stop the whole scan. bash runs its
# TERM trap only after the current foreground tool exits (an nmap sweep can
# take minutes), so a watcher signals the process group directly instead.
# Double fork: the watcher must not be our child, or the plain `wait` in the
# deep-scan stage would wait for it forever. It ends by itself within 2 s of
# this script ending.
if [[ -n "${ND_PARENT_PID:-}" && "$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')" == "$$" ]]; then
  ( (
    trap - TERM
    while kill -0 "$ND_PARENT_PID" 2>/dev/null && kill -0 $$ 2>/dev/null; do sleep 2; done
    kill -0 $$ 2>/dev/null && kill -TERM -- "-$$" 2>/dev/null
  ) </dev/null >/dev/null 2>&1 & )
fi
make_secure_tmp

# ---------------------------------------------------------------- banner
printf '%s\n' "$C_BOLD$C_CYN"
cat <<'BANNER'
  network discovery
  ------------------------------------------------------------
BANNER
printf '%s' "$C_RESET"

# ---------------------------------------------------------------- target
detect_target() {
  read -r _ _ GATEWAY _ IFACE _ < <(ip route show default 2>/dev/null | head -n1)
  [[ -n "${IFACE:-}" ]] || die "no default route - cannot work out which network to scan"
  SELF_IP=$(ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -n1)
  if [[ -z "$TARGET_CIDR" ]]; then
    TARGET_CIDR=$(ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | head -n1)
    TARGET_CIDR=$(python3 -c "
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1], strict=False))" "$TARGET_CIDR")
  fi
}

check_scope() {
  local ok=0 p
  for p in $ALLOWED_PREFIXES; do
    [[ "$TARGET_CIDR" == "$p"* ]] && { ok=1; break; }
  done
  if (( ok )); then return 0; fi
  warn "$TARGET_CIDR is outside private address space."
  if (( ALLOW_PUBLIC )); then
    printf '%sType the target again to confirm you are authorised to scan it: %s' "$C_BOLD" "$C_RESET" >/dev/tty
    local typed; read -r typed </dev/tty
    [[ "$typed" == "$TARGET_CIDR" ]] || die "confirmation did not match - stopping"
    warn "proceeding against $TARGET_CIDR on your confirmation"
  else
    die "refusing to scan a public range without --allow-public"
  fi
}

detect_target

SIZE=$(python3 -c "
import ipaddress,sys
n=ipaddress.ip_network(sys.argv[1]); print(n.num_addresses)" "$TARGET_CIDR")

printf '  interface : %s\n' "$IFACE"
printf '  this host : %s\n' "$SELF_IP"
printf '  gateway   : %s\n' "$GATEWAY"
if [[ -n "${TARGETS_RAW:-}" ]]; then
  [[ -r "$TARGETS_RAW" ]] || die "cannot read target file: $TARGETS_RAW"
  printf '  local net : %s  (used to find MAC targets)\n' "$TARGET_CIDR"
  printf '  targets   : %s\n\n' "$TARGETS_RAW"
else
  printf '  target    : %s  (%s addresses)\n\n' "$TARGET_CIDR" "$SIZE"
fi

check_scope

if (( SIZE > 4096 )) && [[ "$ASSUME_YES" != 1 && -z "${TARGETS_RAW:-}" ]]; then
  warn "$TARGET_CIDR covers $SIZE addresses; the sweep will take a few minutes."
  ask_yes_no "Continue?" y || exit 0
fi

# ---------------------------------------------------------------- run dir
RUN_ID="$(date '+%Y%m%d-%H%M%S')"
RUN_START_ISO="$(date -Is)"
RUN_START_SEC=$SECONDS
RUN_DIR="$OUT_BASE/$RUN_ID"
RAW="$RUN_DIR/raw"
WORK="$RUN_DIR/work"
RUN_LOG="$RUN_DIR/run.log"
mkdir -p "$RAW" "$WORK"
: >"$RUN_LOG"
info "run directory: $RUN_DIR"

if [[ -n "${TARGETS_RAW:-}" ]]; then
  # same validation as the dashboard: private addresses only, no option-like lines
  TARGETS_FILE="$WORK/targets.norm"
  python3 "$BASE_DIR/lib/targets_util.py" normalize "$TARGETS_RAW" "$BASE_DIR/config/settings.conf" \
      >"$TARGETS_FILE" 2>"$WORK/targets.skipped" || true
  while IFS= read -r l; do warn "$l"; done <"$WORK/targets.skipped"
  [[ -s "$TARGETS_FILE" ]] || die "no usable targets in $TARGETS_RAW"
  info "$(wc -l <"$TARGETS_FILE") target(s) accepted"
fi

load_creds

init_sudo
sudo_keepalive_start

[[ "${USE_VAULT:-0}" == 1 ]] && vault_unlock --optional

# ---------------------------------------------------------------- stages
preflight
stage_discover
stage_passive
stage_deep
stage_wan
stage_auth
stage_cloud

# ---------------------------------------------------------------- report
section "Building report"
build_json
build_dashboard
build_text_report
vault_save_if_dirty
prune_old_runs
publish_outputs

section "Done in $(fmt_duration $(( SECONDS - RUN_START_SEC )))"
