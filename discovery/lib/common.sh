#!/usr/bin/env bash
# common.sh - shared helpers: output, logging, prompts, secret handling.
# Sourced by discover.sh. Do not run directly.

# ---------- colours (disabled when not a tty, or NO_COLOR is set) ----------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
  C_BLU=$'\e[34m'; C_CYN=$'\e[36m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''
  C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_CYN=''
fi

# ---------- logging ----------
# Every message also lands in $RUN_LOG once the run directory exists.
_log_raw() {
  [[ -n "${RUN_LOG:-}" ]] && printf '%s %s\n' "$(date '+%H:%M:%S')" "$1" >>"$RUN_LOG"
  return 0
}
section() {
  printf '\n%s%s== %s %s%s\n' "$C_BOLD" "$C_BLU" "$1" \
    "$(printf '=%.0s' $(seq 1 $(( 60 - ${#1} > 0 ? 60 - ${#1} : 3 ))))" "$C_RESET"
  _log_raw "== $1"
}
info() { printf '%s[ .. ]%s %s\n' "$C_CYN" "$C_RESET" "$*"; _log_raw "[ .. ] $*"; }
ok()   { printf '%s[ ok ]%s %s\n' "$C_GRN" "$C_RESET" "$*"; _log_raw "[ ok ] $*"; }
warn() { printf '%s[warn]%s %s\n' "$C_YEL" "$C_RESET" "$*" >&2; _log_raw "[warn] $*"; }
err()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; _log_raw "[FAIL] $*"; }
die()  { err "$*"; exit 1; }
step() { printf '%s  -> %s%s\n' "$C_DIM" "$*" "$C_RESET"; _log_raw "  -> $*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------- secret handling ----------
# Secrets live in shell variables only. They are never written to the report,
# never passed as command-line arguments (argv is world-readable via /proc),
# and are wiped on exit.
declare -a _SECRET_VALUES=()
declare -a _SECRET_VARS=()

# register_secret VARNAME - remember a variable so it can be scrubbed and wiped.
register_secret() {
  local name="$1" val="${!1:-}"
  [[ -z "$val" ]] && return 0
  _SECRET_VARS+=("$name")
  _SECRET_VALUES+=("$val")
}

# scrub - filter stdin, replacing any registered secret with a placeholder.
# Always pipe tool output through this before it reaches a report file.
# The secrets go to sed in a script file in $SECURE_TMP (tmpfs, 0700), not as
# -e arguments: argv is readable by every local user via /proc.
scrub() {
  if (( ${#_SECRET_VALUES[@]} == 0 )); then cat; return; fi
  [[ -n "${SECURE_TMP:-}" && -d "$SECURE_TMP" ]] || make_secure_tmp
  local f="$SECURE_TMP/scrub.$BASHPID.sed" v
  (
    umask 077
    for v in "${_SECRET_VALUES[@]}"; do
      [[ -n "$v" ]] || continue
      printf 's|%s|***REDACTED***|g\n' "$(printf '%s' "$v" | sed 's/[][\\/.*^$|&]/\\&/g')"
    done >"$f"
  )
  sed -f "$f"
  rm -f -- "$f"
}

wipe_secrets() {
  local n
  for n in "${_SECRET_VARS[@]:-}"; do [[ -n "$n" ]] && unset "$n"; done
  _SECRET_VALUES=(); _SECRET_VARS=()
}

# SECURE_TMP - for credential files (snmp.conf etc). Prefers tmpfs so the
# contents never touch the disk. Removed by cleanup().
make_secure_tmp() {
  local base=/tmp
  [[ -d /dev/shm && -w /dev/shm ]] && base=/dev/shm
  SECURE_TMP="$(mktemp -d "$base/netdisc.XXXXXXXX")"
  chmod 700 "$SECURE_TMP"
}

# Run with sudo: files this run created belong to root. Hand them back to the
# user who ran sudo, or the next normal run / the panel can't use them.
give_back_files() {
  [[ $EUID -eq 0 && -n "${SUDO_UID:-}" && "${SUDO_UID}" != 0 ]] || return 0
  local p
  for p in "${RUN_DIR:-}" "$BASE_DIR/reports/latest" "$BASE_DIR/config"; do
    [[ -n "$p" && ( -e "$p" || -L "$p" ) ]] || continue
    find "$p" -user 0 -exec chown -h "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" {} + 2>/dev/null
  done
  return 0
}

cleanup() {
  local rc=$?
  give_back_files
  wipe_secrets
  [[ -n "${SECURE_TMP:-}" && -d "$SECURE_TMP" ]] && rm -rf -- "$SECURE_TMP"
  return $rc
}

# ---------- prompts ----------
# All prompts read from /dev/tty so they still work when stdout is redirected.
# Started from the dashboard (ND_NONINTERACTIVE=1) nobody can answer: prompts
# take their default / come back empty instead of waiting on a terminal.
ask_yes_no() {  # ask_yes_no "question" [default y|n]
  local q="$1" def="${2:-n}" ans hint
  if [[ "${ASSUME_YES:-0}" == 1 ]]; then return 0; fi
  if [[ "${ND_NONINTERACTIVE:-0}" == 1 ]]; then [[ "$def" == y ]]; return; fi
  [[ "$def" == y ]] && hint="[Y/n]" || hint="[y/N]"
  while true; do
    printf '%s%s%s %s ' "$C_BOLD" "$q" "$C_RESET" "$hint" >/dev/tty
    read -r ans </dev/tty || ans=""
    ans="${ans:-$def}"
    case "${ans,,}" in y|yes) return 0;; n|no) return 1;; esac
  done
}

ask_value() {  # ask_value VARNAME "prompt" [default]
  local __var="$1" q="$2" def="${3:-}" ans
  if [[ "${ND_NONINTERACTIVE:-0}" == 1 ]]; then printf -v "$__var" '%s' "$def"; return 0; fi
  if [[ -n "$def" ]]; then
    printf '%s%s%s [%s]: ' "$C_BOLD" "$q" "$C_RESET" "$def" >/dev/tty
  else
    printf '%s%s%s: ' "$C_BOLD" "$q" "$C_RESET" >/dev/tty
  fi
  read -r ans </dev/tty || ans=""
  printf -v "$__var" '%s' "${ans:-$def}"
}

ask_secret() {  # ask_secret VARNAME "prompt" - no echo, registered for scrubbing
  local __var="$1" q="$2" ans
  if [[ "${ND_NONINTERACTIVE:-0}" == 1 ]]; then printf -v "$__var" '%s' ""; return 0; fi
  printf '%s%s%s: ' "$C_BOLD" "$q" "$C_RESET" >/dev/tty
  read -rs ans </dev/tty || ans=""
  printf '\n' >/dev/tty
  printf -v "$__var" '%s' "$ans"
  register_secret "$__var"
}

# ---------- running tools ----------
# run_tool <label> <outfile> <cmd...>
# Runs a command, scrubs secrets from its output, writes it to the raw
# directory, and keeps going if the tool fails - one dead tool must not
# abort the whole scan.
run_tool() {
  local label="$1" out="$2"; shift 2
  step "$label"
  # machine-readable line for the SentinelScan control panel (off by default)
  [[ "${ND_PROGRESS:-0}" == 1 ]] && printf '@@cmd %s\n' "$*"
  local start=$SECONDS
  {
    printf '### %s\n### cmd: %s\n### started: %s\n\n' \
      "$label" "$*" "$(date -Is)"
  } >"$out"
  if "$@" 2>&1 | scrub >>"$out"; then
    printf '\n### finished ok in %ss\n' "$(( SECONDS - start ))" >>"$out"
    _log_raw "     ok: $label ($(( SECONDS - start ))s)"
    return 0
  else
    printf '\n### tool exited non-zero after %ss\n' "$(( SECONDS - start ))" >>"$out"
    warn "$label did not complete cleanly (see $(basename "$out"))"
    return 1
  fi
}

# sudo wrapper - uses the GUI askpass helper when there is no tty cached creds
SUDO=""
init_sudo() {
  if [[ $EUID -eq 0 ]]; then SUDO=""; return 0; fi
  if ! have sudo; then warn "sudo not found; root-only scans will be skipped"; SUDO="__NOSUDO__"; return 1; fi
  if sudo -n true 2>/dev/null; then SUDO="sudo"; return 0; fi
  info "Some scans need root (raw packets, OS fingerprinting)."
  # started from the dashboard: never ask for a password, nobody can type it
  if [[ "${ND_NONINTERACTIVE:-0}" == 1 ]]; then
    warn "sudo not authorised; root-only scans will be skipped"
    SUDO="__NOSUDO__"; return 1
  fi
  if sudo -v; then SUDO="sudo"; ok "sudo authorised for this run"; return 0; fi
  warn "sudo not authorised; root-only scans will be skipped"
  SUDO="__NOSUDO__"; return 1
}
can_root() { [[ "$SUDO" != "__NOSUDO__" ]]; }
# -n: if the sudo ticket ran out mid-scan, fail this one tool instead of hanging on a prompt
as_root() { if [[ -n "$SUDO" && "$SUDO" != "__NOSUDO__" ]]; then sudo -n "$@"; else "$@"; fi; }

# keep the sudo timestamp alive during long scans
sudo_keepalive_start() {
  can_root || return 0
  [[ -z "$SUDO" ]] && return 0
  ( while true; do sudo -n true 2>/dev/null || exit; sleep 50; done ) &
  SUDO_KEEPALIVE_PID=$!
}
sudo_keepalive_stop() {
  [[ -n "${SUDO_KEEPALIVE_PID:-}" ]] && kill "$SUDO_KEEPALIVE_PID" 2>/dev/null
  return 0
}
