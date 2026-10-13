#!/usr/bin/env bash
# vault.sh - manage the encrypted credential store.
#
#   ./vault.sh init              create a new vault
#   ./vault.sh list              list key names (never values)
#   ./vault.sh get KEY           print one value to stdout
#   ./vault.sh set KEY [VALUE]   add or replace an entry (prompts if no VALUE)
#   ./vault.sh rm KEY            delete an entry
#   ./vault.sh edit              open the whole vault in $EDITOR, in tmpfs
#   ./vault.sh passwd            change the master passphrase
#   ./vault.sh template          print the keys the scanner looks for
#
# The file on disk is GPG AES-256 ciphertext at all times.

set -euo pipefail
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$BASE_DIR/lib/common.sh"
# shellcheck source=lib/vault.sh
source "$BASE_DIR/lib/vault.sh"
trap cleanup EXIT INT TERM
make_secure_tmp

# Called by the dashboard: the passphrase arrives on an inherited pipe
# (ND_VAULT_PASS_FD), never argv or env, and nothing may prompt.
if [[ "${ND_VAULT_PASS_FD:-}" =~ ^[0-9]+$ ]]; then
  IFS= read -r VAULT_PASS <&"$ND_VAULT_PASS_FD" || true
  eval "exec $ND_VAULT_PASS_FD<&-"
  register_secret VAULT_PASS
  export ND_NONINTERACTIVE=1
fi

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

KNOWN_KEYS=(
  "SNMP_COMMUNITY        SNMPv2c community string for network gear"
  "SNMP_V3_USER          SNMPv3 username"
  "SNMP_V3_AUTH_PASS     SNMPv3 authentication passphrase"
  "SNMP_V3_PRIV_PASS     SNMPv3 privacy passphrase"
  "SSH_USER              username for authenticated host collection"
  "SSH_PASS              password, if you are not using keys"
  "SSH_KEY_PATH          path to a private key (preferred over SSH_PASS)"
  "ROUTER_USER           gateway/router admin username"
  "ROUTER_PASS           gateway/router admin password"
  "AWS_ACCESS_KEY_ID     AWS access key"
  "AWS_SECRET_ACCESS_KEY AWS secret key"
  "AWS_DEFAULT_REGION    e.g. eu-central-1"
  "AZURE_TENANT_ID       Entra tenant id"
  "AZURE_CLIENT_ID       service principal app id"
  "AZURE_CLIENT_SECRET   service principal secret"
  "GCP_SA_KEY_PATH       path to a GCP service-account json"
)

cmd_init() {
  if vault_exists; then
    warn "a vault already exists at $VAULT_FILE"
    ask_yes_no "Replace it? The current contents are lost." n || exit 0
  fi
  _vault_require_gpg
  vault_init_passphrase
  VAULT=()
  section "Add entries now (blank key to finish)"
  local k v
  while true; do
    ask_value k "Key name (blank to finish)"
    [[ -z "$k" ]] && break
    case "$k" in
      *PASS*|*SECRET*|*TOKEN*|*KEY*|*COMMUNITY*) ask_secret v "Value for $k" ;;
      *) ask_value v "Value for $k" ;;
    esac
    VAULT["$k"]="$v"; register_secret v
  done
  _vault_serialise | _vault_gpg_encrypt || die "encryption failed"
  ok "vault created: $VAULT_FILE (mode $(stat -c %a "$VAULT_FILE"))"
  info "keys stored: ${#VAULT[@]}"
}

cmd_list() {
  vault_unlock
  printf '%s%-28s %s%s\n' "$C_BOLD" "KEY" "VALUE" "$C_RESET"
  local k
  for k in $(printf '%s\n' "${!VAULT[@]}" | sort); do
    printf '%-28s %s\n' "$k" "********"
  done
  printf '\n%d entr(ies). Use "get KEY" to read one.\n' "${#VAULT[@]}"
}

cmd_get() {
  [[ $# -ge 1 ]] || die "usage: vault.sh get KEY"
  vault_unlock
  [[ -n "${VAULT[$1]:-}" ]] || die "no such key: $1"
  printf '%s\n' "${VAULT[$1]}"
}

cmd_set() {
  [[ $# -ge 1 ]] || die "usage: vault.sh set KEY [VALUE]"
  local key="$1" val="${2:-}"
  if vault_exists; then vault_unlock; else _vault_require_gpg; vault_init_passphrase; VAULT=(); fi
  if [[ -z "$val" ]]; then
    case "$key" in
      *PASS*|*SECRET*|*TOKEN*|*KEY*|*COMMUNITY*) ask_secret val "Value for $key" ;;
      *) ask_value val "Value for $key" ;;
    esac
  else
    warn "value given on the command line is visible in your shell history and /proc"
  fi
  VAULT["$key"]="$val"; register_secret val
  _vault_serialise | _vault_gpg_encrypt || die "encryption failed"
  ok "stored $key"
}

cmd_rm() {
  [[ $# -ge 1 ]] || die "usage: vault.sh rm KEY"
  vault_unlock
  [[ -n "${VAULT[$1]:-}" ]] || die "no such key: $1"
  unset 'VAULT[$1]'
  _vault_serialise | _vault_gpg_encrypt || die "encryption failed"
  ok "removed $1"
}

# Edit in tmpfs only. /dev/shm is RAM - the plaintext never reaches the SSD.
cmd_edit() {
  vault_unlock
  local f="$SECURE_TMP/vault.edit"
  ( umask 077; _vault_serialise >"$f" )
  local before after
  before=$(sha256sum "$f" | cut -d' ' -f1)
  "${EDITOR:-nano}" "$f"
  after=$(sha256sum "$f" | cut -d' ' -f1)
  if [[ "$before" == "$after" ]]; then
    info "no changes"
  else
    VAULT=(); _vault_parse "$(cat "$f")"
    _vault_serialise | _vault_gpg_encrypt && ok "vault updated (${#VAULT[@]} entries)"
  fi
  shred -u "$f" 2>/dev/null || rm -f "$f"
}

cmd_passwd() {
  vault_unlock
  info "changing the master passphrase"
  local old="$VAULT_PASS"
  vault_init_passphrase
  if _vault_serialise | _vault_gpg_encrypt; then
    ok "passphrase changed"
  else
    VAULT_PASS="$old"; die "re-encryption failed; vault unchanged"
  fi
}

cmd_template() {
  printf '%sKeys the scanner looks for:%s\n\n' "$C_BOLD" "$C_RESET"
  printf '  %s\n' "${KNOWN_KEYS[@]}"
  printf '\nAnything not in the vault is asked for interactively at scan time.\n'
}

case "${1:-}" in
  init)     shift; cmd_init "$@" ;;
  list|ls)  shift; cmd_list "$@" ;;
  get)      shift; cmd_get "$@" ;;
  set)      shift; cmd_set "$@" ;;
  rm|del)   shift; cmd_rm "$@" ;;
  edit)     shift; cmd_edit "$@" ;;
  passwd)   shift; cmd_passwd "$@" ;;
  template) shift; cmd_template "$@" ;;
  -h|--help|help|"") usage 0 ;;
  *) err "unknown command: $1"; usage 1 ;;
esac
