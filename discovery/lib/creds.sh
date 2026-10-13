#!/usr/bin/env bash
# creds.sh - credentials for this scan, sent by the dashboard through an
# inherited pipe (ND_CREDS_FD) and kept in $SECURE_TMP/creds.json (tmpfs).
# See docs/SCAN_BUILDER.md "Step 2" for where each secret may go.

CREDS_PY="$BASE_DIR/lib/creds.py"
HAVE_CREDS=0

# load_creds - read the pipe once, register every secret for scrub(), apply
# the vault parts (use saved cards / save new ones).
load_creds() {
  [[ -n "${ND_CREDS_FD:-}" ]] || return 0
  [[ "$ND_CREDS_FD" =~ ^[0-9]+$ ]] || { warn "bad ND_CREDS_FD"; return 0; }
  local out
  if ! out=$(python3 "$CREDS_PY" ingest "$SECURE_TMP" <&"$ND_CREDS_FD" 2>&1); then
    eval "exec $ND_CREDS_FD<&-"
    die "$out"
  fi
  eval "exec $ND_CREDS_FD<&-"
  _creds_register_secrets

  VAULT_PASS="$(python3 "$CREDS_PY" vaultpass "$SECURE_TMP")"
  if [[ -n "$VAULT_PASS" ]]; then
    register_secret VAULT_PASS
    # saved cards ticked in the dashboard
    if python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["vault"]["use"] else 1)' \
         "$SECURE_TMP/creds.json" 2>/dev/null; then
      if vault_unlock --optional; then
        local k added
        added=$(for k in "${!VAULT[@]}"; do [[ "$k" == CRED_* ]] && printf '%s=%s\n' "$k" "${VAULT[$k]}"; done \
                | python3 "$CREDS_PY" from-vault "$SECURE_TMP")
        [[ -n "$added" ]] && out+=$'\n'"$added"
        _creds_register_secrets
      fi
    fi
    # cards marked "remember in vault"
    local save; save=$(python3 "$CREDS_PY" to-vault "$SECURE_TMP")
    [[ -n "$save" ]] && vault_store_entries <<<"$save"
    save=""
  fi
  out=$(printf '%s\n' "$out" | grep -v '^$')
  if [[ -n "$out" ]]; then
    HAVE_CREDS=1
    info "credentials for this scan: $(printf '%s\n' "$out" | awk -F'\t' '{printf "%s%s (%s)", (NR>1?", ":""), $2, $1}')"
  fi
}

_creds_register_secrets() {
  local l
  while IFS= read -r l; do [[ -n "$l" ]] && _SECRET_VALUES+=("$l"); done \
    < <(python3 "$CREDS_PY" secrets "$SECURE_TMP")
}

cred_count() { (( HAVE_CREDS )) || { echo 0; return; }; python3 "$CREDS_PY" count "$SECURE_TMP" "$1"; }
cred_pick()  { python3 "$CREDS_PY" pick "$SECURE_TMP" "$1" "$2"; }
cred_hosts() { python3 "$CREDS_PY" hosts "$SECURE_TMP" "$1"; }
cred_get()   { python3 "$CREDS_PY" get "$SECURE_TMP" "$1" "$2"; }
cred_name()  { python3 "$CREDS_PY" name "$SECURE_TMP" "$1"; }
cred_file()  { python3 "$CREDS_PY" tofile "$SECURE_TMP" "$1" "$2" "$3"; }
# first set of a type (cloud providers have one each)
cred_first() { python3 "$CREDS_PY" pick "$SECURE_TMP" "$1" 0.0.0.0; }

# cred_result TYPE NAME HOST RESULT [detail] - one row per login attempt
cred_result() {
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${5:-}" | tr -d '\r' >>"$WORK/cred-use.tsv"
}
