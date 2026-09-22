#!/usr/bin/env bash
# vault.sh - encrypted credential store.
#
# Design rules, in order of importance:
#   1. The vault file on disk is ALWAYS GPG AES-256 ciphertext. There is no
#      code path that writes plaintext credentials to a normal filesystem.
#   2. Decryption goes to memory (a bash associative array) or, for editing,
#      to a 0600 file inside tmpfs (/dev/shm) that is shredded afterwards.
#   3. The master passphrase reaches gpg through a file descriptor, never
#      through argv - argv is readable by any local user via /proc.
#   4. Every value read out is registered with scrub(), so it cannot appear
#      in a report even by accident.

VAULT_FILE="${VAULT_FILE:-$BASE_DIR/config/vault.gpg}"
declare -A VAULT=()
VAULT_LOADED=0
VAULT_PASS=""

vault_exists() { [[ -f "$VAULT_FILE" ]]; }

_vault_require_gpg() {
  have gpg || die "gpg is required for the vault (sudo apt install gnupg)"
}

_vault_gpg_decrypt() {  # stdout = plaintext; passphrase via fd 3
  printf '%s' "$VAULT_PASS" >"$SECURE_TMP/pp"
  gpg --batch --quiet --yes --decrypt \
      --passphrase-file "$SECURE_TMP/pp" \
      --pinentry-mode loopback \
      "$VAULT_FILE" 2>/dev/null
  local rc=$?
  shred -u "$SECURE_TMP/pp" 2>/dev/null || rm -f "$SECURE_TMP/pp"
  return $rc
}

_vault_gpg_encrypt() {  # stdin = plaintext -> $VAULT_FILE
  printf '%s' "$VAULT_PASS" >"$SECURE_TMP/pp"
  local tmp="$VAULT_FILE.new"
  gpg --batch --quiet --yes --symmetric \
      --cipher-algo AES256 --digest-algo SHA512 \
      --s2k-mode 3 --s2k-count 65011712 \
      --passphrase-file "$SECURE_TMP/pp" \
      --pinentry-mode loopback \
      --output "$tmp" 2>/dev/null
  local rc=$?
  shred -u "$SECURE_TMP/pp" 2>/dev/null || rm -f "$SECURE_TMP/pp"
  if (( rc == 0 )); then
    chmod 600 "$tmp" && mv -f "$tmp" "$VAULT_FILE" && chmod 600 "$VAULT_FILE"
  else
    rm -f "$tmp"
  fi
  return $rc
}

# vault_unlock [--optional]
# Loads the vault into memory. With --optional, a missing vault is not an error.
vault_unlock() {
  local optional=0
  [[ "${1:-}" == "--optional" ]] && optional=1
  (( VAULT_LOADED )) && return 0
  [[ -n "${SECURE_TMP:-}" ]] || make_secure_tmp

  if ! vault_exists; then
    (( optional )) && return 1
    die "no vault at $VAULT_FILE - create one with: ./vault.sh init"
  fi
  _vault_require_gpg

  local tries=0 plain
  while (( tries < 3 )); do
    ask_secret VAULT_PASS "Vault passphrase"
    if plain="$(_vault_gpg_decrypt)"; then
      _vault_parse "$plain"
      plain=""
      VAULT_LOADED=1
      ok "vault unlocked (${#VAULT[@]} entries)"
      return 0
    fi
    VAULT_PASS=""
    tries=$((tries+1))
    warn "wrong passphrase ($tries/3)"
  done
  (( optional )) && return 1
  die "could not unlock vault"
}

_vault_parse() {
  local line k v
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    k="${line%%=*}"; v="${line#*=}"
    k="${k// /}"
    [[ -z "$k" ]] && continue
    VAULT["$k"]="$v"
    _SECRET_VALUES+=("$v")      # so scrub() strips it from any report
  done <<<"$1"
}

# vault_get KEY [prompt-text]
# Returns the stored value. If absent, asks interactively and offers to save.
vault_get() {
  local key="$1" prompt="${2:-$1}" val=""
  if (( VAULT_LOADED )) && [[ -n "${VAULT[$key]:-}" ]]; then
    printf '%s' "${VAULT[$key]}"
    return 0
  fi
  case "$key" in
    *PASS*|*SECRET*|*TOKEN*|*KEY*|*COMMUNITY*)
      ask_secret val "$prompt" ;;
    *)
      ask_value val "$prompt" ;;
  esac
  [[ -z "$val" ]] && return 1
  register_secret val
  VAULT["$key"]="$val"
  VAULT_DIRTY=1
  printf '%s' "$val"
}

# Persist anything gathered during the run, if the user wants it kept.
vault_save_if_dirty() {
  [[ "${VAULT_DIRTY:-0}" == 1 ]] || return 0
  (( ${#VAULT[@]} )) || return 0
  echo
  ask_yes_no "Save the credentials you entered into the encrypted vault?" n || return 0
  if ! vault_exists; then
    vault_init_passphrase
  elif [[ -z "$VAULT_PASS" ]]; then
    ask_secret VAULT_PASS "Vault passphrase"
  fi
  _vault_serialise | _vault_gpg_encrypt \
    && ok "vault updated: $VAULT_FILE" \
    || err "could not write vault"
  VAULT_DIRTY=0
}

_vault_serialise() {
  printf '# network-discovery vault\n# written %s\n# format: KEY=value, one per line\n\n' "$(date -Is)"
  local k
  for k in $(printf '%s\n' "${!VAULT[@]}" | sort); do
    printf '%s=%s\n' "$k" "${VAULT[$k]}"
  done
}

vault_init_passphrase() {
  local p1 p2
  while true; do
    ask_secret p1 "New vault passphrase"
    ask_secret p2 "Repeat passphrase"
    [[ "$p1" == "$p2" && -n "$p1" ]] && break
    warn "passphrases did not match (or were empty) - try again"
  done
  if (( ${#p1} < 12 )); then
    warn "that passphrase is short; this file protects every credential you store"
    ask_yes_no "Use it anyway?" n || { vault_init_passphrase; return; }
  fi
  VAULT_PASS="$p1"; register_secret VAULT_PASS
  p1=""; p2=""
}
