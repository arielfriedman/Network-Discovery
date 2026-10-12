#!/usr/bin/env bash
# scan_auth.sh - collection that needs credentials (SNMP, SSH).
# Credentials come from the vault when it has them, otherwise they are asked
# for here. Nothing is ever placed on a command line that appears in /proc.

stage_auth() {
  [[ "$DO_AUTH" == 1 ]] || { info "authenticated collection disabled (enable with --auth)"; return 0; }
  section "Stage 5 - authenticated collection"

  vault_unlock --optional || info "no vault in use; credentials will be asked for as needed"

  auth_snmp
  auth_ssh
}

# ---------------------------------------------------------------- SNMP
auth_snmp() {
  have snmpwalk || { warn "snmpwalk missing - skipping SNMP"; return 0; }

  # Which hosts even have SNMP open? Use the deep-scan result if we have it.
  local -a targets=()
  if [[ -s "$WORK/services.tsv" ]]; then
    mapfile -t targets < <(awk -F'\t' '$2 ~ /^161\// {print $1}' "$WORK/services.tsv" | sort -u)
  fi
  if (( ${#targets[@]} == 0 )); then
    info "no host advertised SNMP (161/udp); you can still point it at one"
    ask_yes_no "Try SNMP against the gateway ($GATEWAY) anyway?" n || return 0
    targets=("$GATEWAY")
  fi

  info "SNMP candidates: ${targets[*]}"
  ask_yes_no "Query them over SNMP?" y || return 0

  local community
  community="$(vault_get SNMP_COMMUNITY 'SNMP community string')" || {
    warn "no community given - skipping SNMP"; return 0; }

  # Pass the community through a config file in tmpfs, not argv.
  local conf="$SECURE_TMP/snmp.conf"
  ( umask 077; printf 'defVersion 2c\ndefCommunity %s\n' "$community" >"$conf" )

  local ip safe
  mkdir -p "$RAW/snmp"
  for ip in "${targets[@]}"; do
    safe="${ip//./_}"
    step "SNMP walk $ip"
    {
      printf '### SNMP %s\n\n' "$ip"
      SNMPCONFPATH="$SECURE_TMP" timeout 30 snmpwalk -Oqv "$ip" \
        1.3.6.1.2.1.1 2>&1 | sed 's/^/system: /'
      printf '\n--- interfaces ---\n'
      SNMPCONFPATH="$SECURE_TMP" timeout 45 snmpwalk -Oqv "$ip" \
        1.3.6.1.2.1.2.2.1.2 2>&1
    } | scrub >"$RAW/snmp/$safe.txt"
  done
  shred -u "$conf" 2>/dev/null || rm -f "$conf"
  ok "SNMP collection done"
}

# ---------------------------------------------------------------- SSH
auth_ssh() {
  have ssh || { warn "ssh missing - skipping"; return 0; }

  local -a targets=()
  if [[ -s "$WORK/services.tsv" ]]; then
    mapfile -t targets < <(awk -F'\t' '$2 ~ /^22\/tcp/ {print $1}' "$WORK/services.tsv" | sort -u)
  fi
  (( ${#targets[@]} == 0 )) && { info "no host has SSH open - skipping"; return 0; }

  info "hosts with SSH open: ${#targets[@]} (${targets[*]:0:6}${targets[*]:6:1:+ ...})"
  ask_yes_no "Log in to these and collect system details?" n || return 0

  local user key pass
  user="$(vault_get SSH_USER 'SSH username')" || return 0
  key="$(vault_get SSH_KEY_PATH 'Path to private key (blank to use a password)')" || key=""

  local -a sshopts=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new
                    -o ConnectTimeout=6 -o PasswordAuthentication=no)
  local use_pass=0
  if [[ -n "$key" && -f "$key" ]]; then
    sshopts+=(-i "$key")
  else
    if have sshpass; then
      pass="$(vault_get SSH_PASS "SSH password for $user")" || return 0
      use_pass=1
      sshopts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=6)
    else
      warn "no key given and sshpass is not installed - skipping SSH collection"
      info "install it with: sudo apt install sshpass   (or use SSH_KEY_PATH instead)"
      return 0
    fi
  fi

  local remote_cmd='
    echo "=== uname ==="; uname -a
    echo "=== os ==="; cat /etc/os-release 2>/dev/null | head -n 4
    echo "=== uptime ==="; uptime
    echo "=== addresses ==="; ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null
    echo "=== listening ==="; (ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null) | head -n 40
    echo "=== disk ==="; df -h --output=source,size,pcent,target 2>/dev/null | head -n 12
    echo "=== containers ==="; (docker ps --format "{{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null || echo "no docker")
  '

  mkdir -p "$RAW/ssh"
  local ip safe
  for ip in "${targets[@]}"; do
    safe="${ip//./_}"
    step "ssh $user@$ip"
    if (( use_pass )); then
      # sshpass -e reads the password from $SSHPASS - not visible in argv
      SSHPASS="$pass" timeout 30 sshpass -e ssh "${sshopts[@]}" "$user@$ip" "$remote_cmd" \
        2>&1 | scrub >"$RAW/ssh/$safe.txt" || warn "  $ip: connection or auth failed"
    else
      timeout 30 ssh "${sshopts[@]}" "$user@$ip" "$remote_cmd" \
        2>&1 | scrub >"$RAW/ssh/$safe.txt" || warn "  $ip: connection or auth failed"
    fi
  done
  pass=""
  ok "SSH collection done ($(ls -1 "$RAW/ssh" 2>/dev/null | wc -l) host(s))"
}
