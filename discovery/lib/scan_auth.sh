#!/usr/bin/env bash
# scan_auth.sh - collection that needs credentials (SNMP, SSH).
# Credentials come from the vault when it has them, otherwise they are asked
# for here. Nothing is ever placed on a command line that appears in /proc.

# what an SSH login collects (read-only commands)
SSH_REMOTE_CMD='
    echo "=== uname ==="; uname -a
    echo "=== os ==="; grep -E "^(PRETTY_NAME|NAME|VERSION_ID|ID|ID_LIKE)=" /etc/os-release 2>/dev/null
    echo "=== uptime ==="; uptime
    echo "=== addresses ==="; ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null
    echo "=== listening ==="; (ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null) | head -n 40
    echo "=== disk ==="; df -h --output=source,size,pcent,target 2>/dev/null | head -n 12
    echo "=== containers ==="; (docker ps -a --format "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "no docker")
    echo "=== model ==="; (tr -d "\000" 2>/dev/null </proc/device-tree/model; echo) | head -n 1
    echo "=== cpu ==="; echo "$(nproc 2>/dev/null) cores, $(uname -m)"
    echo "=== memory ==="; free -h 2>/dev/null | awk "/^Mem:/{print \$2\" total, \"\$7\" available\"}"
    echo "=== services ==="; systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk "{print \$1}" | head -n 80
    echo "=== kubernetes ==="; k=""; for c in kubectl k3s microk8s kubeadm; do command -v $c >/dev/null && k="$k $c"; done
      for s in k3s k3s-agent kubelet snap.microk8s.daemon-kubelite containerd; do systemctl is-active --quiet $s 2>/dev/null && k="$k $s(running)"; done
      echo "${k:-none}"
    echo "=== virt ==="; (systemd-detect-virt 2>/dev/null || echo none) | head -n 1
    echo "=== disks ==="; lsblk -d -b -n -P -o NAME,ROTA,TRAN,SIZE,MODEL,TYPE 2>/dev/null | grep -v -E "TYPE=\"(loop|rom)\"" | head -n 40
    echo "=== packages ==="
      if command -v dpkg-query >/dev/null 2>&1; then echo "manager dpkg $(dpkg-query -f "." -W 2>/dev/null | wc -c)"; apt-mark showmanual 2>/dev/null | head -n 400
      elif command -v rpm >/dev/null 2>&1; then echo "manager rpm $(rpm -qa 2>/dev/null | wc -l)"; (dnf -C -q repoquery --userinstalled --qf "%{name}" 2>/dev/null || rpm -qa --qf "%{NAME}\n" 2>/dev/null) | head -n 400
      elif command -v pacman >/dev/null 2>&1; then echo "manager pacman $(pacman -Qq 2>/dev/null | wc -l)"; pacman -Qeq 2>/dev/null | head -n 400
      elif command -v apk >/dev/null 2>&1; then echo "manager apk $(apk info 2>/dev/null | wc -l)"; head -n 400 /etc/apk/world 2>/dev/null
      fi
      command -v snap >/dev/null 2>&1 && snap list 2>/dev/null | awk "NR>1{print \"snap:\"\$1}" | head -n 100
      command -v flatpak >/dev/null 2>&1 && flatpak list --app --columns=application 2>/dev/null | sed "s/^/flatpak:/" | head -n 100
    echo "=== hypervisor ==="
      S=""; [ "$(id -u)" = 0 ] || S="sudo -n"
      if command -v qm >/dev/null 2>&1; then
        echo "platform proxmox $(pveversion 2>/dev/null | head -n 1)"
        echo "--- list qemu"; $S qm list 2>/dev/null
        echo "--- list lxc"; $S pct list 2>/dev/null
        for id in $($S qm list 2>/dev/null | awk "NR>1{print \$1}" | head -n 300); do echo "--- qemu $id"; $S qm config "$id" 2>/dev/null; done
        for id in $($S pct list 2>/dev/null | awk "NR>1{print \$1}" | head -n 300); do echo "--- lxc $id"; $S pct config "$id" 2>/dev/null; done
        echo "--- storage"; $S cat /etc/pve/storage.cfg 2>/dev/null
        echo "--- pvs"; $S pvs --noheadings -o pv_name,vg_name 2>/dev/null
        echo "--- zpool"; zpool list -v -H -P -L 2>/dev/null
      fi
      if command -v virsh >/dev/null 2>&1; then
        V="virsh -r -c qemu:///system"
        echo "platform libvirt $($V version --daemon 2>/dev/null | awk "/daemon/{print \$NF}")"
        for d in $($V list --all --uuid 2>/dev/null | head -n 300); do
          echo "--- domain $d"; $V dominfo "$d" 2>/dev/null
          echo "# blk"; $V domblklist "$d" --details 2>/dev/null
          echo "# sizes"; for t in $($V domblklist "$d" --details 2>/dev/null | awk "\$2==\"disk\"{print \$3}"); do echo "$t $($V domblkinfo "$d" "$t" 2>/dev/null | awk "/Capacity/{print \$2}")"; done
          echo "# nics"; $V domiflist "$d" 2>/dev/null
        done
      fi
      if command -v qm >/dev/null 2>&1 || command -v virsh >/dev/null 2>&1; then
        echo "--- lsblk"; lsblk -b -n -P -o NAME,PKNAME,ROTA,TRAN,SIZE,MODEL,TYPE 2>/dev/null
        echo "--- df"; df -P 2>/dev/null
      fi
'

stage_auth() {
  [[ "$DO_AUTH" == 1 ]] || { info "authenticated collection disabled (enable with --auth)"; return 0; }
  section "Stage 5 - authenticated collection"

  if (( $(cred_count ssh) + $(cred_count snmp) + $(cred_count proxmox) > 0 )); then
    # credential cards from the dashboard: per host, no prompts
    auth_snmp_cards
    auth_ssh_cards
    auth_proxmox_cards
    return 0
  fi
  if [[ "${ND_NONINTERACTIVE:-0}" == 1 ]]; then
    info "no SSH or SNMP credentials to use - skipping logins"; return 0
  fi
  vault_unlock --optional || info "no vault in use; credentials will be asked for as needed"

  auth_snmp
  auth_ssh
}

# Hosts to try for a service: those the deep scan saw with PORT open; without
# deep-scan data, a quick connect probe of that port on the live hosts. Hosts
# named explicitly on a card are always tried.
_auth_candidates() {  # _auth_candidates TYPE PROTO/PORT -> IPs on stdout
  local type="$1" pp="$2" port="${2%%/*}"
  {
    if [[ -s "$WORK/services.tsv" ]]; then
      awk -F'\t' -v p="^$pp" '$2 ~ p {print $1}' "$WORK/services.tsv"
    elif [[ "$pp" == */tcp && -s "$WORK/hosts.list" ]] && have nmap; then
      nmap -n -Pn -sT -p "$port" --open -T4 -oG - -iL "$WORK/hosts.list" 2>/dev/null \
        | awk '/Ports: .*open/{print $2}'
    elif [[ -s "$WORK/hosts.list" ]]; then
      cat "$WORK/hosts.list"            # UDP (SNMP) without root: just try them
    fi
    cred_hosts "$type" | python3 -c '
import ipaddress, sys
for l in sys.stdin:
    n = ipaddress.ip_network(l.strip())
    if n.num_addresses == 1: print(n.network_address)' 2>/dev/null
  } | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n
}

# ---------------------------------------------------------------- SNMP (cards)
_snmp_conf() {  # _snmp_conf ID -> writes $SECURE_TMP/snmp.conf for that card
  local id="$1" conf="$SECURE_TMP/snmp.conf" ver
  ver="$(cred_get "$id" version)"
  (
    umask 077
    if [[ "$ver" == 2c ]]; then
      printf 'defVersion 2c\ndefCommunity %s\n' "$(cred_get "$id" community)"
    else
      printf 'defVersion 3\ndefSecurityName %s\ndefSecurityLevel %s\n' \
        "$(cred_get "$id" user)" "$(cred_get "$id" level)"
      local lvl; lvl="$(cred_get "$id" level)"
      if [[ "$lvl" != noAuthNoPriv ]]; then
        printf 'defAuthType %s\ndefAuthPassphrase %s\n' "$(cred_get "$id" auth_proto)" "$(cred_get "$id" auth_pass)"
      fi
      if [[ "$lvl" == authPriv ]]; then
        printf 'defPrivType %s\ndefPrivPassphrase %s\n' "$(cred_get "$id" priv_proto)" "$(cred_get "$id" priv_pass)"
      fi
    fi
  ) >"$conf"
}

auth_snmp_cards() {
  (( $(cred_count snmp) > 0 )) || return 0
  have snmpget || { warn "snmpget missing - skipping SNMP"; return 0; }
  local -a targets; mapfile -t targets < <(_auth_candidates snmp "161/udp")
  (( ${#targets[@]} )) || { info "no SNMP candidates"; return 0; }
  info "SNMP: trying ${#targets[@]} host(s)"
  mkdir -p "$RAW/snmp"
  local ip id name safe out rc n_ok=0
  for ip in "${targets[@]}"; do
    id="$(cred_pick snmp "$ip")"; [[ -n "$id" ]] || continue
    name="$(cred_name "$id")"; safe="${ip//./_}"
    _snmp_conf "$id"
    # one quick get first, so dead hosts cost 2 s, not two 30 s walks
    local sport; sport="$(cred_get "$id" port)"
    local agent="udp:$ip:${sport:-161}"
    out=$(SNMPCONFPATH="$SECURE_TMP" timeout 8 snmpget -m "" -t 2 -r 0 -Oqv "$agent" 1.3.6.1.2.1.1.5.0 2>&1); rc=$?
    if (( rc != 0 )); then
      case "$out" in
        *uthenticat*|*"Unknown user"*|*"Decryption error"*|*"wrong digest"*) cred_result snmp "$name" "$ip" auth_failed ;;
        *) cred_result snmp "$name" "$ip" unreachable ;;
      esac
      continue
    fi
    step "SNMP walk $ip ($name)"
    {
      printf '### SNMP %s (credential: %s)\n\n' "$ip" "$name"
      SNMPCONFPATH="$SECURE_TMP" timeout 30 snmpwalk -m "" -Oqv "$agent" 1.3.6.1.2.1.1 2>&1 | sed 's/^/system: /'
      printf '\n--- interfaces ---\n'
      SNMPCONFPATH="$SECURE_TMP" timeout 45 snmpwalk -m "" -Oqv "$agent" 1.3.6.1.2.1.2.2.1.2 2>&1
    } | scrub >"$RAW/snmp/$safe.txt"
    cred_result snmp "$name" "$ip" ok
    n_ok=$((n_ok+1))
  done
  shred -u "$SECURE_TMP/snmp.conf" 2>/dev/null || rm -f "$SECURE_TMP/snmp.conf"
  ok "SNMP: $n_ok host(s) answered"
}

# ---------------------------------------------------------------- SSH (cards)
auth_ssh_cards() {
  (( $(cred_count ssh) > 0 )) || return 0
  have ssh || { warn "ssh missing - skipping"; return 0; }
  local -a targets; mapfile -t targets < <(_auth_candidates ssh "22/tcp")
  (( ${#targets[@]} )) || { info "no host has SSH open - skipping"; return 0; }
  info "SSH: trying ${#targets[@]} host(s)"
  mkdir -p "$RAW/ssh"
  # host keys seen by scans are kept apart from your own ~/.ssh/known_hosts
  local kh="$BASE_DIR/config/known_hosts"
  local ip id name user pass key keyf safe rc out n_ok=0
  for ip in "${targets[@]}"; do
    id="$(cred_pick ssh "$ip")"; [[ -n "$id" ]] || continue
    name="$(cred_name "$id")"; user="$(cred_get "$id" user)"; safe="${ip//./_}"
    local port; port="$(cred_get "$id" port)"
    local -a o=(-p "${port:-22}" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$kh"
                -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o LogLevel=ERROR)
    pass="$(cred_get "$id" password)"; key="$(cred_get "$id" key)"; keyf="$(cred_get "$id" key_path)"
    step "ssh $user@$ip ($name)"
    if [[ -n "$key" || -n "$keyf" ]]; then
      if [[ -n "$key" ]]; then keyf="$SECURE_TMP/key.$id"; [[ -f "$keyf" ]] || cred_file "$id" key "$keyf"; fi
      o+=(-o BatchMode=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no -i "${keyf/#\~/$HOME}")
      out=$(timeout 120 ssh "${o[@]}" "$user@$ip" "$SSH_REMOTE_CMD" 2>&1); rc=$?
    elif have sshpass; then
      o+=(-o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive)
      # sshpass -e reads $SSHPASS: the password is never in argv
      out=$(SSHPASS="$pass" timeout 120 sshpass -e ssh "${o[@]}" "$user@$ip" "$SSH_REMOTE_CMD" 2>&1); rc=$?
    else
      warn "sshpass is not installed - password logins skipped (sudo apt install sshpass)"
      cred_result ssh "$name" "$ip" error "sshpass missing"; continue
    fi
    printf '%s\n' "$out" | scrub >"$RAW/ssh/$safe.txt"
    if (( rc == 0 )); then
      cred_result ssh "$name" "$ip" ok; n_ok=$((n_ok+1))
    elif (( rc == 5 )) || [[ "$out" == *"Permission denied"* ]]; then
      cred_result ssh "$name" "$ip" auth_failed
    elif [[ "$out" == *"Host key verification failed"* || "$out" == *"REMOTE HOST IDENTIFICATION HAS CHANGED"* ]]; then
      cred_result ssh "$name" "$ip" error "host key changed - check $kh"
    else
      cred_result ssh "$name" "$ip" unreachable
    fi
  done
  pass=""; key=""
  ok "SSH: logged in to $n_ok host(s)"
}

# ---------------------------------------------------------------- Proxmox VE API (cards)
# Read-only inventory of every VM and container through the Proxmox REST API
# (lib/vm_inventory.py, docs/VM_INVENTORY.md). The token stays in $SECURE_TMP;
# the certificate is pinned in config/known_tls on first contact.
auth_proxmox_cards() {
  (( $(cred_count proxmox) > 0 )) || return 0
  mkdir -p "$RAW/vms"
  [[ "${ND_PROGRESS:-0}" == 1 ]] && printf '@@cmd %s\n' "vm_inventory.py proxmox (read-only REST)"
  step "Proxmox VE inventory"
  local name host r detail
  while IFS=$'\t' read -r name host r detail; do
    [[ "$r" =~ ^(ok|auth_failed|unreachable|error)$ ]] || { detail="$name $host $r $detail"; r=error; name=proxmox; }
    cred_result proxmox "$name" "$host" "$r" "$detail"
    if [[ "$r" == ok ]]; then ok "Proxmox $host: $detail"; else err "Proxmox $host: ${r//_/ }${detail:+ - $detail}"; fi
  done < <(python3 "$BASE_DIR/lib/vm_inventory.py" proxmox "$SECURE_TMP" "$RAW/vms" "$BASE_DIR/config/known_tls" 2>&1 | scrub)
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

  local remote_cmd="$SSH_REMOTE_CMD"

  mkdir -p "$RAW/ssh"
  local ip safe
  for ip in "${targets[@]}"; do
    safe="${ip//./_}"
    step "ssh $user@$ip"
    if (( use_pass )); then
      # sshpass -e reads the password from $SSHPASS - not visible in argv
      SSHPASS="$pass" timeout 120 sshpass -e ssh "${sshopts[@]}" "$user@$ip" "$remote_cmd" \
        2>&1 | scrub >"$RAW/ssh/$safe.txt" || warn "  $ip: connection or auth failed"
    else
      timeout 120 ssh "${sshopts[@]}" "$user@$ip" "$remote_cmd" \
        2>&1 | scrub >"$RAW/ssh/$safe.txt" || warn "  $ip: connection or auth failed"
    fi
  done
  pass=""
  ok "SSH collection done ($(ls -1 "$RAW/ssh" 2>/dev/null | wc -l) host(s))"
}
