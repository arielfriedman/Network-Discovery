#!/usr/bin/env bash
# scan_local.sh - layer 2/3 discovery, passive service discovery, deep host scan.

# ---------------------------------------------------------------- stage 1
# Host discovery. Two independent sweeps, then merge - arp-scan sees things
# that ignore ICMP, nmap sees things outside the broadcast domain.
stage_discover() {
  section "Stage 1 - host discovery on $TARGET_CIDR"

  if have arp-scan && can_root; then
    run_tool "arp-scan layer-2 sweep" "$RAW/10-arp-scan.txt" \
      as_root arp-scan --interface="$IFACE" --retry=2 --timeout=300 "$TARGET_CIDR" || true
  else
    warn "arp-scan unavailable or no root - skipping layer-2 sweep"
  fi

  if have nmap; then
    local -a png=(-sn -n --max-retries 2 "-T$NMAP_TIMING")
    can_root && png+=(-PR)   # ARP ping is both faster and more reliable on-LAN
    run_tool "nmap ping sweep" "$RAW/11-nmap-sweep.txt" \
      as_root nmap "${png[@]}" -oG "$RAW/11-nmap-sweep.gnmap" "$TARGET_CIDR" || true
  else
    warn "nmap unavailable - discovery will be thin"
  fi

  # neighbour table picks up anything we have talked to recently
  run_tool "kernel neighbour table" "$RAW/12-neigh.txt" ip neigh show || true

  build_host_list
}

# Merge every source into $WORK/hosts.tsv : ip <tab> mac <tab> vendor
build_host_list() {
  local tmp="$WORK/hosts.raw"
  : >"$tmp"

  # arp-scan: "172.16.0.2  aa:bb:cc:dd:ee:ff  Vendor Name"
  if [[ -s "$RAW/10-arp-scan.txt" ]]; then
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$RAW/10-arp-scan.txt" \
      | awk -F'\t' '{printf "%s\t%s\t%s\n",$1,tolower($2),$3}' >>"$tmp" || true
  fi

  # nmap greppable: "Host: 172.16.0.5 ()  Status: Up"
  if [[ -s "$RAW/11-nmap-sweep.gnmap" ]]; then
    awk '/Status: Up/{print $2"\t\t"}' "$RAW/11-nmap-sweep.gnmap" >>"$tmp" || true
  fi

  # ip neigh: "172.16.0.2 dev enp2s0 lladdr aa:bb:.. REACHABLE"
  if [[ -s "$RAW/12-neigh.txt" ]]; then
    awk '/lladdr/{print $1"\t"tolower($5)"\t"}' "$RAW/12-neigh.txt" >>"$tmp" || true
  fi

  # Collapse duplicates, keeping the richest record (longest line) per IP,
  # and sort numerically by octet.
  awk -F'\t' '
    { ip=$1; if (ip=="" ) next
      if (!(ip in best) || length($0) > length(best[ip])) best[ip]=$0 }
    END { for (i in best) print best[i] }
  ' "$tmp" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n >"$WORK/hosts.tsv"

  HOST_COUNT=$(wc -l <"$WORK/hosts.tsv")
  cut -f1 "$WORK/hosts.tsv" >"$WORK/hosts.list"
  ok "$HOST_COUNT live host(s) found"
  cp "$WORK/hosts.tsv" "$RAW/13-hosts-merged.tsv"
}

# ---------------------------------------------------------------- stage 2
# Passive / protocol-specific discovery. These name devices that a port scan
# only shows as an IP.
stage_passive() {
  [[ "$DO_PASSIVE" == 1 ]] || { info "passive discovery disabled"; return 0; }
  section "Stage 2 - passive service discovery"

  if have avahi-browse; then
    run_tool "mDNS / Bonjour (avahi)" "$RAW/20-mdns.txt" \
      timeout 25 avahi-browse -altrp || true
  fi

  if have nbtscan; then
    run_tool "NetBIOS names" "$RAW/21-netbios.txt" \
      nbtscan -q -s $'\t' "$TARGET_CIDR" || true
  fi

  run_tool "SSDP / UPnP discovery" "$RAW/22-ssdp.txt" python3 - <<'PYEOF' || true
import socket, sys
MSG = "\r\n".join([
    'M-SEARCH * HTTP/1.1','HOST: 239.255.255.250:1900','MAN: "ssdp:discover"',
    'MX: 3','ST: ssdp:all','','']).encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
s.settimeout(4)
try:
    s.sendto(MSG, ("239.255.255.250", 1900))
except OSError as e:
    print(f"send failed: {e}"); sys.exit(0)
seen = {}
while True:
    try:
        data, addr = s.recvfrom(65507)
    except socket.timeout:
        break
    txt = data.decode("utf-8", "replace")
    fields = {}
    for line in txt.splitlines()[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            fields[k.strip().upper()] = v.strip()
    key = (addr[0], fields.get("USN", ""))
    if key in seen: continue
    seen[key] = True
    print(f"{addr[0]}\tSERVER={fields.get('SERVER','?')}\t"
          f"ST={fields.get('ST','?')}\tLOCATION={fields.get('LOCATION','?')}")
print(f"\n# {len(seen)} SSDP response(s)")
PYEOF

  if have lldpctl && can_root; then
    run_tool "LLDP / CDP neighbours (switch + port)" "$RAW/23-lldp.txt" \
      as_root lldpctl || true
  fi

  # wireless only makes sense if there is a wifi device
  if have nmcli && nmcli -t -f DEVICE,TYPE device 2>/dev/null | grep -q ':wifi$'; then
    run_tool "nearby wireless networks" "$RAW/24-wifi.txt" \
      nmcli -f SSID,BSSID,CHAN,SIGNAL,SECURITY device wifi list || true
  else
    step "no wireless interface - skipping wifi scan"
  fi

  # reverse DNS for everything we found
  if have dig && [[ -s "$WORK/hosts.list" ]]; then
    step "reverse DNS lookups"
    : >"$RAW/25-rdns.txt"
    while read -r ip; do
      local name
      name=$(dig +short +time=1 +tries=1 -x "$ip" 2>/dev/null | head -n1)
      [[ -n "$name" ]] && printf '%s\t%s\n' "$ip" "${name%.}" >>"$RAW/25-rdns.txt"
    done <"$WORK/hosts.list"
    ok "$(wc -l <"$RAW/25-rdns.txt" 2>/dev/null || echo 0) name(s) resolved"
  fi
}

# ---------------------------------------------------------------- stage 3
# Deep per-host scan: services, versions, OS guess, default scripts.
stage_deep() {
  [[ "$DO_DEEP" == 1 ]] || { info "deep scan disabled"; return 0; }
  have nmap || { warn "nmap missing - skipping deep scan"; return 0; }
  [[ -s "$WORK/hosts.list" ]] || { warn "no hosts to scan"; return 0; }

  section "Stage 3 - deep scan of $HOST_COUNT host(s)"

  if (( DEEP_SCAN_HOST_LIMIT > 0 && HOST_COUNT > DEEP_SCAN_HOST_LIMIT )); then
    warn "$HOST_COUNT hosts exceeds DEEP_SCAN_HOST_LIMIT ($DEEP_SCAN_HOST_LIMIT)."
    ask_yes_no "Deep-scan all of them anyway? This can take hours." n || {
      info "skipping deep scan"; return 0; }
  fi

  local -a opts=(-sV --version-intensity 5 "-T$NMAP_TIMING" -n --open)
  # shellcheck disable=SC2206
  opts+=($NMAP_PORTS)
  if can_root; then
    opts+=(-sS -O --osscan-limit)          # SYN scan + OS fingerprint need root
  else
    opts+=(-sT)                            # fall back to connect scan
    warn "no root - using TCP connect scan, no OS detection"
  fi
  [[ "$DO_VULN" == 1 ]] && opts+=(--script "default,vuln") || opts+=(-sC)

  mkdir -p "$RAW/hosts"
  local ip safe running=0 dispatched=0
  while read -r ip; do
    # keep at most MAX_PARALLEL scans in flight
    while (( running >= MAX_PARALLEL )); do
      wait -n 2>/dev/null || true
      running=$(( running - 1 ))
    done
    safe="${ip//./_}"
    (
      timeout "$HOST_SCAN_TIMEOUT" \
        as_root nmap "${opts[@]}" -oN "$RAW/hosts/$safe.txt" -oX "$RAW/hosts/$safe.xml" "$ip" \
        >/dev/null 2>&1 || true
    ) &
    running=$(( running + 1 ))
    dispatched=$(( dispatched + 1 ))
    printf '\r%s  dispatched %d/%d, %d running%s ' \
      "$C_DIM" "$dispatched" "$HOST_COUNT" "$running" "$C_RESET"
  done <"$WORK/hosts.list"
  printf '\r%*s\r' 60 ''
  step "waiting for the last $running scan job(s)"
  wait
  ok "deep scan complete ($(ls -1 "$RAW/hosts"/*.txt 2>/dev/null | wc -l) host reports)"

  extract_services
}

# Flatten nmap output into ip<TAB>port/proto<TAB>service<TAB>version
extract_services() {
  : >"$WORK/services.tsv"
  : >"$WORK/os.tsv"
  local f ip
  for f in "$RAW"/hosts/*.txt; do
    [[ -e "$f" ]] || continue
    ip=$(basename "$f" .txt); ip="${ip//_/.}"
    awk -v ip="$ip" '
      /^[0-9]+\/(tcp|udp)[ \t]+open/ {
        port=$1; svc=$3; $1=$2=$3="";
        gsub(/^[ \t]+|[ \t]+$/,"");
        printf "%s\t%s\t%s\t%s\n", ip, port, svc, $0
      }' "$f" >>"$WORK/services.tsv"
    awk -v ip="$ip" '
      /^Running:/      { sub(/^Running: /,"");      print ip"\t"$0; exit }
      /^OS details:/   { sub(/^OS details: /,"");   print ip"\t"$0; exit }
      /Aggressive OS guesses:/ { sub(/^Aggressive OS guesses: /,""); print ip"\t"$0; exit }
    ' "$f" >>"$WORK/os.tsv"
  done
  ok "$(wc -l <"$WORK/services.tsv") open service(s) catalogued"
}

# ---------------------------------------------------------------- stage 4
# Gateway, path to the internet, public presence, DNS.
stage_wan() {
  [[ "$DO_WAN" == 1 ]] || { info "WAN checks disabled"; return 0; }
  section "Stage 4 - gateway and internet path"

  run_tool "routing table" "$RAW/30-routes.txt" ip route show || true
  run_tool "DNS configuration" "$RAW/31-dns.txt" \
    bash -c 'resolvectl status 2>/dev/null || cat /etc/resolv.conf' || true

  if [[ -n "$GATEWAY" ]] && have nmap; then
    run_tool "gateway service scan ($GATEWAY)" "$RAW/32-gateway.txt" \
      as_root nmap -sV -T4 --top-ports 200 -n "$GATEWAY" || true
  fi

  if have mtr; then
    run_tool "path to 1.1.1.1 (mtr)" "$RAW/33-path.txt" \
      mtr -r -c 5 -n 1.1.1.1 || true
  elif have traceroute; then
    run_tool "path to 1.1.1.1 (traceroute)" "$RAW/33-path.txt" \
      traceroute -n -w 2 -q 2 1.1.1.1 || true
  fi

  # Public IP lookup talks to an outside service. Ask unless -y was given.
  if [[ "${ASSUME_YES:-0}" == 1 ]] || ask_yes_no "Look up your public IP? (contacts an external service)" y; then
    run_tool "public IP and ASN" "$RAW/34-public-ip.txt" \
      bash -c 'ip=$(curl -s --max-time 8 https://ifconfig.co/ip || curl -s --max-time 8 https://icanhazip.com);
               echo "Public IP: ${ip:-unknown}";
               [ -n "$ip" ] && command -v whois >/dev/null && whois "$ip" 2>/dev/null | grep -iE "^(orgname|netname|descr|country|origin):" | head -n 8' || true
  fi
}
