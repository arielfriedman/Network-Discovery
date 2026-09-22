#!/usr/bin/env bash
# preflight.sh - work out what is missing and install it.

# package -> command it provides
declare -A PKG_CMD=(
  [nmap]=nmap
  [arp-scan]=arp-scan
  [nbtscan]=nbtscan
  [snmp]=snmpwalk
  [lldpd]=lldpctl
  [traceroute]=traceroute
  [mtr-tiny]=mtr
  [dnsutils]=dig
  [avahi-utils]=avahi-browse
  [net-tools]=arp
  [iproute2]=ip
  [jq]=jq
  [vnstat]=vnstat
  [iftop]=iftop
  [nethogs]=nethogs
  [tcpdump]=tcpdump
  [whois]=whois
  [netcat-openbsd]=nc
  [curl]=curl
  [ipcalc]=ipcalc
)

# Optional cloud CLIs - only offered, never forced.
declare -A CLOUD_PKG=(
  [awscli]=aws
  [azure-cli]=az
)

missing_packages() {
  local pkg cmd out=()
  for pkg in "${!PKG_CMD[@]}"; do
    cmd="${PKG_CMD[$pkg]}"
    have "$cmd" || out+=("$pkg")
  done
  printf '%s\n' "${out[@]}" | sort | sed '/^$/d'
}

preflight() {
  section "Stage 0 - preflight"

  local -a missing
  mapfile -t missing < <(missing_packages)

  if (( ${#missing[@]} == 0 )); then
    ok "all scanning tools already present"
  else
    info "${#missing[@]} package(s) missing: ${missing[*]}"
    if [[ "$DO_INSTALL" != 1 ]]; then
      warn "--no-install given; scans needing these tools will be skipped"
    elif ! can_root; then
      warn "no root available; cannot install. Scans will run degraded."
    else
      printf '\n%sThese packages will be installed with apt:%s\n  %s\n\n' \
        "$C_BOLD" "$C_RESET" "${missing[*]}"
      if ask_yes_no "Install them now?" y; then
        step "apt-get update"
        as_root apt-get update -qq 2>&1 | tail -n 3
        step "apt-get install ${missing[*]}"
        if DEBIAN_FRONTEND=noninteractive as_root apt-get install -y -qq "${missing[@]}" 2>&1 | tail -n 15; then
          ok "packages installed"
        else
          warn "some packages failed to install; continuing with what is available"
        fi
      else
        warn "skipping installation; scans will run degraded"
      fi
    fi
  fi

  # lldpd needs to be running for a little while to hear neighbour adverts
  if have lldpctl && can_root; then
    if ! systemctl is-active --quiet lldpd 2>/dev/null; then
      step "starting lldpd (needs ~30s of listening to see neighbours)"
      as_root systemctl start lldpd 2>/dev/null || true
    fi
  fi

  # report which tools we ended up with
  local pkg cmd present=() absent=()
  for pkg in "${!PKG_CMD[@]}"; do
    cmd="${PKG_CMD[$pkg]}"
    have "$cmd" && present+=("$cmd") || absent+=("$cmd")
  done
  {
    printf 'Tools available: %s\n' "$(printf '%s ' "${present[@]}" | tr ' ' '\n' | sort | tr '\n' ' ')"
    printf 'Tools missing  : %s\n' "$(printf '%s ' "${absent[@]}"  | tr ' ' '\n' | sort | tr '\n' ' ')"
  } >"$RAW/00-tools.txt"
  ok "$(( ${#present[@]} )) tools ready, ${#absent[@]} unavailable"
}

# offered separately, only when the cloud stage actually runs
offer_cloud_clis() {
  local pkg cmd want=()
  for pkg in "${!CLOUD_PKG[@]}"; do
    cmd="${CLOUD_PKG[$pkg]}"
    have "$cmd" || want+=("$pkg")
  done
  (( ${#want[@]} == 0 )) && return 0
  can_root || return 0
  [[ "$DO_INSTALL" == 1 ]] || return 0
  info "cloud CLIs not installed: ${want[*]}"
  ask_yes_no "Install cloud CLIs so cloud inventory can run?" n || return 1
  DEBIAN_FRONTEND=noninteractive as_root apt-get install -y -qq "${want[@]}" 2>&1 | tail -n 10
  return 0
}
