#!/usr/bin/env bash
# install.sh - set up SentinelScan on this machine (Debian / Ubuntu / Mint).
#
# From a checkout:     ./install.sh
# Straight from git:   curl -fsSL https://gitlab.com/fritzizi/network-discovery/-/raw/main/install.sh | bash
#
# What it does, each step safe to re-run:
#   1. downloads the project with git (only when run through curl)
#   2. installs packages with apt: Python, PostgreSQL, the scanning tools
#   3. creates a PostgreSQL user and database "sentinel" with a random password,
#      reachable only from this machine
#   4. saves the connection string to panel/settings.local.json (mode 600)
#   5. creates the tables and imports any earlier scan reports
#   6. schedules a nightly database backup (03:17, your crontab, last 14 kept)
#   7. runs the dashboard as a service (starts now and after every reboot) and
#      checks that http://127.0.0.1:8765 answers
#
# Options:
#   --no-db       skip PostgreSQL (the panel works, without history)
#   --no-backup   don't schedule the nightly database backup
#   --no-tools    skip the network scanning tools (nmap, arp-scan, ...)
#   --no-service  don't install the service; start it yourself with ./start.sh
#   --drawio      also install the draw.io desktop app (official .deb from
#                 github.com/jgraph/drawio-desktop, SHA-256 checked) for PDF
#                 and high-resolution PNG of the network drawings, plus xvfb
#   --root        run the service as root: scans get ARP sweep + OS detection
#                 (the Actions terminal stays your own user's shell)
#   --dry-run     print what would be done, change nothing
#
# Environment: SENTINEL_DIR   where curl installs put the project (default ~/sentinelscan)
#              SENTINEL_REPO  git URL to clone from
set -euo pipefail

REPO_URL="${SENTINEL_REPO:-https://gitlab.com/fritzizi/network-discovery.git}"
DB_NAME=sentinel
DB_USER=sentinel
DO_DB=1 DO_TOOLS=1 DO_BACKUP=1 DO_SERVICE=1 AS_ROOT=0 DO_DRAWIO=0 DRY=0
for a in "$@"; do
  case "$a" in
    --no-db) DO_DB=0 ;;
    --no-tools) DO_TOOLS=0 ;;
    --no-backup) DO_BACKUP=0 ;;
    --no-service) DO_SERVICE=0 ;;
    --root) AS_ROOT=1 ;;
    --drawio) DO_DRAWIO=1 ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

if [[ -t 1 ]]; then B=$'\e[1m' G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' N=$'\e[0m'; else B= G= Y= R= N=; fi
say()  { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%sError:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
run()  { if (( DRY )); then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }

# The person installing, even when the script itself runs under sudo.
OWNER="${SUDO_USER:-$(id -un)}"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
as_owner() { if [[ "$(id -un)" == "$OWNER" ]]; then "$@"; else sudo -u "$OWNER" -H "$@"; fi; }
SUDO=""; [[ $EUID -eq 0 ]] || SUDO="sudo"

# ── 0. are we on a supported system? ───────────────────────────────────────
command -v apt-get >/dev/null || die "this installer needs a Debian-based system with apt (Debian, Ubuntu, Mint)."
if [[ -n "$SUDO" ]] && ! command -v sudo >/dev/null; then die "sudo is not installed; run this as root."; fi

# ── 1. get the code (curl | bash case) ─────────────────────────────────────
SELF_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fi
if [[ -z "$SELF_DIR" || ! -f "$SELF_DIR/panel/serve.py" ]]; then
  DEST="${SENTINEL_DIR:-$OWNER_HOME/sentinelscan}"
  say "Downloading SentinelScan to $DEST"
  command -v git >/dev/null || run $SUDO apt-get install -y -qq git
  if [[ -d "$DEST/.git" ]]; then
    run as_owner git -C "$DEST" pull --ff-only
  elif [[ -e "$DEST" ]]; then
    die "$DEST already exists and is not a SentinelScan checkout. Set SENTINEL_DIR to another folder."
  else
    run as_owner git clone --depth 1 "$REPO_URL" "$DEST"
  fi
  (( DRY )) && { echo "  [dry-run] would continue with $DEST/install.sh"; exit 0; }
  exec bash "$DEST/install.sh" "$@"
fi
APP="$SELF_DIR"
cd "$APP"
say "Installing SentinelScan from $APP for user $OWNER"
if [[ -n "$SUDO" ]]; then
  echo "  Some steps need administrator rights; sudo will ask for your password."
fi

# ── 2. packages ────────────────────────────────────────────────────────────
pkgs=(python3 git gnupg ca-certificates curl python3-paramiko)
(( DO_DB )) && pkgs+=(postgresql python3-psycopg2)
if (( DO_TOOLS )); then
  # the same list the network scanner checks for (discovery/lib/preflight.sh)
  mapfile -t tool_pkgs < <(bash -c 'source discovery/lib/preflight.sh >/dev/null 2>&1; printf "%s\n" "${!PKG_CMD[@]}"' | sort)
  pkgs+=("${tool_pkgs[@]}")
fi
missing=()
for p in "${pkgs[@]}"; do
  dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || missing+=("$p")
done
say "Packages"
if (( ${#missing[@]} )); then
  echo "  installing: ${missing[*]}"
  run $SUDO apt-get update -qq
  run $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
  ok "packages installed"
else
  ok "everything already installed"
fi

# ── 3. database ────────────────────────────────────────────────────────────
SETTINGS="$APP/panel/settings.local.json"
if (( DO_DB )); then
  say "PostgreSQL"
  if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
    run $SUDO systemctl enable --now postgresql >/dev/null 2>&1 || warn "could not start the postgresql service"
  fi
  psql_admin() {
    if [[ $EUID -eq 0 ]]; then runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -qtA "$@"
    else sudo -u postgres psql -X -v ON_ERROR_STOP=1 -qtA "$@"; fi
  }
  if (( DRY )); then
    echo "  [dry-run] would create role '$DB_USER' and database '$DB_NAME', write $SETTINGS"
  else
    for _ in $(seq 1 15); do psql_admin -c 'select 1' >/dev/null 2>&1 && break; sleep 1; done
    psql_admin -c 'select 1' >/dev/null || die "PostgreSQL is not answering. Check: sudo systemctl status postgresql"
    PGPORT="$(psql_admin -c 'show port')"

    # Reuse the password we saved last time; otherwise make a new one.
    PW=""
    if [[ -f "$SETTINGS" ]]; then
      PW="$(python3 -c 'import json,sys,urllib.parse as u; d=json.load(open(sys.argv[1])); print(u.urlparse(d.get("database_url","")).password or "")' "$SETTINGS" 2>/dev/null || true)"
    fi
    [[ "$PW" =~ ^[A-Za-z0-9_-]+$ ]] || PW="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"

    if [[ "$(psql_admin -c "select 1 from pg_roles where rolname='$DB_USER'")" == 1 ]]; then
      # the password goes in on stdin (printf is a shell builtin), never on a command line
      printf "ALTER ROLE %s WITH LOGIN PASSWORD '%s';\n" "$DB_USER" "$PW" | psql_admin >/dev/null
      ok "database user '$DB_USER' exists (password refreshed)"
    else
      printf "CREATE ROLE %s WITH LOGIN PASSWORD '%s';\n" "$DB_USER" "$PW" | psql_admin >/dev/null
      ok "created database user '$DB_USER'"
    fi
    if [[ "$(psql_admin -c "select 1 from pg_database where datname='$DB_NAME'")" == 1 ]]; then
      ok "database '$DB_NAME' exists"
    else
      psql_admin -c "CREATE DATABASE $DB_NAME OWNER $DB_USER" >/dev/null
      ok "created database '$DB_NAME'"
    fi

    # Written by the owner, readable only by them (it holds the password).
    as_owner bash -c 'umask 077; cat > "$1"' _ "$SETTINGS" <<EOF
{
  "database_url": "postgresql://$DB_USER:$PW@127.0.0.1:$PGPORT/$DB_NAME"
}
EOF
    chmod 600 "$SETTINGS"
    ok "connection saved to panel/settings.local.json (only $OWNER can read it)"

    as_owner python3 panel/db.py migrate | sed 's/^/  /'
    as_owner python3 panel/db.py import  | sed 's/^/  /'
    as_owner python3 panel/db.py status  | sed 's/^/  /'

    if (( DO_BACKUP )) && command -v crontab >/dev/null; then
      if as_owner python3 panel/db_backup.py schedule on >/dev/null; then
        ok "nightly database backup scheduled (03:17, panel/backups/db/, last 14 kept)"
      else
        warn "could not schedule the nightly backup; turn it on from the History page"
      fi
    elif (( DO_BACKUP )); then
      warn "cron is not installed, so no nightly backup is scheduled (sudo apt install cron)"
    fi
  fi
else
  warn "skipping the database (--no-db): the panel runs, without history"
fi

# ── 4. MAC vendor list (device identification) ────────────────────────────
say "MAC vendor list"
if (( DRY )); then echo "  [dry-run] would download the IEEE vendor registry"
elif as_owner bash discovery/update-vendors.sh >/dev/null 2>&1; then
  ok "current IEEE vendor registry saved (refresh any time: discovery/update-vendors.sh)"
else
  warn "could not download it (offline?); the copies from arp-scan/nmap are used instead"
fi

# ── 4b. draw.io desktop (optional, --drawio) ──────────────────────────────
# PDF / high-resolution PNG of the network drawings. Not in Debian/Ubuntu: the
# official .deb comes from the project's GitHub releases and is checked against
# the SHA-256 list published with the same release.
if (( DO_DRAWIO )); then
  say "draw.io desktop"
  if command -v drawio >/dev/null; then
    ok "already installed ($(dpkg-query -W -f='${Version}' drawio 2>/dev/null || echo present))"
  elif (( DRY )); then
    echo "  [dry-run] would download the latest drawio .deb from github.com/jgraph/drawio-desktop, check its SHA-256, install it and xvfb"
  else
    case "$(dpkg --print-architecture)" in
      amd64) ARCH=amd64 ;; arm64) ARCH=arm64 ;;
      *) ARCH="" ;;
    esac
    DTMP="$(mktemp -d)"
    if [[ -z "$ARCH" ]]; then
      warn "no draw.io package for $(dpkg --print-architecture); the drawings still work (.drawio, SVG, PNG)"
    elif ! TAG="$(curl -fsSL --max-time 20 https://api.github.com/repos/jgraph/drawio-desktop/releases/latest \
                 | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"; then
      warn "could not reach GitHub to find the latest draw.io release; skipped"
    else
      VER="${TAG#v}" DEB="drawio-$ARCH-${TAG#v}.deb"
      URL_D="https://github.com/jgraph/drawio-desktop/releases/download/$TAG"
      if curl -fsSL --max-time 600 -o "$DTMP/$DEB" "$URL_D/$DEB" \
         && curl -fsSL --max-time 30 -o "$DTMP/hashes.txt" "$URL_D/Files-SHA256-Hashes.txt"; then
        WANT="$(awk -v f="$DEB" '$2 == f {print $1}' "$DTMP/hashes.txt")"
        GOT="$(sha256sum "$DTMP/$DEB" | cut -d' ' -f1)"
        if [[ -n "$WANT" && "$WANT" == "$GOT" ]]; then
          chmod 644 "$DTMP/$DEB"; chmod 755 "$DTMP"      # apt's _apt user must read it
          run $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$DTMP/$DEB" xvfb >/dev/null
          ok "draw.io $VER installed (SHA-256 checked) - PDF export is on in the drawing dialog"
        else
          warn "draw.io download did not match the published SHA-256 - not installed"
        fi
      else
        warn "could not download draw.io $VER; skipped"
      fi
    fi
    rm -rf -- "$DTMP"
  fi
fi

# ── 5. the dashboard as a service ─────────────────────────────────────────
chmod +x "$APP/start.sh" "$APP/discovery/discover.sh" "$APP/discovery/vault.sh" 2>/dev/null || true
URL="http://127.0.0.1:8765"
UNIT=/etc/systemd/system/sentinelscan.service
answers() { curl -fsS -o /dev/null --max-time 2 "$URL/" 2>/dev/null; }

# The unit file text
unit_text() {
  local runas
  if (( AS_ROOT )); then
    # SUDO_* tell the panel whose files these are (it hands root-owned files
    # back) and whose shell the Actions terminal opens
    runas="Environment=SUDO_UID=$(id -u "$OWNER") SUDO_GID=$(id -g "$OWNER") SUDO_USER=$OWNER"
  else
    runas="User=$OWNER"$'\n'"Group=$(id -g "$OWNER")"
  fi
  cat <<UNIT
[Unit]
Description=SentinelScan dashboard ($URL)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
$runas
Environment=SENTINEL_NO_BROWSER=1 PYTHONUNBUFFERED=1
ExecStart=/usr/bin/env python3 "$APP/panel/serve.py"
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
}

SERVICE=0
if (( DO_SERVICE )); then
  say "Dashboard service"
  if ! command -v systemctl >/dev/null || [[ ! -d /run/systemd/system ]]; then
    warn "no systemd here (container / WSL?) - start the dashboard yourself with ./start.sh"
  elif (( DRY )); then
    echo "  [dry-run] would write $UNIT (runs as $( (( AS_ROOT )) && echo root || echo "$OWNER")), enable and start it"
  else
    if answers && ! $SUDO systemctl is-active --quiet sentinelscan; then
      warn "a panel started by hand already answers on $URL - stop it (Ctrl-C) and run: sudo systemctl restart sentinelscan"
    fi
    unit_text | $SUDO tee "$UNIT" >/dev/null
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable sentinelscan >/dev/null 2>&1
    $SUDO systemctl restart sentinelscan
    for _ in $(seq 1 30); do answers && break; sleep 0.5; done
    if answers; then
      SERVICE=1
      ok "running as $( (( AS_ROOT )) && echo root || echo "$OWNER"), starts at boot"
    else
      warn "the service did not answer on $URL. Last log lines:"
      $SUDO journalctl -u sentinelscan -n 15 --no-pager 2>/dev/null | sed 's/^/    /' || true
    fi
  fi
fi

# ── 6. done ────────────────────────────────────────────────────────────────
say "Done"
Q="$(printf '%q' "$APP")"   # quoted, in case the folder name has spaces
if (( SERVICE )); then
  printf '\n  %sSentinelScan is running.%s  Open:  %s%s%s\n\n' "$G" "$N" "$B" "$URL" "$N"
  echo "  Service:      sudo systemctl status|restart|stop sentinelscan   (logs: journalctl -u sentinelscan)"
  (( AS_ROOT )) || echo "  Full rights:  re-run the installer with --root (ARP sweep, OS detection)"
else
  cat <<EOF

  Start the dashboard:   $Q/start.sh
  Then open:             $URL
  For the checks that need root (ARP sweep, OS detection, full host audit):
                         sudo $Q/start.sh
EOF
fi
cat <<EOF
  Update later:  git -C $Q pull && $Q/install.sh

  Scan and configure only networks and devices you own or are authorised to manage.
EOF
