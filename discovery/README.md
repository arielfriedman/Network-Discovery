# Network discovery

In-depth discovery of your homelab network and any cloud accounts you connect.
Runs a staged scan, writes a report to your Desktop, prints a summary to the
screen, and builds an offline HTML dashboard.

Everything is local. No agent, no backend, no telemetry.

> **Scan only networks you own or are authorised to test.** Port scanning and OS
> fingerprinting are intrusive on someone else's network and illegal in many
> places without permission. The script enforces private address space by
> default (see [Scope guard](#scope-guard)); that guard is a safety net, not a
> substitute for having permission.

```
./discover.sh                # scan the network you are on
./discover.sh --quick        # discovery only, no per-host port scan
./discover.sh --auth --vault # also log in to hosts, using stored credentials
./discover.sh --targets ip.txt        # only the hosts in the file (see below)
./vault.sh init              # set up the encrypted credential store
```

## Scanning a list of targets

`--targets FILE` scans only what is in the file instead of the whole network.
One entry per line; the kind is detected automatically:

```
# comments and blank lines are ignored; CSV files use the first column
172.16.0.30            an IP address
172.16.4.0/24          a range
bc:24:11:aa:bb:cc      a MAC address (also BC-24-11-AA-BB-CC or bc24.11aa.bbcc)
nas.lan                a hostname
```

- MAC addresses are found by sweeping the local range first, so they only
  work for devices on the same network segment as the scanner.
- Hostnames are resolved with the system resolver; names that don't resolve
  are reported, not dropped.
- Public addresses, option-like lines (`-oX`) and CSV headers are skipped
  with a message. Limits: 4096 entries, 65,536 addresses.
- `--pn` also scans listed hosts that don't answer the ping sweep.
- The report's *Listed targets* section shows what became of every line
  (`up`, `assumed_up`, `no_response`, `unresolved`, `not_seen`).

The dashboard's Scan page does the same with typed lists or uploaded files.
Design: [docs/SCAN_BUILDER.md](../docs/SCAN_BUILDER.md).

## What it does, in stages

| Stage | What runs | Needs root |
|---|---|---|
| 0 Preflight | works out which tools are missing, installs them with apt | yes, to install |
| 1 Discovery | `arp-scan` layer-2 sweep, `nmap -sn` ping sweep, kernel neighbour table | better with |
| 2 Passive | mDNS/Bonjour (`avahi-browse`), NetBIOS (`nbtscan`), SSDP/UPnP, LLDP/CDP neighbours, reverse DNS, wifi list | LLDP only |
| 3 Deep scan | per-host `nmap -sV -sC` with OS fingerprinting, run in parallel | for SYN + OS |
| 4 WAN | routes, DNS config, gateway service scan, `mtr` path, public IP + ASN | for gateway scan |
| 5 Authenticated | SNMP walk, SSH system collection — **asks for credentials** | no |
| 6 Cloud | AWS, Azure, GCP and Kubernetes via their CLIs; DigitalOcean, Linode, Hetzner, Vultr, Scaleway, Cloudflare, IBM Cloud, OVHcloud, Alibaba Cloud and Oracle Cloud via their REST APIs (credential card needed, see [docs/CLOUD_PROVIDERS.md](../docs/CLOUD_PROVIDERS.md)) | no |

Stages 5 and 6 are off or auto-skipped unless you ask for them.

## Output

Each run creates `reports/<timestamp>/`:

```
summary.txt        the human report  (also copied to the Desktop)
dashboard.html     self-contained dashboard (also copied to the Desktop)
findings.json      machine-readable, feeds the dashboard
run.log            what happened, with timings
raw/               every tool's unedited output
  hosts/           per-host nmap results (.txt and .xml)
  snmp/  ssh/  cloud/
work/              intermediate tables
```

`reports/latest` always points at the newest run. Old runs beyond `KEEP_RUNS`
(default 20) are pruned automatically.

## Host profiles: OS, apps, system details

After the port scan each host gets a profile (`lib/host_profile.py`):

- **OS** with the clue it came from: nmap's OS fingerprint (needs root), else
  service banners - e.g. `OpenSSH 9.6p1 Ubuntu 3ubuntu13` is Ubuntu 24.04,
  `+deb12u` is Debian 12, RDP/SMB build numbers name the Windows version -
  or `/etc/os-release` when an SSH login card works.
- **Apps**: known software by page title / server / product (Uptime Kuma,
  Grafana, Home Assistant, Pi-hole, Portainer, Nextcloud, Jellyfin, Plex,
  databases, ...); other web apps by their page title. `lib/http_probe.py`
  reads titles on ports nmap didn't recognise as web (one plain GET each).
  Matches resting only on the usual port are marked "(likely)".
- **Containers from the network**: Docker API (2375/2376, an open 2375 is
  flagged), Kubernetes API (6443/16443), kubelet (10250), etcd (2379).
- **System details** (SSH login card only): OS release, kernel, hardware
  model, CPU / RAM, uptime, running systemd services, Docker containers
  (`docker ps -a`), Kubernetes (k3s / microk8s / kubelet / containerd).
  Docker and Kubernetes that don't expose ports can only be seen this way.

## Device types (Raspberry Pi, ...)

Every network scan labels hosts it can identify, with the evidence and a
confidence (`discovery/lib/device_types.py`):

| Evidence | Confidence |
|---|---|
| MAC address registered to the maker (IEEE registry) | high |
| board model read over SSH (`/proc/device-tree/model`), when a login card works | high, and gives the exact model |
| OS fingerprint or service banner naming it | medium |
| only the host / mDNS name (`raspberrypi`, `rpi4-...`) | low |

Types: Raspberry Pi, router / Wi-Fi, printer, IP camera, NAS / storage,
TV / streamer, game console, smart home / IoT, Apple device, phone / tablet,
Windows PC / server, Linux server (fallback). Two independent medium clues
count as high; a vendor that also makes ordinary PCs or phones (HP, Samsung)
counts only as low on its own. More types are added as rules in the same file.
MAC vendors come from `config/ieee-oui.csv`, fetched from the IEEE by
`./update-vendors.sh` (the installer runs it; refresh every few months),
falling back to the older copies shipped with arp-scan and nmap. Devices
with a randomised (locally administered) MAC can't be identified this way.
The dashboard and History can filter by type.

## Credentials from the dashboard

The dashboard's credential cards (SSH, SNMP v2c/v3, AWS, Azure, GCP,
Kubernetes) reach `discover.sh` through an inherited pipe (`ND_CREDS_FD`),
are held in tmpfs for the run only, and are redacted from every report.
Cards ticked *Remember in vault* are stored here as `CRED_<name>` entries.
Details: [docs/SCAN_BUILDER.md](../docs/SCAN_BUILDER.md#step-2---credentials).

## The credential vault

`vault.sh` keeps usernames, passwords and API keys in **one GPG AES-256
encrypted file**, `config/vault.gpg`.

```
./vault.sh init         create it, and add entries interactively
./vault.sh template     show the key names the scanner looks for
./vault.sh list         list key names (values stay hidden)
./vault.sh set KEY      add or replace one entry
./vault.sh get KEY      print one value
./vault.sh rm KEY       delete one entry
./vault.sh edit         edit everything in $EDITOR, inside tmpfs
./vault.sh passwd       change the master passphrase
```

How it protects things:

- The file on disk is **always ciphertext** — AES-256, SHA-512, iterated S2K.
  There is no code path that writes plaintext credentials to your SSD.
- `vault.sh edit` decrypts into `/dev/shm` (RAM) at mode 0600 and shreds it after.
- The master passphrase reaches `gpg` through a file, never through a command-line
  argument — argv is readable by any local user through `/proc`.
- Values are registered with a scrubber, so if a tool ever echoes one back it is
  replaced with `***REDACTED***` before anything is written to a report.
- SNMP communities go to `snmpwalk` through a temporary `snmp.conf`, and SSH
  passwords through `sshpass -e` (an environment variable), so neither appears
  in the process list.

If a credential is not in the vault, the scanner asks for it at the moment it is
needed and offers to save it afterwards. You never have to use the vault at all.

**What it is not:** the vault is only as strong as its passphrase, and once
unlocked the values sit in the memory of a normal user process. It protects a
file at rest — a stolen disk, a backup, a synced folder. It does not protect you
from malware already running as your user.

## Scope guard

The script refuses to scan anything outside private address space
(RFC1918, CGNAT, link-local) unless you pass `--allow-public` **and** retype the
target to confirm. That is there so an accidental run on a VPN, hotel wifi or
guest network cannot sweep somebody else's addresses. Change
`ALLOWED_PREFIXES` in `config/settings.conf` if your lab uses something unusual.

## Tuning

`config/settings.conf` holds the defaults — nmap timing, port range, parallelism,
per-host timeout, the deep-scan host cap, and which stages run. Command-line
flags beat the file. Run `./discover.sh --help` for the flag list.

Large subnets are handled in two passes. On a `/19` (8,190 addresses) the sweep
finishes in a couple of minutes, and the deep stage only runs against hosts that
actually answered — stopping to ask first if that number is above
`DEEP_SCAN_HOST_LIMIT` (default 256).

## Packages it installs

`nmap arp-scan nbtscan snmp lldpd traceroute mtr-tiny dnsutils avahi-utils
net-tools jq vnstat iftop nethogs tcpdump whois netcat-openbsd ipcalc`

Cloud CLIs (`awscli`, `azure-cli`) are only offered, never installed silently.
It always shows the list and asks before running apt.

## Dashboard

`dashboard.html` is one self-contained file — open it by double-clicking, no
server needed. Stat tiles, findings, three breakdown charts with hover detail,
and a filterable, sortable host table. Follows your system light/dark setting,
with a toggle that overrides it.

## Requirements

- A Debian/Ubuntu-family Linux (it installs with `apt`). Tested on Linux Mint 22.
- `bash`, `python3`, `gpg` — all standard on those systems.
- `sudo` for the stages that need raw packets and OS fingerprinting. Everything
  else degrades gracefully without it and says so in the report.

No Node, no npm, no Python packages, no internet access needed except by the
tools that obviously need it (apt, the public-IP lookup, cloud CLIs).

## Contributing

Issues and merge requests welcome. The code is plain bash with one Python step
for JSON assembly; `lib/` holds one file per stage, and each stage is expected
to skip itself cleanly when its tools or credentials are absent.
