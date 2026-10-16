# SentinelScan

A local security dashboard for your own network. From one browser page on
`127.0.0.1` you can audit this machine, discover the devices on your LAN,
inventory your cloud accounts, keep the history of every scan in PostgreSQL,
and configure network devices with guided wizards.

> **Scan and configure only networks and devices you own or are authorised to manage.**

## Install

On Debian, Ubuntu or Linux Mint:

```bash
curl -fsSL https://gitlab.com/fritzizi/network-discovery/-/raw/main/install.sh | bash
```

or from a checkout:

```bash
git clone https://gitlab.com/fritzizi/network-discovery.git sentinelscan
cd sentinelscan && ./install.sh
```

The installer asks for your sudo password once, then:

1. installs Python, PostgreSQL and the scanning tools with `apt`
2. creates a PostgreSQL user and database called `sentinel` with a random password,
   reachable only from this machine
3. saves the connection string to `panel/settings.local.json` (readable only by you, never committed)
4. creates the tables and imports any earlier scan reports
5. starts the dashboard as a service (`sentinelscan`, also after a reboot), checks that it
   answers, and prints the address to open: **http://127.0.0.1:8765**

It is safe to run again; that is also how you update: `git pull && ./install.sh`.
Options: `--root` (the service runs as root, so scans get the ARP sweep and OS detection),
`--no-service` (start it yourself with `./start.sh`), `--drawio` (draw.io desktop for PDF drawings), `--no-db` (no PostgreSQL, no history),
`--no-tools` (skip nmap and friends), `--no-backup`, `--dry-run`. With curl:
`curl -fsSL .../install.sh | bash -s -- --root`.

Manage the service with `sudo systemctl status|restart|stop sentinelscan`
(logs: `journalctl -u sentinelscan`).

> The curl line works once the repository is public. While it is private, GitLab answers
> with its sign-in page; clone with your GitLab login and run `./install.sh` instead.

## Run

```bash
./start.sh          # then open http://127.0.0.1:8765
sudo ./start.sh     # same, with the checks that need root (ARP sweep, OS detection, full host audit)
```

Stop a running panel first (Ctrl-C) - only one can use port 8765, and the
second start says so. Started with sudo, the browser is not opened for you
(open the address yourself), the Actions terminal is still your own user's
shell, and files the panel and its scans write are handed back to your user.
SSH logins to other machines (credential cards) don't need sudo here.

| Page | What it does |
|---|---|
| **Scan** | pick *this host*, *the network* or *the cloud* (AWS, Azure, GCP, Kubernetes, DigitalOcean, Linode, Hetzner, Vultr, Scaleway, Cloudflare, IBM Cloud, OVHcloud, Alibaba Cloud, Oracle Cloud - read-only), start, watch live progress, read the dashboard. For the network: the whole local range or a list of IPs, ranges, MAC addresses and hostnames (typed or uploaded as `ip.txt` / `mac.txt` / `hostnames.txt`), plus a checklist of what to run. Hosts are labelled by device type (Raspberry Pi first) with the evidence. Optional credential cards (SSH, SNMP, Proxmox VE, AWS, Azure, GCP, Kubernetes) for logins, used for that scan only or remembered in the encrypted vault. With a Proxmox token or an SSH login to a Proxmox/libvirt host, VMs are listed with vCPU, RAM, disks (NVMe/SSD/HDD) and matched to what runs inside them (`docs/VM_INVENTORY.md`) |
| **Network drawing** | after a network scan (and for saved ones in History): a drawing of the network - gateway, hosts by device type, hypervisors with their VMs - as preview, `.drawio` (edit in draw.io / diagrams.net), PNG, or PDF with draw.io desktop (`docs/DIAGRAMS.md`) |
| **History** | every saved scan, what is new or resolved since the previous one, and the activity log. *Clear history…* deletes one scan, scans older than 30 / 90 / 365 days, or all (optionally with their report files); the activity log is kept as the audit trail |
| **Actions** | saved commands for this machine (31 starter actions with per-distro variants: packages, services, logs, disks, network, firewall, Docker, Kubernetes); run with live output, paste your own, drag one onto another to combine, export / import |
| **Devices** | add FortiGate, Cisco, Palo Alto and Check Point devices, back up configs, run wizards |

## Layout

| Folder | What it is |
|---|---|
| `panel/` | the dashboard server (`serve.py`, standard library only), host-audit engine, `db.py`, web pages |
| `discovery/` | the network / cloud scanner and the encrypted credential vault — see [discovery/README.md](discovery/README.md) |
| `db/migrations/` | PostgreSQL schema, applied in order by `python3 panel/db.py migrate` |
| `docs/` | design notes, roadmaps, and [DEVLOG.md](docs/DEVLOG.md): every change with the problems hit and how it was tested |

## Device wizard

The **Devices** page manages firewalls, switches and routers:

| Vendor | Models | How it connects |
|---|---|---|
| Fortinet | FortiGate 100F, 200E (FortiOS 7.4 / 7.6) | REST API with an API token |
| Cisco | Catalyst 9200 / 9300, Catalyst 8200 / 8300, ISR 1100 (IOS-XE); Catalyst 1200 / 1300 | SSH |
| Palo Alto | PA-440/450/460, PA-1410/1420, PA-3410/3420, VM-Series | XML API |
| Check Point | Quantum Spark 1600-2000; Quantum Force 9100/9200 via the Management Server | Spark API / Management API |

How a change works:

1. **Connect.** On first contact you confirm the device's certificate or SSH host-key fingerprint;
   credentials are only ever sent to that confirmed device, and are kept in memory only
   (never in the database or on disk).
2. **Pick a wizard and fill in the form.** Every field is validated, so input cannot turn into extra commands.
3. **Preview.** You see the exact API calls or CLI lines, plus the undo steps.
4. **Apply.** A full configuration backup is stored first, then the change is sent
   (and committed / published where the vendor needs it). Cisco IOS-XE changes use an auto-revert timer.
5. **Roll back** any change from the Changes tab, or download the backup taken before it.

No equipment to try it on? Start the simulated lab and add the devices it prints:

```bash
cd panel && python3 -m devices.lab
```

Supported models and API details: [docs/DEVICE_MODELS.md](docs/DEVICE_MODELS.md).

## Database

```bash
python3 panel/db.py status     # connected? which migrations ran?
python3 panel/db.py migrate    # create / upgrade tables
python3 panel/db.py import     # load earlier JSON reports
python3 panel/db_backup.py run                 # back up now (panel/backups/db/, newest 14 kept)
python3 panel/db_backup.py schedule on|off     # nightly at 03:17 via your crontab (install.sh turns it on)
```

Restore a backup (replaces the current contents):
`pg_restore --clean --if-exists --no-owner -d "<database_url>" panel/backups/db/<file>.dump`.
The History page shows the backups, takes one on demand and switches the schedule.

The connection string comes from `$SENTINEL_DATABASE_URL`, or `panel/settings.local.json`.
Without a database the panel still works and saves scans as files; History stays empty.
Device passwords and API keys are never stored in the database.

## False positives

If the rootkit check flags something you have verified, add its name, path or a glob to
`panel/rootkit_allowlist.txt`.
