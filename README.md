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

It is safe to run again; that is also how you update: `git pull && ./install.sh`.
Options: `--no-db` (no PostgreSQL, no history), `--no-tools` (skip nmap and friends), `--dry-run`.

## Run

```bash
./start.sh          # then open http://127.0.0.1:8765
sudo ./start.sh     # same, with the checks that need root (ARP sweep, OS detection, full host audit)
```

| Page | What it does |
|---|---|
| **Scan** | pick *this host*, *the network* or *the cloud*, start, watch live progress, read the dashboard |
| **History** | every saved scan, what is new or resolved since the previous one, and the activity log |
| **Devices** | add FortiGate, Cisco, Palo Alto and Check Point devices, back up configs, run wizards |

## Layout

| Folder | What it is |
|---|---|
| `panel/` | the dashboard server (`serve.py`, standard library only), host-audit engine, `db.py`, web pages |
| `discovery/` | the network / cloud scanner and the encrypted credential vault — see [discovery/README.md](discovery/README.md) |
| `db/migrations/` | PostgreSQL schema, applied in order by `python3 panel/db.py migrate` |
| `docs/` | design notes and roadmaps |

## Database

```bash
python3 panel/db.py status     # connected? which migrations ran?
python3 panel/db.py migrate    # create / upgrade tables
python3 panel/db.py import     # load earlier JSON reports
```

The connection string comes from `$SENTINEL_DATABASE_URL`, or `panel/settings.local.json`.
Without a database the panel still works and saves scans as files; History stays empty.
Device passwords and API keys are never stored in the database.

## False positives

If the rootkit check flags something you have verified, add its name, path or a glob to
`panel/rootkit_allowlist.txt`.
