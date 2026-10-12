# SentinelScan

A local security dashboard for your own network: audit this machine, discover
the devices on your LAN, inventory your cloud accounts, and (coming) configure
network devices — all from a browser page served on `127.0.0.1`.

| Folder | What it is |
|---|---|
| `panel/` | the dashboard (`python3 panel/serve.py`) and the host-audit engine |
| `discovery/` | the network / cloud discovery scanner and encrypted credential vault — see [discovery/README.md](discovery/README.md) |
| `db/` | PostgreSQL schema |
| `docs/` | design notes and roadmaps |

> **Scan and configure only networks and devices you own or are authorised to manage.**
