# Scan builder: checklist, targets, credentials, virtualization

Status: step 1 done (2026-10-13). Each step is logged in `DEVLOG.md`.

| Step | What | Status |
|---|---|---|
| 1 | Checklist of scan parts + targets by IP / CIDR / MAC / hostname, typed or uploaded (`ip.txt`, `mac.txt`, `hostnames.txt`) | done |
| 2 | Credentials per system type, typed per scan, optional "remember in vault" | planned |
| 3 | VM tagging by MAC prefix + read-only Proxmox inventory | planned |
| 4 | vCenter / ESXi / Hyper-V / libvirt inventory | planned |

## Step 1 - checklist and targets

### What the user sees (Scan page, "The network")

- **Targets**: *Whole local network* (auto-detected range, as before) or
  *Specific targets*. Specific targets are typed one per line, or loaded from
  one or more `.txt` / `.csv` files. Each line is classified automatically:

  | Line | Kind |
  |---|---|
  | `172.16.0.30` | IP |
  | `172.16.4.0/24` | range (CIDR) |
  | `bc:24:11:aa:bb:cc`, `BC-24-11-AA-BB-CC`, `bc24.11aa.bbcc` | MAC |
  | `pve.lan`, `nas` | hostname |

  Blank lines and `#` comments are ignored; CSV files use the first column.
  Common column titles (`IP Address`, `Hostname`, `Name`, `MAC`, ...) are
  skipped as headers. A bare 12-hex-digit token (`bc2411aabbcc`) is read as a
  MAC address, not a hostname. The page shows the counts per kind and lists
  skipped lines with the reason before starting.
- **Checklist** of scan parts:

  | Item | discover.sh flag | Default |
  |---|---|---|
  | Find live hosts | always on | on |
  | Names: mDNS, NetBIOS, SSDP, LLDP, reverse DNS | `--no-passive` when off | on |
  | Ports and services (top 1000 / all ports) | `--quick` when off, `--deep` for all | off |
  | Vulnerability scripts (slow, noisy) | `--vuln` | off |
  | Gateway and internet path | `--no-wan` when off | on for whole network, off for specific targets |
  | Scan listed hosts even if they don't answer ping | `-Pn` for listed single IPs | off |

### How targets are resolved (`discovery/lib/targets.sh`)

1. The rules live in one place, `discovery/lib/targets_util.py`. The panel
   (`panel/targets.py` imports it) validates every line on the server and
   writes `kind<TAB>value<TAB>source` lines to `panel/reports/<scan>-targets.txt`
   (deleted when the scan ends) for `discover.sh --targets FILE`.
   `discover.sh` normalizes the file again with the same code, so a raw
   `ip.txt` works from the command line too.
2. **Hostnames** are resolved with `getent ahostsv4`; unresolved names are
   reported, not dropped silently.
3. **MAC addresses** have no IP until the network tells us. The local range is
   swept (ARP with root, ping sweep without), then MACs are matched against
   the sweep and the kernel neighbour table. A MAC that is not on the local
   network segment can't be found this way; it is reported as "not seen".
4. **IPs and ranges** are swept with nmap (`-iL`).
5. Only the requested hosts go into the report. The neighbour table and
   broadcast discovery (mDNS, SSDP) still add names to those hosts, but never
   add extra hosts.
6. Result per input line: `work/targets.tsv` and a `targets` array in
   `findings.json`: kind, value, source file, resolved IP, status
   (`up`, `no_response`, `unresolved`, `not_seen`).

### Limits and safety

- At most 4096 lines and 65,536 addresses in total per scan.
- Every IP and range must be in private address space (`ALLOWED_PREFIXES`),
  the same rule as the whole-network scan. Public targets are refused.
- Hostnames must be valid DNS names (letters, digits, `-`, `.`; no leading
  `-`), so a line can never be read as an nmap option.
- Uploaded files are read in the browser and only their text lines are sent;
  the file itself is not stored.

### Panel API

| Call | Purpose |
|---|---|
| `POST /api/targets/parse` `{targets:[{line, source}]}` | preview: counts per kind, address total, skipped lines with reasons |
| `POST /api/scan/start` `{scope:"network", target_mode:"network"\|"targets", targets:[...], options:{names, ports:"off"\|"top"\|"all", vuln, wan, pn}}` | validates again; `400` with `errors` when nothing usable or over a limit |

Older clients that send only `scan_type: quick|full` still work (ports off / top).

### Stopping

The panel starts `discover.sh` in its own process group, so **Stop** kills
the group (nmap included). If the panel itself dies, `discover.sh` notices
within 2 s (`ND_PARENT_PID` watcher) and stops the group too.

### Database (migration `005_scan_targets.sql`)

- `scans.options jsonb` - which checklist items were selected.
- `scans.target_spec jsonb` - `{mode: "network"|"targets", counts: {...}, files: [...]}`.
- `scan_targets` - one row per input line: `kind`, `value`, `source`,
  `resolved_ip inet`, `status`.

## Step 2 - credentials (planned)

Secrets are typed per scan and passed to `discover.sh` through an inherited
pipe (never argv, env or disk). "Remember in vault" writes them to the GPG
vault. The database stores only metadata (`credentials`,
`scan_credential_use`), never the secret.

## Steps 3-4 - virtualization (planned)

MAC-prefix tagging (`BC:24:11` Proxmox, `52:54:00` QEMU/KVM, `00:50:56` /
`00:0C:29` / `00:05:69` VMware, `00:15:5D` Hyper-V, `08:00:27` VirtualBox,
`00:16:3E` Xen, `00:1C:42` Parallels), hypervisor ports (8006, 443+902, 5480,
5985/5986), then read-only API inventory per platform. Hypervisors become
`devices` rows with `kind = 'hypervisor'`; VMs go in a per-scan `vms` table.
