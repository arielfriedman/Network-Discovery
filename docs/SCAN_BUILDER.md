# Scan builder: checklist, targets, credentials, virtualization

Status: steps 1 and 2 done (2026-10-13). Each step is logged in `DEVLOG.md`.

| Step | What | Status |
|---|---|---|
| 1 | Checklist of scan parts + targets by IP / CIDR / MAC / hostname, typed or uploaded (`ip.txt`, `mac.txt`, `hostnames.txt`) | done |
| 2 | Credentials per system type, typed per scan, optional "remember in vault" | done |
| 3 | VM tagging by MAC prefix + read-only Proxmox inventory | paused (see DEVLOG 2026-10-13) |
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

## Step 2 - credentials

Status: done (2026-10-13). Code: `discovery/lib/creds.py` (rules, shared with
the panel), `discovery/lib/creds.sh`, `scan_auth.sh` (`*_cards`),
`scan_cloud.sh`, `panel/web/creds.js`, migration `007_credentials.sql`.

### What the user sees

- **Network scan:** checklist item *Log in with credentials*. Each credential
  is a card: type, a name, which hosts it is for (IPs / ranges, blank = any
  host that offers the service), and the fields:

  | Type | Fields |
  |---|---|
  | SSH | user; password, or a pasted private key, or a key file path on this machine |
  | SNMP v2c | community |
  | SNMP v3 | user, security level, auth protocol + password, privacy protocol + password |

  Several cards of the same type are allowed; for each host the first card
  whose host list matches is used.
- **Cloud scan:** one card per selected provider (AWS, Azure, GCP,
  Kubernetes, and the providers added later). Leaving a card empty uses the
  CLI's existing sign-in on this machine, as before.
- **Vault:** *Remember in vault* (per card) + the vault passphrase stores
  the card in the encrypted vault. Saved cards are listed by name (from the
  database, never the secret) and can be ticked for a scan; the passphrase
  unlocks them.

### Where secrets go (and never go)

```
browser --HTTPS? no: 127.0.0.1 only, token-protected POST-->  serve.py (memory)
serve.py --inherited pipe (fd), never argv/env/disk-->  discover.sh
discover.sh -> creds.py ingest -> $SECURE_TMP/creds.json (tmpfs /dev/shm, 0600, deleted on exit)
per tool:  SSH password  -> SSHPASS env of sshpass only
           SSH key       -> 0600 file in $SECURE_TMP
           SNMP          -> snmp.conf in $SECURE_TMP (SNMPCONFPATH), never argv
           AWS           -> AWS_* env of the aws process
           Azure secret  -> 0600 file read by `az ... -p @file`; AZURE_CONFIG_DIR in $SECURE_TMP
           GCP key JSON  -> 0600 file; CLOUDSDK_CONFIG in $SECURE_TMP
           kubeconfig    -> 0600 file; KUBECONFIG points at it
```

- Never in: the database, the activity log, `findings.json`, reports, the
  scan status API, process arguments. Every secret is registered with
  `scrub()` so tool output is redacted before it is written.
- Logins made for a scan are isolated (`AZURE_CONFIG_DIR`, `CLOUDSDK_CONFIG`,
  `KUBECONFIG` in `$SECURE_TMP`) so nothing stays signed in afterwards.
- The vault stays the only place secrets are kept on disk (GPG AES-256).
  A saved card is one vault entry `CRED_<slug>=<base64 JSON>`; the old flat
  keys (`SSH_USER`, `SNMP_COMMUNITY`, ...) keep working for the CLI.

### Behaviour worth knowing

- SSH and SNMP cards have an optional port (default 22 / 161). Hosts to
  try: those the port scan saw with the port open; without port-scan data
  a quick TCP probe of port 22 (SSH) or every live host (SNMP, UDP can't be
  probed without root); hosts named on a card are always tried.
- SSH host keys seen by scans go to `discovery/config/known_hosts`
  (git-ignored), not `~/.ssh/known_hosts`; first contact is trusted
  (`accept-new`), a changed key is reported as an error, not accepted.
- SSH passwords need `sshpass` (now in the installer's tool list); keys with
  a passphrase are not supported (`BatchMode`).
- SNMP v2c with a wrong community gets no answer at all, so it is reported
  as `unreachable`, not `auth_failed`. SNMP v3 reports wrong passwords.
- Cloud cards: leave the card out to use the CLI's own sign-in on this
  machine, as before. With a card, AWS gets `AWS_*` env with empty
  `AWS_CONFIG_FILE` / `AWS_SHARED_CREDENTIALS_FILE` (no `~/.aws` profiles
  mixed in); Azure, GCP and Kubernetes log in inside `$SECURE_TMP`.
- A wrong vault passphrase: warning, scan continues without the saved cards.

### Panel API

| Call | Purpose |
|---|---|
| `POST /api/scan/start` `{..., credentials: {sets: [...], vault: {passphrase, use: [CRED_x]}}}` | validated with `creds.py` rules; 400 with the reason |
| `GET /api/credentials` | saved cards (metadata only) |
| `POST /api/credentials/forget` `{vault_key, passphrase}` | remove from the vault (`vault.sh rm`, passphrase on a pipe) and the database |

### Results

Each login attempt is recorded (`work/cred-use.tsv` -> `findings.json`
`credential_use` -> table `scan_credential_use`): credential name, type,
host, result (`ok`, `auth_failed`, `unreachable`, `error`). Saved cards get
a `credentials` row (name, type, hosts, vault key, last used, last result).

## Steps 3-4 - virtualization (planned)

MAC-prefix tagging (`BC:24:11` Proxmox, `52:54:00` QEMU/KVM, `00:50:56` /
`00:0C:29` / `00:05:69` VMware, `00:15:5D` Hyper-V, `08:00:27` VirtualBox,
`00:16:3E` Xen, `00:1C:42` Parallels), hypervisor ports (8006, 443+902, 5480,
5985/5986), then read-only API inventory per platform. Hypervisors become
`devices` rows with `kind = 'hypervisor'`; VMs go in a per-scan `vms` table.
