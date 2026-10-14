# Development log

Every change to SentinelScan is recorded here: what changed, why, the problems
and errors hit on the way (with cause and fix), and how it was verified.
Newest entries first. Feature-level design lives in the other files in `docs/`.

## How we work (procedure)

1. **Plan** - write or update the design doc for the feature in `docs/` before
   coding when the change is bigger than a fix.
2. **Build** in small steps. Database changes go in a new numbered file in
   `db/migrations/` (never edit an applied migration); `install.sh` and
   `python3 panel/db.py migrate` apply them on existing installs.
3. **Test** - against the lab simulators (`cd panel && python3 -m devices.lab`),
   the scratch Postgres, and, for scans, a real run on the home network
   (172.16.0.0/19, authorised). Record the exact checks and results below.
4. **Document** - add an entry here in the same commit: change, reason,
   issues/errors with cause and fix, verification, anything left unverified.
5. **Commit and push** to GitLab (`git@gitlab.com:fritzizi/network-discovery.git`)
   after each finished piece.

Entry template:

```
## YYYY-MM-DD - title (commit)
**Change:** ...
**Why:** ...
**Issues / errors:** symptom -> cause -> fix
**Verified:** what was run and the result
**Not verified / follow-up:** ...
```

---

## 2026-10-14 - Host profiles (OS, apps, system) and more device types
**Change:**
- `discovery/lib/host_profile.py`: reads nmap XML per host; OS from banners
  (Ubuntu by OpenSSH version, Debian by `+debNN`, Windows by RDP/SMB build,
  `(Ubuntu)` style server headers, IIS) or `/etc/os-release` over SSH, with
  `os_source` / `os_confidence`; apps by title / server / product (~30
  known), other web apps by page title; Docker / Kubernetes / etcd ports;
  `profile_findings` (open Docker API without TLS = high).
- `discovery/lib/http_probe.py` (one GET per HTTP-looking port, title +
  Server header, same-host redirects only) as a deep-scan step.
- SSH collection adds `docker ps -a` with ports, CPU, memory, running
  services, Kubernetes components; `sh`-compatible.
- `device_types.py`: 12 types (router, printer, camera, NAS, TV / streamer,
  console, smart home, Apple, phone, Windows, Linux server, Raspberry Pi)
  using vendor, mDNS, SSDP, ports, apps, OS, names, gateway role, random
  MAC; two medium clues = high; "Linux server" only as a fallback.
- Report: OS source, app chips, expandable system details (dashboard,
  summary.txt, History); stored in `hosts.extra`. Targeted network scans
  default to the top-1000 port scan. Cloud provider label "(add an API
  token below)". `docs/ACTIONS_PLAN.md` records the Actions page idea.
**Why:** user: scanning a Pi showed no OS (it runs Ubuntu 24.04), no
description of the servers on it, nothing about Docker or Kubernetes; and
"add whatever we can scan and identify".
**Issues / errors:**
- The data was there but unused: nmap printed `OpenSSH 9.6p1 Ubuntu
  3ubuntu13.19` and `http-title: Pi-Ai Control Dashboard`, but only nmap's
  root-only OS fingerprint fed the report and web titles were dropped.
- nmap called Uptime Kuma on 3001 "nessus?" and skipped its http scripts ->
  `http_probe.py`; the page title confirmed "Uptime Kuma".
- The user's second Pi scan had the port scan off (default "Off" even for
  one target) -> targeted scans default to top 1000.
- Docker / Kubernetes on the Pis expose no ports, so they are invisible
  without an SSH login; stated in the docs and UI instead of guessed.
- Rule review before use: "switch" (network switches), "envy" (HP laptops),
  bare "wiz" (wizard), "dial" -> removed / narrowed; "Router / gateway" and
  "Router / Wi-Fi" competed for the same box -> one type.
- `2>/dev/null` after a failing `<` redirect still printed the error in
  `sh` -> redirect order fixed.
- Deleted the superseded `~/sentinelscan` folder on the user's request after
  checking every file existed in the repo (only `rootkits.py` differed: the
  old, pre-fix version) and that it held no credentials.
**Verified:**
- Rule tests: 17 cases, including false-positive checks (`core-switch`,
  `hp-envy-laptop`, `wizard` -> no type; HP with Windows ports -> Windows,
  HP with `_ipp` + 9100 -> printer; Samsung + "living room" -> TV, Samsung +
  "Galaxy" -> phone).
- Real targeted scan through the panel (172.16.0.37, .38 and 127.0.0.1 with
  an SSH key card against the test sshd), 25 s: both Pis "Ubuntu 24.04 (from
  SSH)", apps Pi-Ai Control Dashboard :5000 and Uptime Kuma :3001, type
  Raspberry Pi (high); 127.0.0.1 OS "Linux Mint 22.3" from os-release,
  kernel, CPU, memory, uptime, 40 services; all saved in Postgres.
- Whole-network classification of an earlier run: router (high, 3 clues),
  NAS, TV, Raspberry Pi.
**Not verified:** Docker / Kubernetes sections against a host that has
them (none reachable with a login here); Windows build mapping against a
real Windows host.

## 2026-10-14 - Device types: Raspberry Pi; MAC addresses lost on big sweeps
**Change:**
- `discovery/lib/device_types.py`: vendor lookup from the IEEE registry
  (`config/ieee-oui.csv` from the new `discovery/update-vendors.sh`, else
  arp-scan's / nmap's copies) and rule-based device typing with evidence and
  confidence. Raspberry Pi rules: MAC vendor (high), board model over SSH
  (high, gives the model), OS fingerprint / banner (medium), host name (low).
  Locally administered (random) MACs are flagged, not looked up.
- SSH login collection also reads `/proc/device-tree/model`.
- `findings.json`: `device_type`, `device_model`, `device_confidence`,
  `device_evidence` per host, `device_types` counts, a "N Raspberry Pi(s)"
  note. `summary.txt` prints the type. Dashboard: Type column and a
  device-type filter. History: Type column. Migration `008_device_types.sql`.
- `install.sh` fetches the vendor registry; preflight suggests a refresh
  when it is missing or older than 90 days (never downloads during a scan).
**Why:** user asked for an option to scan for and identify Raspberry Pis.
**Issues / errors:**
- *Vendors were missing on every scan without root* (pre-existing): only
  arp-scan (root) supplied vendor names. -> local IEEE lookup for any host
  with a MAC.
- *Most MAC addresses were lost on large sweeps without root*
  (pre-existing, timing-dependent): the /19 sweep left ~500 FAILED entries
  in the kernel neighbour table; its garbage collector (gc_thresh2/3 =
  512/1024 here) then evicts the real entries. One panel scan kept MACs for
  3 of 14 hosts. -> `refresh_neighbours`: one ping per live host right
  before reading the table (ARP happens even if the host drops ping).
  Same scan afterwards: 12 of 14 hosts with MAC and vendor (the two without:
  this PC itself, and one host that didn't answer).
- The vendor files shipped with the OS (April 2024) lack newer Raspberry Pi
  prefixes; the two Pis on the home network (88:A2:9E) were unidentified.
  Confirmed in the official IEEE registry: 88:A2:9E and 2C:CF:67 =
  "Raspberry Pi (Trading) Ltd" -> `update-vendors.sh` instead of a hard-coded
  list.
- Rules tightened before use: "rpi" in banners would match unrelated text;
  "pi-hole" runs on any Linux box -> removed.
**Verified:** rule tests (vendor, model, name, OS -> right type and
confidence; `pi-hole`, `api-server`/`spiderman`, `rpcbind`, Synology -> no
type); vendor lookup for the five Pi prefixes in the OS data and the two new
ones from the IEEE file; full panel scan of 172.16.0.0/19 without root ->
both Pis (.37, .38) identified "high", saved in Postgres with evidence,
note in the report; dashboard screenshot with Type column and filter.
**Not verified:** the SSH board-model path against a real Pi (needs a login
card for one; tested only that a non-Pi gives no model).

## 2026-10-13 - Nightly database backups
**Change:** `panel/db_backup.py`: `run` (pg_dump custom format to
`panel/backups/db/sentinel-YYYYmmdd-HHMMSS.dump`, 0600, folder 0700, written
as `.part` then renamed; prunes to the newest 14 or `backup_keep` in
`settings.local.json`), `list`, `schedule on|off|status` (user crontab,
03:17, tagged line; other cron jobs untouched; removes the crontab instead
of leaving it empty). History page: *Database backups* section (list,
download, *Back up now*, nightly switch, restore command). Panel:
`GET /api/db/backups`, `GET /api/db/backups/<name>/download`,
`POST /api/db/backups/run`, `POST /api/db/backups/schedule`. `install.sh`
schedules it (new `--no-backup`). Activity log: `db.backup`,
`db.backup.schedule`. Postgres roadmap step 8 marked done.
**Why:** user asked to "add the db" - read as the nightly database backup
from the open list (roadmap step 8).
**Decisions:** crontab instead of the systemd timer the roadmap suggested:
works for a normal user without root or `loginctl enable-linger`, and the
panel can switch it. The password reaches pg_dump through a temporary
pgpass file (0600, /dev/shm), never argv. No restore button in the panel:
restoring replaces everything, so it stays a deliberate command.
**Issues / errors:**
- With a wrong password the message was libpq's last line, "password
  retrieved from file /dev/shm/...", hiding the cause -> pick the FATAL /
  error line and mask the temp path.
- Found in the History screenshot (pre-existing): cloud scans were saved
  with the local range (172.16.0.0/19) as their target, because a cloud-only
  run still fills `meta.target` -> saved as "cloud accounts".
**Verified (scratch Postgres 16, pg_dump 16.15):** two backups; `ps` sampled
during the dump - password never in a command line; temp pgpass removed;
wrong password -> clear error, no partial file; restore of a backup into a
new database -> same scans, migrations and append-only trigger (activity
differs by the one `db.backup` row written after the dump); prune to 2
removed the 2 oldest. Schedule tested against a stand-in `crontab` (the real
crontab was not touched): existing job kept, on twice -> one line, off ->
only ours removed, empty -> crontab removed; the exact cron line run under
`env -i` from the repo path with spaces -> backup written, logged. Panel:
run without token 403; run, schedule, list; download byte-identical; path
traversal attempts 404. Screenshot of the History section.
**Not verified:** the real nightly run by cron on this machine (would
change the user's crontab; `install.sh` or the History switch will turn it
on).

## 2026-10-13 - Scan builder step 3 paused
**What happened:** while writing the first file of step 3 (VM tagging by
MAC prefix, hypervisor detection, Proxmox inventory), the response was
stopped by a safety check. The partial file
(`discovery/lib/virt_api.py`, 3.2 KB, never committed) was deleted. Before
that, the Proxmox API details had been checked against the official docs
(token header `PVEAPIToken=USER@REALM!TOKENID=UUID`; `/cluster/resources?type=vm`
fields; `/nodes/{node}/lxc/{vmid}/interfaces`; privilege-separated tokens
need their own PVEAuditor ACL).
**Status:** step 3 is not being continued in this session.

## 2026-10-13 - Ten more cloud providers
**Change:** cloud scan now also covers DigitalOcean, Akamai/Linode, Hetzner
Cloud, Vultr, Scaleway, Cloudflare, IBM Cloud (VPC), OVHcloud, Alibaba Cloud
and Oracle Cloud through their official REST APIs:
`discovery/lib/cloud_api.py` (standard library; Oracle signing uses
python3-cryptography), wired in `scan_cloud.sh` (`cloud_api`), counted in
`build_json.py` from `raw/cloud/api-*.json`. Credential card types added in
`creds.py` and `panel/web/creds.js` (with a least-privilege hint per
provider); the provider list on the Scan page lists all 14; the panel only
accepts known provider names for `CLOUD_PROVIDERS`. Research reference
`docs/CLOUD_PROVIDERS.md` (with implementation notes and open [verify]
items). Test kit: `discovery/tests/cloud_sim.py` +
`discovery/tests/test_cloud_api.py`.
**Why:** user asked to add all the providers to the cloud scan.
**Decisions:**
- REST instead of 10 more CLIs: nothing extra to install, and every request
  is a read-only GET that we control. AWS / Azure / GCP / Kubernetes keep
  their CLIs (SigV4 / MSAL / gcloud auth are better left to the vendors).
- These providers need a card (no "existing sign-in" to fall back on).
- Vultr has no read-only API keys - the card says so and suggests the IP
  allowlist.
- Pagination links are followed only on the original host; 200-page cap.
**Issues / errors:**
- IBM IAM returns HTTP 400 (`BXNIM0415E`) for a wrong API key; the collector
  first reported that as `unreachable`. Caught by the simulator test, fixed.
- Card type list reset to the first entry after every *Add credential*
  (found when the scripted screenshot added two AWS cards instead of OVH and
  Vultr) -> the page remembers the last type.
- API provider cards said "leave this card out to use the CLI's own
  sign-in", which only applies to the four CLI providers -> hint fixed.
- OVH endpoint (a select with a default) was flagged "missing" until
  touched -> required-field check merges defaults (same class of bug as the
  SSH / SNMP field visibility in step 2).
- Cloud tile text still said "AWS, Azure, GCP and Kubernetes. Needs a cloud
  CLI" -> updated.
**Verified:**
- `test_cloud_api.py`: 20/20 (each provider with valid credentials -> all
  resource lists complete across pages, including IBM over 2 regions,
  Scaleway across zones, OCI over root + 1 compartment; and with wrong
  credentials -> `auth_failed`).
- `discover.sh --cloud-only` with DigitalOcean + Cloudflare (valid) and
  Hetzner (wrong token) cards against the simulator: counts in the report,
  Hetzner flagged as rejected, no token in summary / dashboard / findings.
- Through the panel API: SSH card in a cloud scan -> 400; Linode + Scaleway
  (valid) and IBM (wrong key) -> scan complete, logins `ok`/`ok`/
  `auth_failed`, cloud counts saved in Postgres.
- Screenshots of the cloud card form (Hetzner, OVHcloud, Vultr).
**Not verified / follow-up:** no real account for any of the ten providers
was used. The simulator is built from our reading of the docs, so it can't
catch a misreading; the [verify] items in `docs/CLOUD_PROVIDERS.md` (Vultr
endpoints, Hetzner DNS path, OCI DNS, Alibaba policy names, IBM role
pairing) need a real account each.

## 2026-10-13 - Scan builder step 2: credentials
**Change:**
- Scan page: credential cards - network scan (checklist item *Log in with
  credentials*): SSH (password / pasted key / key file, port) and SNMP v2c /
  v3 (port), each for a host list or any host; cloud scan: AWS, Azure, GCP,
  Kubernetes. *Remember in vault* per card, saved cards listed by name with
  *use* / *forget*, vault passphrase field. The page wipes secrets after the
  scan starts. `panel/web/creds.js`.
- Transport: panel -> `discover.sh` over an inherited pipe (`ND_CREDS_FD`,
  `pass_fds`), written from a thread; `creds.py ingest` stores
  `$SECURE_TMP/creds.json` (tmpfs, 0600). `creds.py` holds the validation
  rules and the panel imports them (same pattern as `targets_util.py`).
- `scan_auth.sh`: `auth_ssh_cards` / `auth_snmp_cards` pick the first card
  whose hosts match, record every attempt (`work/cred-use.tsv` ->
  `findings.json` `credential_use` -> table `scan_credential_use`).
- `scan_cloud.sh`: cards for AWS / Azure / GCP / Kubernetes with isolated
  logins (`AZURE_CONFIG_DIR`, `CLOUDSDK_CONFIG`, `KUBECONFIG`, empty AWS
  config files) inside `$SECURE_TMP`; Azure secret via `--password @file`.
- Vault: `vault_store_entries` (non-interactive save, `@@vault-saved` lines
  for the panel), `vault_unlock` uses a supplied passphrase once,
  `vault.sh` accepts the passphrase on `ND_VAULT_PASS_FD`.
- Migration `007_credentials.sql` (`credentials` metadata, never secrets;
  `scan_credential_use`). History detail shows *Listed targets* (step 1) and
  *Logins*. `GET /api/credentials`, `POST /api/credentials/forget`.
- `sshpass` added to the tool list (installer installs it).
- Cloud provider research saved as `docs/CLOUD_PROVIDERS.md` (for the next
  task: more providers).
**Why:** user asked for an option to enter their own passwords per system;
design agreed: per scan, optional "remember in vault", DB metadata only.
**Issues / errors:**
- *`scrub()` leaked every secret into `sed`'s argv* (pre-existing): it built
  `sed -e 's|<secret>|...|'` arguments, readable by any local user in
  `/proc/*/cmdline` while sed ran. Now a sed script file in `$SECURE_TMP`
  (`sed -f`, deleted after); `|` and `&` in secrets are now escaped too.
- *Prompts could hang dashboard scans* (pre-existing, made worse by keeping
  the panel's terminal for sudo): with `--auth`, `vault_get` -> `ask_secret`
  reads `/dev/tty`, which from a background process group stops the scan
  (SIGTTIN). `ask_*` now return the default / empty when
  `ND_NONINTERACTIVE=1`, and dashboard scans never enter the old prompt flow.
- *Azure secret on the command line* (pre-existing): `az login -p "$secret"`.
  With a card it is now `--password @file`. The old prompt flow (CLI use
  without a card) still passes it as an argument - left for the CLI path,
  noted here.
- *`az login` / `gcloud auth` persisted logins in the user's profile*
  (pre-existing) -> isolated config dirs when a card is used.
- SSH / SNMP were hard-wired to ports 22 / 161; there is no sshd / snmpd on
  this machine and unprivileged test servers can't bind low ports -> added
  an optional port per card (also useful for real devices).
- Fields that depend on a select (SSH password, SNMP v3 privacy fields)
  didn't show until the select was touched: visibility used the stored value
  only -> merge with defaults. Found in the screenshot.
- `snmpwalk` printed "Cannot find module (SNMPv2-MIB)" noise into reports ->
  `-m ""` (numeric OIDs, no MIB loading).
- A wrong passphrase on *forget* surfaced as "vault locked and no passphrase
  given" -> "wrong vault passphrase".
**Verified:**
- Test servers from Ubuntu packages, unprivileged in the scratch dir:
  `sshd` on 127.0.0.1:2222 (key + password auth), `snmpd` on 127.0.0.1:1161
  (v2c community + v3 user, SHA/AES); `sshpass` likewise.
- `discover.sh` with cards on fd 3: SSH key login ok, SNMP v3 ok; wrong SSH
  password -> `auth_failed`, wrong v3 password -> `auth_failed`, wrong v2c
  community -> `unreachable`; rejected logins appear in *Worth a look*.
- While scanning, `ps -eo args` sampled every 0.5 s: no secret in any
  command line. No secret in the run folder; `$SECURE_TMP` removed at exit.
  `scrub()` tested with `pa$$|w.rd&[x]*^`, `a/b\c`.
- Vault (separate test vault file, not the real one): save -> GPG AES-256
  file 0600; reuse with passphrase only -> login ok; wrong passphrase ->
  warning, scan continues.
- Through the panel API: cloud card in a network scan 400; save without
  passphrase 400; full scan -> complete, both logins `ok`, card saved
  (`credentials` row, `last_result ok`), `pg_dump` of the database and the
  status API contain no secret; forget with wrong passphrase 400, then
  forget -> removed from vault and database.
- Cloud cards with stand-in `aws` / `az` / `gcloud` / `kubectl` scripts that
  log what they receive: correct env, `--password @file` with a 0600 file,
  isolated config dirs, kubeconfig 0600, no secret in any argv, nothing
  written to `~/.azure` or `~/.config/gcloud`; wrong keys -> `auth_failed`.
- Screenshots: Scan page with SSH + SNMP v3 cards and the missing-field
  list; History detail with listed targets and logins.
**Not verified / follow-up:** real cloud CLIs (none installed here) - in
particular that `az login --password @file` reads the file (Azure CLI's
documented `@file` convention, not confirmed for this flag); SSH / SNMP
against real network devices; SNMP v3 with SHA-256/512 or AES-256 (needs
agent support).

## 2026-10-13 - Clear history
**Change:** History page: *Clear history…* (all saved scans, or older than
30 / 90 / 365 days, optionally with report files) and *Delete this scan* on
the scan detail view. `POST /api/history/delete {refs | older_than_days | all,
files}`; `db.delete_scans()` (findings, hosts, services, targets go with the
scan through `ON DELETE CASCADE`). Migration `006_scan_interrupted.sql` adds
status `interrupted`; the panel marks scans left `running` by an earlier
panel as `interrupted` at startup.
**Why:** user asked for an option to clear history.
**Decisions:**
- The activity log is not cleared. It is append-only by a database trigger
  (001) because it is the audit trail; each deletion is itself logged
  (`history.delete` with count and scan refs). If a way to prune the log is
  wanted later, it should be a separate, deliberate retention setting.
- Running scans are never deleted.
- Report files are only removed inside the app's own folders
  (`panel/reports/<ref>.*`, a run folder directly under
  `discovery/reports/`); a `report_path` pointing anywhere else is ignored.
**Issues / errors:** scans whose panel had been killed during testing were
stuck as `running` forever, so "clear all" could never remove them -> the
startup `interrupted` marking above.
**Verified (scratch Postgres, panel API):** no token 403; empty request 400;
"older than 30 days" deleted the 3 aged fixtures and their report file /
run folder (3 removed) while a fixture report outside the app folders was
kept; a fresh scan and the running scan were kept; delete-one and delete-all
worked; three `history.delete` entries in the activity log;
`mark_interrupted()` fixed 4 stale rows. Screenshot of the History page with
the clear panel open.

## 2026-10-13 - Scan builder step 1: checklist + target lists
**Change:**
- Scan page, *The network*: *Whole local network* or *Specific targets*
  (typed, or uploaded `.txt` / `.csv` files; IPs, ranges, MAC addresses,
  hostnames, auto-detected), live preview of counts and skipped lines, and a
  checklist: names, ports (off / top 1000 / all), vulnerability scripts,
  gateway and internet path, scan listed hosts that ignore ping.
- `discover.sh --targets FILE` and `--pn`; new `discovery/lib/targets_util.py`
  (one set of parsing rules for the CLI and the panel; `panel/targets.py`
  imports it), `stage_discover_targets` in `scan_local.sh`, a *Listed
  targets* section in `summary.txt`, `targets` + `meta.mode` in
  `findings.json`.
- Panel: `POST /api/targets/parse`, `start_scan` validates server-side
  (400 with reasons), request body capped at 2 MB, raw target list kept out
  of the activity log.
- Migration `005_scan_targets.sql`: `scans.options`, `scans.target_spec`,
  `scan_targets` table. The panel now applies pending migrations at startup,
  so an update doesn't silently stop saving.
- Design: `docs/SCAN_BUILDER.md`. User docs: README, discovery/README.
**Why:** user asked for a checklist of what to scan and scanning by IP / MAC /
hostname with file upload (`ip.txt`, `mac.txt`, `hostnames.txt`).
**Issues / errors:**
- *Deep scan never ran (pre-existing, since the import in 1035518).*
  `timeout "$HOST_SCAN_TIMEOUT" as_root nmap ...` - `as_root` is a bash
  function and `timeout` can only exec programs: "failed to run command
  'as_root': No such file or directory" (127), hidden by `>/dev/null 2>&1`.
  Every "Full" network scan reported "deep scan complete (0 host reports)".
  Fix: `as_root timeout ... nmap`; nmap's stderr now kept in
  `raw/hosts/<ip>.err` when non-empty.
- *Scan survived the panel being killed.* The scan runs in its own process
  group, so nothing stopped it. First fix (PR_SET_PDEATHSIG via ctypes) did
  not work: bash defers its TERM trap until the foreground command (a 76 s
  nmap sweep) ends - measured 152 s before the orphan exited. Second fix: a
  watcher subshell that signals the whole group when `ND_PARENT_PID` is gone.
- *That watcher hung every scan with a port scan.* It was a background job
  of `discover.sh`, and `stage_deep` ends with a plain `wait`, which waited
  for the watcher forever (seen as "waiting for the last 2 scan job(s)" for
  10+ minutes). Fix: double fork so it is not our child; it also exits by
  itself within 2 s of the script ending. Verified: panel `kill -9` -> whole
  scan gone within 3 s.
- Broadcast discovery (mDNS / SSDP / NetBIOS) and the neighbour table would
  have added hosts that were not listed; `targets_util.py finish` and
  `build_json.py` now keep only the listed hosts (a Proxmox VM at .35 that
  answered mDNS was correctly left out).
- CSV header lines (`Name`, `IP Address`) were accepted as hostnames ->
  skipped as "looks like a column header".
- A range like `10.0.0.0/7` starts with an allowed prefix but covers public
  space -> both the first and last address must be private.
- `inet[]::text` prints `/32` -> `host()` per element (same trap as before).
- Checklist labels inherited the small uppercase `.field label` style ->
  `.field label.chk` override.
- Testing mistakes, not product bugs: `pgrep -f` / `pkill -f` matched my own
  shell's command line (false "2 processes left", and one test shell killed
  itself); a test request went to an older test server that then exited on
  its timer, leaving an orphan (which led to finding the bug above).
**Verified:**
- Parser: public IPs and ranges, `-oX`, `999.1.1.1`, IPv6, 70-char junk,
  headers refused with reasons; MAC formats `aa:..`, `AA-..`, `aabb.ccdd.eeff`.
- CLI on the home network, list of IP / dead IP / /28 / `localhost` /
  unresolvable name / real MAC / fake MAC / 8.8.8.8: 57 s, every line got
  the right status, only listed hosts in the report.
- Panel API: no token 403; only-public list 400; `10.0.0.0/8` 400 (limit);
  targeted scan (IP + MAC + dead IP) with top-1000 ports through the panel ->
  complete in 2m08s, deep scan 2 host reports, gateway 53/80, pve
  22/111/3128/8008, saved to Postgres with `scan_targets` rows and options,
  temp target file removed.
- Note for step 3: Proxmox's web UI port 8006 is not in nmap's top 1000, so
  hypervisor detection must probe it explicitly.
- Postgres: migration 005 applied; saving the same scan twice doesn't
  duplicate target rows.
- Scan page screenshot (Firefox headless): preview counts and skipped lines.
**Not verified / follow-up:** MAC lookup with root (arp-scan path) - needs
sudo; uploading a real file through the browser file picker (logic tested
through the same code path with typed lines).

## 2026-10-13 - Network scan used no sudo while the page said "admin" (d26b7c7)
**Change:** `panel/serve.py` starts `discover.sh` with `process_group=0` (own
process group, same session) instead of `start_new_session=True`, and sets
`ND_NONINTERACTIVE=1`. `discovery/lib/common.sh`: `init_sudo` never prompts when
non-interactive; `as_root` uses `sudo -n`. Start page messages rewritten.
**Why:** user reported the network scan said "no admin rights for arp" while the
local PC scan said it had admin rights.
**Issues / errors:**
- sudo tickets are per terminal session (`timestamp_type=tty`). The panel's
  `sudo -n true` check passed in its terminal, but `discover.sh` ran in a new
  session with no terminal, so the ticket never applied -> ARP sweep and OS
  detection always skipped. Fix: keep the child in the panel's session.
- Keeping the terminal created a hang risk: `sudo -v` (password prompt) from a
  background process group would get SIGTTIN and stop forever. Fix: no prompts
  when `ND_NONINTERACTIVE=1`; `sudo -n` everywhere so an expired ticket fails
  one tool instead of hanging.
- The host scan never used sudo at all; the "Admin rights available" tick on
  its page was misleading. It now says whether the panel runs as root.
**Verified:** scan started/stopped under a pseudo-terminal (`script -qec`):
no hang, Stop leaves no nmap processes.
**Not verified:** the sudo-unlocked path (needs the user's password). User to
check: `sudo -v && ./start.sh`, log should show "arp-scan layer-2 sweep".

## 2026-10-13 - Network scan appeared stuck (49e06fd)
**Change:** unprivileged nmap ping sweep tuned (`--max-retries 1
--min-parallelism 100 --initial-rtt-timeout 200ms --max-rtt-timeout 400ms`);
NetBIOS (`nbtscan`) queries only discovered hosts (`-f hosts.list`, 120 s
timeout); dashboard shows "(running Xm Ys)" for steps over 10 s.
**Why:** user reported "network scan gets stuck".
**Issues / errors:**
- Run 20261013-133248: ping sweep of 172.16.0.0/19 (8192 addresses) without
  root took 637 s. Without root nmap uses TCP connect probes and each empty
  address waits out ARP resolution. Progress bar does not move inside one step,
  so it looked frozen.
- After that `nbtscan` started on the whole /19 instead of the 13 live hosts.
- `--stats-every` printed nothing for the unprivileged ping scan, so progress
  inside nmap can't be parsed; replaced with an elapsed timer.
**Verified:** tuned sweep 54 s, same 13 hosts. Full quick scan
(`--yes --no-install --no-cloud --quick`, no sudo): 2m51s, sweep 76 s,
NetBIOS 1 s, report built.

## 2026-10-12 and earlier - repo, Postgres, rootkit allowlist, device wizard
(Reconstructed from the session notes; commits f6a23db .. 88adbba.)
- **Repo:** panel + discovery tool merged into one GitLab repo with
  `install.sh` (also curl-installable) and `start.sh`.
  Issues: `ND_DIR` was a hard-coded home path -> made relative to the repo;
  `reports/latest` symlink was absolute -> relative (`summarize.sh`).
- **Postgres:** migrations 001-004, `panel/db.py` (fails soft, retries every
  30 s), History page, append-only activity log.
  Issues: `ip::text` showed `/32` -> `host()`; previous-scan diff matched the
  wrong scan because `localhost` vs `127.0.0.1` -> `_norm_target`;
  `install.sh`: `psql -v` variables don't work with `-c` and root needs
  `runuser` -> SQL piped on stdin with a runuser/sudo branch.
- **Rootkit check:** false CRITICAL because `nc` matched inside `timesyncd`
  -> whole-word match on `Exec*` lines only, skip package-owned vendor alias
  symlinks; `panel/rootkit_allowlist.txt` added. A comment swallowed the rest
  of the `KNOWN_MODULES` line during an edit -> fixed.
- **Device wizard:** FortiGate, Cisco, Palo Alto, Check Point drivers with
  simulators. Issues: FortiGate `fill()` ran outside `try` -> moved inside;
  leftover test devices broke uniqueness -> cleaned; lab plugins invisible
  under `python3 -m` -> `__main__` imports `devices.lab`; multi-select
  interface validation fixed. Tests: Cisco 101/101, Palo Alto 91/91,
  Check Point 81/81, FortiGate end-to-end incl. CSRF/rebinding/pin mismatch.
  Not verified on real hardware: see `docs/DEVICE_MODELS.md` [verify] items.
