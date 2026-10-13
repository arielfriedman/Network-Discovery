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
