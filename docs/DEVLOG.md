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

## 2026-10-18 - Actions follow the terminal's machine (ssh typed in a terminal)
**Change:** (1) Clicking a terminal tab on the Actions page sets "Run on" to that tab's machine.
(2) `panel/terminal.py` detects `ssh` running in the foreground of a terminal on this machine
(`tcgetpgrp` on the pty, the `ssh` process in that group, `ssh -G` with its arguments for the real
host/user/port incl. `~/.ssh/config` aliases) and reports it with each poll and in `/api/term/list`.
(3) The tab name shows `→ user@host`; a yellow bar says the actions still run on this machine and
offers "Connect actions to user@host…" (Connect dialog pre-filled) or "Run actions there" when that
machine is already connected. (4) Clicking an action while the active terminal is in such an ssh
session asks: connect actions there / type into that terminal / run on this machine / cancel.
Docs: `docs/ACTIONS_PLAN.md` (new section), `docs/USER_GUIDE.md` (Actions).
**Why (user report):** "when opening a new terminal in actions tab, when connecting to other devices
with ssh the actions still only run on the local machine and not on the connected ssh session device".
**Cause:** actions always run where the "Run on" dropdown points. A terminal tab never changed it,
and an `ssh` typed inside a local terminal is invisible to the panel - the actions had no way to
know about that session.
**Issues / errors:** first Connect pre-fill switched the login method to "Key file" whenever a key
file existed -> wrong when the user logged in with a password -> the key path is filled in, the
method stays Password. Test-only: no sshd on this machine and the outage had wiped the old test kit
-> rebuilt: scratch PostgreSQL (port 55432) and a small paramiko SSH server (port 2222, marks its
shells with `SIM_SSH=1`); test panel on 8790.
**Verified:** API: at the prompt `ssh` is null; after typing `ssh -p 2222 tester@127.0.0.1` it is
`tester@127.0.0.1:2222` (at the password prompt and after login); after `exit` null again; an alias
from an ssh config file (`ssh -F cfg simalias`) resolved to `aliasuser@127.0.0.1:2222`. Headless Brave,
scripted, 20/20 checks: tab name and bar appear; action click asks; "Type into terminal" runs in the
ssh session (`WHERE=1`); "Run on this machine" runs locally (`WHERE=local`); Connect dialog pre-filled
(127.0.0.1 / 2222 / tester / Password); after connecting, Run on = that machine, bar hidden, action runs
there (`WHERE=1`); tab clicks switch Run on both ways; bar button switches to the open connection;
after `exit` tab name and bar back to normal; page reload keeps the state; no JavaScript errors.
Screenshots checked.
**Not verified / follow-up:** by hand in the user's browser against a real device; panel running as
root (uses the user's `~/.ssh/config` for `ssh -G`); `ssh` started from a terminal on an SSH-connected
machine (a hop further) is not detected - only terminals on this machine.

## 2026-10-17 - Copy on GitHub
**Change:** the repo is also on GitHub: https://github.com/arielfriedman/Network-Discovery (public).
Remote `github` added, and `origin` has two push URLs (GitLab, then GitHub), so one `git push`
updates both; fetch still comes from GitLab, which stays the main copy. README links both.
**Why:** the user wants a GitHub link to send to people.
**Issues / errors:** none. The user's existing SSH key already logs in to GitHub, so no token was
needed; the empty repo was created by the user on github.com (no `gh` CLI here).
**Verified:** first push of all 39 commits; GitHub and GitLab `main` at the same commit; a logged-out
clone from GitHub shows only the no-reply email. This commit was pushed with one `git push` and
checked on both.
**Not verified / follow-up:** another checkout (or worktree created elsewhere) doesn't get the second
push URL automatically: `git remote set-url --add --push origin git@github.com:arielfriedman/Network-Discovery.git`
(after adding the GitLab one the same way).

## 2026-10-16 - History rewritten: commit email -> GitLab no-reply (force-push)
**Change:** all 38 commits now carry `35605392-fritzizi@users.noreply.gitlab.com` as author and
committer instead of the personal Gmail address; file contents unchanged (same tree). Force-pushed
to GitLab with the user's approval; the repo's `user.email` is set to the no-reply address, so
new commits use it too. Commit hashes changed (e.g. the user guide is now 6a8401c, was fb50945).
**Why:** the repo is public; every commit's email is visible to anyone who clones it.
**How:** backup bundle of the old history first (`~/network-discovery-before-rewrite-2026-10-16.bundle`);
whole history scanned for tokens, keys, passwords, the email and real MACs (only test placeholders
found; private 172.16.x.x addresses in DEVLOG left in, not reachable from the internet);
`git filter-branch --env-filter` in a separate clone, checked the tree matched, then
`git push --force-with-lease`.
**Issues / errors:** rewriting in the working checkout was blocked by the auto-mode safety check
-> did it in a scratch clone instead, pushed only after the user said "approved, push it". The
repo was made public before the push, so the old emails were public for a short while.
**Verified:** a fresh logged-out clone shows only the no-reply address on all 38 commits.
**Not verified / follow-up:** GitLab still serves old commits by their hash (e.g. /-/commit/6c79f13
answers 200) until its housekeeping prunes unreachable objects (Settings -> General -> Advanced ->
Housekeeping). Anyone who cloned before the push still has the old history.

## 2026-10-16 - User guide (this commit)
**Change:** new `docs/USER_GUIDE.md`, linked at the top of the README: ground rules, install and
open, the pages, a first scan step by step, reading results and the drawing, credential cards and
the vault, where every file is kept, normal vs root mode, common problems (port 8765 in use, page
not opening, scan looks stuck, SSH login errors, no admin rights, empty History, no PDF button,
rootkit false alarm), updating and removing. README: dropped the note that the curl line needs the
repo to be public (it is public now).
**Why:** the user asked for a basic manual so new users understand what everything is and where it
is; the existing docs assume you already know the project.
**Issues / errors:** first draft said the menu has five pages -> the drawing is a button, not a menu
item (nav in `panel/web/common.js` has four) -> corrected.
**Verified:** every button label, path, command and message in the guide checked against the code
(`panel/web/*.html`, `common.js`, `creds.js`, `serve.py` port message, `install.sh` DB names and
options, `discovery/README.md`). Anonymous `git clone https://gitlab.com/fritzizi/network-discovery.git`
works and the raw install.sh URL answers 200 (repo public).
**Not verified / follow-up:** the "Remove" steps were not run. The commit-email history rewrite is
prepared but not pushed yet (needs the user's approval for a force-push).

## 2026-10-16 - Example network drawing in README and docs (this commit)
**Change:** README and `docs/DIAGRAMS.md` show a picture of the Network drawing feature
(`docs/images/network-drawing.png`, plus the SVG preview). It is made from made-up example data
(`docs/examples/example-findings.json`, 192.168.1.0/24, 10 hosts, a Proxmox host with 2 running and
1 stopped guest), and the matching `docs/examples/example-network.drawio` is included. DIAGRAMS.md has
the command to make them again. `diagrams.py`: the title skips empty parts.
**Why:** the user asked to put the drawing feature in the repo with an image. The feature itself was
already committed (7b1ceaa, cce326a); the README had no picture of it. Example data instead of a real
scan, so no real host names, IPs or MAC addresses go into the repo (it may go public).
**Issues / errors:** the title read "SentinelScan · 192.168.1.0/24 · · 10 hosts" -> a scan without a
`started` time left an empty part between the dots -> empty parts are now left out.
**Verified:** generated with draw.io 32.4.1 CLI (scratchpad, not installed): PNG 3781x1211, looked at it
- internet, gateway, LAN line, hypervisor holding its VMs (stopped one dashed), groups by type, scanner
bold. Title now "SentinelScan · 192.168.1.0/24 · 10 hosts"; a real scan's title still includes the time
("... · 2026-10-15 07:46 · 16 hosts"). `py_compile` ok.
**Not verified / follow-up:** how GitLab renders the README image (repo is private; check in the browser).

## 2026-10-16 - Drawings checked in the real draw.io; installer --drawio
**Change:** `diagrams.export`: fixed the CLI arguments (`-s 2` was inserted between `-b` and its value)
and PDFs now use `-a --crop` (every page, each cropped to its drawing). Lines from the groups to the LAN
line carry draw.io exit/entry points, so draw.io routes them where the SVG preview draws them.
`install.sh --drawio`: latest official draw.io .deb from github.com/jgraph/drawio-desktop releases,
SHA-256 checked against the release's `Files-SHA256-Hashes.txt`, installed with xvfb; amd64/arm64.
**Why:** the open "not verified" items of the drawing feature (real draw.io, CLI PNG/PDF), and the
PDF button needs the app.
**Issues / errors:** power outage: /tmp was wiped (scratchpad test files and the scratch PostgreSQL are
gone); the repo was clean and pushed. Real draw.io export failed with "input file/directory not found:
10" -> argument order bug above. In draw.io all group lines met the LAN line at one point (draw.io ignores
waypoints when it routes to a cell's centre) -> pinned exit/entry points. The first PDF was split over 4 A4
sheets -> `--crop`.
**Verified:** draw.io desktop 32.4.1, official .deb, SHA-256 matched the published list, unpacked into the
scratchpad (not installed; test wrapper adds `--no-sandbox` because the unpacked chrome-sandbox isn't
setuid). Sample scan (16 hosts + 3 VMs): PNG 3093x1907 in 3.1 s, ends with a complete IEND chunk; PDF 2 pages
(Network, Virtual machines), cropped. Looked at both: boxes, groups, labels and straight lines to the LAN
line as in the preview. Installer block with apt replaced by echo: real download + hash match -> "installed";
forced hash mismatch -> "did not match ... not installed"; `--dry-run --drawio` prints the plan.
**Not verified / follow-up:** a real `sudo ./install.sh --drawio` (apt install of the .deb), export from the
panel running as a systemd service (xvfb path).

## 2026-10-16 - Network drawings of a scan (draw.io)
**Change:** new `panel/diagrams.py`: from a network scan's findings.json, one layout written as
a `.drawio` file (page "Network": internet, gateway, LAN line, hosts grouped by device type,
hypervisors holding their VMs; page "Virtual machines" with vCPU/RAM/disks when listed) and as SVG
(preview). PNG/PDF through the draw.io desktop CLI when installed (xvfb-run without a display,
`--no-sandbox` as root, PNG end-chunk repair); without it the PNG is drawn from the SVG in the
browser. "Open in diagrams.net" link with the drawing in the #fragment (deflate + base64 of the
encodeURIComponent'd XML). `serve.py`: `/api/diagram/<scan>/drawio|svg|png|pdf|link` and
`/api/diagram/tools`; the scan's findings.json comes from the live scan or the saved scan's
`report_path`, only inside discovery/reports; downloads logged as `scan.diagram`. UI: "Network
drawing" button on the Scan page when a network scan finishes and on saved network scans in
History, opening a dialog (`openDiagram` in common.js). Doc: `docs/DIAGRAMS.md`.
**Why:** the user wants drawings of a finished scan, "with drawio-skill if possible else something
similar". The drawio-skill is instructions for an AI assistant (write draw.io XML, export with the
draw.io CLI); it can't run inside the dashboard for its users, so the panel produces the same
open format itself and uses the same CLI when present.
**Issues / errors:** the gateway showed "_gateway" (systemd-resolved's alias for the default
gateway, not a real name) -> ignored as a name. Host names, vendors and apps come from the network
-> labels are plain text (html=0) and XML-escaped in both outputs.
**Verified:** rendered your 16-host scan of 2026-10-15 plus 3 sample VMs on 172.16.0.30 to SVG and
looked at a screenshot (groups, LAN line, gateway, hypervisor with a running VM, a container and a
stopped (dashed) VM). drawio output: XML parses, ids unique, every parent/source/target exists, edges
have geometry, 2 pages. Hostile host name `<script>...<svg onload=...>` stays text: no script
element or on* attribute in either output. Test panel (port 8792, scratch DB, saved test scan): drawio
200 (byte-identical to the generator), svg 200, link 200, png/pdf 409 "draw.io desktop app is not
installed", path-like and unknown ids 404. Headless Brave click-through of History: button shown,
dialog opens, preview loads (1604x982), diagrams.net link built, PNG download offered, dialog
closes. The link decodes back to the identical XML. Test scan, report folder and test page removed.
**Not verified / follow-up:** opening the .drawio in the real draw.io app or diagrams.net (no draw.io
desktop here, and I did not send scan data to the diagrams.net site), the CLI PNG/PDF path, a live
scan's button on the Scan page (same function as History), very large networks (100+ hosts).

## 2026-10-16 - Installer: dashboard as a service, checked address at the end
**Change:** `install.sh` step 5 writes `/etc/systemd/system/sentinelscan.service`, enables and
(re)starts it, waits up to 15 s for http://127.0.0.1:8765 to answer, and ends with "SentinelScan
is running. Open: http://127.0.0.1:8765" (or the journal's last lines if it doesn't answer).
Runs as the installing user by default; `--root` runs it as root with SUDO_UID/SUDO_GID/SUDO_USER
set, so the panel hands files back and the Actions terminal stays the user's shell (2026-10-16
entry below). `--no-service` keeps the old "start it yourself" ending; no systemd (WSL, containers)
falls back to that too. `curl` added to the packages. `serve.py`: `SENTINEL_NO_BROWSER=1` (set by
the unit) doesn't open a browser; the port-in-use message mentions the service when it exists.
**Why:** the user wants: get it with curl, dependencies installed automatically, and at the end a
local address that works.
**Issues / errors:** the repository is private: the raw install.sh URL answers 302 to
`/users/sign_in`, so `curl | bash` can't work for others until the repo is public (which waits on
the planned history rewrite). My first edit attempt nested heredocs in one shell command: the
outer heredoc ended at an inner `EOF`, and the rest ran as shell commands -> `systemctl
daemon-reload/enable/restart sentinelscan` as the user, which failed (polkit "Connection timed
out"); no unit was written and no file changed (checked). Redone from a patch script.
**Verified:** generated units (folder name with spaces; user mode and --root) pass
`systemd-analyze verify`. The panel started by systemd (`systemd-run --user`, spare port 8791,
SENTINEL_NO_BROWSER=1) answered after ~1 s, no browser opened. curl path: `cat install.sh |
bash -s -- --dry-run` with SENTINEL_REPO = a local copy -> clone step; the cloned installer's
dry run goes through packages, PostgreSQL, vendor list, service, done.
**Not verified / follow-up:** a real install with sudo/apt and the real system service (needs the
user's password), a fresh machine, the public curl URL (repo private).

## 2026-10-16 - Fix: sudo ./start.sh, Stop leaving nmap running, SSH password logins without sshpass
**Change:** (1) `serve.py` start: if port 8765 is taken it says so (with the pid from `ss`) and
exits, instead of a Python traceback. Run as root: prints "running as root", doesn't open a browser
as root, hands root-owned files under panel/, discovery/reports and discovery/config back to
SUDO_UID after each scan and on exit (`_give_back`). The Actions terminal drops to the sudo user's
own shell (`terminal.py`). `discover.sh` run with sudo does the same for its run folder,
`reports/latest` and config (`give_back_files` in cleanup). (2) Stop: `_kill_group` also signals
every process below the scan (read from /proc), and all `timeout` calls in the scan scripts use
`--foreground`. (3) `discovery/lib/ssh_pass.py` (paramiko): password SSH logins for credential
cards when sshpass is missing. (4) The "no admin rights" note on the Scan page says how to get them
(`sudo ./start.sh`) and that SSH logins don't need it.
**Why:** the user ran `sudo ./start.sh` but scans still said "sudo not authorised". A scan
with a root SSH card for the Proxmox host also showed no root/login use.
**Issues / errors:** sudo start had no effect -> the old panel (user fritz, 20 h old) still held
port 8765, so the new one crashed with `OSError: [Errno 98] Address already in use` and the browser
kept talking to the old, non-root one -> clear message. Stopped scans left nmap running
(an orphan found 5 min after Stop, and again after the panel exited) -> GNU `timeout` puts its
command in its own process group, so killing discover.sh's group missed it -> `--foreground`
and a /proc tree kill. The SSH card wasn't used -> (a) that scan was still in stage 3 (all 65535
ports + vuln scripts, up to 10 min); logins run in stage 5, after the port scan; (b) sshpass is
not installed and the panel runs with `--no-install`, so password logins would have been skipped
("sshpass missing") -> paramiko fallback. Side effect of my testing: a 5 s test start of the
panel while the user's panel was down opened a browser tab and ran `mark_interrupted` (the scan
whose panel had already stopped was marked interrupted).
**Verified:** plain vs `--foreground` timeout under a group kill (plain: child survived;
foreground: stopped). `_kill_group` on a script with both kinds: all 4 children gone. Port-in-use
message on a spare busy port: text with pid, exit 1. ssh_pass.py against a paramiko test server:
login + output + stderr + remote exit code 3 (5 of 5), host key stored once, wrong password -> 5
"Permission denied", changed host key -> 255 "Host key verification failed" (password not sent),
refused port -> 255, client stderr empty. t_term 17/17, t_poll 6/6, stage 3 hang test OK.
**Not verified / follow-up:** anything as real root (`_give_back`, terminal dropping to the user,
discover.sh `give_back_files`) - needs the user's sudo. A real password login to the Proxmox host
through ssh_pass.py.

## 2026-10-15 - More detail from a scan without logins (hostname, Proxmox, extra ports)
**Change:** (1) Host name from the TLS certificate (SAN DNS names, then CN) when DNS, mDNS and
NetBIOS give none (`host_profile.name_from_cert`, `hostname_source: "TLS certificate"`).
(2) Apps Proxmox VE, ProxMenux Monitor, VMware ESXi, XCP-ng, and a device type "Hypervisor"
(`device_types.py`) from their banners/titles, plus a note in the report that a Proxmox card or an
SSH login is needed for VMs, CPU, memory and disks. (3) nmap's "Site doesn't have a title" note
is no longer listed as an app. (4) The deep scan also scans `EXTRA_PORTS` (settings.conf: 8006,
8007, 8123, 32400, Docker/Kubernetes APIs, MQTT ... 19 ports outside nmap's top 1000):
`deep_ports()` turns "--top-ports N" + extras into one `-p` list, because nmap can't combine them.
(5) `http_probe.py` also tries ports nmap could not name ("wpl-analytics?") or that speak TLS, skips
raw print ports (9100-9102, 515), and follows a plain-HTTP to HTTPS redirect on the same port.
**Why:** the user's scan of 172.16.0.30 (Proxmox host) showed almost nothing: no name, "Linux
server", and a junk app "Site doesn't have a title.". The Proxmox web UI on 8006 was never
scanned (not in the top 1000).
**Issues / errors:** first port list differed from nmap's top 1000 by ~70 ports -> nmap breaks
frequency ties by lower port number, my `sort -rg` didn't -> `sort -k1,1gr -k2,2n`. Port 8006
was skipped by the title probe -> nmap names it "wpl-analytics?" -> probe unnamed ports too. 8006 over
plain HTTP answered only 301 to https -> follow that redirect with TLS.
**Verified:** `deep_ports` list = nmap's own `--top-ports 1000` list (compared with `nmap -v -oG`)
plus the 19 extras, nothing missing. `-p-` and empty EXTRA_PORTS stay unchanged. Rebuilt
findings of run 20261015-102002 (plus port 8006 as nmap names it): hostname pve.fritz.local (TLS
certificate), type Hypervisor (high), apps Proxmox VE (3128, 8006) and ProxMenux Monitor, no junk
app, the new note shown. Live probe of 172.16.0.30:8006 -> "pve - Proxmox Virtual Environment".
test_vm_inventory and test_cloud_api (20/20) pass; the stage 3 hang test still passes.
**Not verified / follow-up:** no full new scan from the panel yet. Without logins a scan can only
see ports, banners and page titles; VMs/CPU/RAM/disks need the Proxmox card or an SSH login.

## 2026-10-15 - Fix: scan hung at "waiting for the last N scan job(s)" (stage 3)
**Change:** `stage_deep` in `discovery/lib/scan_local.sh` keeps the PIDs of its own nmap jobs
and waits only for those (`wait "${pids[@]}"`). The MAX_PARALLEL limit counts live PIDs
(`kill -0`) instead of using `wait -n`.
**Why:** the user's scan of 172.16.0.30 (run 20261015-100947) sat at 51 % "waiting for the
last 1 scan job(s)" for good, although nmap had finished at 10:10:44 (50.8 s, report written).
**Issues / errors:** hang at the end of stage 3 -> plain `wait` waits for *every* background
job of the shell, including the sudo keep-alive loop from `sudo_keepalive_start`
(common.sh), which never ends while sudo stays valid -> wait only for our own PIDs. It only
showed when sudo was authorised (no keep-alive otherwise). The same bug made `wait -n` in
the throttle count wrong ("2 running" when only 1 was).
**Verified:** test script with a never-ending background loop (like the keep-alive) and a
fake nmap (2 s per host), 5 hosts, MAX_PARALLEL=2: the old code hung (killed by `timeout 20`,
exit 124). The new code finished in 7 s with 5 host reports and at most 2 jobs at once.
`bash -n` OK.
**Not verified / follow-up:** not yet re-run as a real scan from the panel.

## 2026-10-15 - VM inventory: VMs on Proxmox / libvirt hypervisors (scan-builder step 3)
**Change:** Network scans list the VMs and containers on hypervisors and join them with the
hosts found on the network. New `discovery/lib/vm_inventory.py`: (a) Proxmox VE REST API with
an API token (new credential card "Proxmox VE": host, token ID, secret, optional cert SHA-256),
GET only: nodes, storage, physical disks, LVM/ZFS layout, qemu + lxc configs, live CPU/RAM,
guest agent get-osinfo / network-get-interfaces / get-fsinfo; (b) parser for a new
`=== hypervisor ===` section of the SSH collection (`qm`/`pct config`, `storage.cfg`, `pvs`,
`zpool`, `virsh -r dominfo/domblklist/domblkinfo/domiflist`, `lsblk`, `df`); (c) `merge()`
matches VMs to hosts by MAC then IP. Each disk gets the physical media behind its storage
(nvme/ssd/hdd/network). The SSH collection also gathers in every guest: `systemd-detect-virt`,
disks with media (`lsblk`), package counts + manually installed packages (dpkg/rpm/pacman/apk,
snap, flatpak). Dashboard + History page: new "Virtual machines" table (VM, state, OS, vCPU,
RAM, disks, IPs, ports/apps/services/packages from inside the guest); host rows say
"VM x on y" / "proxmox host" / "likely VM (MAC)". Stored in `hosts.extra` and `scans.summary`
(no migration). SSH timeout 30 s -> 120 s (a hypervisor with many guests runs one
`qm config` per guest). Files: `discovery/lib/{vm_inventory.py,scan_auth.sh,host_profile.py,
build_json.py,creds.py,summarize.sh,dashboard.template.html}`, `panel/{serve.py,db.py}`,
`panel/web/{creds.js,index.html,history.html}`, `discovery/tests/{pve_sim.py,test_vm_inventory.py}`,
`docs/VM_INVENTORY.md`, `.gitignore` (`discovery/config/known_tls`).
**Why:** user asked for VM details (CPU, memory, HDD/SSD/NVMe, services, apps) when a scan
runs. Step 3 had been paused since 2026-10-13; resumed after the user reported that stop as
a false positive.
**Design:** Proxmox certificates are self-signed, so the API connection pins the cert's
SHA-256 (card value, or trust-on-first-use in `config/known_tls`) and checks it on every
connection before the token is sent. Guest agent `exec`/`file-read` are never used (they run
code in the VM). Proxmox cards are accepted for network scans only (`creds.LAN_TYPES`); the host
must be a private IPv4. A VM's OS comes from the guest agent, else from an SSH login to the
guest, else from the Proxmox `ostype`.
**Issues / errors:** (1) test page for `creds.js` showed `esc is not defined` -> `esc` lives in
index.html, not common.js; harness only, code fine. (2) end-to-end shell test did nothing ->
sourcing `creds.sh` resets `HAVE_CREDS=0`; set it after sourcing (test only). (3) first
render showed the OS as "Linux (2.6+ kernel)" (Proxmox `ostype`) although the SSH login knew
"Debian 12" -> the guest's own answer now wins unless the guest agent answered. (4) Proxmox
version string was the full `pveversion` line -> trimmed to the number.
**Verified:** `test_vm_inventory.py` 38/38 (API: VM/LXC fields, vCPU = cores x sockets,
cdrom/template skipped, LVM-thin -> nvme, ZFS mirror -> hdd+ssd, NFS -> network, guest agent
OS/IPs, GET only, no exec, wrong token -> auth_failed, changed cert refused before the token is
sent, public host refused; SSH: Proxmox incl. snapshot sections and dir storage via df+lsblk,
libvirt; guest disks/packages/virt; MAC join). `test_cloud_api.py` 20/20. The new remote
command run locally (bash -n + real output). `auth_proxmox_cards` run end to end against the
simulator (login row ok, json written, cert pinned once). `build_json.py` + dashboard on a fake
run: rendered in headless Firefox, no JS errors. `history.html` parses with no errors; Proxmox
card renders and flags missing fields. `serve.parse_credentials` accepts proxmox for network,
refuses it for cloud.
**Not verified / follow-up:** not yet run against the real Proxmox host (172.16.0.30) or a
real libvirt host; needs a PVEAuditor token or root SSH from the user. vCenter/ESXi/Hyper-V
still step 4.

---

## 2026-10-14 - Actions: several terminals as tabs
**Change:** The Terminal pane has tabs: "+ New terminal on <machine>" opens another
shell on the machine in "Run on" (mix this machine and SSH machines); click a tab to
switch, × closes it. Up to 8 at once (was 4). All open tabs come back after a page
reload. `>_` / "Open terminal there" reuse a tab on that machine if one is open.
New `POST /api/term/poll` (one long-poll for all tabs). Files: `panel/terminal.py`
(`poll`, `_ANY`, `_GEN`), `panel/serve.py` (route; `_send` ignores a closed
connection), `panel/web/actions.html`, `style.css`.
**Why:** user asked for at least 5 terminal windows to switch between.
**Issues found (fixed):**
- One long-poll per tab would hit the browser's ~6 connections per server limit at
  6 tabs and block typing. Fix: one shared poll for all tabs.
- Race: a new tab could start blank for up to 20 s, because the shared poll had
  already started without it. Seen in headless Brave (remote tab empty) and reproduced
  over HTTP. Fix: adding a tab aborts the poll and starts a new one that includes it;
  the server also ends a waiting poll when a terminal opens or closes.
- Cancelled polls made the server write to a closed connection. `_send` now ignores
  BrokenPipe/ConnectionReset quietly.
**Verified:** 6/6 poll tests (6 terminals, idle wait, wakes only for the one that
printed, open ends the wait, unknown/closed ids reported gone); earlier 17/17 terminal
tests (limit now 8). Headless Brave, scripted: 5 local tabs + connect → 6th tab on the
SSH machine, typing in tab 6 shows within 2 s, tab 2 keeps its own output, closing tab 3
leaves 5 on the server, reload brings all 5 back with their output, no JS errors.
Screenshot checked.
**Not verified:** by hand in the user's browser.

## 2026-10-14 - Actions: one-click run, clear "connected" state
**Change:** (1) Clicking an action (the row or ▶) runs it at once; the Output shows
each command as it runs. Dangerous actions still show the commands and ask first.
"Show the commands before running" (remembered per browser) brings back the
two-step flow for everything. A `>_` button on each action types it into the terminal.
(2) After connecting to a machine: a green banner "Connected to user@host (name) ·
distro · sudo" with "Open terminal there" and "Disconnect"; the Terminal tab opens a
shell on that machine right away; the terminal's button says which machine it
opens on, and offers "Switch terminal to …" when Run on changed. Output title shows
where the action ran. Files: `panel/web/actions.html`, `style.css`.
**Why (user feedback):** "why do I also need to click Run?" and "connect only gives
'connected' without actually being connected or an option to run any command".
**Cause of the second:** the activity log showed the SSH connect to 172.16.0.37 *did*
work (22:56) and a local terminal had been opened (22:55). The page just didn't show
it: the only change was the "Run on" dropdown, and the open terminal stayed on this
machine. The terminal itself works in Brave (checked headless: draws and takes typing).
**Verified (headless Brave, scripted clicks, test sshd):** one click runs a safe action
with no confirm box; dangerous action shows the confirm box and doesn't run; connect →
fingerprint confirm → banner shown, terminal tab opens a shell on the remote machine,
typing runs there; clicking an action then runs on the remote (Output title shows it);
Disconnect hides the banner, returns to this machine, closes that terminal; no JS errors.
Screenshot checked.
**Not verified:** by hand in the user's own browser.

## 2026-10-14 - Actions: interactive terminal (stage 4)
**Change:** Terminal tab on the Actions page: a real shell on this machine or on a
machine connected over SSH, drawn with xterm.js (vendored, `panel/web/vendor/xterm/`,
npm checksums verified), long-polling over the panel's HTTP API. "Type into terminal"
button on actions. New `panel/terminal.py`; routes `/api/term/*` in `panel/serve.py`;
`actions.html`, `style.css`. Details: `docs/ACTIONS_PLAN.md` "Terminal".
**Why:** plan stage 4; lets the user answer prompts (sudo passwords, y/n) themselves.
**Decisions:** long-polling instead of WebSocket so the stdlib server needs no new
package; all terminal calls are POST with the token (output can hold secrets); typed
text and output are never logged or stored in the database.
**Issues found in testing:**
- Headless Firefox screenshot showed an empty terminal. Cause: xterm.js doesn't draw
  inside the off-screen iframe the screenshot harness used (its buffer had the right
  text). Not a product bug: loading the page directly draws correctly.
- The scrollbar track was white on the dark terminal. Fixed with dark scrollbar colours.
**Verified:** 17/17 API tests: token required, local shell (TERM=xterm-256color, size,
database settings not in env), resize, reload replays output, bad offset resets, close
kills the shell and its background job, `exit` ends the session, ended sessions
reaped, 4-terminal limit, idle close, remote shell over the test sshd with correct size,
sudo password typed in the terminal (stand-in sudo), disconnect ends the remote
terminal, closed machine refused. Browser: page opened a shell and showed coloured
output (screenshot).
**Not verified:** typing by hand in a real browser (only scripted input), full-screen
programs (htop/nano), real sudo, a real remote machine.

## 2026-10-14 - Actions: run on a machine you connect to over SSH
**Change:** Actions can now run on another machine. A "Connect to a machine…" dialog
(password / pasted key / key file, optional sudo password) plus a "Run on" picker.
Host-key fingerprint must be confirmed on first contact, then pinned. Steps resolve to
the remote machine's distro. Migration `011_action_targets.sql` (no secrets stored).
Files: `panel/action_targets.py`, `panel/actions.py` (`distro_from`, `_run_remote`,
`_run_local`, `start(..., target_id)`, `list_actions(target_id)`), `panel/serve.py`
(target API, 409 `needs_trust`), `panel/web/actions.html`, `style.css`. Details in
`docs/ACTIONS_PLAN.md` "Remote targets". The earlier WIP commit (e8cbfa6) is now wired.
**Why:** user asked to open a connection to a device before running actions on it.
**Issues found in testing (fixed):**
- The sudo password showed in the output. Cause: the remote pty echoes what the panel
  sends. Fix: `stty -echo` at the start of each step, and the password is also
  replaced with "[sudo password hidden]" in the output (passwords of 4+ characters).
- `run_step` had no time limit. Added the same 30-minute step timeout as local runs.
**Verified:** 22/22 tests against a test sshd on 127.0.0.1:2222 with a fake `sudo` on PATH:
first-contact trust, wrong trust refused, pin reuse, changed host key refused and
re-trusted, remote run, `sudo -n` fail with hint, sudo password fed with marker and
password hidden, wrong sudo password stops, Stop kills the remote command, pasted-key
login, bad login and unreachable errors, run stores target, HTTP API (409, list,
closed target 400, forget). Screenshots of the page and dialog checked. Panel-local runs unchanged.
**Not verified:** password login (the test sshd has no PAM), a real Raspberry Pi / other
distro, real `sudo` (only the stand-in), the full Connect click-through in a browser.

## 2026-10-14 - Actions page, stages 1-3
**Change:** new *Actions* tab (`panel/web/actions.html`, `panel/actions.py`,
migration `010_actions.sql`, endpoints under `/api/actions`). Details in
`docs/ACTIONS_PLAN.md` ("Built").
**Why:** user asked to start the Actions page now (plan agreed earlier:
command menu left, output right, paste commands into buttons, drag to
combine, works across distros).
**Decisions:** one run at a time; steps run through `bash -o pipefail -c`
in their own process group (Stop kills nmap-style children too); `sudo`
becomes `sudo -n` so a password prompt can't hang the run; database
settings stripped from the environment; editing a starter action keeps only
this machine's variant (the editor says so); deleting a starter action
hides it (otherwise it would come back on the next load).
**Issues / errors:**
- Pasted lines ending in `\` kept the indentation of the next line
  (`apt list    --upgradable`) -> joined with one space.
- A blank line before the first command in the output -> only between steps.
- Test mistake: "did the stopped run still print `end`?" matched the echoed
  command line (`$ echo start; sleep 30; echo end`); the recorded exit code
  -15 shows the step was killed.
**Verified (scratch Postgres, Linux Mint 22.3):** migration 010; 31 starter
actions / 10 folders; variant resolution for Mint (debian), Rocky (rhel),
Tumbleweed (`zypper dup`), Arch, Alpine; paste parsing (comments,
continuations); save; destructive command auto-flagged; combine; run with
stop at first failure (exit codes 0, 1); dangerous action refused without
confirmation; `sudo true` fails at once with the hint; second run refused
while one runs; Stop -> status stopped, exit -15; no SENTINEL_/PG variables
in the action environment; runs recorded. Panel API: run without token 403,
paste-save, run with live output, export / import (name made unique).
Browser: running a starter action through the confirmation, and the
combine dialog after dragging one action onto another (screenshots).
**Not verified:** the non-debian variants on real Rocky / openSUSE / Arch /
Alpine machines (resolution only); long-running real upgrades.

## 2026-10-14 - Pre-public cleanup: backup-drive path removed (38e37f4)
**Change:** `docs/INTEGRATION_PLAN.md` no longer names the backup drive's
folder path. **Still to do before going public:** the path remains in older
commits; remove it in the same history rewrite as the commit e-mail.
**Also decided:** a fix for deep scans waiting on the sudo keepalive loop
(plain `wait` in `stage_deep`) was written and then dropped at the user's
request; not committed. Symptom if it recurs: a sudo deep scan stays at
"waiting for the last N scan job(s)" after nmap has finished.

## 2026-10-14 - Device read-only mode; FortiGate facts for production use (ddb0a8b)
**Change:** devices are **read-only by default** (migration
`009_device_read_only.sql`, also for devices already added): connect,
overview, backups and previews work; `apply` and `rollback` are refused
(the preview is kept, so it can be applied after switching).
`set_read_only` - switching it off needs the device name typed back;
`POST /api/devices/<id>/mode`; banner + *Allow changes…* / *Back to
read-only* on the device page, badge in the list, Apply disabled with an
explanation; activity log `device.read_only.on|off`.
`docs/FORTIGATE_FIRST_CONTACT.md`: read-only REST API admin on the
FortiGate (GUI steps, CLI marked [verify]), trusted host = panel only,
read-only first connection, what to report back, the later path to
changes. Catalog / `DEVICE_MODELS.md` updated for FortiOS 8.0.
**Why:** the user wants the device wizard tested on real hardware next;
they have FG-100F and FG-200E units, none lab or spare, so the first real
contact must not be able to change anything - enforced by the panel and,
independently, by the token's FortiGate profile.
**Research (official Fortinet docs, 2026-10-14):** FortiOS 8.0.1 build
0245 supports FG-100F and FG-200E (also 7.6.7); 8.0 API is token-only,
token in the header, REST API admin trusted hosts may not be 0.0.0.0/0;
FortiGate-VM permanent trial (since 7.2.1): 1 vCPU / 2 GB, 3 interfaces /
policies / routes, one per FortiCloud account - a possible free lab on
Proxmox.
**Issues / errors:**
- **Correction:** `DEVICE_MODELS.md` and the catalog said the 200E reached
  end of sale in Oct 2025 (from the first research round, not re-checked).
  No end-of-order notice could be found now; the Fortinet community says
  none is scheduled, and 8.0.1 still supports it. Fixed, with sources.
- Whether the config-backup endpoint is GET or POST on 8.0 is not
  documented publicly; the driver already falls back from GET to POST.
  Marked [verify].
- This DEVLOG entry missed commit ddb0a8b: its anchor heading no longer
  matched because the side-note agent had added the process note below;
  added afterwards.
- Test setup: the scratch DB still had an old test device at 127.0.0.1
  (devices are unique by address), and the address wizard's field is
  `subnet`, not `value` - test fixes, no product change.
**Verified (FortiGate simulator + scratch Postgres):** new device
read-only; backup allowed; apply refused and nothing reached the
simulator; wrong name refused; after switching, the same preview applied;
rollback refused while read-only, allowed after switching back; activity
log entries; screenshot of the banner.
**Not verified:** anything on a real FortiGate - next step is the user's
read-only first contact.

## 2026-10-14 - Process note: two agents committed in the same checkout
While the host-profile work was being finished, a second agent (started for
the Actions page idea, `docs/ACTIONS_PLAN.md`) committed the whole working
tree as `adf0784`, including the host-profile files, with its own README /
DEVLOG text. The first agent's README edit then failed its own check (the
file had changed) and its commit `882f927` only carried the dashboard
caption change. Nothing was lost; both commits are pushed and the DEVLOG
entry below is accurate. **Rule from now on:** one agent works in the
checkout at a time; a parallel agent uses its own git worktree and branch.

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
