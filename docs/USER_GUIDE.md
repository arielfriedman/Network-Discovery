# SentinelScan user guide

This guide is for people who are new to SentinelScan. It explains what each part
does, where things are kept, and what to do when something goes wrong.
For the details of one feature, follow the links to the other files in `docs/`.

**Contents**

1. [Ground rules](#1-ground-rules)
2. [Install and open the dashboard](#2-install-and-open-the-dashboard)
3. [The pages](#3-the-pages)
4. [Your first scan](#4-your-first-scan)
5. [Reading the results and the drawing](#5-reading-the-results-and-the-drawing)
6. [Device passwords and the vault](#6-device-passwords-and-the-vault)
7. [Where everything is kept](#7-where-everything-is-kept)
8. [Normal mode and root mode](#8-normal-mode-and-root-mode)
9. [Common problems](#9-common-problems)
10. [Updating and removing](#10-updating-and-removing)

---

## 1. Ground rules

Read these before your first scan.

1. **Scan only networks and devices you own, or that you have written permission to test.**
   Port scans and OS detection on someone else's network can be illegal. The scanner
   refuses public addresses unless you force it, but that guard does not replace permission.
2. **The dashboard is for this computer only.** It listens on `127.0.0.1` (this machine),
   not on your network. Don't put it on the internet.
3. **Passwords go in the vault, never in a file or the database.** See section 6.
4. **Scan results describe your real network.** Don't share report files publicly.
5. **Device changes are previewed first.** Check the preview before you press Apply
   on the Devices page.

---

## 2. Install and open the dashboard

You need Debian, Ubuntu or Linux Mint and a user with `sudo` rights.

**Step 1: install.** In a terminal, run:

```bash
curl -fsSL https://gitlab.com/fritzizi/network-discovery/-/raw/main/install.sh | bash
```

Or download the code first and run the installer from the folder:

```bash
git clone https://gitlab.com/fritzizi/network-discovery.git sentinelscan
cd sentinelscan
./install.sh
```

The installer asks for your password once. It installs the tools, sets up the
database, and starts the dashboard as a background service.

**Step 2: open it.** When the installer finishes, it prints:

```
SentinelScan is running. Open: http://127.0.0.1:8765
```

Open that address in your browser. The dashboard keeps running after a reboot.

**Useful installer options** (add them after `./install.sh`, or after `bash -s --` with curl):

| Option | What it does |
|---|---|
| `--root` | the service runs as root, so scans can do more (section 8) |
| `--drawio` | also installs draw.io desktop, for PDF network drawings |
| `--no-service` | no background service; you start it yourself with `./start.sh` |
| `--no-db` | no database; scans are still saved as files, but History stays empty |
| `--dry-run` | shows what it would do, changes nothing |

**Start and stop it**

| I want to... | Command |
|---|---|
| see if it runs | `sudo systemctl status sentinelscan` |
| restart it | `sudo systemctl restart sentinelscan` |
| stop it | `sudo systemctl stop sentinelscan` |
| run it by hand instead | `./start.sh` (stop the service first) |

---

## 3. The pages

The menu at the top of the dashboard has four pages. The top bar also shows
whether the database is connected, and a light/dark theme button.

| Page | Use it to... |
|---|---|
| **Scan** | start a scan of this computer, your network, or a cloud account, and watch it live |
| **History** | see every saved scan, what changed since the last one, and the activity log |
| **Actions** | run saved commands on this machine (packages, services, logs, disks...) and open terminals |
| **Devices** | connect to firewalls and switches (FortiGate, Cisco, Palo Alto, Check Point), back up their config, and make guided changes |
| **Network drawing** | a button on the Scan page and in History, not a menu item: draws your network from a scan |

### Scan

Choose one of three kinds of scan:

- **This host**: checks this computer's own security, such as open ports, firewall,
  SSH settings, users, updates and hardening.
- **The network**: finds the devices on your network (your LAN): their names, makers,
  open ports, operating systems and the apps they run.
- **The cloud**: lists servers, networks, firewalls and DNS in your cloud accounts
  (AWS, Azure, GCP, Kubernetes and ten more). It only reads; it never changes anything.

### History

- Click a scan to see its findings, hosts, logins and virtual machines.
- **Clear history…** deletes old scans. The activity log is always kept.
- **Database backups** shows the nightly backups and makes one on demand.

### Actions

- Pick an action, press run, and watch the output live.
- You can add your own commands, drag one onto another to combine them, and export or import them.
- The **Terminal** tab opens up to 8 shell tabs, on this machine or over SSH.

### Devices

- **Add device**, then **Connect**. On first contact you confirm the device's fingerprint.
- **Wizards**: fill in a form, then **Preview changes**, then Apply.
- **Changes** lists what was done, with roll back. **Backups** holds a copy of the config taken before each change.
- No real equipment? Run `cd panel && python3 -m devices.lab` for simulated devices.
  Details: [DEVICE_MODELS.md](DEVICE_MODELS.md).

---

## 4. Your first scan

A good first scan is your own network.

1. Open **Scan** and choose **The network**.
2. Leave **Whole local network** selected. To scan only some devices, choose
   **Specific targets** and type one per line: an IP (`192.168.1.10`), a range
   (`192.168.1.0/24`), a MAC address, or a host name.
3. Read the checks under the form:
   - ✓ green: ready.
   - ! orange: works, but something is skipped (for example "No admin rights", see section 8).
   - ✗ red: fix this first.
4. Optional: add a **credential card** (SSH, SNMP, Proxmox...) so the scan can log in to
   machines and see more. See section 6.
5. Press **Start scan**.
6. Watch the progress bar and the **Live activity log**. A whole network can take
   from a few minutes to much longer. The deep port scan is the slow part.
7. When it finishes you get the results, **Open dashboard**, **Download JSON** and **Network drawing**.

To stop early, press **Stop scan**. It stops everything the scan started.

---

## 5. Reading the results and the drawing

**The results page**

- **Stat tiles** at the top: how many hosts, services and makers were found.
- **Findings**: things worth a look, such as an open Docker API or old software.
- **Hosts table**: one row per device, with IP, name, maker, device type, OS, open ports and apps.
  Filter or sort it. The device type shows its evidence and how sure it is (high / medium / low).
- **Virtual machines**: shown when a Proxmox or SSH card listed them.

The same results stay in **History**. Each new scan shows what is new or gone since the last one.

**The network drawing**

Press **Network drawing**. You see a picture like this:

![Example network drawing](images/network-drawing.png)

- At the top left: the internet and your gateway (router).
- The thick line is your local network.
- Boxes are grouped by device type. Each box shows the name, IP, OS or maker, and open ports.
- A hypervisor (for example Proxmox) holds its VMs. Stopped VMs are dashed.
- **Your own computer** (the scanner) has a bold border.

Download it as:

| Format | Use it for |
|---|---|
| `.drawio` | editing in the draw.io app or on diagrams.net |
| SVG / PNG | a picture for notes or reports |
| PDF | printing (needs draw.io desktop: `./install.sh --drawio`) |
| Open in diagrams.net | editing in the browser without downloading |

More: [DIAGRAMS.md](DIAGRAMS.md).

---

## 6. Device passwords and the vault

Some checks need to log in to a device, for example SSH to a Linux server or a
Proxmox API token. You give those logins with **credential cards** on the Scan page.

1. Under credentials, choose a type (SSH, SNMP, Proxmox VE, AWS...) and press **Add credential**.
2. Fill in the card: user name, password or key, and which hosts it is for.
3. Choose one:
   - **Leave "Remember in vault" off**: the login is used for this scan only, then forgotten.
     It is never written to disk.
   - **Tick "Remember in vault"**: it is saved, encrypted, for next time. You need the
     **vault passphrase**.
4. Next time, saved logins appear under **Saved in the vault**. Tick the ones to use and
   type the passphrase. **forget** removes one.

**How the vault keeps them safe**

- The vault is one encrypted file, `discovery/config/vault.gpg` (GPG, AES-256).
  It is never stored in plain text.
- The database only keeps the login's name and whether it worked, never the password.
- Passwords are blanked out (`***REDACTED***`) in every report and log.
- If you forget the passphrase, the saved logins are lost. Nobody can recover them.
  Add them again.

You can also manage the vault in a terminal, from the `discovery` folder:

```bash
./vault.sh list        # names only, values stay hidden
./vault.sh set KEY     # add or replace one
./vault.sh rm KEY      # delete one
./vault.sh passwd      # change the passphrase
```

**Rules for logins**

- Use a read-only or audit account when you can (for example a Proxmox API token with only the audit role).
- Don't reuse your main admin password.
- Never paste passwords into Actions or into notes. Use the cards.

---

## 7. Where everything is kept

All paths are inside the SentinelScan folder (the one you cloned or installed).

| What | Where |
|---|---|
| network and cloud scan reports | `discovery/reports/<date-time>/`, newest in `discovery/reports/latest` |
| inside each report | `summary.txt` (readable report), `dashboard.html` (open by double-click), `findings.json` (data), `run.log` (what ran, with times), `raw/` (each tool's own output) |
| host scan reports | `panel/reports/` |
| scan history, activity log, devices | the PostgreSQL database `sentinel` (on this machine only) |
| database backups | `panel/backups/db/` (the newest 14 are kept, made nightly at 03:17) |
| saved logins (vault) | `discovery/config/vault.gpg` (encrypted) |
| scanner settings | `discovery/config/settings.conf` (speed, ports, which stages run) |
| your own overrides | `discovery/config/settings.local.conf` |
| database connection | `panel/settings.local.json` (only your user can read it) |
| SSH host keys seen | `discovery/config/known_hosts` |
| rootkit false alarms | `panel/rootkit_allowlist.txt` |
| dashboard service log | `journalctl -u sentinelscan` |
| change history (for developers) | `docs/DEVLOG.md` |

Reports, settings with passwords, and the vault are never uploaded to git.

---

## 8. Normal mode and root mode

The dashboard can run as your normal user or as root (admin).

| | Normal mode | Root mode |
|---|---|---|
| How to start | default install, or `./start.sh` | `./install.sh --root`, or `sudo ./start.sh` |
| Find devices (ping sweep) | yes | yes |
| Ports, services, apps | yes | yes |
| ARP sweep (finds devices that ignore ping) | no | yes |
| OS detection (nmap fingerprint) | no | yes |
| Host scan: password hashes, protected logs | partly | yes |
| SSH logins to other machines (cards) | yes | yes |

The Scan page tells you which mode you are in. If it says
"No admin rights", the scan still works and only those extra checks are skipped.

**Root mode for one session, without reinstalling:**

1. Stop the panel (`sudo systemctl stop sentinelscan`, or Ctrl-C if you started it by hand).
2. Run `sudo -v` and type your password.
3. Within 15 minutes, run `./start.sh`.

Or run `sudo ./start.sh`. Started with sudo, no browser opens by itself; open
http://127.0.0.1:8765 yourself. Files the scans write still belong to your user,
and the Actions terminal is still your normal user.

**Rule:** use root mode only when you need the extra checks.

---

## 9. Common problems

**"Port 8765 is already in use"**
A dashboard is already running, often the background service.
- Just open http://127.0.0.1:8765. It is probably already there.
- To start a different one (for example with sudo), stop the old one first:
  `sudo systemctl stop sentinelscan`, or kill the pid the message shows.

**The page does not open**
- Check the service: `sudo systemctl status sentinelscan`.
- Read its log: `journalctl -u sentinelscan -n 50`.
- Restart it: `sudo systemctl restart sentinelscan`.

**The scan looks stuck**
- Look at the **Live activity log**. If new lines still appear, it is working.
  The deep port scan of a server with many ports (for example a Proxmox host) can take many minutes.
- For a quicker scan, use **Specific targets** with only the devices you need,
  or untick the slow checks.
- **Stop scan** really stops it, including all nmap processes.

**SSH login on a card fails**
- The History page **Logins** section and the activity log say why:
  - "Permission denied (wrong user name or password)": check the card.
  - "password login not allowed": the server only allows keys. Use a key card,
    or allow passwords in its `/etc/ssh/sshd_config`.
  - "REMOTE HOST IDENTIFICATION HAS CHANGED": the server's key is different from last time.
    If you reinstalled that machine, remove its line from `discovery/config/known_hosts`.
    If you didn't, don't continue: someone may be in the middle.
  - "connect to host ... port 22": the machine is off, SSH is not running, or a firewall blocks it.
- The SSH login runs near the end of a network scan, after the port scan. Wait for it.

**"No admin rights" on the Scan page**
This is normal in normal mode. See section 8 to get the extra checks.

**History is empty**
The database is missing or not reachable. Run `python3 panel/db.py status`.
If it says not connected, run `./install.sh` again. It is safe to re-run.

**PDF button missing in the drawing**
draw.io desktop is not installed. Run `./install.sh --drawio`, then restart the dashboard.
`.drawio`, SVG and PNG work without it.

**The rootkit check flags something you know is fine**
Add its name or path to `panel/rootkit_allowlist.txt`.

---

## 10. Updating and removing

**Update** (from the SentinelScan folder):

```bash
git pull
./install.sh
```

The installer is safe to run again. It keeps your data, vault and settings.

**Remove**

```bash
sudo systemctl disable --now sentinelscan
sudo rm /etc/systemd/system/sentinelscan.service
python3 panel/db_backup.py schedule off
```

Then delete the folder. That also deletes your reports and vault, so copy them first if you want to keep them.
The database stays in PostgreSQL until you drop it:
`sudo -u postgres dropdb sentinel && sudo -u postgres dropuser sentinel`.
