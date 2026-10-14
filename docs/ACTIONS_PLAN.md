# Actions page (planned)

Status: stages 1-3 built 2026-10-14 (`panel/actions.py`, `panel/web/actions.html`,
migration `010_actions.sql`). Stage 5 (remote hosts over SSH) built 2026-10-14
(see "Remote targets"). Stage 4 (interactive terminal) is next.

## What the user asked for

- Left: a menu of commands / actions; right: a terminal session.
- An action like **Update** runs `sudo apt update`; **Upgrade** runs the upgrade.
- Drag one action onto another -> a *Name* field opens ("update+upgrade") ->
  a new action that runs both in order.
- The whole menu is fully customizable.
- It must cover "all the Linux commands" and work on Ubuntu, Red Hat,
  CentOS, Fedora, Mint, SUSE, Pop!_OS and similar.
- Users can paste an entire command (or several lines) and save it as a new
  named button.

## Design

- **Action** = name, ordered steps, target (this machine; later hosts
  through SSH credential cards), *dangerous* flag, *stop at first failure*
  (default on). Combining creates a new action; the originals stay.
- **Distro-aware steps.** A built-in action is one generic step with a
  variant per distro family, picked from `/etc/os-release` (`ID`, then
  `ID_LIKE`) on the machine it runs on:

  | Family | Distros | update / upgrade | install | firewall |
  |---|---|---|---|---|
  | debian | Ubuntu, Mint, Pop!_OS, Debian, Raspberry Pi OS, Kali | `apt update` / `apt upgrade` | `apt install` | ufw |
  | rhel | RHEL, CentOS Stream, Rocky, Alma, Fedora (`yum` on CentOS 7) | `dnf check-update` / `dnf upgrade` | `dnf install` | firewalld |
  | suse | openSUSE Leap / Tumbleweed, SLES | `zypper refresh` / `zypper update` (`dup` on Tumbleweed) | `zypper install` | firewalld |
  | arch | Arch, Manjaro, EndeavourOS | `pacman -Sy` / `pacman -Syu` | `pacman -S` | - |
  | alpine | Alpine | `apk update` / `apk upgrade` | `apk add` | - |

  Common commands (systemctl, journalctl, ss, ip, df, du, free, ps, docker,
  kubectl) are the same everywhere and need no variants.
- **Library ("all the Linux commands")**: a categorised starter set -
  packages, services, disks, network, users, logs, processes, firewall,
  Docker, Kubernetes, system info - plus any command the user adds.
- **Customizable**: add / edit / duplicate / rename / reorder / folders /
  delete; export and import as JSON.
- **New button from pasted commands**: *New action* -> paste one command or
  a multi-line block -> each non-empty line becomes a step (a trailing `\`
  continues the line; `#` lines are comments) -> name it -> save. The
  preview shows the parsed steps before saving, and the same approval rule
  applies when it runs.
- **Storage**: new migration (actions, steps, folders); every run in the
  append-only activity log (who, exact commands, exit codes, duration).

## Safety (the panel becomes a remote shell)

- Show the exact commands before running; extra confirmation for dangerous
  actions (reboot, rm, prune, firewall changes).
- sudo passwords are typed into the terminal when asked, never stored.
- Panel stays on 127.0.0.1 with its per-launch token; before it is ever
  reachable from the network, the login page and roles (with a separate
  "run commands" permission) must exist.

## Build order

1. Saved actions, run non-interactively, live output in the right pane,
   approval step (Python `pty` + polling; standard library).
2. Distro detection and per-family variants; the starter library.
3. Drag-to-combine, editor, folders, import / export.
4. Full interactive terminal (xterm.js + WebSocket / long-poll).
5. Run on remote hosts through SSH credential cards, results per host.

## Built (stages 1-3)

- 31 starter actions in 10 folders (Packages, System, Services, Logs, Disks,
  Network, Firewall, Docker, Kubernetes, Power); package and firewall actions
  have variants for the debian, rhel, suse, arch and alpine families
  (openSUSE Tumbleweed upgrades with `zypper dup`). Detected from
  `/etc/os-release`; actions with no command for this machine are greyed out.
- Run: the exact commands are shown first; *Run* starts them; output streams
  into the right pane; *Stop* kills the step's process group; 30-minute
  limit per step; one run at a time; recent runs listed with exit codes
  (tables `action_runs`, `action_run_steps`, last 256 KB of output per step).
- `sudo` inside a step runs as `sudo -n`: no prompt that nobody can answer;
  the output says to run `sudo -v` in the panel's terminal. Stage 4 will take
  passwords in the terminal itself.
- The panel's database settings are removed from the actions' environment.
- New action by pasting (one per line, `\` continues, `#` comments); edit,
  delete (a deleted starter action stays deleted; *Restore starter actions*
  brings them back), folders, search, drag one action onto another to
  combine (a new action; originals stay), export / import JSON.
- Destructive commands (rm -r, reboot, mkfs, dd, prune, kubectl delete, ...)
  mark the action dangerous automatically; dangerous actions need a ticked
  confirmation. Every create / edit / run / stop is in the activity log.
- Not yet: reordering by drag (drag is used for combining), interactive
  input, remote hosts.

## Remote targets (built 2026-10-14)

Actions can run on another machine over SSH. "Connect to a machine…" opens a dialog:
address (suggests machines used before and SSH hosts from scans), port, user, and
login by password, pasted private key or key file. The first time, the panel shows the
machine's SSH host key fingerprint and only connects after you confirm it; the
fingerprint is then pinned, and a changed key is refused until you confirm again.
After connecting, "Run on" switches to that machine: the distro is read from its
`/etc/os-release`, so each action shows the commands for *that* machine.

- Secrets (password, key, passphrase, sudo password) live only in the panel's memory
  while connected; Disconnect (or a panel restart) drops them. The database
  (`action_targets`, migration 011) keeps host, port, user, fingerprint, distro, last use.
- sudo: with a sudo password, `sudo` becomes `sudo -S -p <random marker>` and the panel
  answers the prompt over the SSH session. Echo is off on the remote pty and the
  password is also scrubbed from the output. A wrong password stops the step after one try.
  Without a sudo password, `sudo -n` fails at once with a hint.
- Stop closes the SSH channel; the remote command gets the hang-up and ends.
- Recent runs show where each action ran (`action_runs.target`).
- Code: `panel/action_targets.py`, `actions.start(..., target_id)`, API
  `GET /api/actions/targets`, `POST /api/actions/targets/{connect,disconnect,forget}`,
  `GET /api/actions?target=<id>`.

## Resume here

Next: stage 4 (interactive terminal).
