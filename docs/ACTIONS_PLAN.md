# Actions page (planned)

Status: idea agreed 2026-10-14, not started. Scheduled after the firewall
wizard real-hardware work.

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
