# VM inventory: virtual machines on your hypervisors

A network scan can list every VM and container on the hypervisors it reaches. For each one
you get vCPU, RAM, disks and the physical media behind them (NVMe / SSD / HDD / network
storage), its IPs, OS and state. The VM is then matched to the host the scan found on the
network, so the same row also shows that guest's open ports, apps, running services and
installed packages.

Everything is read-only. Code: `discovery/lib/vm_inventory.py`, the SSH collection in
`discovery/lib/scan_auth.sh`, guest details in `discovery/lib/host_profile.py`.
Tests: `python3 discovery/tests/test_vm_inventory.py` (Proxmox API simulator in
`discovery/tests/pve_sim.py`).

## How to use it

Scan page → *The network* → tick **Log in with credentials**, then add one or both:

| Card | What it gives | What to set up on the hypervisor |
|---|---|---|
| **Proxmox VE** (host IP, API token ID, token secret, optional certificate SHA-256) | All VMs and LXC containers on every cluster node: vCPU, RAM, live CPU/RAM use, disks with storage and physical media, MACs, state; through the QEMU guest agent also the guest OS name, IPs and filesystems | Datacenter → Permissions → API Tokens: add a token (privilege separation on), give it the **PVEAuditor** role on `/`. For guest-agent details also `VM.GuestAgent.Audit` (PVE 9) or `VM.Monitor` (PVE 8). The VM needs the agent installed and enabled (Options → QEMU Guest Agent) |
| **SSH** for the hypervisor (Proxmox host or any Linux KVM/libvirt host) | Same VM list from `qm`/`pct config` (Proxmox) or `virsh -r` (libvirt), with disk media worked out from `lsblk` | root, or a user with passwordless `sudo` for `qm`/`pct`/`pvs` (Proxmox), or in the `libvirt` group (libvirt) |
| **SSH** for the guests (same card with a range, or one card per group) | Inside each VM: OS, CPU, RAM, disks, running services, installed packages (dpkg/rpm/pacman/apk + snap + flatpak), Docker containers | a normal user is enough |

Without any of these the scan still marks hosts whose MAC prefix belongs to a hypervisor
(`BC:24:11` Proxmox, `52:54:00` QEMU/KVM, VMware, Hyper-V, VirtualBox, Xen, Parallels) as
"likely VM".

Results: a **Virtual machines** table in the scan dashboard and on the History page, a
"VM … on …" / "proxmox host · N guests" note on the host rows, and a line per hypervisor
under *Worth a look*.

## How the pieces join

1. Proxmox API (`vm_inventory.py proxmox`) writes `raw/vms/proxmox-<ip>.json`.
2. The SSH login to a hypervisor adds a `=== hypervisor ===` section to `raw/ssh/<ip>.txt`.
3. `build_json.py` calls `vm_inventory.merge()`: the API result wins; the SSH result only
   fills in disk media the API could not work out (e.g. `dir` storage). VMs are matched to
   scanned hosts by MAC, then by IP (guest agent / container config).
4. `findings.json` gets `vms`, `hypervisors`, `stats.vms`; hosts get `vm`, `hypervisor`
   or `vm_guess`. The panel stores these in `hosts.extra` and `scans.summary` (no new table).

### Disk media

- **Proxmox API:** `/nodes/{node}/disks/list` gives each physical disk's type. Storage →
  disk: LVM / LVM-thin via the volume group's PVs (`/disks/lvm`), ZFS via the pool's leaf
  devices (`/disks/zfs/{pool}`), NFS/CIFS/PBS/Ceph/iSCSI = `network`.
- **SSH:** the same mapping from `/etc/pve/storage.cfg`, `pvs`, `zpool list -v -H -P -L`,
  `df` and `lsblk` (partition → disk via `PKNAME`; `TRAN=nvme` → nvme, `ROTA=0` → ssd,
  `ROTA=1` → hdd).
- `emulated_ssd` = the Proxmox `ssd=1` flag (what the guest is told), not the real media.
- Inside a guest, disks with a QEMU/VMware/Hyper-V model or `vd*`/`xvd*` names are shown
  as `virtual` - only the hypervisor knows the real media.

## Security

- Only GET requests to the Proxmox API. The guest agent's `exec` and `file-read` endpoints
  run code / read files inside the VM and are never called (the test checks this).
- The token secret stays in the scan's tmpfs credential file, is never in argv, and is
  scrubbed from all output like the other secrets.
- Proxmox uses a self-signed certificate: the card's SHA-256 fingerprint is checked if
  given, otherwise the certificate is trusted on first use and pinned in
  `discovery/config/known_tls` (gitignored). A changed certificate stops the inventory
  before the token is sent; delete the line if the host was reinstalled.
- The Proxmox host must be a private (RFC 1918) or loopback IPv4 address.
- SSH commands are read-only (`qm config`, `pct config`, `virsh -r`, `lsblk`, `df`,
  package listings). `sudo -n` is tried only for `qm`/`pct`/`pvs`/`storage.cfg` and fails
  silently if a password would be needed.

## Not covered yet

- VMware vCenter / ESXi and Hyper-V (scan-builder step 4).
- Proxmox clusters are read through one node's API (it answers for all nodes); over SSH
  only the node you log in to is listed.
- Not yet tried against the real Proxmox host (172.16.0.30); tested against the simulator
  and recorded `qm`/`virsh` output.
