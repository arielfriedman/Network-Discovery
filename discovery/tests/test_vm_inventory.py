#!/usr/bin/env python3
"""Tests for lib/vm_inventory.py: the Proxmox API path against tests/pve_sim.py
(HTTPS, self-signed, certificate pinning), the SSH parsers (qm/pct and virsh
output), and the join of VMs with scanned hosts.

  python3 discovery/tests/test_vm_inventory.py      (needs openssl)
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib")); sys.path.insert(0, str(HERE))
import creds  # noqa: E402
import host_profile  # noqa: E402
import pve_sim  # noqa: E402
import vm_inventory as vi  # noqa: E402

PORT = 9918
fails = 0


def check(name, cond, info=""):
    global fails
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  {info}"))
    fails += not cond


def cert(d, tag):
    c, k = os.path.join(d, f"{tag}.crt"), os.path.join(d, f"{tag}.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", f"/CN={tag}",
                    "-keyout", k, "-out", c], check=True, capture_output=True)
    return c, k


def run(tmp, secret, fp=""):
    sec = os.path.join(tmp, "sec"); os.makedirs(sec, exist_ok=True)
    f = {"host": "127.0.0.1", "port": str(PORT), "token_id": pve_sim.TOKEN_ID, "token_secret": secret}
    if fp:
        f["fingerprint"] = fp
    creds.store(sec, {"sets": [creds.validate({"type": "proxmox", "name": "pve", "fields": f}, 1)], "vault": {}})
    out = subprocess.run([sys.executable, str(HERE.parent / "lib" / "vm_inventory.py"), "proxmox", sec,
                          os.path.join(tmp, "vms"), os.path.join(tmp, "known_tls")], capture_output=True, text=True)
    return out.stdout.strip().split("\t")


with tempfile.TemporaryDirectory() as tmp:
    # ── API ──
    c1, k1 = cert(tmp, "a")
    srv = pve_sim.serve(PORT, c1, k1); threading.Thread(target=srv.serve_forever, daemon=True).start()
    r = run(tmp, pve_sim.SECRET)
    check("api: login ok", r[2] == "ok", r)
    check("api: certificate pinned on first use", os.path.exists(os.path.join(tmp, "known_tls")))
    inv = json.load(open(os.path.join(tmp, "vms", "proxmox-127.0.0.1.json")))
    vms = {v["id"]: v for v in inv["vms"]}
    check("api: 2 VMs + 1 container, template skipped", sorted(vms) == ["100", "101", "200"], sorted(vms))
    w = vms["100"]
    check("api: vCPU = cores x sockets", w["vcpus"] == 4, w["vcpus"])
    check("api: memory", w["memory_mb"] == 4096)
    check("api: OS from guest agent", w["os"] == "Debian GNU/Linux 12 (bookworm)", w["os"])
    check("api: IPs from guest agent (no loopback)", w["ips"] == ["10.9.0.21"], w["ips"])
    check("api: cdrom not a disk", [d["id"] for d in w["disks"]] == ["scsi0", "scsi1"], w["disks"])
    d0, d1 = w["disks"]
    check("api: lvm-thin disk on NVMe", d0["media"] == ["nvme"] and d0["emulated_ssd"] and d0["size_gb"] == 32, d0)
    check("api: zfs mirror disk on hdd+ssd", d1["media"] == ["hdd", "ssd"], d1)
    check("api: NFS disk is network", vms["101"]["disks"][0]["media"] == ["network"], vms["101"]["disks"])
    check("api: stopped VM keeps OS type", vms["101"]["os"] == "Windows 11 / Server 2022+")
    check("api: container IP from config", vms["200"]["ips"] == ["10.9.0.53"], vms["200"]["ips"])
    check("api: node disks listed", len(inv["nodes"][0]["disks"]) == 3)
    check("api: only GET requests", all(m == "GET" for m, _ in pve_sim.SEEN))
    check("api: no exec endpoint touched", not any("exec" in p or "file-read" in p for _, p in pve_sim.SEEN))
    r = run(tmp, "99999999-0000-0000-0000-000000000000")
    check("api: wrong token -> auth_failed", r[2] == "auth_failed", r)
    srv.shutdown(); srv.server_close()
    # same address, different certificate: must refuse
    c2, k2 = cert(tmp, "b")
    srv = pve_sim.serve(PORT, c2, k2); threading.Thread(target=srv.serve_forever, daemon=True).start()
    n = len(pve_sim.SEEN)
    r = run(tmp, pve_sim.SECRET)
    check("api: changed certificate refused", r[2] == "error" and "changed" in r[3], r)
    check("api: token not sent to the changed host", len(pve_sim.SEEN) == n, pve_sim.SEEN[n:])
    srv.shutdown(); srv.server_close()
    try:
        creds.validate({"type": "proxmox", "fields": {"host": "8.8.8.8", "token_id": "a@pve!b", "token_secret": "x" * 36}}, 1)
        check("creds: public host refused", False)
    except creds.Bad:
        check("creds: public host refused", True)

# ── SSH: Proxmox ──
PVE_SSH = """platform proxmox pve-manager/8.2.4/faa83925c9641325 (running kernel: 6.8.12-1-pve)
--- list qemu
      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID
       100 web01                running    4096              32.00 1234
--- list lxc
VMID       Status     Lock         Name
200        running                 pihole
--- qemu 100
boot: order=scsi0
cores: 2
memory: 4096
name: web01
net0: virtio=BC:24:11:AA:BB:01,bridge=vmbr0
ostype: l26
scsi0: local-lvm:vm-100-disk-0,size=32G
scsi1: big:100/vm-100-disk-1.qcow2,size=1T
sockets: 1

[snap1]
memory: 1024
--- lxc 200
cores: 1
hostname: pihole
memory: 512
net0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:03,ip=dhcp,type=veth
rootfs: local-lvm:vm-200-disk-0,size=8G
--- storage
dir: local
\tpath /var/lib/vz
\tcontent iso,backup

lvmthin: local-lvm
\tthinpool data
\tvgname pve

dir: big
\tpath /mnt/big
--- pvs
  /dev/nvme0n1p3 pve
--- zpool
--- lsblk
NAME="nvme0n1" PKNAME="" ROTA="0" TRAN="nvme" SIZE="500107862016" MODEL="Samsung SSD 980" TYPE="disk"
NAME="nvme0n1p3" PKNAME="nvme0n1" ROTA="0" TRAN="" SIZE="499000000000" MODEL="" TYPE="part"
NAME="sda" PKNAME="" ROTA="1" TRAN="sata" SIZE="4000787030016" MODEL="WDC WD40" TYPE="disk"
NAME="sda1" PKNAME="sda" ROTA="1" TRAN="" SIZE="4000000000000" MODEL="" TYPE="part"
--- df
Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/mapper/pve-root  98559220  10000000  83000000      11% /
/dev/sda1     3844640564 100000000 3500000000       3% /mnt/big
"""
inv = vi.parse_ssh("10.9.0.30", PVE_SSH)
v = {x["id"]: x for x in inv["vms"]}
check("ssh pve: version", inv["version"] == "8.2.4", inv["version"])
check("ssh pve: VM + container", sorted(v) == ["100", "200"], sorted(v))
check("ssh pve: snapshot section ignored", v["100"]["memory_mb"] == 4096 and v["100"]["vcpus"] == 2, v["100"])
check("ssh pve: status from qm list", v["100"]["status"] == "running" and v["200"]["status"] == "running")
check("ssh pve: lvm-thin -> nvme", v["100"]["disks"][0]["media"] == ["nvme"], v["100"]["disks"])
check("ssh pve: dir storage -> hdd via df+lsblk", v["100"]["disks"][1]["media"] == ["hdd"] and v["100"]["disks"][1]["size_gb"] == 1024,
      v["100"]["disks"][1])
check("ssh pve: container MAC", v["200"]["nics"][0]["mac"] == "bc:24:11:aa:bb:03")

# ── SSH: libvirt ──
LV_SSH = """platform libvirt 10.0.0
--- domain 3f2a-uuid
Id:             1
Name:           ubuntu-vm
UUID:           3f2a0000-0000-0000-0000-000000000000
OS Type:        hvm
State:          running
CPU(s):         4
Max memory:     8388608 KiB
Used memory:    8388608 KiB
# blk
 Type   Device   Target   Source
------------------------------------------------------------------------
 file   disk     vda      /var/lib/libvirt/images/ubuntu.qcow2
 file   cdrom    sda      -
# sizes
vda 53687091200
# nics
 Interface   Type     Source    Model    MAC
-------------------------------------------------------------
 vnet0       bridge   br0       virtio   52:54:00:12:34:56
--- lsblk
NAME="sda" PKNAME="" ROTA="0" TRAN="sata" SIZE="1000000000000" MODEL="SSD" TYPE="disk"
NAME="sda2" PKNAME="sda" ROTA="0" TRAN="" SIZE="999000000000" MODEL="" TYPE="part"
--- df
Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/sda2      960000000 100000000 800000000      12% /
"""
inv2 = vi.parse_ssh("10.9.0.40", LV_SSH)
u = inv2["vms"][0]
check("ssh libvirt: domain", u["name"] == "ubuntu-vm" and u["vcpus"] == 4 and u["memory_mb"] == 8192, u)
check("ssh libvirt: disk on ssd, cdrom skipped", [(d["id"], d["media"], d["size_gb"]) for d in u["disks"]] == [("vda", ["ssd"], 53.7)],
      u["disks"])
check("ssh libvirt: nic", u["nics"] == [{"mac": "52:54:00:12:34:56", "bridge": "br0", "model": "virtio"}])

# ── in-guest details ──
h = {"ip": "10.9.0.21", "os": None}
host_profile.build(h, None, """=== os ===
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
=== services ===
nginx.service
ssh.service
=== virt ===
kvm
=== disks ===
NAME="sda" ROTA="1" TRAN="" SIZE="34359738368" MODEL="QEMU HARDDISK" TYPE="disk"
=== packages ===
manager dpkg 412
nginx
openssh-server
snap:lxd
""")
sy = h["system"]
check("guest: virtualization", sy["virtualization"] == "kvm")
check("guest: emulated disk marked virtual", sy["disks"][0]["media"] == "virtual", sy["disks"])
check("guest: packages", sy["packages"]["count"] == 412 and sy["packages"]["installed"] == ["nginx", "openssh-server"]
      and sy["packages"]["snap"] == ["lxd"], sy["packages"])

# ── join ──
hosts = {"10.9.0.21": {**h, "mac": "BC:24:11:AA:BB:01", "ports": [{"port": "80/tcp"}], "apps": [{"name": "nginx"}]},
         "10.9.0.30": {"ip": "10.9.0.30", "mac": "aa:aa:aa:aa:aa:aa", "ports": [], "apps": []},
         "10.9.0.77": {"ip": "10.9.0.77", "mac": "52:54:00:99:99:99", "ports": [], "apps": []}}
vms, hvs = vi.merge(hosts, None, {"10.9.0.30": PVE_SSH})
web = next(x for x in vms if x["name"] == "web01")
check("join: VM matched to host by MAC", web.get("host_ip") == "10.9.0.21", web)
check("join: guest services on VM row", web["guest"]["services"] == ["nginx", "ssh"] and web["guest"]["packages"] == 412, web["guest"])
check("join: host knows it is a VM", hosts["10.9.0.21"]["vm"]["name"] == "web01")
check("join: hypervisor marked", hosts["10.9.0.30"]["hypervisor"]["vms"] == 2)
check("join: MAC-prefix guess for unknown VM", hosts["10.9.0.77"].get("vm_guess") == "QEMU/KVM")

print("\n" + ("all passed" if not fails else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
