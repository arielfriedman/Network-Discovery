#!/usr/bin/env python3
"""A tiny Proxmox VE API stand-in for tests/test_vm_inventory.py: HTTPS with a
self-signed certificate, API token auth, one node, two VMs, one container."""
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN_ID, SECRET = "audit@pve!scan", "11111111-2222-3333-4444-555555555555"
GIB = 2**30
DATA = {
    "/version": {"version": "8.2.4", "release": "8.2"},
    "/storage": [{"storage": "local", "type": "dir", "path": "/var/lib/vz"},
                 {"storage": "local-lvm", "type": "lvmthin", "vgname": "pve", "thinpool": "data"},
                 {"storage": "tank", "type": "zfspool", "pool": "tank/vmdata"},
                 {"storage": "nas", "type": "nfs"}],
    "/nodes": [{"node": "pve", "status": "online", "maxcpu": 8, "maxmem": 32 * GIB, "mem": 12 * GIB, "cpu": 0.07}],
    "/nodes/pve/disks/list": [
        {"devpath": "/dev/nvme0n1", "type": "nvme", "model": "Samsung 980", "size": 500107862016, "used": "LVM", "health": "PASSED"},
        {"devpath": "/dev/sdb", "type": "hdd", "model": "WDC WD40", "size": 4000787030016, "used": "ZFS", "health": "PASSED",
         "by_id_link": "/dev/disk/by-id/ata-WDC_WD40-XYZ"},
        {"devpath": "/dev/sdc", "type": "ssd", "model": "Crucial MX500", "size": 1000204886016, "used": "ZFS", "health": "PASSED"}],
    "/nodes/pve/disks/lvm": {"children": [{"name": "pve", "children": [{"name": "/dev/nvme0n1p3"}]}]},
    "/nodes/pve/disks/zfs": [{"name": "tank"}],
    "/nodes/pve/disks/zfs/tank": {"children": [{"name": "mirror-0", "children": [
        {"name": "ata-WDC_WD40-XYZ-part1"}, {"name": "sdc1"}]}]},
    "/nodes/pve/qemu": [
        {"vmid": 100, "name": "web01", "status": "running", "cpus": 4, "maxmem": 4 * GIB, "mem": 2 * GIB, "cpu": 0.12, "uptime": 3600},
        {"vmid": 101, "name": "win11", "status": "stopped", "cpus": 2, "maxmem": 8 * GIB},
        {"vmid": 9000, "name": "tmpl", "status": "stopped", "template": 1}],
    "/nodes/pve/qemu/100/config": {"name": "web01", "cores": 2, "sockets": 2, "memory": "4096", "ostype": "l26", "agent": "1",
                                   "scsi0": "local-lvm:vm-100-disk-0,size=32G,ssd=1", "scsi1": "tank:vm-100-disk-1,size=500G",
                                   "ide2": "local:iso/debian.iso,media=cdrom", "net0": "virtio=BC:24:11:AA:BB:01,bridge=vmbr0"},
    "/nodes/pve/qemu/101/config": {"name": "win11", "cores": 2, "memory": "8192", "ostype": "win11",
                                   "sata0": "nas:101/vm-101-disk-0.qcow2,size=64G", "net0": "e1000=BC:24:11:AA:BB:02,bridge=vmbr0"},
    "/nodes/pve/qemu/100/agent/get-osinfo": {"result": {"pretty-name": "Debian GNU/Linux 12 (bookworm)"}},
    "/nodes/pve/qemu/100/agent/network-get-interfaces": {"result": [
        {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
        {"name": "eth0", "hardware-address": "bc:24:11:aa:bb:01", "ip-addresses": [{"ip-address": "10.9.0.21", "ip-address-type": "ipv4"}]}]},
    "/nodes/pve/qemu/100/agent/get-fsinfo": {"result": [{"mountpoint": "/", "type": "ext4", "total-bytes": 31e9, "used-bytes": 9e9}]},
    "/nodes/pve/lxc": [{"vmid": 200, "name": "pihole", "status": "running", "cpus": 1, "maxmem": 512 * 2**20, "mem": 100 * 2**20}],
    "/nodes/pve/lxc/200/config": {"hostname": "pihole", "cores": 1, "memory": 512, "ostype": "debian",
                                  "rootfs": "local-lvm:vm-200-disk-0,size=8G",
                                  "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:03,ip=10.9.0.53/24,type=veth"},
    "/nodes/pve/lxc/200/interfaces": [{"name": "eth0", "ip-addresses": [{"ip-address": "10.9.0.53", "ip-address-type": "inet"}]}],
}
SEEN = []          # (method, path) of every request, so the test can check nothing but GET was sent


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        b = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        SEEN.append(("GET", self.path))
        if self.headers.get("Authorization") != f"PVEAPIToken={TOKEN_ID}={SECRET}":
            return self._send(401, {"data": None})
        p = self.path.split("?")[0].removeprefix("/api2/json")
        if p in DATA:
            return self._send(200, {"data": DATA[p]})
        self._send(404, {"data": None})

    def do_POST(self):
        SEEN.append(("POST", self.path)); self._send(501, {})


def serve(port, cert, key):
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv
