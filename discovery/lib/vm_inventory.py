#!/usr/bin/env python3
"""Virtual machines on the hypervisors a scan can see (docs/VM_INVENTORY.md).

Two read-only sources, one result shape:

  * Proxmox VE REST API with an API token (credential card "proxmox"):
      vm_inventory.py proxmox SECURE_DIR OUT_DIR KNOWN_TLS
    GET requests only. Writes OUT_DIR/proxmox-<host>.json and prints one
    result line for the login record: ok | auth_failed | unreachable | error.
  * The SSH login (scan_auth.sh): when the host has qm/pct (Proxmox) or
    virsh (libvirt/KVM) the "=== hypervisor ===" section lists the guests;
    parse_ssh() turns it into the same shape.

build_json.py calls merge() to join VMs with the hosts the scan found (by MAC,
then by IP), so a VM row shows what the hypervisor knows (vCPU, RAM, disks and
the physical media behind them) next to what the network scan and a login to
the guest found (open ports, apps, running services, packages).

VM record:
  {platform, hypervisor, node, id, name, kind (qemu|lxc|libvirt), status, os,
   vcpus, memory_mb, mem_used_mb, cpu_pct, uptime_s, agent,
   disks: [{id, size_gb, storage, media: [nvme|ssd|hdd|usb|network|...], emulated_ssd}],
   nics: [{mac, bridge, model}], ips: [...], fs: [{mount, type, size_gb, used_gb}], source}

The guest agent's `exec` / `file-read` endpoints are never used: they run
commands inside the VM. Only get-osinfo, get-fsinfo and network-get-interfaces.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import urllib.parse
from pathlib import Path

TIMEOUT = 15
UA = "SentinelScan-inventory/1.0 (read-only)"

# MAC prefixes hypervisors hand out to guests: the VM is visible even without credentials
VM_MAC_PREFIXES = {
    "bc:24:11": "Proxmox VE", "52:54:00": "QEMU/KVM", "00:50:56": "VMware", "00:0c:29": "VMware",
    "00:05:69": "VMware", "00:15:5d": "Hyper-V", "08:00:27": "VirtualBox", "00:16:3e": "Xen",
    "00:1c:42": "Parallels",
}
# Proxmox "ostype" -> readable name (when the guest agent cannot tell)
PVE_OSTYPE = {"l26": "Linux (2.6+ kernel)", "l24": "Linux 2.4", "win11": "Windows 11 / Server 2022+",
              "win10": "Windows 10 / Server 2016-2019", "win8": "Windows 8 / Server 2012", "win7": "Windows 7",
              "wvista": "Windows Vista", "wxp": "Windows XP", "w2k8": "Windows Server 2008", "w2k3": "Windows Server 2003",
              "w2k": "Windows 2000", "solaris": "Solaris", "other": "other"}
DISK_KEYS = re.compile(r"^(scsi|virtio|sata|ide)\d+$|^(rootfs|mp\d+)$")


# ── helpers ──────────────────────────────────────────────────────────────────
def _size_gb(s) -> float | None:
    """'32G' / '512M' / '1T' / bytes -> GB."""
    if s is None or s == "":
        return None
    if isinstance(s, (int, float)):
        return round(s / 1e9, 1)
    m = re.match(r"^\s*([\d.]+)\s*([KMGT]?)i?B?\s*$", str(s), re.I)
    if not m:
        return None
    mul = {"": 1 / 1e9, "K": 1 / 1024 / 1024, "M": 1 / 1024, "G": 1, "T": 1024}[m.group(2).upper()]
    return round(float(m.group(1)) * mul, 1)


def _opts(spec: str) -> tuple[str, dict]:
    """'local-lvm:vm-100-disk-0,size=32G,ssd=1' -> ('local-lvm:vm-100-disk-0', {...})."""
    parts = str(spec).split(",")
    first, kv = parts[0], {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        kv[k.strip()] = v.strip()
    if "=" in first:                       # net0: virtio=BC:24:11:..,bridge=vmbr0
        k, _, v = first.partition("=")
        kv[k.strip()] = v.strip()
        kv["_first_key"] = k.strip()
        first = v.strip()
    return first, kv


def _media(row: dict) -> str:
    """lsblk / Proxmox disk row -> nvme | ssd | hdd | usb | unknown."""
    t = str(row.get("type") or "").lower()
    if t in ("nvme", "ssd", "hdd", "usb"):
        return t
    tran = str(row.get("tran") or "").lower()
    if tran == "nvme" or str(row.get("name", "")).startswith("nvme"):
        return "nvme"
    if tran == "usb":
        return "usb"
    rota = str(row.get("rota", ""))
    return {"0": "ssd", "1": "hdd"}.get(rota, "unknown")


def config_vm(kind: str, vmid: str, cfg: dict, storage_media: dict, base: dict) -> dict:
    """A qm/pct config (dict of key -> value string) -> VM record."""
    vm = {**base, "id": str(vmid), "kind": kind, "name": cfg.get("name") or cfg.get("hostname") or f"{kind} {vmid}"}
    if kind == "qemu":
        cores, sockets = int(cfg.get("cores") or 1), int(cfg.get("sockets") or 1)
        vm["vcpus"] = int(cfg.get("vcpus") or cores * sockets)
    else:
        vm["vcpus"] = int(cfg.get("cores") or 0) or None       # LXC without "cores" may use every host core
    mem = str(cfg.get("memory") or "")
    m = re.search(r"(\d+)", mem)
    vm["memory_mb"] = int(m.group(1)) if m else (512 if kind == "lxc" else None)
    if cfg.get("ostype"):
        vm["os"] = PVE_OSTYPE.get(cfg["ostype"], cfg["ostype"])
    vm["agent"] = "configured" if kind == "qemu" and str(cfg.get("agent", "0")).split(",")[0] in ("1", "enabled=1") else (
        "off" if kind == "qemu" else "")
    disks, nics = [], []
    for k, v in cfg.items():
        if DISK_KEYS.match(k):
            vol, o = _opts(v)
            if o.get("media") == "cdrom" or vol in ("none", "cdrom"):
                continue
            storage = vol.split(":")[0] if ":" in vol else ("(host path)" if vol.startswith("/") else vol)
            disks.append({"id": k, "size_gb": _size_gb(o.get("size")), "storage": storage,
                          "media": storage_media.get(storage, []) or (["unknown"] if storage else []),
                          "emulated_ssd": o.get("ssd") == "1", "path": vol if vol.startswith("/") else ""})
        elif re.match(r"^net\d+$", k):
            _, o = _opts(v)
            mac = o.get("hwaddr") or (o.get(o.get("_first_key", ""), "") if o.get("_first_key") in
                                      ("virtio", "e1000", "e1000e", "rtl8139", "vmxnet3") else "")
            nics.append({"mac": mac.lower(), "bridge": o.get("bridge", ""),
                         "model": o.get("_first_key") if kind == "qemu" else "veth"})
            ip = o.get("ip", "")
            if ip and ip not in ("dhcp", "manual"):
                vm.setdefault("ips", []).append(ip.split("/")[0])
    vm["disks"] = sorted(disks, key=lambda d: d["id"])
    vm["nics"] = nics
    vm.setdefault("ips", [])
    return vm


# ── Proxmox over the REST API ────────────────────────────────────────────────
class AuthError(Exception):
    pass


class Unreachable(Exception):
    pass


class PinError(Exception):
    pass


class PinnedHTTPS(http.client.HTTPSConnection):
    """Proxmox ships a self-signed certificate: instead of a CA check, the
    certificate's SHA-256 must match the card's fingerprint or the one seen
    the first time (trust on first use, like SSH host keys)."""

    def __init__(self, host, port, expect: str | None, **kw):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        super().__init__(host, port, timeout=TIMEOUT, context=ctx, **kw)
        self.expect = expect
        self.seen = None

    def connect(self):
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        self.seen = hashlib.sha256(der).hexdigest()
        if self.expect and self.seen != self.expect:
            self.close()
            raise PinError(self.seen)


def _norm_fp(fp: str) -> str:
    return re.sub(r"[^0-9a-f]", "", (fp or "").lower())


class PVE:
    def __init__(self, host, port, token_id, secret, expect_fp):
        self.host, self.port = host, int(port)
        self.auth = f"PVEAPIToken={token_id}={secret}"
        self.expect = expect_fp
        self.seen_fp = None

    def get(self, path: str):
        conn = PinnedHTTPS(self.host, self.port, self.expect)
        try:
            conn.request("GET", "/api2/json" + path, headers={"Authorization": self.auth, "User-Agent": UA,
                                                              "Accept": "application/json"})
            r = conn.getresponse()
            body = r.read()
            self.seen_fp = conn.seen
            self.expect = self.expect or conn.seen          # every later request must see the same cert
        except PinError as e:
            raise PinError(str(e))
        except (OSError, http.client.HTTPException) as e:
            raise Unreachable(f"{self.host}:{self.port}: {e}")
        finally:
            conn.close()
        if r.status == 401:
            raise AuthError(f"HTTP 401 from {self.host}: token rejected")
        if r.status == 403:
            raise PermissionError(f"HTTP 403 {path}")
        if r.status >= 400:
            raise Unreachable(f"HTTP {r.status} {path}: {body[:200].decode('utf-8', 'replace')}")
        try:
            return json.loads(body or b"{}").get("data")
        except ValueError:
            raise Unreachable(f"{path}: answer is not JSON (is this a Proxmox VE host?)")


def _q(s) -> str:
    return urllib.parse.quote(str(s), safe="")


def _pve_storage_media(api: PVE, node: str, storages: list[dict], errors: list) -> tuple[dict, list]:
    """storage id -> media types of the physical disks behind it, and the node's disks."""
    try:
        disks = api.get(f"/nodes/{_q(node)}/disks/list") or []
    except PermissionError:
        errors.append(f"{node}: no permission to list disks (needs Sys.Audit)"); return {}, []
    except Unreachable as e:
        errors.append(f"{node}: disks: {e}"); return {}, []
    by_name = {}
    for d in disks:
        dev = os.path.basename(d.get("devpath") or "")
        by_name[dev] = d
        if d.get("by_id_link"):
            by_name[os.path.basename(d["by_id_link"])] = d
    node_disks = [{"dev": d.get("devpath"), "model": (d.get("model") or "").strip(), "size_gb": _size_gb(d.get("size")),
                   "media": _media(d), "used": d.get("used") or "", "health": d.get("health") or "",
                   "wearout": d.get("wearout")} for d in disks]

    def leaf_disk(name: str):
        name = os.path.basename(name or "")
        for cand in (name, re.sub(r"(-part|_part|p)?\d+$", "", name)):
            if cand in by_name:
                return by_name[cand]
        return None

    vg_media, pool_media = {}, {}
    try:
        lvm = api.get(f"/nodes/{_q(node)}/disks/lvm") or {}
        for vg in lvm.get("children", []):
            vg_media[vg.get("name")] = sorted({_media(d) for pv in vg.get("children", [])
                                               if (d := leaf_disk(pv.get("name")))})
    except (PermissionError, Unreachable):
        pass
    try:
        for pool in api.get(f"/nodes/{_q(node)}/disks/zfs") or []:
            det = api.get(f"/nodes/{_q(node)}/disks/zfs/{_q(pool['name'])}") or {}
            leaves, stack = [], list(det.get("children", []))
            while stack:
                c = stack.pop()
                (stack.extend(c["children"]) if c.get("children") else leaves.append(c.get("name")))
            pool_media[pool["name"]] = sorted({_media(d) for n in leaves if (d := leaf_disk(n))})
    except (PermissionError, Unreachable):
        pass

    media = {}
    for s in storages:
        t, sid = s.get("type"), s.get("storage")
        if t in ("lvmthin", "lvm"):
            media[sid] = vg_media.get(s.get("vgname"), [])
        elif t == "zfspool":
            media[sid] = pool_media.get(str(s.get("pool", "")).split("/")[0], [])
        elif t in ("nfs", "cifs", "pbs", "rbd", "cephfs", "iscsi", "iscsidirect", "glusterfs"):
            media[sid] = ["network"]
        elif t == "dir" and all(d.get("used") for d in disks) and len({_media(d) for d in disks}) == 1:
            media[sid] = [_media(disks[0])]          # one kind of disk in the node: it must be on that
    return media, node_disks


def proxmox(secure_dir: str, out_dir: str, known_tls: str) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import creds
    doc = creds.load(secure_dir)
    cards = [s for s in doc["sets"] if s["type"] == "proxmox"]
    if not cards:
        print("error\tno Proxmox card"); return 1
    for c in cards:
        r = _proxmox_one(c, out_dir, known_tls)
        print(f"{c['name']}\t{c['fields']['host']}\t{r[0]}\t{r[1]}")
    return 0


def _known(path: str) -> dict:
    out = {}
    try:
        for line in open(path):
            p = line.split()
            if len(p) == 2:
                out[p[0]] = p[1]
    except OSError:
        pass
    return out


def _proxmox_one(card: dict, out_dir: str, known_tls: str) -> tuple[str, str]:
    f = card["fields"]
    host, port = f["host"], int(f.get("port") or 8006)
    hp = f"{host}:{port}"
    known = _known(known_tls)
    expect = _norm_fp(f.get("fingerprint", "")) or known.get(hp)
    api = PVE(host, port, f["token_id"], f["token_secret"], expect)
    errors = []
    try:
        version = api.get("/version") or {}
    except PinError as e:
        return "error", (f"TLS certificate of {hp} changed (now sha256 {e}); if the host was reinstalled, "
                         f"remove its line from config/known_tls")
    except AuthError as e:
        return "auth_failed", str(e)
    except PermissionError:
        return "auth_failed", "token has no access (give it the PVEAuditor role on /)"
    except Unreachable as e:
        return "unreachable", str(e)
    if api.seen_fp and hp not in known:
        fd = os.open(known_tls, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(f"{hp} {api.seen_fp}\n")

    out = {"platform": "proxmox", "host": host, "version": version.get("version"), "nodes": [], "vms": [],
           "errors": errors, "source": "api"}
    try:
        storages = api.get("/storage") or []
    except (PermissionError, Unreachable) as e:
        storages = []
        errors.append(f"storage list: {e} (needs Datastore.Audit)")
    agent_denied = False
    for n in api.get("/nodes") or []:
        node = n.get("node")
        nd = {"name": node, "status": n.get("status"), "cpus": n.get("maxcpu"),
              "memory_gb": round((n.get("maxmem") or 0) / 2**30, 1), "cpu_pct": round((n.get("cpu") or 0) * 100, 1),
              "mem_used_gb": round((n.get("mem") or 0) / 2**30, 1)}
        out["nodes"].append(nd)
        if n.get("status") != "online":
            continue
        media, nd["disks"] = _pve_storage_media(api, node, storages, errors)
        for kind in ("qemu", "lxc"):
            try:
                guests = api.get(f"/nodes/{_q(node)}/{kind}") or []
            except (PermissionError, Unreachable) as e:
                errors.append(f"{node} {kind} list: {e}"); continue
            for g in guests:
                vmid = g.get("vmid")
                if str(g.get("template", "0")) == "1":
                    continue
                try:
                    cfg = api.get(f"/nodes/{_q(node)}/{kind}/{vmid}/config") or {}
                except (PermissionError, Unreachable) as e:
                    errors.append(f"{kind} {vmid} config: {e}"); cfg = {"name": g.get("name")}
                vm = config_vm(kind, vmid, cfg, media, {"platform": "proxmox", "hypervisor": host, "node": node,
                                                         "source": "api"})
                vm.update(status=g.get("status"), uptime_s=g.get("uptime"),
                          cpu_pct=round((g.get("cpu") or 0) * 100, 1) if g.get("status") == "running" else None,
                          mem_used_mb=round((g.get("mem") or 0) / 2**20) if g.get("status") == "running" else None)
                if not vm.get("vcpus"):
                    vm["vcpus"] = g.get("cpus")
                if g.get("status") == "running":
                    if kind == "lxc":
                        try:
                            for itf in api.get(f"/nodes/{_q(node)}/lxc/{vmid}/interfaces") or []:
                                for a in itf.get("ip-addresses", []) or []:
                                    if a.get("ip-address-type") == "inet" and not a["ip-address"].startswith("127."):
                                        vm["ips"].append(a["ip-address"])
                        except (PermissionError, Unreachable):
                            pass
                    elif vm["agent"] == "configured" and not agent_denied:
                        agent_denied = _agent(api, node, vmid, vm)
                vm["ips"] = sorted(set(vm["ips"]))
                out["vms"].append(vm)
    if agent_denied:
        errors.append("guest agent details need VM.GuestAgent.Audit (PVE 9) or VM.Monitor (PVE 8) on the token")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, f"proxmox-{host}.json"), "w") as fh:
        json.dump(out, fh, indent=1)
    return "ok", f"{len(out['vms'])} guest(s) on {len(out['nodes'])} node(s)" + (f"; {len(errors)} note(s)" if errors else "")


def _agent(api: PVE, node: str, vmid, vm: dict) -> bool:
    """Read-only guest agent calls. Returns True when the token may not use them."""
    base = f"/nodes/{_q(node)}/qemu/{vmid}/agent"
    try:
        osi = (api.get(f"{base}/get-osinfo") or {}).get("result", {})
        vm["os"] = osi.get("pretty-name") or osi.get("name") or vm.get("os")
        vm["agent"] = "running"
    except PermissionError:
        return True
    except Unreachable:
        vm["agent"] = "configured, not answering"
        return False
    try:
        for itf in (api.get(f"{base}/network-get-interfaces") or {}).get("result", []):
            if itf.get("name") == "lo":
                continue
            for a in itf.get("ip-addresses", []) or []:
                if a.get("ip-address-type") == "ipv4":
                    vm["ips"].append(a["ip-address"])
    except (PermissionError, Unreachable):
        pass
    try:
        vm["fs"] = [{"mount": f.get("mountpoint"), "type": f.get("type"),
                     "size_gb": _size_gb(f.get("total-bytes")), "used_gb": _size_gb(f.get("used-bytes"))}
                    for f in (api.get(f"{base}/get-fsinfo") or {}).get("result", [])
                    if f.get("total-bytes") and f.get("type") not in ("squashfs", "tmpfs", "overlay")][:20]
    except (PermissionError, Unreachable):
        pass
    return False


# ── the SSH collection (scan_auth.sh "=== hypervisor ===") ───────────────────
def _blocks(text: str) -> list[tuple[str, list[str]]]:
    out, cur = [], None
    for line in text.splitlines():
        if line.startswith("--- "):
            cur = (line[4:].strip(), []); out.append(cur)
        elif cur is not None:
            cur[1].append(line)
    return out


def _lsblk(lines: list[str]) -> dict:
    """lsblk -P rows by device name."""
    rows = {}
    for l in lines:
        r = {k.lower(): v for k, v in re.findall(r'(\w+)="([^"]*)"', l)}
        if r.get("name"):
            rows[r["name"]] = r
    return rows


def _phys(rows: dict, dev: str) -> dict | None:
    """Follow PKNAME up to the physical disk (partition -> disk, LV -> PV -> disk)."""
    name, seen = os.path.basename(dev or ""), set()
    while name in rows and name not in seen:
        seen.add(name)
        r = rows[name]
        if r.get("type") == "disk":
            return r
        name = r.get("pkname") or ""
    return None


def _mount_dev(df_lines: list[str], path: str) -> str | None:
    best, dev = "", None
    for l in df_lines:
        p = l.split()
        if len(p) >= 2 and p[0].startswith("/dev/") and path.startswith(p[-1]) and len(p[-1]) > len(best):
            best, dev = p[-1], p[0]
    return dev


def parse_ssh(ip: str, section: str) -> dict | None:
    """The "=== hypervisor ===" text of one host -> {platform, host, version, vms, nodes} or None."""
    if not section or "platform " not in section:
        return None
    head = [l for l in section.splitlines() if l.startswith("platform ")]
    blocks = _blocks(section)
    b = {}
    for name, lines in blocks:
        b.setdefault(name.split()[0], []).append((name, lines))
    lsrows = _lsblk(next((ls for _, ls in b.get("lsblk", [])), []))
    df = next((ls for _, ls in b.get("df", [])), [])

    def media_of_dev(dev):
        r = _phys(lsrows, dev)
        return _media(r) if r else None

    vms, platform, version = [], None, ""
    # Proxmox: qm / pct configs, storage.cfg, pvs, zpool
    if any(h.startswith("platform proxmox") for h in head):
        platform = "proxmox"
        version = next(h for h in head if h.startswith("platform proxmox"))[len("platform proxmox"):].strip()
        m = re.search(r"pve-manager/([\d.]+)", version)
        version = m.group(1) if m else version[:40]
        storages, cur = {}, None
        for l in next((ls for _, ls in b.get("storage", [])), []):
            m = re.match(r"^(\w+):\s*(\S+)", l)
            if m:
                cur = storages.setdefault(m.group(2), {"type": m.group(1)})
            elif cur is not None and l.strip():
                k, _, v = l.strip().partition(" ")
                cur[k] = v.strip()
        vg_pvs = {}
        for l in next((ls for _, ls in b.get("pvs", [])), []):
            p = l.split()
            if len(p) == 2:
                vg_pvs.setdefault(p[1], []).append(p[0])
        pools, pool = {}, None
        for l in next((ls for _, ls in b.get("zpool", [])), []):
            if not l.strip():
                continue
            if not l.startswith("\t"):
                pool = l.split("\t")[0].strip(); pools[pool] = []
            elif pool:
                pools[pool] += [x.strip() for x in l.split("\t") if x.strip().startswith("/dev/")][:1]
        media = {}
        for sid, s in storages.items():
            t = s["type"]
            if t in ("lvmthin", "lvm"):
                devs = vg_pvs.get(s.get("vgname", ""), [])
            elif t == "zfspool":
                devs = pools.get(s.get("pool", "").split("/")[0], [])
            elif t in ("dir", "btrfs"):
                d = _mount_dev(df, s.get("path", ""))
                devs = [d] if d else []
            elif t in ("nfs", "cifs", "pbs", "rbd", "cephfs", "iscsi", "iscsidirect", "glusterfs"):
                media[sid] = ["network"]; continue
            else:
                devs = []
            media[sid] = sorted({m for d in devs if (m := media_of_dev(d))})
        status = {}
        for name, lines in b.get("list", []):
            for l in lines:
                p = l.split()
                if p and p[0].isdigit():
                    kind = name.split()[1] if len(name.split()) > 1 else "qemu"
                    st = p[2] if kind == "qemu" else p[1]
                    status[(kind, p[0])] = st
        for kind in ("qemu", "lxc"):
            for name, lines in b.get(kind, []):
                vmid = name.split()[1] if len(name.split()) > 1 else "?"
                cfg = {}
                for l in lines:
                    if l.startswith("["):              # snapshot sections follow the live config
                        break
                    k, sep, v = l.partition(":")
                    if sep and re.match(r"^[\w-]+$", k):
                        cfg[k] = v.strip()
                if cfg.get("template") == "1":
                    continue
                vm = config_vm(kind, vmid, cfg, media, {"platform": "proxmox", "hypervisor": ip, "node": "",
                                                         "source": "ssh"})
                vm["status"] = status.get((kind, vmid), "")
                vms.append(vm)
    # libvirt: virsh dominfo / domblklist --details / domiflist
    if any(h.startswith("platform libvirt") for h in head):
        platform = platform or "libvirt"
        for name, lines in b.get("domain", []):
            info, disks, nics, section_ = {}, [], [], "info"
            for l in lines:
                if l.startswith("# "):
                    section_ = l[2:].strip(); continue
                if section_ == "info":
                    k, sep, v = l.partition(":")
                    if sep:
                        info[k.strip().lower()] = v.strip()
                elif section_ == "blk":
                    p = l.split(None, 3)
                    if len(p) == 4 and p[1] == "disk" and p[0] in ("file", "block", "volume", "network"):
                        src = p[3]
                        dev = src if p[0] == "block" else _mount_dev(df, src)
                        m = ["network"] if p[0] == "network" else ([x] if (x := media_of_dev(dev or "")) else ["unknown"])
                        disks.append({"id": p[2], "size_gb": None, "storage": os.path.dirname(src) if p[0] == "file" else p[0],
                                      "media": m, "emulated_ssd": False, "path": src})
                elif section_ == "sizes":
                    p = l.split()
                    if len(p) == 2 and p[1].isdigit():
                        for d in disks:
                            if d["id"] == p[0]:
                                d["size_gb"] = _size_gb(int(p[1]))
                elif section_ == "nics":
                    p = l.split()
                    if len(p) == 5 and re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", p[4], re.I):
                        nics.append({"mac": p[4].lower(), "bridge": p[2], "model": p[3]})
            mem = re.match(r"(\d+)", info.get("max memory", ""))
            vms.append({"platform": "libvirt", "hypervisor": ip, "node": "", "source": "ssh",
                        "id": info.get("id", "-") if info.get("id", "-") != "-" else info.get("uuid", "")[:8],
                        "kind": "libvirt", "name": info.get("name") or name.split()[-1],
                        "status": info.get("state", ""), "vcpus": int(info["cpu(s)"]) if info.get("cpu(s)", "").isdigit() else None,
                        "memory_mb": round(int(mem.group(1)) / 1024) if mem else None, "os": None, "agent": "",
                        "disks": disks, "nics": nics, "ips": []})
    if not platform:
        return None
    return {"platform": platform, "host": ip, "version": version, "vms": vms, "nodes": [], "errors": [],
            "source": "ssh"}


# ── joining VMs with the scanned hosts ───────────────────────────────────────
def guess_from_mac(mac: str | None) -> str | None:
    return VM_MAC_PREFIXES.get((mac or "").lower()[:8])


def merge(hosts: dict, vm_dir: str | None, ssh_sections: dict) -> tuple[list[dict], list[dict]]:
    """Fill host["vm"] / host["hypervisor"], return (vms, hypervisors).

    hosts: ip -> host dict (from build_json); ssh_sections: ip -> "=== hypervisor ===" text."""
    invs = []
    if vm_dir and os.path.isdir(vm_dir):
        for fn in sorted(os.listdir(vm_dir)):
            if fn.endswith(".json"):
                try:
                    invs.append(json.load(open(os.path.join(vm_dir, fn))))
                except (OSError, ValueError):
                    pass
    api_hosts = {i["host"] for i in invs}
    for ip, sec in ssh_sections.items():
        inv = parse_ssh(ip, sec)
        if not inv:
            continue
        if ip in api_hosts:
            # the API already listed these guests: borrow only the disk media it could not work out
            api = next(i for i in invs if i["host"] == ip)
            by = {(v["kind"], v["id"]): v for v in inv["vms"]}
            for v in api["vms"]:
                s = by.get((v["kind"], v["id"]))
                for d in v.get("disks", []):
                    sd = next((x for x in (s or {}).get("disks", []) if x["id"] == d["id"]), None)
                    if sd and d.get("media") in ([], ["unknown"]) and sd.get("media"):
                        d["media"] = sd["media"]
        else:
            invs.append(inv)

    by_mac = {h["mac"].lower(): h for h in hosts.values() if h.get("mac")}
    vms, hypervisors = [], []
    for inv in invs:
        hv = hosts.get(inv["host"])
        hypervisors.append({"host": inv["host"], "platform": inv["platform"], "version": inv.get("version"),
                            "source": inv.get("source"), "nodes": inv.get("nodes", []), "vms": len(inv["vms"]),
                            "errors": inv.get("errors", [])})
        if hv is not None:
            hv["hypervisor"] = {"platform": inv["platform"], "version": inv.get("version"), "vms": len(inv["vms"]),
                                "running": sum(1 for v in inv["vms"] if v.get("status") == "running")}
        for v in inv["vms"]:
            h = next((by_mac[n["mac"]] for n in v.get("nics", []) if n.get("mac") in by_mac), None)
            if h is None:
                h = next((hosts[i] for i in v.get("ips", []) if i in hosts), None)
            if h is not None:
                v["host_ip"] = h["ip"]
                h["vm"] = {"platform": inv["platform"], "hypervisor": inv["host"], "name": v["name"],
                           "id": v["id"], "kind": v["kind"], "vcpus": v.get("vcpus"), "memory_mb": v.get("memory_mb"),
                           "disks": v.get("disks", [])}
                sy = h.get("system") or {}
                v["guest"] = {"os": sy.get("os_release") or h.get("os"),
                              "ports": [p["port"] for p in h.get("ports", [])],
                              "apps": [a["name"] for a in h.get("apps", [])],
                              "services": sy.get("services", []),
                              "packages": (sy.get("packages") or {}).get("count"),
                              "docker": [c["name"] for c in sy.get("docker", [])],
                              "logged_in": bool(sy)}
                if v["guest"]["os"] and (not v.get("os") or v.get("agent") != "running"):
                    v["os"] = v["guest"]["os"]           # the guest's own answer beats the hypervisor's OS type
            vms.append(v)
    for h in hosts.values():
        if "vm" not in h and (g := guess_from_mac(h.get("mac"))):
            h["vm_guess"] = g
    vms.sort(key=lambda v: (v["hypervisor"], v.get("node") or "", int(v["id"]) if str(v["id"]).isdigit() else 0, v["name"]))
    return vms, hypervisors


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "proxmox":
        sys.exit(proxmox(sys.argv[2], sys.argv[3], sys.argv[4]))
    sys.exit(__doc__)
