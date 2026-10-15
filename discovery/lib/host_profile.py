"""Host profiles: what runs on a host, worked out from what the scan saw.

Used by build_json.py. Reads nmap's XML per host (product, version, CPE,
script output such as web page titles and certificates) and, when an SSH
login card worked, the collected system details. Produces for each host:

  os, os_source, os_confidence      best OS guess and the clue it came from
  apps   [{name, port, category, evidence}]   recognised software / web apps
  system {os_release, kernel, model, cpu, memory, services, docker, kubernetes,
          virtualization, disks [{name, media, size_gb, model}], packages {manager, count, installed, snap, flatpak}}
                                    only from an SSH login
  findings [{level, text}]          things worth a look (e.g. open Docker API)

Every guess carries the clue it was based on, so the report can say why.
"""
from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET

# ── OS from service banners ──────────────────────────────────────────────────
# OpenSSH version shipped by each Ubuntu release (the package suffix,
# e.g. "3ubuntu13", changes with updates; the upstream version does not).
UBUNTU_OPENSSH = {"7.6p1": "18.04", "8.2p1": "20.04", "8.9p1": "22.04",
                  "9.6p1": "24.04", "9.7p1": "24.10", "9.9p1": "25.04"}
# Windows build number -> name (from RDP / SMB NTLM info)
WINDOWS_BUILDS = [(26100, "Windows 11 24H2 / Server 2025"), (22631, "Windows 11 23H2"), (22621, "Windows 11 22H2"),
                  (22000, "Windows 11"), (20348, "Windows Server 2022"), (19041, "Windows 10"),
                  (17763, "Windows Server 2019 / Windows 10 1809"), (14393, "Windows Server 2016"),
                  (9600, "Windows Server 2012 R2 / 8.1"), (7601, "Windows 7 / Server 2008 R2")]


def os_from_banner(product: str, version: str, extrainfo: str) -> tuple[str, str] | None:
    """(os, evidence) from one service, or None."""
    text = f"{product} {version} {extrainfo}"
    if product == "OpenSSH":
        m = re.match(r"(\d+\.\d+p\d+)\s+Ubuntu", version or "")
        if m:
            rel = UBUNTU_OPENSSH.get(m.group(1))
            return (f"Ubuntu {rel}" if rel else "Ubuntu", f"SSH: {product} {version}")
        m = re.search(r"\+deb(\d+)u", version or "")
        if m:
            return (f"Debian {m.group(1)}", f"SSH: {product} {version}")
        if "Debian" in text:
            return ("Debian", f"SSH: {product} {version}")
        if "FreeBSD" in text:
            return ("FreeBSD", f"SSH: {product} {version}")
    m = re.search(r"\((Ubuntu|Debian|CentOS|Red Hat|Fedora|Raspbian)\)", text)
    if m:
        return (m.group(1), f"{product or 'service'} banner: {text.strip()[:80]}")
    if "Microsoft-IIS" in text or "Microsoft HTTPAPI" in text:
        return ("Windows", f"web server: {text.strip()[:60]}")
    return None


def windows_from_build(s: str) -> str | None:
    m = re.search(r"10\.0\.(\d{4,5})", s or "") or re.search(r"6\.\d\.(\d{4})", s or "")
    if not m:
        return None
    b = int(m.group(1))
    for build, name in WINDOWS_BUILDS:
        if b >= build:
            return f"{name} (build {b})"
    return f"Windows (build {b})"


# ── apps ─────────────────────────────────────────────────────────────────────
# (name, category, regex on "title | server | product version | headers", ports it is usually on or None)
APPS = [
    ("Uptime Kuma", "monitoring", r"uptime kuma", {3001}),
    ("Grafana", "monitoring", r"grafana", None),
    ("Prometheus", "monitoring", r"prometheus", None),
    ("Zabbix", "monitoring", r"zabbix", None),
    ("Home Assistant", "smart home", r"home assistant", None),
    ("Node-RED", "smart home", r"node-red", None),
    ("Pi-hole", "network", r"pi-hole", None),
    ("AdGuard Home", "network", r"adguard", None),
    ("Nginx Proxy Manager", "network", r"nginx proxy manager", None),
    ("Traefik", "network", r"traefik", None),
    ("UniFi Network", "network", r"unifi", None),
    ("Portainer", "containers", r"portainer", None),
    ("Cockpit", "admin", r"cockpit", None),
    ("Webmin", "admin", r"webmin|MiniServ", None),
    ("Jellyfin", "media", r"jellyfin", None),
    ("Plex", "media", r"plex", {32400}),
    ("Emby", "media", r"emby", None),
    ("Nextcloud", "files", r"nextcloud", None),
    ("Synology DSM", "NAS", r"synology|DiskStation", None),
    ("TrueNAS", "NAS", r"truenas|freenas", None),
    ("OctoPrint", "3D printing", r"octoprint", None),
    ("Gitea", "dev", r"gitea", None),
    ("GitLab", "dev", r"gitlab", None),
    ("Jenkins", "dev", r"jenkins", None),
    ("Vaultwarden", "security", r"vaultwarden|bitwarden", None),
    ("Mosquitto MQTT", "smart home", r"mosquitto|mqtt", {1883, 8883}),
    ("PostgreSQL", "database", r"postgresql", {5432}),
    ("MySQL / MariaDB", "database", r"mysql|mariadb", {3306}),
    ("Redis", "database", r"redis", {6379}),
    ("MongoDB", "database", r"mongodb", {27017}),
    ("Samba / Windows shares", "files", r"samba|microsoft-ds|netbios-ssn", {139, 445}),
    ("CUPS / IPP printing", "printing", r"\bcups\b|\bipp\b", {631}),
]


def _ports(xml_path: str) -> tuple[list[dict], dict]:
    """Ports with product details and script output, plus host-level script output."""
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError):
        return [], {}
    host = root.find("host")
    if host is None:
        return [], {}
    out = []
    for p in host.findall("ports/port"):
        st = p.find("state")
        if st is None or st.get("state") != "open":
            continue
        s = p.find("service")
        d = {"port": int(p.get("portid")), "proto": p.get("protocol"),
             "service": s.get("name", "") if s is not None else "",
             "product": s.get("product", "") if s is not None else "",
             "version": s.get("version", "") if s is not None else "",
             "extrainfo": s.get("extrainfo", "") if s is not None else "",
             "ostype": s.get("ostype", "") if s is not None else "",
             "tunnel": s.get("tunnel", "") if s is not None else "",
             "cpe": [c.text for c in (s.findall("cpe") if s is not None else []) if c.text],
             "scripts": {sc.get("id"): (sc.get("output") or "").strip() for sc in p.findall("script")}}
        out.append(d)
    hostscripts = {sc.get("id"): (sc.get("output") or "").strip() for sc in host.findall("hostscript/script")}
    return out, hostscripts


def _title(p: dict) -> str:
    t = p["scripts"].get("http-title", "")
    t = re.sub(r"^\s*Did not follow redirect to .*$", "", t, flags=re.M).strip()
    return t.splitlines()[0][:100] if t else ""


def _ssh_sections(text: str) -> dict:
    """=== name === blocks from the SSH collection."""
    out, cur = {}, None
    for line in (text or "").splitlines():
        m = re.match(r"^=== (.+) ===$", line.strip())
        if m:
            cur = m.group(1); out[cur] = []
        elif cur:
            out[cur].append(line)
    return {k: "\n".join(v).strip() for k, v in out.items()}


def build(h: dict, xml_path: str | None, ssh_text: str = "", http: dict | None = None) -> None:
    """Fill in os / apps / system / findings on host dict h."""
    ports, hostscripts = _ports(xml_path) if xml_path and os.path.exists(xml_path) else ([], {})
    apps, findings, os_votes = [], [], []

    # OS: nmap's own fingerprint (root) stays first; banners and protocols otherwise
    if h.get("os"):
        os_votes.append((h["os"], "nmap OS fingerprint", "high"))
    for p in ports:
        g = os_from_banner(p["product"], p["version"], p["extrainfo"])
        if g:
            os_votes.append((g[0], g[1], "medium"))
        for c in p["cpe"]:
            if c.startswith("cpe:/o:microsoft:windows"):
                os_votes.append(("Windows", f"service CPE {c}", "medium"))
        for sid in ("rdp-ntlm-info", "smb-os-discovery"):
            w = windows_from_build(p["scripts"].get(sid, "") or hostscripts.get(sid, ""))
            if w:
                os_votes.append((w, sid.replace("-", " "), "high"))
    for sid, out in hostscripts.items():
        if sid == "smb-os-discovery":
            m = re.search(r"OS: (.+)", out)
            if m:
                os_votes.append((m.group(1).strip(), "SMB OS discovery", "high"))

    # apps
    for p in ports:
        page = (http or {}).get(p["port"], {})
        title = _title(p) or page.get("title", "")
        server = p["scripts"].get("http-server-header", "") or page.get("server", "")
        hay = " | ".join(x for x in (title, server, p["product"], p["version"], p["extrainfo"],
                                     p["scripts"].get("fingerprint-strings", "")[:2000]) if x)
        hit = None
        named = " | ".join(x for x in (title, server, p["product"], p["extrainfo"]) if x)
        for name, cat, rx, usual in APPS:
            if re.search(rx, named, re.I):                      # named by title / server / product
                hit = (name, cat, ""); break
            if usual and p["port"] in usual and re.search(rx, hay, re.I):
                hit = (name, cat, " (likely)"); break           # only the usual port + a response pattern
        if hit:
            apps.append({"name": hit[0] + hit[2], "category": hit[1], "port": p["port"],
                         "evidence": (title or server or f"{p['product']} {p['version']}".strip()
                                      or f"port {p['port']} answers like {hit[0]}")[:100]})
        elif title:
            apps.append({"name": title, "category": "web app", "port": p["port"],
                         "evidence": f"page title on port {p['port']}"
                                     + (f" ({p['product']})" if p["product"] else "")})
        elif p["product"] and not re.search(r"ssh", p["product"] + p["service"], re.I):
            apps.append({"name": f"{p['product']} {p['version']}".strip()[:60], "category": p["service"] or "service",
                         "port": p["port"], "evidence": "service version detection"})

        # containers / Kubernetes seen from the network
        if p["port"] in (2375, 2376) and ("docker" in hay.lower() or p["service"] in ("docker", "http")):
            apps.append({"name": "Docker Engine API", "category": "containers", "port": p["port"], "evidence": hay[:80]})
            if p["port"] == 2375 and not p["tunnel"]:
                findings.append({"level": "high", "text": f"{h['ip']}: Docker API open without TLS on port 2375 "
                                 "- anyone on the network can run containers as root"})
        if p["port"] in (6443, 16443) or "kubernetes" in hay.lower() or "k3s" in hay.lower():
            apps.append({"name": "Kubernetes API server" + (" (microk8s)" if p["port"] == 16443 else ""),
                         "category": "containers", "port": p["port"], "evidence": hay[:80] or f"port {p['port']}"})
        if p["port"] == 10250:
            apps.append({"name": "Kubernetes kubelet", "category": "containers", "port": 10250, "evidence": "port 10250"})
        if p["port"] in (2379, 2380) and ("etcd" in hay.lower() or not hay):
            apps.append({"name": "etcd", "category": "containers", "port": p["port"], "evidence": hay[:80] or "port 2379"})
            findings.append({"level": "warn", "text": f"{h['ip']}: etcd reachable on port {p['port']} (Kubernetes state store)"})

    # system details from an SSH login
    system = {}
    sec = _ssh_sections(ssh_text)
    if sec:
        m = re.search(r'PRETTY_NAME="?([^"\n]+)', sec.get("os", ""))
        if m:
            system["os_release"] = m.group(1).strip()
            os_votes.insert(0, (system["os_release"], "SSH login: /etc/os-release", "high"))
        if sec.get("uname"):
            system["kernel"] = sec["uname"].split("\n")[0][:160]
        if sec.get("model") and "No such" not in sec["model"]:
            system["model"] = sec["model"].strip("\x00 ")[:100]
        for k in ("cpu", "memory", "uptime"):
            if sec.get(k):
                system[k] = sec[k].split("\n")[0][:120]
        if sec.get("services"):
            system["services"] = [s.split()[0].replace(".service", "") for s in sec["services"].splitlines() if s.strip()][:80]
        cont = sec.get("containers", "")
        if cont and "no docker" not in cont:
            rows = [r.split("\t") for r in cont.splitlines() if r.strip() and "\t" in r]
            system["docker"] = [{"name": r[0], "image": r[1] if len(r) > 1 else "", "status": r[2] if len(r) > 2 else "",
                                 "ports": r[3] if len(r) > 3 else ""} for r in rows][:100]
        virt = sec.get("virt", "").strip()
        if virt and virt != "none":
            system["virtualization"] = virt.split("\n")[0][:40]       # systemd-detect-virt: kvm, vmware, lxc, ...
        disks = []
        for line in sec.get("disks", "").splitlines():
            r = {k.lower(): v for k, v in re.findall(r'(\w+)="([^"]*)"', line)}
            if not r.get("name"):
                continue
            tran, rota = r.get("tran", "").lower(), r.get("rota")
            media = ("nvme" if tran == "nvme" or r["name"].startswith("nvme") else "usb" if tran == "usb"
                     else "ssd" if rota == "0" else "hdd" if rota == "1" else "unknown")
            model = r.get("model", "").strip()
            # inside a VM the "disk" is whatever the hypervisor emulates; the hypervisor knows the real media
            if re.search(r"QEMU|VMware|Virtual|VBOX|Msft", model, re.I) or r["name"].startswith(("vd", "xvd")):
                media = "virtual"
            size = int(r["size"]) if r.get("size", "").isdigit() else 0
            disks.append({"name": r["name"], "media": media, "size_gb": round(size / 1e9, 1), "model": model[:60]})
        if disks:
            system["disks"] = disks[:40]
        pk = sec.get("packages", "")
        m = re.match(r"manager (\w+) (\d+)", pk)
        if m:
            rest = [l.strip() for l in pk.splitlines()[1:] if l.strip()]
            system["packages"] = {"manager": m.group(1), "count": int(m.group(2)),
                                  "installed": [l for l in rest if ":" not in l][:400],
                                  "snap": [l[5:] for l in rest if l.startswith("snap:")][:100],
                                  "flatpak": [l[8:] for l in rest if l.startswith("flatpak:")][:100]}
        k8s = sec.get("kubernetes", "")
        if k8s and "none" not in k8s.lower():
            system["kubernetes"] = [l.strip() for l in k8s.splitlines() if l.strip()][:20]

    if os_votes:
        rank = {"high": 0, "medium": 1, "low": 2}
        best = sorted(os_votes, key=lambda v: rank[v[2]])[0]
        h["os"], h["os_source"], h["os_confidence"] = best[0], best[1], best[2]
    # one entry per (name, port)
    seen, uniq = set(), []
    for a in apps:
        k = (a["name"], a["port"])
        if k not in seen:
            seen.add(k); uniq.append(a)
    h["apps"] = uniq
    if system:
        h["system"] = system
    h["profile_findings"] = findings
