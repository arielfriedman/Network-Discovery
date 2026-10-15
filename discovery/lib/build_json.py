#!/usr/bin/env python3
"""Merge every scan artefact into one findings.json.

Reads file paths from the environment (set by summarize.sh) so it stays a
pure data step with no argument plumbing. Missing inputs are normal - any
stage can be skipped - so every read is tolerant.
"""
import json, os, re, sys, glob, collections

def lines(path):
    if not path or not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [l.rstrip("\n") for l in fh if l.strip() and not l.startswith("###")]

env = os.environ.get

# ---------------------------------------------------------------- hosts
hosts = {}
for line in lines(env("HOSTS")):
    parts = (line.split("\t") + ["", ""])[:3]
    ip, mac, vendor = parts[0].strip(), parts[1].strip(), parts[2].strip()
    if not ip:
        continue
    hosts[ip] = {"ip": ip, "mac": mac or None, "vendor": vendor or None,
                 "hostname": None, "os": None, "ports": [],
                 "mdns": None, "netbios": None, "ssdp": None}

def host(ip):
    return hosts.setdefault(ip, {"ip": ip, "mac": None, "vendor": None,
                                 "hostname": None, "os": None, "ports": [],
                                 "mdns": None, "netbios": None, "ssdp": None})

# ---------------------------------------------------------------- names
for line in lines(env("RDNS")):
    p = line.split("\t")
    if len(p) >= 2:
        host(p[0])["hostname"] = p[1]

for line in lines(env("NETBIOS")):
    p = line.split("\t")
    if len(p) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", p[0]):
        h = host(p[0])
        h["netbios"] = p[1].strip()
        h["hostname"] = h["hostname"] or p[1].strip()

# avahi -p output: +;iface;proto;name;type;domain  /  =;...;address;port;txt
for line in lines(env("MDNS")):
    f = line.split(";")
    if len(f) >= 8 and f[0] == "=":
        addr = next((x for x in f if re.match(r"^\d+\.\d+\.\d+\.\d+$", x)), None)
        if addr:
            h = host(addr)
            name = f[3].replace("\\032", " ")
            h["mdns"] = f"{name} ({f[4]})" if len(f) > 4 else name
            h["hostname"] = h["hostname"] or name

for line in lines(env("SSDP")):
    p = line.split("\t")
    if p and re.match(r"^\d+\.\d+\.\d+\.\d+$", p[0]):
        srv = next((x[7:] for x in p if x.startswith("SERVER=")), "")
        h = host(p[0])
        if srv and not h["ssdp"]:
            h["ssdp"] = srv

# ---------------------------------------------------------------- os
for line in lines(env("OSFILE")):
    p = line.split("\t", 1)
    if len(p) == 2:
        host(p[0])["os"] = p[1].strip()

# ---------------------------------------------------------------- services
for line in lines(env("SERVICES")):
    p = (line.split("\t") + ["", "", ""])[:4]
    ip, port, svc, ver = p[0], p[1], p[2], p[3].strip()
    if not ip or not port:
        continue
    host(ip)["ports"].append({"port": port, "service": svc or "unknown",
                              "version": ver or None})

for h in hosts.values():
    h["ports"].sort(key=lambda x: int(re.match(r"\d+", x["port"]).group()) if re.match(r"\d+", x["port"]) else 0)

# ---------------------------------------------------------------- vendor + device type
# Without root there is no arp-scan, so hosts have a MAC (neighbour table) but
# no vendor: look it up in the local IEEE data. Then classify device types.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import device_types  # noqa: E402
import host_profile  # noqa: E402
import vm_inventory  # noqa: E402
profile_findings = []
hv_sections = {}           # ip -> "=== hypervisor ===" text from the SSH login
http_pages = {}
if env("HTTPJSON") and os.path.exists(env("HTTPJSON")):
    try:
        for r in json.load(open(env("HTTPJSON"))):
            http_pages.setdefault(r["ip"], {})[int(r["port"])] = r
    except (ValueError, KeyError, TypeError):
        pass
for h in hosts.values():
    if h["mac"] and not h["vendor"]:
        if device_types.is_local_mac(h["mac"]):
            h["mac_random"] = True          # randomised / software MAC: no vendor to find
        else:
            h["vendor"] = device_types.vendor_for_mac(h["mac"])
    ssh_text = ""
    if env("SSHDIR"):
        f = os.path.join(env("SSHDIR"), h["ip"].replace(".", "_") + ".txt")
        if os.path.exists(f):
            ssh_text = open(f, encoding="utf-8", errors="replace").read()
            hv = host_profile._ssh_sections(ssh_text).get("hypervisor", "")
            if "platform " in hv:
                hv_sections[h["ip"]] = hv
    xml = os.path.join(env("HOSTSDIR") or "", h["ip"].replace(".", "_") + ".xml") if env("HOSTSDIR") else None
    host_profile.build(h, xml, ssh_text, http_pages.get(h["ip"], {}))        # os (with its source), apps, system, findings
    profile_findings += h.pop("profile_findings", [])
    device_types.classify(h, ssh_text, env("META_GW"))

# ---------------------------------------------------------------- cloud
cloud, cloud_total = {}, 0
cdir = env("CLOUDDIR")
if cdir and os.path.isdir(cdir):
    counters = {
        "aws":   {"aws-vpcs.json": ("VPCs", "Vpcs"),
                  "aws-subnets.json": ("Subnets", "Subnets"),
                  "aws-instances.json": ("EC2 instances", "Reservations"),
                  "aws-sgs.json": ("Security groups", "SecurityGroups"),
                  "aws-elb.json": ("Load balancers", "LoadBalancers"),
                  "aws-dns.json": ("Route53 zones", "HostedZones")},
        "azure": {"az-vnets.json": ("Virtual networks", None),
                  "az-nsgs.json": ("Network security groups", None),
                  "az-vms.json": ("Virtual machines", None),
                  "az-pips.json": ("Public IPs", None)},
        "gcp":   {"gcp-networks.json": ("Networks", None),
                  "gcp-subnets.json": ("Subnets", None),
                  "gcp-instances.json": ("Instances", None),
                  "gcp-firewall.json": ("Firewall rules", None)},
    }
    for prov, files in counters.items():
        got = {}
        for fname, (label, key) in files.items():
            path = os.path.join(cdir, fname)
            if not os.path.exists(path):
                continue
            try:
                raw = open(path, encoding="utf-8", errors="replace").read()
                raw = raw[raw.index("{") if "{" in raw else raw.index("["):] if ("{" in raw or "[" in raw) else raw
                data = json.loads(raw)
            except Exception:
                continue
            if key and isinstance(data, dict):
                n = len(data.get(key, []))
                if key == "Reservations":
                    n = sum(len(r.get("Instances", [])) for r in data.get(key, []))
            elif isinstance(data, list):
                n = len(data)
            elif isinstance(data, dict):
                n = len(next((v for v in data.values() if isinstance(v, list)), []))
            else:
                n = 0
            got[label] = n
            cloud_total += n
        if got:
            cloud[prov] = got
    # REST API providers (lib/cloud_api.py)
    for f in sorted(glob.glob(os.path.join(cdir, "api-*.json"))):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        if d.get("counts"):
            cloud[d.get("label") or d.get("provider")] = d["counts"]
            cloud_total += sum(d["counts"].values())
    for f in glob.glob(os.path.join(cdir, "k8s-*.txt")):
        n = max(0, len(lines(f)) - 1)
        cloud.setdefault("kubernetes", {})[os.path.basename(f)[4:-4]] = n
        cloud_total += n

# ---------------------------------------------------------------- notable
# With --targets only the requested hosts belong in the report: mDNS / SSDP /
# NetBIOS answers name them but must not add other hosts from the network.
targets = []
if env("TARGETS"):
    listed = {(l.split("\t") + [""])[0].strip() for l in lines(env("HOSTS"))}
    hosts = {ip: h for ip, h in hosts.items() if ip in listed}
    for line in lines(env("TARGETS")):
        p = (line.split("\t") + [""] * 6)[:6]
        targets.append(dict(zip(("kind", "value", "source", "ip", "status", "detail"), p)))

# ---------------------------------------------------------------- virtual machines
# Hypervisor inventories (Proxmox API, qm/pct or virsh over SSH) joined with the
# hosts above: a VM row gets the guest's ports, apps and services, a host row
# learns which VM it is (lib/vm_inventory.py).
vms, hypervisors = vm_inventory.merge(hosts, env("VMDIR"), hv_sections)

notable = []
RISKY = {"23": "telnet", "21": "ftp", "445": "smb", "3389": "rdp",
         "5900": "vnc", "1900": "upnp", "161": "snmp", "11211": "memcached",
         "6379": "redis", "27017": "mongodb", "3306": "mysql", "5432": "postgres"}
seen_risky = collections.defaultdict(list)
for h in hosts.values():
    for p in h["ports"]:
        num = p["port"].split("/")[0]
        if num in RISKY:
            seen_risky[RISKY[num]].append(h["ip"])
for svc, ips in sorted(seen_risky.items()):
    lvl = "warn" if svc in ("telnet", "ftp", "vnc", "rdp", "smb") else "info"
    notable.append({"level": lvl,
                    "text": f"{svc} reachable on {len(ips)} host(s): {', '.join(ips[:5])}"
                            + (" ..." if len(ips) > 5 else "")})

unnamed = [h for h in hosts.values() if not h["hostname"] and not h["vendor"]]
if unnamed:
    notable.append({"level": "info",
                    "text": f"{len(unnamed)} host(s) gave no name and no vendor - worth identifying"})

open_sgs = lines(env("AWSOPEN"))
if open_sgs:
    notable.append({"level": "warn",
                    "text": f"{len(open_sgs)} AWS security-group rule(s) allow 0.0.0.0/0"})

# ---------------------------------------------------------------- aggregates
vendor_counts = collections.Counter(
    (h["vendor"] or "unknown").split(",")[0][:28] for h in hosts.values())
port_counts = collections.Counter(
    f"{p['port']} {p['service']}" for h in hosts.values() for p in h["ports"])
os_counts = collections.Counter()
for h in hosts.values():
    if h["os"]:
        fam = re.split(r"[,(]", h["os"])[0].strip()[:30]
        os_counts[fam or "unknown"] += 1
    else:
        os_counts["unidentified"] += 1

# ---------------------------------------------------------------- listed targets
if targets:
    missing = [t for t in targets if t["status"] in ("no_response", "unresolved", "not_seen")]
    if missing:
        notable.append({"level": "info",
                        "text": f"{len(missing)} listed target(s) not found: "
                                + ", ".join(t["value"] for t in missing[:5])
                                + (" ..." if len(missing) > 5 else "")})

# ---------------------------------------------------------------- logins
# one row per login attempt (scan_auth.sh / scan_cloud.sh); never secrets
credential_use = []
for line in lines(env("CREDUSE")):
    p = (line.split("\t") + [""] * 5)[:5]
    credential_use.append(dict(zip(("type", "name", "host", "result", "detail"), p)))
failed = [c for c in credential_use if c["result"] == "auth_failed"]
if failed:
    notable.append({"level": "warn",
                    "text": f"{len(failed)} login(s) rejected: "
                            + ", ".join(f"{c['name']} on {c['host']}" for c in failed[:4])
                            + (" ..." if len(failed) > 4 else "")})

# ---------------------------------------------------------------- host profiles
listed_ips = set(hosts)
for f in profile_findings:
    if f["text"].split(":")[0] in listed_ips:
        notable.append(f)
for hv in hypervisors:
    run = sum(1 for v in vms if v["hypervisor"] == hv["host"] and v.get("status") == "running")
    notable.append({"level": "info", "text": f"{hv['host']}: {hv['platform']} hypervisor with {hv['vms']} VM(s)/container(s), "
                                             f"{run} running (from the {'API' if hv['source'] == 'api' else 'SSH login'})"})
    for e in hv.get("errors", [])[:3]:
        notable.append({"level": "info", "text": f"{hv['host']}: VM inventory incomplete - {e}"})
unmatched = [v for v in vms if v.get("status") == "running" and not v.get("host_ip")]
if unmatched:
    notable.append({"level": "info", "text": f"{len(unmatched)} running VM(s) not seen on the scanned network: "
                    + ", ".join(v["name"] for v in unmatched[:5]) + (" ..." if len(unmatched) > 5 else "")})
guessed = [h for h in hosts.values() if h.get("vm_guess")]
if guessed and not hypervisors:
    notable.append({"level": "info", "text": f"{len(guessed)} host(s) look like VMs by their MAC address "
                    "- add a Proxmox card or an SSH login to the hypervisor for CPU, memory and disk details"})
app_counts = collections.Counter(a["name"] for h in hosts.values() for a in h.get("apps", [])
                                 if a["category"] != "web app")

# ---------------------------------------------------------------- device types
type_counts = collections.Counter(h["device_type"] for h in hosts.values() if h.get("device_type"))
pis = [h for h in hosts.values() if h.get("device_type") == "Raspberry Pi"]
if pis:
    notable.append({"level": "info",
                    "text": f"{len(pis)} Raspberry Pi(s): " + ", ".join(
                        h["ip"] + (f" ({h['device_model']})" if h.get("device_model") else "")
                        + ("" if h["device_confidence"] == "high" else f" [{h['device_confidence']} confidence]")
                        for h in pis[:6]) + (" ..." if len(pis) > 6 else "")})

host_list = sorted(hosts.values(),
                   key=lambda h: [int(x) for x in h["ip"].split(".")] if re.match(r"^\d+\.\d+\.\d+\.\d+$", h["ip"]) else [0, 0, 0, 0])

out = {
    "meta": {
        "run_id": env("META_ID", ""),
        "started": env("META_START", ""),
        "target": (f"{len(targets)} listed target(s)" if targets else env("META_CIDR", "")),
        "mode": "targets" if targets else "network",
        "local_net": env("META_CIDR", ""),
        "interface": env("META_IFACE", ""),
        "gateway": env("META_GW", ""),
        "scanner_ip": env("META_SELF", ""),
    },
    "stats": {
        "hosts": len(hosts),
        "services": sum(len(h["ports"]) for h in hosts.values()),
        "distinct_ports": len(port_counts),
        "named_hosts": sum(1 for h in hosts.values() if h["hostname"]),
        "vendors": len([v for v in vendor_counts if v != "unknown"]),
        "cloud_resources": cloud_total,
        "vms": len(vms),
        "hypervisors": len(hypervisors),
    },
    "hosts": host_list,
    "top_ports": [{"label": k, "count": v} for k, v in port_counts.most_common(12)],
    "vendors": [{"label": k, "count": v} for k, v in vendor_counts.most_common(10)],
    "os_families": [{"label": k, "count": v} for k, v in os_counts.most_common(8)],
    "device_types": [{"label": k, "count": v} for k, v in type_counts.most_common()],
    "apps": [{"label": k, "count": v} for k, v in app_counts.most_common(15)],
    "cloud": cloud,
    "vms": vms,
    "hypervisors": hypervisors,
    "notable": notable,
    "targets": targets,
    "credential_use": credential_use,
}
print(json.dumps(out, indent=2))
