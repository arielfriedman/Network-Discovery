#!/usr/bin/env python3
"""Helpers for scanning a list of targets instead of the whole local range.

  targets_util.py normalize RAW_FILE SETTINGS_CONF > TARGETS_IN
      Classifies and validates a user's list (one IP / CIDR / MAC / hostname
      per line, '#' comments, CSV first column, or lines already in the
      kind<TAB>value<TAB>source format). Invalid lines go to stderr.

  targets_util.py plan   TARGETS_IN WORK "PREFIXES"
      Resolves hostnames, writes WORK/sweep.list (IPs and ranges for nmap -iL)
      and WORK/resolve.tsv (hostname -> IPs). Prints NEED_MAC=0|1.

  targets_util.py finish TARGETS_IN WORK RAW PN
      After the sweeps: decides which hosts belong in the report, rewrites
      WORK/hosts.tsv and WORK/hosts.list to only those, and writes
      WORK/targets.tsv with one status row per input line.

Normalized file format (also written by panel/targets.py): kind<TAB>value<TAB>source,
kind in ip | cidr | mac | host.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import sys
from pathlib import Path

IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

# ── parsing and validation (shared with the panel) ──────────────────────────
MAX_LINES = 4096
MAX_ADDRESSES = 65536

_MAC_SEP = re.compile(r"^([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})$")
_MAC_DOT = re.compile(r"^([0-9a-f]{4})\.([0-9a-f]{4})\.([0-9a-f]{4})$")      # Cisco style
_MAC_BARE = re.compile(r"^[0-9a-f]{12}$")
# RFC 1123 labels; no leading '-' anywhere, so a name can never look like an option
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*\.?$")
# first-column titles in exported CSV files; never real targets
HEADER_WORDS = {"ip", "ips", "ip address", "ipaddress", "ip_address", "address", "addresses",
                "mac", "mac address", "macaddress", "mac_address", "hostname", "hostnames",
                "host", "hosts", "name", "fqdn", "dns name", "target", "targets", "device"}
_SOURCE = re.compile(r"[^A-Za-z0-9_. -]")


def allowed_prefixes(settings) -> list[str]:
    """ALLOWED_PREFIXES from discovery/config/settings.conf (same rule as discover.sh)."""
    try:
        for line in Path(settings).read_text().splitlines():
            m = re.match(r'^\s*ALLOWED_PREFIXES="([^"]*)"', line)
            if m:
                return m.group(1).split()
    except OSError:
        pass
    return ["10.", "172.16.", "192.168."]


def normalize_mac(s: str) -> str | None:
    s = s.strip().lower()
    m = _MAC_SEP.match(s)
    if m:
        return ":".join(m.groups())
    m = _MAC_DOT.match(s)
    if m:
        s = "".join(m.groups())
    if _MAC_BARE.match(s):
        return ":".join(s[i:i + 2] for i in range(0, 12, 2))
    return None


def classify(token: str):
    """Return (kind, normalized value) or (None, reason)."""
    t = token.strip()
    mac = normalize_mac(t)
    if mac:
        return "mac", mac
    try:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            if net.version != 4:
                return None, "only IPv4 ranges are supported"
            return ("ip", str(net.network_address)) if net.prefixlen == 32 else ("cidr", str(net))
        ip = ipaddress.ip_address(t)
        if ip.version != 4:
            return None, "only IPv4 addresses are supported"
        return "ip", str(ip)
    except ValueError:
        pass
    if re.match(r"^[0-9./]+$", t):
        return None, "not a valid IP address or range"
    h = t.lower()
    if len(h) <= 253 and _HOST.match(h):
        return "host", h.rstrip(".")
    return None, "not an IP, range, MAC address or hostname"


def parse(entries: list[dict], prefixes: list[str]) -> dict:
    """entries: [{"line": "...", "source": "typed" | "mac.txt"}].
    CSV lines use the first column; '#' starts a comment."""
    targets, errors, seen, addresses = [], [], set(), 0
    for n, e in enumerate(entries[: MAX_LINES * 2], 1):
        raw = str(e.get("line", ""))
        source = _SOURCE.sub("", str(e.get("source") or "typed"))[:60] or "typed"
        text = raw.split("#", 1)[0].split(",", 1)[0].strip().strip('"')
        if not text:
            continue
        if text.lower() in HEADER_WORDS:
            errors.append({"line": raw[:80], "source": source, "error": "looks like a column header"})
            continue
        kind, value = classify(text)
        if kind is None:
            errors.append({"line": raw[:80], "source": source, "error": value})
            continue
        if kind in ("ip", "cidr"):
            net = ipaddress.ip_network(value)
            first, last = str(net.network_address), str(net.broadcast_address)
            if not all(any(a.startswith(p) for p in prefixes) for a in (first, last)):
                errors.append({"line": raw[:80], "source": source,
                               "error": "outside private address space; public targets are refused"})
                continue
            addresses += net.num_addresses
        if (kind, value) in seen:
            continue
        seen.add((kind, value))
        targets.append({"kind": kind, "value": value, "source": source})
    if len(targets) > MAX_LINES:
        errors.append({"line": "", "source": "", "error": f"more than {MAX_LINES} targets"})
    if addresses > MAX_ADDRESSES:
        errors.append({"line": "", "source": "",
                       "error": f"ranges cover {addresses} addresses; the limit is {MAX_ADDRESSES}"})
    counts = {k: sum(1 for t in targets if t["kind"] == k) for k in ("ip", "cidr", "mac", "host")}
    return {"targets": targets, "errors": errors, "counts": counts, "addresses": addresses}



def normalize(raw_file, settings):
    """CLI form of parse(): raw user file -> normalized lines on stdout."""
    src = Path(raw_file).name
    entries = []
    for line in Path(raw_file).read_text(errors="replace").splitlines():
        p = line.split("\t")
        if len(p) >= 2 and p[0] in ("ip", "cidr", "mac", "host"):
            entries.append({"line": p[1], "source": p[2] if len(p) > 2 else src})
        else:
            entries.append({"line": line, "source": src})
    r = parse(entries, allowed_prefixes(settings))
    for e in r["errors"]:
        print(f"skipped: {e['line']!r} ({e['source']}): {e['error']}", file=sys.stderr)
    for t in r["targets"]:
        print(f"{t['kind']}\t{t['value']}\t{t['source']}")
    return 0 if r["targets"] and not any(not e["line"] for e in r["errors"]) else 1



def read_targets(path):
    out = []
    for line in Path(path).read_text().splitlines():
        p = line.split("\t")
        if len(p) >= 2 and p[0] in ("ip", "cidr", "mac", "host"):
            out.append((p[0], p[1].strip(), p[2].strip() if len(p) > 2 else "typed"))
    return out


def allowed(ip, prefixes):
    return any(ip.startswith(p) for p in prefixes)


def plan(tin, work, prefixes):
    work = Path(work)
    prefixes = prefixes.split()
    sweep, resolve, need_mac = [], [], 0
    for kind, value, _ in read_targets(tin):
        if kind in ("ip", "cidr"):
            sweep.append(value)
        elif kind == "mac":
            need_mac = 1
        elif kind == "host":
            try:
                ips = sorted({ai[4][0] for ai in socket.getaddrinfo(value, None, socket.AF_INET)})
            except (socket.gaierror, UnicodeError):
                ips = []
            ok = [ip for ip in ips if allowed(ip, prefixes)]
            refused = [ip for ip in ips if ip not in ok]
            resolve.append((value, ",".join(ok), ",".join(refused)))
            sweep.extend(ok)
    (work / "sweep.list").write_text("".join(f"{s}\n" for s in dict.fromkeys(sweep)))
    (work / "resolve.tsv").write_text("".join(f"{h}\t{ok}\t{bad}\n" for h, ok, bad in resolve))
    print(f"NEED_MAC={need_mac}")


def _tsv(path):
    p = Path(path)
    if not p.exists():
        return []
    return [l.split("\t") for l in p.read_text(errors="replace").splitlines() if l and not l.startswith("###")]


def finish(tin, work, raw, pn):
    work, raw = Path(work), Path(raw)
    targets = read_targets(tin)
    pn = pn == "1"

    # what the network told us
    hosts = {}                                       # ip -> [ip, mac, vendor]
    for p in _tsv(work / "hosts.tsv"):
        if p and IPV4.match(p[0]):
            hosts[p[0]] = (p + ["", ""])[:3]
    up_sweep = set()
    gnmap = raw / "11-nmap-sweep.gnmap"
    if gnmap.exists():
        for l in gnmap.read_text(errors="replace").splitlines():
            m = re.match(r"^Host: (\S+) .*Status: Up", l)
            if m:
                up_sweep.add(m.group(1))
    mac_to_ip = {}
    for ip, h in hosts.items():
        if h[1]:
            mac_to_ip.setdefault(h[1].lower(), ip)
    resolved = {p[0]: [x for x in p[1].split(",") if x] for p in _tsv(work / "resolve.tsv") if p}
    refused = {p[0]: [x for x in (p[2] if len(p) > 2 else "").split(",") if x]
               for p in _tsv(work / "resolve.tsv") if p}

    keep, rows = set(), []
    for kind, value, source in targets:
        row = {"kind": kind, "value": value, "source": source, "ip": "", "status": "", "detail": ""}
        if kind == "ip":
            row["ip"] = value
            if value in up_sweep:
                row["status"] = "up"; keep.add(value)
            elif pn:
                row["status"] = "assumed_up"; keep.add(value)
                row["detail"] = "did not answer the sweep; scanned anyway"
            else:
                row["status"] = "no_response"
        elif kind == "cidr":
            net = ipaddress.ip_network(value)
            live = sorted((ip for ip in up_sweep if ipaddress.ip_address(ip) in net),
                          key=lambda s: tuple(int(x) for x in s.split(".")))
            keep.update(live)
            row["status"] = "up" if live else "no_response"
            row["detail"] = f"{len(live)} of {net.num_addresses} addresses answered"
        elif kind == "host":
            ips = resolved.get(value, [])
            if not ips:
                row["status"] = "unresolved"
                if refused.get(value):
                    row["detail"] = "resolves only to public address(es) " + ", ".join(refused[value]) + "; refused"
            else:
                row["ip"] = ",".join(ips)
                live = [ip for ip in ips if ip in up_sweep or pn]
                keep.update(live)
                row["status"] = "up" if any(ip in up_sweep for ip in ips) else ("assumed_up" if pn else "no_response")
        elif kind == "mac":
            ip = mac_to_ip.get(value.lower())
            if ip:
                row["ip"] = ip; row["status"] = "up"; keep.add(ip)
            else:
                row["status"] = "not_seen"
                row["detail"] = "not on the local network segment, or switched off"
        rows.append(row)

    # hosts.tsv / hosts.list now hold only what was asked for
    for ip in keep:
        hosts.setdefault(ip, [ip, "", ""])
    kept = sorted(keep, key=lambda s: tuple(int(x) for x in s.split(".")))
    (work / "hosts.tsv").write_text("".join("\t".join(hosts[ip]) + "\n" for ip in kept))
    (work / "hosts.list").write_text("".join(f"{ip}\n" for ip in kept))
    with open(work / "targets.tsv", "w") as fh:
        for r in rows:
            fh.write("\t".join(r[k].replace("\t", " ") for k in
                               ("kind", "value", "source", "ip", "status", "detail")) + "\n")
    print(len(kept))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "normalize" and len(sys.argv) == 4:
        sys.exit(normalize(*sys.argv[2:]))
    elif cmd == "plan" and len(sys.argv) == 5:
        plan(*sys.argv[2:])
    elif cmd == "finish" and len(sys.argv) == 6:
        finish(*sys.argv[2:])
    else:
        sys.exit(__doc__)
