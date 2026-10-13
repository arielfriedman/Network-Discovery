"""Device type identification from what a scan already collected.

Used by build_json.py. Each rule looks at one kind of evidence; a host gets
the type with the strongest evidence, and every piece of evidence is listed
so the report can say *why* it thinks a host is, say, a Raspberry Pi.

Evidence strength: "high" (MAC vendor registered to the maker, or the board
model read over SSH), "medium" (OS fingerprint / SSH banner naming it),
"low" (only the hostname or mDNS name suggests it - people rename things).

MAC vendors come from the IEEE registry: config/ieee-oui.csv when
./update-vendors.sh has fetched the current one, else the copies shipped with
arp-scan (/usr/share/arp-scan/ieee-oui.txt) and nmap
(/usr/share/nmap/nmap-mac-prefixes). No vendor list lives in this file.
"""
from __future__ import annotations

import os
import re

# config/ieee-oui.csv (./update-vendors.sh, current IEEE registry) first, then
# the copies shipped with arp-scan and nmap
OUI_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "ieee-oui.csv")
OUI_FILES = ("/usr/share/arp-scan/ieee-oui.txt", "/usr/share/nmap/nmap-mac-prefixes")
_oui: dict[str, str] | None = None


def vendor_for_mac(mac: str | None) -> str | None:
    """Registered vendor of a MAC address, from the local IEEE data."""
    global _oui
    if not mac:
        return None
    if _oui is None:
        _oui = {}
        if os.path.exists(OUI_CSV):
            import csv
            with open(OUI_CSV, encoding="utf-8", errors="replace", newline="") as fh:
                for row in csv.reader(fh):
                    if len(row) >= 3 and row[0] == "MA-L" and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1]):
                        _oui[row[1].upper()] = row[2].strip()
        for path in OUI_FILES:
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("#") or len(line) < 8:
                        continue
                    key, _, name = line.strip().partition("\t" if "\t" in line else " ")
                    key = key.upper()
                    if re.fullmatch(r"[0-9A-F]{6}", key):
                        _oui.setdefault(key, name.strip())
    key = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()[:6]
    return _oui.get(key)


# A locally administered MAC (second hex digit 2, 6, A or E) is random or
# software-assigned, so its "vendor" means nothing.
def is_local_mac(mac: str | None) -> bool:
    return bool(mac) and re.match(r"^[0-9a-fA-F]([26aeAE])", mac) is not None


RULES = [
    # (type, field, regex, strength, evidence text)
    ("Raspberry Pi", "vendor", r"raspberry\s*pi", "high", "MAC address registered to Raspberry Pi"),
    ("Raspberry Pi", "model", r"raspberry\s*pi", "high", "board model read over SSH"),
    ("Raspberry Pi", "os", r"raspbian|raspberry", "medium", "OS fingerprint"),
    ("Raspberry Pi", "banner", r"raspbian|raspberry", "medium", "service banner"),
    # (not "pi-hole": it runs on any Linux box)
    ("Raspberry Pi", "names", r"(^|[^a-z])(raspberry\s*pi|raspberrypi|rpi\d*)([^a-z]|$)", "low", "host name"),
]
RANK = {"high": 3, "medium": 2, "low": 1}


def classify(h: dict, ssh_text: str = "") -> None:
    """Adds device_type / device_model / device_confidence / device_evidence to host h."""
    model = None
    m = re.search(r"=== model ===\s*\n([^\n=]+)", ssh_text or "")
    if m and m.group(1).strip() and "No such file" not in m.group(1):
        model = m.group(1).strip().strip("\x00")
    fields = {
        "vendor": h.get("vendor") or "",
        "model": model or "",
        "os": h.get("os") or "",
        "banner": " ".join(f"{p.get('service') or ''} {p.get('version') or ''}" for p in h.get("ports") or []),
        "names": " ".join(x for x in (h.get("hostname"), h.get("mdns"), h.get("netbios")) if x).lower(),
    }
    found: dict[str, list[tuple[str, str]]] = {}
    for dtype, field, rx, strength, text in RULES:
        if fields[field] and re.search(rx, fields[field], re.I):
            found.setdefault(dtype, []).append((strength, f"{text}: {fields[field][:80]}"))
    if not found:
        return
    best = max(found, key=lambda t: max(RANK[s] for s, _ in found[t]))
    ev = sorted(found[best], key=lambda e: -RANK[e[0]])
    h["device_type"] = best
    h["device_confidence"] = ev[0][0]
    h["device_evidence"] = [e for _, e in ev]
    if model:
        h["device_model"] = model
