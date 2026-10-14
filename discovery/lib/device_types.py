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


# (type, field, regex, strength, evidence text). Fields: vendor, model, os,
# banner (service product/version), names (host / mDNS / NetBIOS names),
# mdns (announced service types), ssdp, ports (" 22 80 9100 "), apps, role.
# A vendor that also makes ordinary PCs or phones (HP, Samsung, Sony) is only
# "low" on its own; it takes a second clue to be sure.
RULES = [
    ("Raspberry Pi", "vendor", r"raspberry\s*pi", "high", "MAC address registered to Raspberry Pi"),
    ("Raspberry Pi", "model", r"raspberry\s*pi", "high", "board model read over SSH"),
    ("Raspberry Pi", "os", r"raspbian|raspberry", "medium", "OS fingerprint"),
    ("Raspberry Pi", "banner", r"raspbian|raspberry", "medium", "service banner"),
    # (not "pi-hole": it runs on any Linux box)
    ("Raspberry Pi", "names", r"(^|[^a-z])(raspberry\s*pi|raspberrypi|rpi\d*)([^a-z]|$)", "low", "host name"),

    ("Router / Wi-Fi", "role", r"gateway", "high", "it is this network's default gateway"),
    ("Router / Wi-Fi", "vendor", r"ubiquiti|mikrotik|routerboard|netgear|zyxel|ruckus|aruba|meraki|cambium|draytek|avm gmbh|technicolor|sagemcom|arris", "medium", "network equipment maker"),
    ("Router / Wi-Fi", "vendor", r"tp-link|asustek|d-link|linksys|tenda|huawei", "low", "maker of routers (and other devices)"),
    ("Router / Wi-Fi", "ssdp", r"internetgatewaydevice|miniupnpd|asuswrt|openwrt|fritz!box", "high", "UPnP router announcement"),
    ("Router / Wi-Fi", "apps", r"unifi network", "medium", "router / controller app"),

    ("Printer", "mdns", r"_ipp|_ipps|_printer|_pdl-datastream|_scanner", "high", "announces a printing service (mDNS)"),
    ("Printer", "ports", r" (9100|515) ", "medium", "printer port (9100 raw / 515 LPD)"),
    ("Printer", "vendor", r"brother|seiko epson|canon|lexmark|kyocera|xerox|ricoh|konica|oki data|zebra|sharp corp", "medium", "printer maker"),
    ("Printer", "vendor", r"hewlett|\bhp\b", "low", "HP (makes printers and PCs)"),
    ("Printer", "names", r"printer|laserjet|officejet|deskjet|pixma|ecotank|mfc-|brn[0-9a-f]{6}", "medium", "printer-style name"),

    ("IP camera", "vendor", r"hikvision|dahua|axis comm|reolink|amcrest|uniview|zhejiang uniview|hanwha|vivotek|foscam|wyze|arlo|eufy", "high", "camera maker"),
    ("IP camera", "ports", r" 554 ", "medium", "RTSP video stream port"),
    ("IP camera", "names", r"camera|\bcam\d*\b|ipc-|nvr|dvr", "low", "camera-style name"),

    ("NAS / storage", "vendor", r"synology|qnap|asustor|terramaster|buffalo|drobo|western digital", "high", "NAS maker"),
    ("NAS / storage", "apps", r"synology dsm|truenas", "high", "NAS operating system"),
    ("NAS / storage", "names", r"\bnas\b|diskstation|truenas|unraid|openmediavault", "medium", "NAS-style name"),

    ("TV / streamer", "mdns", r"_googlecast", "high", "Chromecast / Google TV announcement"),
    ("TV / streamer", "ssdp", r"samsung|webos|lge|roku|sony.*bravia|mediarenderer|dial-multiscreen", "medium", "smart TV / DLNA announcement"),
    ("TV / streamer", "vendor", r"roku|tcl|hisense|vizio|amlogic", "medium", "TV / streamer maker"),
    ("TV / streamer", "names", r"\btv\b|television|living room|bravia|chromecast|fire ?tv|apple ?tv|shield", "medium", "TV-style name"),

    ("Game console", "vendor", r"sony interactive|nintendo", "high", "game console maker"),
    ("Game console", "names", r"playstation|\bps[345]\b|xbox|nintendo", "medium", "console name"),

    ("Smart home / IoT", "vendor", r"espressif|tuya|shelly|allterco|itead|signify|philips lighting|lifx|ring llc|nest labs|ecobee|sonos|wiz connected|xiaomi|yeelink|govee|meross|tado|netatmo|ezviz", "medium", "smart-home / IoT chip or brand"),
    ("Smart home / IoT", "mdns", r"_hap\._tcp|_homekit|_matter|_esphomelib|_shelly|_sonos|_hue", "high", "smart-home service announcement (HomeKit / Matter / ESPHome)"),
    ("Smart home / IoT", "vendor", r"amazon technologies", "medium", "Amazon device (Echo / Fire / Ring)"),
    ("Smart home / IoT", "apps", r"home assistant|node-red|mosquitto", "medium", "smart-home hub software"),

    ("Apple device", "vendor", r"\bapple\b", "medium", "MAC address registered to Apple"),
    ("Apple device", "mdns", r"_airplay|_companion-link|_apple-mobdev|_raop|_device-info.*(macbook|imac|iphone|ipad)", "medium", "Apple service announcement"),

    ("Phone / tablet", "names", r"iphone|ipad|android|galaxy|pixel|oneplus|redmi|xiaomi|huawei-p|sm-[a-z]\d", "medium", "phone-style name"),
    ("Phone / tablet", "random", r"yes", "low", "randomised MAC address (typical for phones)"),

    ("Windows PC / server", "os", r"windows", "high", "Windows identified"),
    ("Windows PC / server", "ports", r" 3389 ", "medium", "Remote Desktop port"),
    ("Windows PC / server", "ports", r" 135 .* 445 | 445 .* 135 ", "medium", "Windows RPC + file sharing ports"),

    ("Linux server", "os", r"ubuntu|debian|centos|red hat|rocky|alma|fedora|suse|arch|linux", "low", "Linux OS"),
    ("Linux server", "ports", r" 22 ", "low", "SSH server"),
]
RANK = {"high": 3, "medium": 2, "low": 1}


def classify(h: dict, ssh_text: str = "", gateway: str | None = None) -> None:
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
        "mdns": h.get("mdns") or "",
        "ssdp": h.get("ssdp") or "",
        "ports": " " + " ".join(str(p.get("port", "")).split("/")[0] for p in h.get("ports") or []) + " ",
        "apps": " | ".join(a.get("name", "") for a in h.get("apps") or []),
        "role": "gateway" if gateway and h.get("ip") == gateway else "",
        "random": "yes" if h.get("mac_random") else "",
    }
    found: dict[str, list[tuple[str, str]]] = {}
    for dtype, field, rx, strength, text in RULES:
        if fields[field] and re.search(rx, fields[field], re.I):
            detail = "" if field in ("role", "random", "ports") else f": {fields[field].strip()[:80]}"
            found.setdefault(dtype, []).append((strength, text + detail))
    if not found:
        return
    # strongest single clue wins; more clues break ties. Two independent
    # medium clues count as high; a type resting on low clues only stays low.
    def score(t):
        ranks = sorted((RANK[s] for s, _ in found[t]), reverse=True)
        return (ranks[0], len(ranks))
    # "Linux server" is a fallback: any specific type beats it
    specific = [t for t in found if t != "Linux server"]
    best = max(specific or found, key=score)
    ev = sorted(found[best], key=lambda e: -RANK[e[0]])
    conf = ev[0][0]
    if conf == "medium" and sum(1 for s, _ in ev if s == "medium") >= 2:
        conf = "high"
    if best == "Linux server" and len(ev) >= 2 and conf == "low":
        conf = "medium"
    h["device_type"] = best
    h["device_confidence"] = conf
    h["device_evidence"] = [e for _, e in ev]
    if model:
        h["device_model"] = model
