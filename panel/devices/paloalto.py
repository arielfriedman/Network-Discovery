"""
Palo Alto Networks driver - PAN-OS XML API (PAN-OS 11.1 / 11.2 / 12.1).

Use a dedicated admin account for SentinelScan (Device > Administrators), with
a role that allows the XML API: Configuration, Operational Requests, Commit
and Export. The superuser role works; a custom Admin Role is better.

The password is sent once, in an HTTPS POST body (never in the URL), to get an
API key; every later request carries only the key, in the X-PAN-KEY header.

PAN-OS has a candidate configuration: the wizard's changes become active only
when committed. A commit takes *every* pending change on the firewall,
including other admins' uncommitted edits - the preview warns when there are
any. If the commit fails, the candidate is reverted to the running config.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlencode
from xml.sax.saxutils import escape, quoteattr

from .base import (DeviceError, Driver, Field, Plan, PinnedHTTPS, Step, ValidationError, Wizard, fill,
                   v_address, v_choice, v_cidr, v_hostname, v_iface, v_ip, v_list, v_name, v_port, v_text)

DEV = "/config/devices/entry[@name='localhost.localdomain']"
SYSTEM = DEV + "/deviceconfig/system"
MGMT_PROFILES = DEV + "/network/profiles/interface-management-profile"
VSYS_RE = re.compile(r"^vsys[1-9][0-9]{0,2}$")
_UNSAFE = re.compile(r"[\x00-\x1f\x7f'\"\[\]<>&/\\]")
_UNSAFE_IFACE = re.compile(r"[\x00-\x1f\x7f'\"\[\]<>&\\]")
TRUE = (True, "true", "on", "1", "yes")
PROFILE_OFF = ["http", "telnet", "snmp", "http-ocsp", "response-pages", "userid-service",
               "userid-syslog-listener-ssl", "userid-syslog-listener-udp"]
PROFILE_ON = ["https", "ssh", "ping"]


# ── XML helpers: every user value goes through escape() / quoteattr() ───────
def xname(s: str, iface: bool = False) -> str:
    """A name inside an xpath predicate [@name='...']. Validated upstream; this is the last line of defence."""
    s = str(s)
    if not s or (_UNSAFE_IFACE if iface else _UNSAFE).search(s):
        raise ValidationError(f"'{s}' contains characters that cannot be used in a PAN-OS name")
    return s


def entry(container_xpath: str, name: str, iface: bool = False) -> str:
    return f"{container_xpath}/entry[@name='{xname(name, iface)}']"


def el(tag: str, inner: str = "", name: str | None = None) -> str:
    """Tag names are constants from this file; inner is already-escaped XML."""
    attr = f" name={quoteattr(name)}" if name is not None else ""
    return f"<{tag}{attr}>{inner}</{tag}>"


def txt(tag: str, value) -> str:
    return el(tag, escape(str(value)))


def members(tag: str, items) -> str:
    return el(tag, "".join(txt("member", m) for m in items))


def _msg(root: ET.Element) -> str:
    parts = []
    for m in root.iter("msg"):
        lines = [(ln.text or "").strip() for ln in m.iter("line")]
        parts.append(" ".join(x for x in lines if x) if lines else "".join(m.itertext()).strip())
    if not parts:
        parts = [(ln.text or "").strip() for ln in root.iter("line")]
    return re.sub(r"\s+", " ", " ".join(p for p in parts if p)).strip()


def _strip_meta(e: ET.Element) -> ET.Element:
    """Config 'get' adds admin / dirtyId / time attributes; they must not go back to the device."""
    for n in e.iter():
        for a in ("admin", "dirtyId", "time", "uuid"):
            n.attrib.pop(a, None)
    return e


def _truthy(v) -> bool:
    return v in TRUE


def v_portspec(v, what: str = "port") -> str:
    """'443', '80,443', '8000-8080'."""
    def one(s):
        if "-" in s:
            a, _, b = s.partition("-")
            a, b = v_port(a, what), v_port(b, what)
            if a > b:
                raise ValidationError(f"{what}: range {a}-{b} is backwards")
            return f"{a}-{b}"
        return str(v_port(s, what))
    out = v_list(v, one, what, 16)
    if not out:
        raise ValidationError(f"{what} is required")
    return ",".join(out)


def v_addr_member(s: str, what: str) -> str:
    """'any', an IP / CIDR, or an address object name."""
    if s == "any":
        return s
    if re.match(r"^[0-9./]+$", s):
        net = v_cidr(s, what)
        return str(net.network_address) if net.prefixlen == 32 else str(net)
    return v_name(s, what)


class PanOS(Driver):
    vendor = "paloalto"
    label = "Palo Alto"
    default_port = 443
    auth_fields = [
        Field("username", "Username", placeholder="sentinel-api"),
        Field("password", "Password", "password",
              help="Sent once over the pinned HTTPS connection to get an API key; never stored."),
        Field("vsys", "Virtual system", required=False, default="vsys1",
              help="Leave as vsys1 unless the firewall runs multiple virtual systems."),
    ]
    poll_interval = 2.0         # seconds between commit job polls
    commit_timeout = 600.0

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.http = PinnedHTTPS(self.address, self.port, self.pin, timeout=60)
        self.vsys = (self.creds.get("vsys") or "vsys1").strip()
        if not VSYS_RE.match(self.vsys):
            raise ValidationError("virtual system: use vsys1, vsys2, ...")
        self.VSYS = f"{DEV}/vsys/entry[@name='{self.vsys}']"
        self.key = ""
        self.foreign_pending = False      # other admins' uncommitted changes seen at the last preview
        self._zones: tuple[float, list[str]] = (0.0, [])

    # ── transport ───────────────────────────────────────────────────────────
    def probe_fingerprint(self) -> str:
        return self.http.fingerprint()

    def _parse(self, status: int, data: bytes) -> ET.Element:
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            raise DeviceError(f"PAN-OS: HTTP {status}, the reply is not XML "
                              f"({data[:120].decode(errors='replace')!r})") from None
        if root.tag != "response":
            raise DeviceError(f"PAN-OS: unexpected reply <{root.tag}>")
        return root

    def _keygen(self) -> None:
        user = v_text(self.creds.get("username"), 63, "username")
        pw = self.creds.get("password") or ""
        if not user or not pw:
            raise DeviceError("PAN-OS needs a username and password")
        body = urlencode({"type": "keygen", "user": user, "password": pw}).encode()
        status, _, data = self.http.request("POST", "/api/", body,
                                            {"Content-Type": "application/x-www-form-urlencoded"})
        root = self._parse(status, data)
        key = (root.findtext("./result/key") or "").strip()
        if root.get("status") != "success" or not key:
            raise DeviceError(f"PAN-OS refused the login: {_msg(root) or f'HTTP {status}'}")
        self.key = key

    def api(self, params: dict, method: str = "POST", raw: bool = False, _retry: bool = True):
        if not self.key:
            self._keygen()
        headers = {"X-PAN-KEY": self.key}
        if method == "POST":
            path, body = "/api/", urlencode(params).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            path, body = "/api/?" + urlencode(params), None
        status, hdrs, data = self.http.request(method, path, body, headers)
        if raw and status == 200 and not data.lstrip()[:10].startswith(b"<response"):
            return data
        root = self._parse(status, data)
        if root.get("status") != "success":
            msg = _msg(root) or f"HTTP {status}"
            if _retry and (root.get("code") == "22" or "session" in msg.lower() and "expired" in msg.lower()
                           or "invalid key" in msg.lower()):
                self.key = ""            # API key expired: log in again once
                return self.api(params, method, raw, _retry=False)
            if status == 403 or root.get("code") == "403":
                raise DeviceError(f"PAN-OS: permission denied - {msg}. Check the admin role's XML API rights.")
            raise DeviceError(f"PAN-OS: {msg}")
        if status >= 400:
            raise DeviceError(f"PAN-OS: HTTP {status} - {_msg(root)}")
        return data if raw else root

    def op(self, cmd: str) -> ET.Element:
        return self.api({"type": "op", "cmd": cmd})

    def get(self, xpath: str) -> ET.Element | None:
        """Candidate config node at xpath, or None."""
        res = self.api({"type": "config", "action": "get", "xpath": xpath}).find("result")
        if res is None or res.get("count") == "0" or len(res) == 0:
            return None
        return _strip_meta(res[0])

    def exists(self, xpath: str) -> bool:
        return self.get(xpath) is not None

    # ── read ────────────────────────────────────────────────────────────────
    def connect(self) -> None:
        self.key = ""
        self._keygen()
        self.facts_cache = self.facts()

    def close(self) -> None:
        self.key = ""

    def facts(self) -> dict:
        s = self.op("<show><system><info></info></system></show>").find("./result/system")
        if s is None:
            raise DeviceError("PAN-OS: 'show system info' returned nothing")
        f = lambda k: (s.findtext(k) or "").strip()
        return {"hostname": f("hostname"), "model": f("model"), "version": f("sw-version"),
                "serial": f("serial"), "uptime": f("uptime"), "vsys": self.vsys}

    def interfaces(self) -> list[dict]:
        r = self.op("<show><interface>all</interface></show>").find("result")
        hw = {}
        for e in (r.findall("./hw/entry") if r is not None else []):
            hw[(e.findtext("name") or "").strip()] = (e.findtext("state") or "").strip()
        out = []
        for e in (r.findall("./ifnet/entry") if r is not None else []):
            name = (e.findtext("name") or "").strip()
            ip = (e.findtext("ip") or "").strip()
            zone = (e.findtext("zone") or "").strip()
            phys = name.split(".")[0]
            out.append({"name": name, "ip": "" if ip in ("N/A", "") else ip, "zone": zone,
                        "status": hw.get(name) or hw.get(phys, ""),
                        "description": f"zone {zone}" if zone else ""})
        self.iface_cache = out
        return out

    def zones(self) -> list[str]:
        at, cached = self._zones
        if cached and time.time() - at < 60:
            return cached
        try:
            z = self.get(f"{self.VSYS}/zone")
            names = [e.get("name") for e in z.findall("entry")] if z is not None else []
        except DeviceError:
            names = []
        self._zones = (time.time(), names)
        return names

    def backup(self) -> str:
        try:
            data = self.api({"type": "export", "category": "configuration"}, method="GET", raw=True)
            text = data.decode("utf-8", errors="replace")
            if text.lstrip().startswith("<config") or "<config " in text[:300]:
                return text
        except DeviceError:
            pass
        cfg = self.api({"type": "config", "action": "show", "xpath": "/config"}).find("./result/config")
        if cfg is None:
            raise DeviceError("PAN-OS returned something that is not a configuration")
        return ET.tostring(cfg, encoding="unicode")

    def pending_changes(self) -> bool:
        r = self.op("<check><pending-changes></pending-changes></check>")
        return (r.findtext("result") or "").strip().lower() == "yes"

    # ── run a plan ──────────────────────────────────────────────────────────
    def execute(self, steps, values=None):
        values = dict(values or {})
        results = []
        for st in steps:
            ex = st.extra or {}
            try:
                action = ex.get("action")
                if action not in ("set", "edit", "delete", "move"):
                    raise DeviceError(f"unknown PAN-OS config action {action!r}")
                xpath = fill(ex.get("xpath", ""), values)
                if not xpath.startswith("/config/"):
                    raise DeviceError(f"refusing xpath outside /config: {xpath[:80]}")
                params = {"type": "config", "action": action, "xpath": xpath}
                if action in ("set", "edit"):
                    params["element"] = ex["element"]
                if action == "move":
                    params["where"] = v_choice(ex.get("where", "top"), ["top", "bottom"], "where")
                root = self.api(params)
            except DeviceError as e:
                detail = str(e)
                if results:     # earlier steps sit in the candidate config: don't leave half a change behind
                    try:
                        self.discard()
                        detail += " - the earlier steps were reverted (candidate configuration discarded)"
                    except DeviceError as e2:
                        detail += f" - the earlier steps could NOT be reverted: {e2}"
                results.append({"step": st.title, "ok": False, "detail": detail})
                break
            results.append({"step": st.title, "ok": True, "detail": _msg(root) or "command succeeded"})
        return results, values

    def commit(self) -> str:
        root = self.api({"type": "commit", "cmd": "<commit></commit>"})
        msg = _msg(root)
        job = (root.findtext(".//job") or "").strip()
        if not job:
            if "no changes" in msg.lower():
                return "nothing to commit (" + msg + ")"
            return msg or "committed"
        if not job.isdigit():
            raise DeviceError(f"PAN-OS: unexpected commit job id {job!r}")
        deadline = time.time() + self.commit_timeout
        while time.time() < deadline:
            r = self.op(f"<show><jobs><id>{int(job)}</id></jobs></show>")
            j = r.find(".//job")
            if j is not None and (j.findtext("status") or "").strip() == "FIN":
                result = (j.findtext("result") or "").strip()
                details = " ".join((ln.text or "").strip() for ln in j.iter("line") if (ln.text or "").strip())
                if result == "OK":
                    return f"commit job {job} finished" + (f": {details}" if details else "")
                raise DeviceError(f"commit job {job} failed ({result or 'FAIL'}): {details or 'no details'}")
            time.sleep(self.poll_interval)
        raise DeviceError(f"commit job {job} still running after {int(self.commit_timeout // 60)} minutes; "
                          "check Monitor > Tasks on the firewall")

    def discard(self) -> str:
        """Revert the candidate to the running configuration."""
        if self.foreign_pending:
            # Someone else has uncommitted work: only revert this admin's changes (PAN-OS 8.0+ partial revert).
            user = escape(str(self.creds.get("username", "")))
            try:
                r = self.op(f"<revert><config><partial><admin><member>{user}</member></admin>"
                            "</partial></config></revert>")
                return _msg(r) or "reverted this admin's changes"
            except DeviceError as e:
                raise DeviceError("Other admins have uncommitted changes, so the whole candidate was not "
                                  f"reverted, and reverting only this admin's changes failed: {e}") from None
        try:
            return _msg(self.op("<revert><config></config></revert>")) or "candidate reverted"
        except DeviceError:
            r = self.op("<load><config><from>running-config.xml</from></config></load>")
            return _msg(r) or "running configuration loaded into the candidate"

    # ── shared wizard plumbing ──────────────────────────────────────────────
    def _finish(self, plan: Plan) -> Plan:
        plan.commit = True
        try:
            self.foreign_pending = self.pending_changes()
        except DeviceError as e:
            self.foreign_pending = True     # unknown: be careful on discard
            plan.notes.insert(0, f"Could not check for other admins' uncommitted changes ({e}).")
            return plan
        if self.foreign_pending:
            plan.notes.insert(0, "WARNING: the firewall already has UNCOMMITTED CHANGES (another admin, or an "
                                 "earlier unfinished change). Apply ends with a commit, and a PAN-OS commit "
                                 "activates ALL pending changes, not just these. Review them on the firewall "
                                 "(Commit > Preview Changes) before applying.")
        return plan

    def _new(self, xpath: str, what: str) -> str:
        if self.exists(xpath):
            raise ValidationError(f"{what} already exists on the firewall. Choose another name.")
        return xpath

    def _zone_list(self, v, what: str, allow_any: bool = True) -> list[str]:
        zs = v_list(v, lambda s: s if s == "any" and allow_any else v_name(s, what), what, 16)
        if not zs:
            raise ValidationError(f"{what}: choose at least one zone")
        if "any" in zs and len(zs) > 1:
            raise ValidationError(f"{what}: 'any' cannot be combined with other zones")
        live = self.zones()
        unknown = [z for z in zs if z != "any" and live and z not in live]
        if unknown:
            raise ValidationError(f"{what}: zone {', '.join(unknown)} does not exist in {self.vsys} "
                                  f"(zones: {', '.join(live)})")
        return zs

    def _addr_list(self, v, what: str) -> list[str]:
        out = v_list(v or "any", lambda s: v_addr_member(s, what), what, 32)
        if "any" in out and len(out) > 1:
            raise ValidationError(f"{what}: 'any' cannot be combined with other entries")
        return out or ["any"]

    def _zone_field(self, name, label, multi=True, **kw) -> Field:
        zs = self.zones()
        if zs:
            opts = ([["any", "any"]] if multi else []) + [[z, z] for z in zs]
            return Field(name, label, "multiselect" if multi else "select", options=opts, **kw)
        return Field(name, label, help=(kw.pop("help", "") + " Zone names, comma separated.").strip(), **kw)

    def _rule_xml(self, src_z, dst_z, src, dst, apps, svc, action, desc) -> str:
        return (members("from", src_z) + members("to", dst_z) + members("source", src)
                + members("destination", dst) + members("source-user", ["any"]) + members("category", ["any"])
                + members("application", apps) + members("service", svc) + txt("action", action)
                + txt("log-start", "no") + txt("log-end", "yes") + (txt("description", desc) if desc else ""))

    # ── wizards ─────────────────────────────────────────────────────────────
    def wizards(self):
        iface = lambda name, label, **kw: Field(name, label, "select", source="interfaces", **kw)
        top = Field("top", "Move the new rule(s) to the top of the rulebase", "checkbox", required=False,
                    default=False, help="Otherwise PAN-OS adds them at the bottom, after every existing rule.")
        return [
            Wizard("system", "Hostname, DNS and NTP", "Name the firewall and point it at your DNS and time servers.", [
                Field("hostname", "Hostname", placeholder="PA-HQ"),
                Field("dns1", "Primary DNS", default="1.1.1.1"),
                Field("dns2", "Secondary DNS", required=False, default="9.9.9.9",
                      help="Leave empty to keep the current secondary."),
                Field("ntp1", "Primary NTP server", required=False, default="pool.ntp.org",
                      help="IP or host name. Leave empty to keep the current NTP settings."),
                Field("ntp2", "Secondary NTP server", required=False, default=""),
            ], self._w_system, "System"),
            Wizard("address", "Address object", "A named host or network to use in rules.", [
                Field("name", "Name", placeholder="srv-web01"),
                Field("subnet", "IP or network", placeholder="192.168.10.20 or 192.168.10.0/24"),
                Field("description", "Description", required=False),
            ], self._w_address, "Objects"),
            Wizard("service", "Service object", "A TCP or UDP port (or ports) to use in rules.", [
                Field("name", "Name", placeholder="tcp-8443"),
                Field("protocol", "Protocol", "select", default="tcp", options=[["tcp", "TCP"], ["udp", "UDP"]]),
                Field("port", "Destination port(s)", placeholder="8443  or  80,443  or  8000-8080"),
                Field("description", "Description", required=False),
            ], self._w_service, "Objects"),
            Wizard("security", "Security rule", "Allow or deny traffic between zones.", [
                Field("name", "Rule name", placeholder="LAN-to-Internet-web"),
                self._zone_field("from_zone", "From zone(s)"),
                self._zone_field("to_zone", "To zone(s)"),
                Field("source", "Source", default="any", help="'any', IPs / networks, or address object names."),
                Field("destination", "Destination", default="any"),
                Field("application", "Application", default="any",
                      help="'any' or App-ID names such as ssl, web-browsing, dns."),
                Field("service", "Service", default="application-default",
                      help="'application-default' (recommended), 'any', or service object names."),
                Field("action", "Action", "select", default="allow",
                      options=[["allow", "Allow"], ["deny", "Deny"], ["drop", "Drop"]]),
                Field("description", "Description", required=False),
                top,
            ], self._w_security, "Policy"),
            Wizard("portforward", "Port forward (destination NAT)",
                   "Publish an internal server on a public IP and port, with a matching security rule.", [
                Field("name", "Name", placeholder="web01-https"),
                self._zone_field("from_zone", "Outside zone (traffic comes from)", multi=False),
                self._zone_field("to_zone", "Zone of the public IP", multi=False, required=False,
                                 help="Usually the same as the outside zone."),
                Field("public_ip", "Public IP", placeholder="203.0.113.10"),
                Field("protocol", "Protocol", "select", default="tcp", options=[["tcp", "TCP"], ["udp", "UDP"]]),
                Field("public_port", "Public port", "number", placeholder="443"),
                Field("internal_ip", "Internal server IP", placeholder="192.168.10.20"),
                Field("internal_port", "Internal port", "number", required=False,
                      help="Leave empty to keep the same port."),
                self._zone_field("server_zone", "Zone the server is in", multi=False),
                Field("source", "Allowed sources", default="any", required=False,
                      help="Restrict who can reach the server: IPs / networks or address objects."),
                Field("add_rule", "Also create the security rule that allows it", "checkbox",
                      required=False, default=True),
                top,
            ], self._w_portforward, "Policy"),
            Wizard("mgmtprofile", "Interface management profile",
                   "Create or tighten a profile that allows only HTTPS, SSH and ping, and optionally bind it to an "
                   "interface. HTTP, Telnet and the other services are turned off.", [
                Field("name", "Profile name", default="mgmt-https-ssh-ping"),
                Field("permitted", "Permitted IPs", required=False,
                      help="Optional: only these addresses / networks may manage the firewall through it."),
                iface("interface", "Bind to interface", required=False, help="Optional. Layer-3 interfaces only."),
                Field("confirm_lockout", "I checked that my own address is in Permitted IPs (or I manage the "
                      "firewall through MGT)", "checkbox", required=False, default=False),
            ], self._w_mgmtprofile, "Hardening"),
        ]

    # (a) hostname / DNS / NTP
    def _w_system(self, p, drv):
        host = v_hostname(p["hostname"])
        dns1 = v_ip(p["dns1"], "primary DNS")
        dns2 = v_ip(p["dns2"], "secondary DNS") if str(p.get("dns2") or "").strip() else ""
        ntp1 = v_address(p["ntp1"]) if str(p.get("ntp1") or "").strip() else ""
        ntp2 = v_address(p["ntp2"]) if str(p.get("ntp2") or "").strip() else ""
        if ntp2 and not ntp1:
            raise ValidationError("secondary NTP needs a primary NTP server")
        notes = []
        cur_host = self.get(f"{SYSTEM}/hostname")
        dns = self.get(f"{SYSTEM}/dns-setting")
        if dns is not None and dns.find("dns-proxy-object") is not None:
            raise ValidationError("This firewall takes its DNS servers from a DNS proxy object. "
                                  "Change them in the DNS proxy (Network > DNS Proxy) instead.")
        old_dns1 = (dns.findtext("servers/primary") if dns is not None else None)
        old_dns2 = (dns.findtext("servers/secondary") if dns is not None else None)
        ntp = self.get(f"{SYSTEM}/ntp-servers")
        old_ntp = {}
        for k in ("primary", "secondary"):
            n = ntp.find(f"{k}-ntp-server") if ntp is not None else None
            old_ntp[k] = None if n is None else {
                "addr": n.findtext("ntp-server-address"),
                "auth": n.find("authentication-type")[0].tag if n.find("authentication-type") is not None
                and len(n.find("authentication-type")) else "none"}

        servers = txt("primary", dns1) + (txt("secondary", dns2) if dns2 else "")
        steps = [Step("Set hostname", "POST", "/api/", extra={"action": "set", "xpath": SYSTEM,
                                                              "element": txt("hostname", host)}),
                 Step("Set DNS servers", "POST", "/api/", extra={
                     "action": "set", "xpath": SYSTEM, "element": el("dns-setting", el("servers", servers))})]
        undo = [Step("Restore hostname", "POST", "/api/", extra={
                    "action": "set", "xpath": SYSTEM, "element": txt("hostname", cur_host.text or "")})
                if cur_host is not None and (cur_host.text or "").strip() else
                Step("Remove hostname", "POST", "/api/", extra={"action": "delete", "xpath": f"{SYSTEM}/hostname"})]
        for leaf, old in (("primary", old_dns1), ("secondary", old_dns2)):
            if leaf == "secondary" and not dns2:
                continue
            undo.append(Step(f"Restore {leaf} DNS", "POST", "/api/", extra={
                            "action": "set", "xpath": SYSTEM, "element": el("dns-setting", el("servers", txt(leaf, old)))})
                        if old else
                        Step(f"Remove {leaf} DNS", "POST", "/api/", extra={
                            "action": "delete", "xpath": f"{SYSTEM}/dns-setting/servers/{leaf}"}))
        if not dns2 and old_dns2:
            notes.append(f"Secondary DNS stays {old_dns2}.")

        if ntp1:
            inner = ""
            for k, addr in (("primary", ntp1), ("secondary", ntp2)):
                if not addr:
                    continue
                auth = "" if old_ntp[k] else el("authentication-type", "<none/>")
                inner += el(f"{k}-ntp-server", txt("ntp-server-address", addr) + auth)
                if old_ntp[k] and old_ntp[k]["auth"] != "none":
                    notes.append(f"The current {k} NTP server uses {old_ntp[k]['auth']} authentication. The key "
                                 "stays configured; update it on the firewall if the new server uses another one.")
                xp = f"{SYSTEM}/ntp-servers/{k}-ntp-server"
                undo.append(Step(f"Restore {k} NTP server", "POST", "/api/", extra={
                                "action": "set", "xpath": SYSTEM, "element": el("ntp-servers", el(
                                    f"{k}-ntp-server", txt("ntp-server-address", old_ntp[k]["addr"])))})
                            if old_ntp[k] and old_ntp[k]["addr"] else
                            Step(f"Remove {k} NTP server", "POST", "/api/", extra={"action": "delete", "xpath": xp}))
            if ntp is None:     # nothing configured before: undo removes the whole block
                undo = [u for u in undo if "NTP" not in u.title]
                undo.append(Step("Remove NTP servers", "POST", "/api/", extra={
                    "action": "delete", "xpath": f"{SYSTEM}/ntp-servers"}))
            steps.append(Step("Set NTP servers", "POST", "/api/", extra={
                "action": "set", "xpath": SYSTEM, "element": el("ntp-servers", inner)}))
            if not ntp2 and old_ntp["secondary"]:
                notes.append(f"Secondary NTP stays {old_ntp['secondary']['addr']}.")
        if host != (cur_host.text if cur_host is not None else ""):
            notes.append("The hostname changes in the prompt and logs after the commit. "
                         "If the firewall is managed by Panorama, a template may override these settings.")
        summary = (f"Hostname {host}, DNS {dns1}{' / ' + dns2 if dns2 else ''}"
                   + (f", NTP {ntp1}{' / ' + ntp2 if ntp2 else ''}" if ntp1 else ""))
        return self._finish(Plan(summary, steps, undo, notes))

    # (b) address object
    def _w_address(self, p, drv):
        name = v_name(p["name"], "name")
        net = v_cidr(p["subnet"], "IP or network")
        desc = v_text(p.get("description"), 255, "description")
        xp = self._new(entry(f"{self.VSYS}/address", name), f"Address object {name}")
        elem = txt("ip-netmask", str(net)) + (txt("description", desc) if desc else "")
        return self._finish(Plan(f"Address object {name} = {net}",
                                 [Step(f"Create address {name}", "POST", "/api/",
                                       extra={"action": "set", "xpath": xp, "element": elem})],
                                 [Step(f"Delete address {name}", "POST", "/api/",
                                       extra={"action": "delete", "xpath": xp})]))

    # (c) service object
    def _w_service(self, p, drv):
        name = v_name(p["name"], "name")
        proto = v_choice(p.get("protocol", "tcp"), ["tcp", "udp"], "protocol")
        port = v_portspec(p["port"], "destination port")
        desc = v_text(p.get("description"), 255, "description")
        xp = self._new(entry(f"{self.VSYS}/service", name), f"Service object {name}")
        elem = el("protocol", el(proto, txt("port", port))) + (txt("description", desc) if desc else "")
        return self._finish(Plan(f"Service {name} = {proto}/{port}",
                                 [Step(f"Create service {name}", "POST", "/api/",
                                       extra={"action": "set", "xpath": xp, "element": elem})],
                                 [Step(f"Delete service {name}", "POST", "/api/",
                                       extra={"action": "delete", "xpath": xp})]))

    # (d) security rule
    def _w_security(self, p, drv):
        name = v_name(p["name"], "rule name")
        src_z = self._zone_list(p.get("from_zone"), "from zone")
        dst_z = self._zone_list(p.get("to_zone"), "to zone")
        src = self._addr_list(p.get("source"), "source")
        dst = self._addr_list(p.get("destination"), "destination")
        apps = v_list(p.get("application") or "any", lambda s: v_name(s, "application"), "application", 32)
        if "any" in apps and len(apps) > 1:
            raise ValidationError("application: 'any' cannot be combined with other applications")
        svc = v_list(p.get("service") or "application-default", lambda s: v_name(s, "service"), "service", 32)
        if len(svc) > 1 and ({"any", "application-default"} & set(svc)):
            raise ValidationError("service: 'any' / 'application-default' cannot be combined with other services")
        action = v_choice(p.get("action", "allow"), ["allow", "deny", "drop"], "action")
        desc = v_text(p.get("description"), 1024, "description")
        xp = self._new(entry(f"{self.VSYS}/rulebase/security/rules", name), f"Security rule {name}")
        steps = [Step(f"Create security rule {name}", "POST", "/api/", extra={
            "action": "set", "xpath": xp, "element": self._rule_xml(src_z, dst_z, src, dst, apps, svc, action, desc)})]
        notes = []
        if _truthy(p.get("top")):
            steps.append(Step(f"Move {name} to the top", "POST", "/api/",
                              extra={"action": "move", "xpath": xp, "where": "top"}))
            notes.append("The rule goes to the TOP of the security rulebase, above every existing rule.")
        else:
            notes.append("PAN-OS adds new rules at the BOTTOM of the rulebase: any broader rule above it matches "
                         "first. Tick 'Move to the top', or reorder in Policies > Security.")
        if action == "allow" and apps == ["any"] and svc == ["any"]:
            notes.append("Application any + service any allows every port and protocol. Prefer specific "
                         "applications with service application-default.")
        if action == "allow" and src == ["any"] and dst == ["any"]:
            notes.append("Source and destination are both 'any'.")
        return self._finish(Plan(f"{action.upper()} {','.join(src_z)} → {','.join(dst_z)} "
                                 f"({','.join(apps)} / {','.join(svc)})", steps,
                                 [Step(f"Delete security rule {name}", "POST", "/api/",
                                       extra={"action": "delete", "xpath": xp})], notes))

    # (e) destination NAT / port forward
    def _w_portforward(self, p, drv):
        name = v_name(p["name"], "name")
        svc_name, rule_name = v_name(f"{name}-svc", "service name"), v_name(f"{name}-allow", "rule name")
        out_z = self._zone_list(p.get("from_zone"), "outside zone", allow_any=False)
        ip_z = self._zone_list(p.get("to_zone") or out_z, "zone of the public IP", allow_any=False)
        srv_z = self._zone_list(p.get("server_zone"), "server zone", allow_any=False)
        if len(out_z) != 1 or len(ip_z) != 1 or len(srv_z) != 1:
            raise ValidationError("choose exactly one zone in each zone field")
        pub = v_ip(p["public_ip"], "public IP")
        proto = v_choice(p.get("protocol", "tcp"), ["tcp", "udp"], "protocol")
        pport = v_port(p["public_port"], "public port")
        inner = v_ip(p["internal_ip"], "internal server IP")
        iport = v_port(p["internal_port"], "internal port") if str(p.get("internal_port") or "").strip() else pport
        src = self._addr_list(p.get("source"), "allowed sources")
        add_rule = _truthy(p.get("add_rule", True))

        svc_xp = self._new(entry(f"{self.VSYS}/service", svc_name), f"Service object {svc_name}")
        nat_xp = self._new(entry(f"{self.VSYS}/rulebase/nat/rules", name), f"NAT rule {name}")
        sec_xp = entry(f"{self.VSYS}/rulebase/security/rules", rule_name)
        if add_rule:
            self._new(sec_xp, f"Security rule {rule_name}")
        desc = f"Port forward {proto}/{pport} to {inner}:{iport} (SentinelScan)"
        xlate = txt("translated-address", inner) + (txt("translated-port", iport) if iport != pport else "")
        nat = (members("from", out_z) + members("to", ip_z) + members("source", src) + members("destination", [pub])
               + txt("service", svc_name) + txt("to-interface", "any")
               + el("destination-translation", xlate) + txt("description", desc))
        steps = [Step(f"Create service {svc_name} ({proto}/{pport})", "POST", "/api/", extra={
                     "action": "set", "xpath": svc_xp, "element": el("protocol", el(proto, txt("port", pport)))}),
                 Step(f"Create NAT rule {name}", "POST", "/api/", extra={"action": "set", "xpath": nat_xp, "element": nat})]
        undo = [Step(f"Delete NAT rule {name}", "POST", "/api/", extra={"action": "delete", "xpath": nat_xp}),
                Step(f"Delete service {svc_name}", "POST", "/api/", extra={"action": "delete", "xpath": svc_xp})]
        top = _truthy(p.get("top"))
        if top:
            steps.append(Step(f"Move NAT rule {name} to the top", "POST", "/api/",
                              extra={"action": "move", "xpath": nat_xp, "where": "top"}))
        if add_rule:
            steps.append(Step(f"Create security rule {rule_name}", "POST", "/api/", extra={
                "action": "set", "xpath": sec_xp,
                "element": self._rule_xml(out_z, srv_z, src, [pub], ["any"], [svc_name], "allow", desc)}))
            if top:
                steps.append(Step(f"Move {rule_name} to the top", "POST", "/api/",
                                  extra={"action": "move", "xpath": sec_xp, "where": "top"}))
            undo.insert(0, Step(f"Delete security rule {rule_name}", "POST", "/api/",
                                extra={"action": "delete", "xpath": sec_xp}))
        notes = ["This exposes an internal server to everyone who can reach the public IP"
                 + (". Restrict 'Allowed sources' if you can." if src == ["any"] else f" from {', '.join(src)}."),
                 "The security rule uses the PRE-NAT destination (the public IP) and the POST-NAT zone "
                 f"({srv_z[0]}) - that is how PAN-OS matches destination NAT."]
        if not add_rule:
            notes.append("No security rule is created: traffic stays blocked until a rule allows it.")
        if not top:
            notes.append("New NAT and security rules go to the BOTTOM of their rulebases; a broader rule above "
                         "can match first.")
        return self._finish(Plan(f"{out_z[0]} {pub} {proto}/{pport} → {inner}:{iport} ({srv_z[0]})",
                                 steps, undo, notes))

    # (f) interface management profile
    def _iface_xpath(self, name: str) -> str:
        n = xname(v_iface(name), iface=True)
        base = f"{DEV}/network/interface"
        m = re.match(r"^(ethernet\d+/\d+)(?:\.(\d+))?$", n)
        if m:
            x = f"{base}/ethernet/entry[@name='{m.group(1)}']/layer3"
            return x + (f"/units/entry[@name='{n}']" if m.group(2) else "")
        m = re.match(r"^(ae\d+)(?:\.(\d+))?$", n)
        if m:
            x = f"{base}/aggregate-ethernet/entry[@name='{m.group(1)}']/layer3"
            return x + (f"/units/entry[@name='{n}']" if m.group(2) else "")
        for kind in ("vlan", "loopback", "tunnel"):
            if n == kind or n.startswith(kind + "."):
                return f"{base}/{kind}" + (f"/units/entry[@name='{n}']" if "." in n else "")
        raise ValidationError(f"{n}: management profiles can be bound to layer-3 ethernet, ae, vlan, loopback "
                              "or tunnel interfaces only")

    def _my_ip(self) -> str:
        try:
            with socket.create_connection((self.address, self.port), timeout=5) as s:
                return s.getsockname()[0]
        except OSError:
            return ""

    def _w_mgmtprofile(self, p, drv):
        name = v_name(p["name"], "profile name")
        permitted = v_list(p.get("permitted"), lambda s: str(v_cidr(s, "permitted IP")), "permitted IPs", 32)
        ifname = str(p.get("interface") or "").strip()
        notes, steps, undo = [], [], []
        xp = entry(MGMT_PROFILES, name)
        old = self.get(xp)
        elem = "".join(txt(k, "yes") for k in PROFILE_ON) + "".join(txt(k, "no") for k in PROFILE_OFF)
        if permitted:
            elem += el("permitted-ip", "".join(el("entry", "", name=n) for n in permitted))
        steps.append(Step(f"{'Update' if old is not None else 'Create'} profile {name}", "POST", "/api/",
                          extra={"action": "set", "xpath": xp, "element": elem}))
        if old is not None:
            undo.append(Step(f"Restore profile {name}", "POST", "/api/",
                             extra={"action": "edit", "xpath": xp, "element": ET.tostring(old, encoding="unicode")}))
            was = [k for k in PROFILE_OFF if (old.findtext(k) or "").strip() == "yes"]
            notes.append(f"Profile {name} exists and is tightened: HTTPS, SSH and ping on"
                         + (f"; {', '.join(was)} turned off" if was else "") + ". Its permitted IPs "
                         + ("get the new ones added (existing entries stay)." if permitted else "are kept."))
        else:
            undo.append(Step(f"Delete profile {name}", "POST", "/api/", extra={"action": "delete", "xpath": xp}))

        if ifname:
            ixp = self._iface_xpath(ifname)
            if not self.exists(ixp):
                raise ValidationError(f"{ifname} is not a configured layer-3 interface on the firewall")
            cur = self.get(f"{ixp}/interface-management-profile")
            cur_name = (cur.text or "").strip() if cur is not None else ""
            live = next((i for i in (self.iface_cache or self.interfaces()) if i["name"] == ifname), {})
            if (live.get("ip") or "").split("/")[0] == self.address and permitted:
                me = self._my_ip()
                inside = me and any(ipaddress.ip_address(me) in ipaddress.ip_network(n) for n in permitted)
                if not inside and not _truthy(p.get("confirm_lockout")):
                    raise ValidationError(f"You manage the firewall through {ifname} ({self.address}) and this "
                                          f"computer ({me or 'unknown address'}) is not in Permitted IPs: the "
                                          "commit would lock you out. Add it, or tick the confirmation.")
            steps.append(Step(f"Bind {name} to {ifname}", "POST", "/api/", extra={
                "action": "set", "xpath": ixp, "element": txt("interface-management-profile", name)}))
            undo.insert(0, Step(f"Restore the profile on {ifname}", "POST", "/api/", extra={
                "action": "set", "xpath": ixp, "element": txt("interface-management-profile", cur_name)})
                if cur_name else
                Step(f"Unbind the profile from {ifname}", "POST", "/api/", extra={
                    "action": "delete", "xpath": f"{ixp}/interface-management-profile"}))
            if cur_name and cur_name != name:
                notes.append(f"{ifname} currently uses profile {cur_name}; it is replaced by {name}.")
            if "untrust" in (live.get("zone") or "").lower() or "wan" in (live.get("zone") or "").lower():
                notes.append(f"{ifname} is in zone {live.get('zone')}: HTTPS / SSH management there is reachable "
                             "from the internet. Set Permitted IPs, or use GlobalProtect / a VPN instead.")

        # warn about other weak spots
        allp = self.get(MGMT_PROFILES)
        weak = []
        for e in (allp.findall("entry") if allp is not None else []):
            if e.get("name") == name:
                continue
            bad = [k for k in ("http", "telnet") if (e.findtext(k) or "").strip() == "yes"]
            if bad:
                weak.append(f"{e.get('name')} ({'/'.join(bad)})")
        if weak:
            notes.append("Other profiles still allow unencrypted management: " + ", ".join(weak) + ".")
        svc = self.get(f"{SYSTEM}/service")
        mgt_bad = [k for k in ("http", "telnet")
                   if svc is None or (svc.findtext(f"disable-{k}") or "").strip() != "yes"]
        if mgt_bad:
            notes.append("The MGT port is not covered by interface profiles and still allows "
                         + " and ".join(x.upper() for x in mgt_bad)
                         + ": turn them off in Device > Setup > Interfaces > Management.")
        return self._finish(Plan(f"Profile {name}: HTTPS, SSH, ping only"
                                 + (f", bound to {ifname}" if ifname else "")
                                 + (f", permitted {', '.join(permitted)}" if permitted else ""), steps, undo, notes))
