"""
PA-440 (PAN-OS 11.1) simulator for the device lab: the XML API at /api/.

Keeps a candidate and a running configuration tree. Supports keygen (POST
form body), the op commands the driver uses, config get / show / set / edit /
delete / move on absolute xpaths with [@name='x'] predicates, commit jobs that
finish after a couple of polls (with commit-time reference validation),
pending-changes, revert (full and per admin) and configuration export.

    cd panel && python3 -m devices.lab paloalto
"""
from __future__ import annotations

import copy
import ipaddress
import re
import secrets
import threading
import xml.etree.ElementTree as ET
from urllib.parse import parse_qs, urlparse
from xml.sax.saxutils import escape

from .lab import HOST, JSONHandler, register, serve_https

PAN_USER, PAN_PASS = "admin", "lab-pan-pass"

BASE_CONFIG = """<config version="11.1.0" urldb="paloaltonetworks" detail-version="11.1.0">
 <mgt-config><users><entry name="admin"><phash>$5$labsalt$notarealhash</phash>
  <permissions><role-based><superuser>yes</superuser></role-based></permissions></entry></users></mgt-config>
 <shared/>
 <devices><entry name="localhost.localdomain">
  <deviceconfig><system>
   <type><static/></type><ip-address>192.168.1.1</ip-address><netmask>255.255.255.0</netmask>
   <hostname>PA-440-LAB</hostname><timezone>UTC</timezone>
   <dns-setting><servers><primary>8.8.8.8</primary></servers></dns-setting>
   <service><disable-telnet>yes</disable-telnet><disable-http>no</disable-http></service>
  </system></deviceconfig>
  <network>
   <interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.2/29"/></ip></layer3></entry>
    <entry name="ethernet1/2"><layer3><ip><entry name="192.168.10.1/24"/></ip>
      <interface-management-profile>allow-all</interface-management-profile>
      <units><entry name="ethernet1/2.20"><tag>20</tag><ip><entry name="192.168.20.1/24"/></ip></entry></units>
     </layer3></entry>
    <entry name="ethernet1/3"><layer3><ip><entry name="10.10.10.1/24"/></ip></layer3></entry>
    <entry name="ethernet1/4"/><entry name="ethernet1/5"/><entry name="ethernet1/6"/>
    <entry name="ethernet1/7"/><entry name="ethernet1/8"/>
   </ethernet></interface>
   <profiles><interface-management-profile>
    <entry name="allow-all"><https>yes</https><http>yes</http><ssh>yes</ssh><telnet>yes</telnet><ping>yes</ping></entry>
   </interface-management-profile></profiles>
  </network>
  <vsys><entry name="vsys1">
   <zone>
    <entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
    <entry name="trust"><network><layer3><member>ethernet1/2</member><member>ethernet1/2.20</member></layer3></network></entry>
    <entry name="dmz"><network><layer3><member>ethernet1/3</member></layer3></network></entry>
   </zone>
   <address><entry name="lan-net"><ip-netmask>192.168.10.0/24</ip-netmask></entry></address>
   <service/>
   <rulebase>
    <security><rules><entry name="trust-to-untrust">
     <from><member>trust</member></from><to><member>untrust</member></to>
     <source><member>lan-net</member></source><destination><member>any</member></destination>
     <source-user><member>any</member></source-user><category><member>any</member></category>
     <application><member>any</member></application><service><member>application-default</member></service>
     <action>allow</action><log-end>yes</log-end>
    </entry></rules></security>
    <nat><rules/></nat>
   </rulebase>
  </entry></vsys>
 </entry></devices>
</config>"""

STEP_RE = re.compile(r"/([A-Za-z0-9_\-.]+)(?:\[@name='([^'\[\]<>]*)'\])?")
# leaf nodes that must not contain child elements (an injected '<x>' would show up here)
LEAVES = {"description", "hostname", "ip-netmask", "port", "primary", "secondary", "ntp-server-address",
          "action", "translated-address", "translated-port", "interface-management-profile", "member",
          "log-end", "log-start", "to-interface", "https", "http", "ssh", "telnet", "ping", "snmp"}
BUILTIN_SERVICES = {"any", "application-default", "service-http", "service-https"}


class SimError(Exception):
    def __init__(self, msg, code="12"):
        super().__init__(msg)
        self.code = code


def _strip(e):
    """Pretty-printed BASE_CONFIG has whitespace text; normalise it away."""
    for n in e.iter():
        if len(n):
            n.text = None
        n.tail = None
    return e


def _canon(e) -> bytes:
    return ET.tostring(e)


def parse_xpath(xp: str):
    pos, out = 0, []
    while pos < len(xp):
        m = STEP_RE.match(xp, pos)
        if not m:
            raise SimError(f"Invalid xpath near '{xp[pos:pos + 30]}'", "12")
        out.append((m.group(1), m.group(2)))
        pos = m.end()
    if not out or out[0] != ("config", None):
        raise SimError("xpath must start with /config", "12")
    return out[1:]


def resolve(root, steps, create=False):
    node = root
    for tag, name in steps:
        nxt = next((c for c in node if c.tag == tag and (name is None or c.get("name") == name)), None)
        if nxt is None:
            if not create:
                return None
            nxt = ET.SubElement(node, tag, {"name": name} if name is not None else {})
        node = nxt
    return node


def check_leaves(e):
    for n in e.iter():
        if n.tag in LEAVES and len(n):
            raise SimError(f"{n.tag}: unexpected element <{n[0].tag}>", "12")


def merge(dst, src):
    for c in src:
        if c.tag == "member":
            if not any(x.tag == "member" and x.text == c.text for x in dst):
                dst.append(copy.deepcopy(c))
            continue
        match = next((x for x in dst if x.tag == c.tag and x.get("name") == c.get("name")), None)
        if match is None:
            dst.append(copy.deepcopy(c))
        elif len(c):
            merge(match, c)
        else:
            for x in list(match):
                match.remove(x)
            match.text = c.text


def fragment(element: str):
    try:
        f = ET.fromstring(f"<root>{element}</root>")
    except ET.ParseError as e:
        raise SimError(f"Malformed element: {e}", "12") from None
    check_leaves(f)
    return f


class PanSim:
    def __init__(self):
        self.running = _strip(ET.fromstring(BASE_CONFIG))
        self.candidate = copy.deepcopy(self.running)
        self.keys: set[str] = set()
        self.jobs: dict[int, dict] = {}
        self.next_job = 1
        self.fail_next_commit: str | None = None
        self.foreign: list[tuple[str, str]] = []      # other admins' uncommitted set operations
        self.password_in_url = False
        self.requests: list[tuple[str, str, str]] = []  # (method, path, type)
        self.lock = threading.RLock()

    # helpers for tests: simulate another admin editing the candidate
    def other_admin_set(self, xpath: str, element: str):
        with self.lock:
            merge(resolve(self.candidate, parse_xpath(xpath), create=True), fragment(element))
            self.foreign.append((xpath, element))

    def vsys(self, root=None):
        return resolve(root if root is not None else self.candidate,
                       parse_xpath("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"))

    # ── config actions ──────────────────────────────────────────────────────
    def config(self, q):
        action, xp = q.get("action", ""), q.get("xpath", "")
        steps = parse_xpath(xp)
        if action in ("get", "show"):
            root = self.candidate if action == "get" else self.running
            node = resolve(root, steps)
            if node is None:
                if action == "show":
                    raise SimError("No such node", "7")
                return '<response status="success" code="19"><result total-count="0" count="0"/></response>'
            out = copy.deepcopy(node)
            if action == "get":
                out.set("admin", "admin")
                out.set("dirtyId", "3")
                out.set("time", "2026/10/12 20:00:00")
            return (f'<response status="success" code="19"><result total-count="1" count="1">'
                    f'{ET.tostring(out, encoding="unicode")}</result></response>')
        if action == "set":
            f = fragment(q.get("element", ""))
            self._validate_values(f)
            merge(resolve(self.candidate, steps, create=True), f)
            return '<response status="success" code="20"><msg>command succeeded</msg></response>'
        if action == "edit":
            f = fragment(q.get("element", ""))
            if len(f) != 1 or f[0].tag != steps[-1][0] or f[0].get("name") != steps[-1][1]:
                raise SimError("edit breaks config validity", "12")
            self._validate_values(f)
            parent = resolve(self.candidate, steps[:-1], create=True)
            old = resolve(parent, steps[-1:])
            if old is not None:
                idx = list(parent).index(old)
                parent.remove(old)
                parent.insert(idx, f[0])
            else:
                parent.append(f[0])
            return '<response status="success" code="20"><msg>command succeeded</msg></response>'
        if action == "delete":
            parent = resolve(self.candidate, steps[:-1])
            node = resolve(parent, steps[-1:]) if parent is not None else None
            if node is None:
                return '<response status="success" code="7"><msg>Object doesn\'t exist</msg></response>'
            self._check_refs(steps, node)
            parent.remove(node)
            return '<response status="success" code="20"><msg>command succeeded</msg></response>'
        if action == "move":
            parent = resolve(self.candidate, steps[:-1])
            node = resolve(parent, steps[-1:]) if parent is not None else None
            if node is None:
                raise SimError("No such node", "7")
            where = q.get("where", "")
            if where not in ("top", "bottom"):
                raise SimError(f"move: unsupported where '{where}'", "12")
            parent.remove(node)
            parent.insert(0, node) if where == "top" else parent.append(node)
            return '<response status="success" code="20"><msg>command succeeded</msg></response>'
        raise SimError(f"Unknown action {action}", "12")

    def _validate_values(self, f):
        for n in f.iter():
            t = (n.text or "").strip()
            if n.tag == "hostname" and not re.match(r"^[A-Za-z0-9][A-Za-z0-9\-_.]{0,62}$", t):
                raise SimError(f"hostname '{t}' is not a valid value", "12")
            if n.tag == "ip-netmask":
                try:
                    ipaddress.ip_network(t, strict=False)
                except ValueError:
                    raise SimError(f"'{t}' is not a valid ip-netmask", "12") from None
            if n.tag == "action" and t not in ("allow", "deny", "drop", "reset-client", "reset-server", "reset-both"):
                raise SimError(f"action '{t}' is not a valid value", "12")
            if n.tag == "port" and not re.match(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$", t):
                raise SimError(f"port '{t}' is not a valid value", "12")

    def _check_refs(self, steps, node):
        tags = [s[0] for s in steps]
        name = node.get("name")
        if len(tags) >= 2 and tags[-2] in ("address", "service") and name:
            refs = [r.get("name") for r in self.vsys().iter("entry") if r.find("from") is not None
                    and (any(m.text == name for m in r.iter("member")) or r.findtext("service") == name)]
            if refs:
                raise SimError(f"{name} cannot be deleted because of references from: "
                               + ", ".join(r for r in refs if r), "12")
        if len(tags) >= 2 and tags[-2] == "interface-management-profile" and name:
            if any(x.text == name for x in self.candidate.iter("interface-management-profile")):
                raise SimError(f"{name} cannot be deleted because it is used by an interface", "12")

    # ── commit ──────────────────────────────────────────────────────────────
    def validate(self, cfg) -> list[str]:
        errs = []
        vs = self.vsys(cfg)
        zones = {e.get("name") for e in vs.findall("./zone/entry")}
        addrs = {e.get("name") for e in vs.findall("./address/entry")}
        svcs = {e.get("name") for e in vs.findall("./service/entry")} | BUILTIN_SERVICES
        profiles = {e.get("name") for e in cfg.findall(
            "./devices/entry/network/profiles/interface-management-profile/entry")}
        for e in cfg.iter("entry"):
            for p in e.findall("interface-management-profile"):
                if p.text not in profiles:
                    errs.append(f"interface-management-profile '{p.text}' is not a valid reference")

        def is_ip(s):
            try:
                ipaddress.ip_network(s, strict=False)
                return True
            except ValueError:
                return False
        for kind in ("security", "nat"):
            for r in vs.findall(f"./rulebase/{kind}/rules/entry"):
                rn = r.get("name")
                for side in ("from", "to"):
                    for m in r.findall(f"{side}/member"):
                        if m.text != "any" and m.text not in zones:
                            errs.append(f"rulebase -> {kind} -> rules -> {rn} -> {side} '{m.text}' is not a valid reference")
                for side in ("source", "destination"):
                    for m in r.findall(f"{side}/member"):
                        if m.text != "any" and m.text not in addrs and not is_ip(m.text):
                            errs.append(f"rulebase -> {kind} -> rules -> {rn} -> {side} '{m.text}' is not a valid reference")
                svc = [m.text for m in r.findall("service/member")] or [r.findtext("service")]
                for s in svc:
                    if s and s not in svcs:
                        errs.append(f"rulebase -> {kind} -> rules -> {rn} -> service '{s}' is not a valid reference")
        return errs

    def commit(self):
        if _canon(self.candidate) == _canon(self.running):
            return '<response status="success" code="19"><msg>There are no changes to commit.</msg></response>'
        jid = self.next_job
        self.next_job += 1
        errs = self.validate(self.candidate)
        if self.fail_next_commit:
            errs.append(self.fail_next_commit)
            self.fail_next_commit = None
        self.jobs[jid] = {"polls": 2, "errs": errs, "snapshot": copy.deepcopy(self.candidate), "done": False}
        return (f'<response status="success" code="19"><result><msg><line>Commit job enqueued with jobid {jid}'
                f'</line></msg><job>{jid}</job></result></response>')

    def job(self, jid: int):
        j = self.jobs.get(jid)
        if not j:
            raise SimError(f"job {jid} not found", "12")
        if j["polls"] > 0:
            j["polls"] -= 1
            return (f'<response status="success"><result><job><id>{jid}</id><type>Commit</type><status>ACT</status>'
                    f'<result>PEND</result><progress>{60 - 30 * j["polls"]}</progress><details/></job></result></response>')
        if not j["done"]:
            j["done"] = True
            if not j["errs"]:
                self.running = j["snapshot"]
                self.foreign = []
        if j["errs"]:
            lines = "".join(f"<line>{escape(x)}</line>" for x in ["Validation Error:"] + j["errs"]
                            + ["Commit failed"])
            return (f'<response status="success"><result><job><id>{jid}</id><type>Commit</type><status>FIN</status>'
                    f'<result>FAIL</result><progress>100</progress><details>{lines}</details></job></result></response>')
        return (f'<response status="success"><result><job><id>{jid}</id><type>Commit</type><status>FIN</status>'
                f'<result>OK</result><progress>100</progress><details><line>Configuration committed successfully'
                f'</line></details></job></result></response>')

    # ── op commands ─────────────────────────────────────────────────────────
    def op(self, cmd: str):
        try:
            c = ET.fromstring(cmd)
        except ET.ParseError:
            raise SimError("Malformed command", "17") from None
        path, n = [c.tag], c
        while len(n):
            n = n[0]
            path.append(n.tag)
        key, arg = "/".join(path), (n.text or "").strip()
        if key == "show/system/info":
            host = resolve(self.running, parse_xpath(
                "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/hostname"))
            return ('<response status="success"><result><system>'
                    f'<hostname>{escape(host.text if host is not None else "")}</hostname>'
                    '<ip-address>192.168.1.1</ip-address><model>PA-440</model><family>400</family>'
                    '<serial>021201000001</serial><sw-version>11.1.4-h7</sw-version>'
                    '<uptime>12 days, 3:04:05</uptime><multi-vsys>off</multi-vsys>'
                    '<app-version>8900-9123</app-version></system></result></response>')
        if key == "show/interface" and arg == "all":
            return self.show_interfaces()
        if key == "check/pending-changes":
            yes = _canon(self.candidate) != _canon(self.running)
            return f'<response status="success"><result>{"yes" if yes else "no"}</result></response>'
        if key == "show/jobs/id":
            return self.job(int(arg))
        if key == "revert/config":
            self.candidate, self.foreign = copy.deepcopy(self.running), []
            return '<response status="success"><result>Candidate configuration reverted to running.</result></response>'
        if key == "revert/config/partial/admin/member":
            self.candidate = copy.deepcopy(self.running)
            for xp, elem in self.foreign:      # keep the other admins' edits
                merge(resolve(self.candidate, parse_xpath(xp), create=True), fragment(elem))
            return f'<response status="success"><result>Reverted changes by {escape(arg)}.</result></response>'
        if key == "load/config/from" and arg == "running-config.xml":
            self.candidate, self.foreign = copy.deepcopy(self.running), []
            return '<response status="success"><msg><line>Config loaded from running-config.xml</line></msg></response>'
        raise SimError(f"{' -> '.join(path)} is unexpected", "17")

    def show_interfaces(self):
        cfg = self.running
        zone_of = {}
        for z in self.vsys(cfg).findall("./zone/entry"):
            for m in z.iter("member"):
                zone_of[m.text] = z.get("name")
        ifnet, hw = [], []
        eth = resolve(cfg, parse_xpath("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet"))
        idx = 16
        for e in eth.findall("entry"):
            name = e.get("name")
            subs = [(name, e.find("layer3"))]
            subs += [(u.get("name"), u) for u in e.findall("./layer3/units/entry")]
            for nm, node in subs:
                ip = node.find("./ip/entry") if node is not None else None
                ifnet.append(f"<entry><name>{escape(nm)}</name><zone>{escape(zone_of.get(nm, ''))}</zone>"
                             f"<fwd>vr:default</fwd><vsys>1</vsys><dyn-addr/><addr6/><tag>0</tag>"
                             f"<ip>{escape(ip.get('name')) if ip is not None else 'N/A'}</ip><id>{idx}</id><addr/></entry>")
                idx += 1
            up = name in ("ethernet1/1", "ethernet1/2", "ethernet1/3")
            hw.append(f"<entry><name>{escape(name)}</name><duplex>{'full' if up else 'auto'}</duplex><type>0</type>"
                      f"<state>{'up' if up else 'down'}</state><st>{'1000/full/up' if up else 'ukn/ukn/down(autoneg)'}</st>"
                      f"<mac>00:1b:17:00:01:{idx:02x}</mac><mode>(autoneg)</mode><speed>{'1000' if up else 'ukn'}</speed>"
                      f"<id>{idx}</id></entry>")
        return (f'<response status="success"><result><ifnet>{"".join(ifnet)}</ifnet>'
                f'<hw>{"".join(hw)}</hw></result></response>')


def panos_handler(sim: PanSim):
    class H(JSONHandler):
        def xml(self, code, text, ctype="application/xml"):
            self.send_json(code, text, ctype)

        def _params(self, method):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
            if "password" in q:
                sim.password_in_url = True
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n).decode() if n else ""
                q.update({k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()})
            return u.path, q

        def _route(self, method):
            path, q = self._params(method)
            if path.rstrip("/") != "/api":
                return self.xml(404, '<response status="error"><msg>Not found</msg></response>')
            t = q.get("type", "")
            sim.requests.append((method, self.path, t))
            with sim.lock:
                if t == "keygen":
                    if q.get("user") == PAN_USER and q.get("password") == PAN_PASS:
                        k = "LUFRPT1" + secrets.token_urlsafe(24)
                        sim.keys.add(k)
                        return self.xml(200, f'<response status="success"><result><key>{k}</key></result></response>')
                    return self.xml(403, '<response status="error" code="403"><result><msg>Invalid Credential'
                                         '</msg></result></response>')
                key = self.headers.get("X-PAN-KEY") or q.get("key")
                if key not in sim.keys:
                    return self.xml(403, '<response status="error" code="403"><result><msg>Invalid Credential'
                                         '</msg></result></response>')
                try:
                    if t == "op":
                        return self.xml(200, sim.op(q.get("cmd", "")))
                    if t == "config":
                        return self.xml(200, sim.config(q))
                    if t == "commit":
                        c = ET.fromstring(q.get("cmd") or "<x/>")
                        if c.tag != "commit":
                            raise SimError("commit: malformed cmd", "17")
                        return self.xml(200, sim.commit())
                    if t == "export" and q.get("category") == "configuration":
                        return self.xml(200, ET.tostring(sim.running, encoding="unicode"))
                    raise SimError(f"unsupported request type '{t}'", "12")
                except (SimError, ET.ParseError) as e:
                    code = getattr(e, "code", "12")
                    return self.xml(200, f'<response status="error" code="{code}"><msg><line>{escape(str(e))}'
                                         '</line></msg></response>')

        def do_GET(self): self._route("GET")
        def do_POST(self): self._route("POST")
    return H


def start_paloalto(port: int = 9443):
    sim = PanSim()
    srv = serve_https(panos_handler(sim), port, "paloalto")
    return sim, srv, {"vendor": "paloalto", "family": "panos", "model": "PA-440 / PA-450 / PA-460",
                      "address": HOST, "port": port,
                      "creds": {"username": PAN_USER, "password": PAN_PASS, "vsys": "vsys1"}}


register("paloalto", start_paloalto)
