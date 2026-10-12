"""
FortiGate driver - FortiOS REST API (7.4 / 7.6) with an API token.

Create the token on the FortiGate once (CLI, as a super_admin):

    config system api-user
        edit "sentinel"
            set accprofile "super_admin"
            set vdom "root"
            config trusthost
                edit 1
                    set ipv4-trusthost <this PC's IP> 255.255.255.255
                next
            end
        next
    end
    execute api-user generate-key sentinel

The key is shown once. Backups need a super_admin profile.
FortiOS applies every change immediately (there is no candidate config), so
each wizard carries its own undo steps, and a full backup is taken first.
"""
from __future__ import annotations

import json
from urllib.parse import quote, urlencode

from .base import (DeviceError, Driver, Field, Plan, PinnedHTTPS, Step, ValidationError, Wizard, fill,
                   v_choice, v_cidr, v_hostname, v_iface, v_int, v_ip, v_ipv4, v_list, v_name, v_port, v_text)

SERVICES = ["ALL", "HTTP", "HTTPS", "SSH", "DNS", "PING", "NTP", "SMTP", "SMTPS", "IMAPS", "RDP",
            "SAMBA", "SNMP", "SYSLOG", "TELNET", "FTP", "ALL_ICMP"]
ACCESS = ["ping", "https", "ssh", "http", "telnet", "snmp", "fgfm", "radius-acct", "ftm", "speed-test"]


def q(name: str) -> str:
    return quote(name, safe="")


class FortiGate(Driver):
    vendor = "fortinet"
    label = "FortiGate"
    default_port = 443
    auth_fields = [
        Field("token", "API token", "password", help="From 'execute api-user generate-key <name>'. See the help below."),
        Field("vdom", "VDOM", required=False, default="root", help="Leave as root unless you use multiple VDOMs."),
    ]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.http = PinnedHTTPS(self.address, self.port, self.pin)
        self.vdom = (self.creds.get("vdom") or "root").strip()
        v_name(self.vdom, "VDOM")

    # ── transport ───────────────────────────────────────────────────────────
    def probe_fingerprint(self) -> str:
        return self.http.fingerprint()

    def api(self, method: str, path: str, body=None, params: dict | None = None, raw: bool = False):
        p = dict(params or {})
        p.setdefault("vdom", self.vdom)
        url = f"{path}?{urlencode(p)}"
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": f"Bearer {self.creds.get('token', '')}", "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        status, hdrs, resp = self.http.request(method, url, data, headers)
        if raw and status == 200:
            return status, resp
        try:
            j = json.loads(resp or b"{}")
        except ValueError:
            j = {}
        if raw:
            return status, resp
        if status == 401:
            raise DeviceError("FortiGate refused the API token (401). Check the token and the api-user's trusthost.")
        if status == 403:
            raise DeviceError("FortiGate: permission denied (403). The api-user's profile does not allow this.")
        if status >= 400 or (isinstance(j, dict) and j.get("status") == "error"):
            detail = j.get("cli_error") or j.get("error") or resp[:200].decode(errors="replace")
            raise DeviceError(f"FortiGate {method} {path}: HTTP {status} - {detail}")
        return j

    # ── read ────────────────────────────────────────────────────────────────
    def connect(self) -> None:
        self.facts_cache = self.facts()

    def facts(self) -> dict:
        j = self.api("GET", "/api/v2/monitor/system/status")
        r = j.get("results", {}) or {}
        return {"hostname": r.get("hostname", ""),
                "model": r.get("model") or f"{r.get('model_name', 'FortiGate')} {r.get('model_number', '')}".strip(),
                "version": f"{j.get('version', '')} build {j.get('build', '')}".strip(),
                "serial": j.get("serial", "")}

    def interfaces(self) -> list[dict]:
        j = self.api("GET", "/api/v2/cmdb/system/interface",
                     params={"format": "name|ip|status|alias|allowaccess|type|description|role"})
        out = []
        for i in j.get("results", []):
            ip = (i.get("ip") or "").split()
            addr = ""
            if len(ip) == 2 and ip[0] != "0.0.0.0":
                try:
                    addr = f"{ip[0]}/{v_cidr(f'{ip[0]}/{ip[1]}', host_ok=True).prefixlen}"
                except ValidationError:
                    addr = " ".join(ip)
            out.append({"name": i.get("name", ""), "ip": addr, "status": i.get("status", ""),
                        "description": i.get("alias") or i.get("description") or "",
                        "type": i.get("type", ""), "role": i.get("role", ""),
                        "allowaccess": i.get("allowaccess", "")})
        self.iface_cache = out
        return out

    def backup(self) -> str:
        path = "/api/v2/monitor/system/config/backup"
        status, data = self.api("GET", path, params={"scope": "global"}, raw=True)
        if status == 405:                       # FortiOS 7.6 wants POST
            status, data = self.api("POST", path, params={"scope": "global"}, raw=True)
        if status != 200:
            raise DeviceError(f"FortiGate backup failed: HTTP {status}. Backups need a super_admin API profile.")
        text = data.decode("utf-8", errors="replace")
        if not text.lstrip().startswith("#config-version") and "config system" not in text:
            raise DeviceError("FortiGate returned something that is not a configuration file")
        return text

    # ── run a plan ──────────────────────────────────────────────────────────
    def execute(self, steps, values=None):
        values = dict(values or {})
        results = []
        for st in steps:
            try:
                path = fill(st.path, {k: q(str(v)) for k, v in values.items()})
                j = self.api(st.method, path, st.body)
            except DeviceError as e:
                results.append({"step": st.title, "ok": False, "detail": str(e)})
                break
            for key, src in st.capture.items():
                if src in j:
                    values[key] = j[src]
            results.append({"step": st.title, "ok": True,
                            "detail": f"HTTP {j.get('http_status', 200)}" + (f", id {j['mkey']}" if "mkey" in j else "")})
        return results, values

    # ── wizards ─────────────────────────────────────────────────────────────
    def wizards(self):
        iface = lambda name, label, **kw: Field(name, label, "select", source="interfaces", **kw)
        return [
            Wizard("basics", "Hostname, DNS and NTP", "Name the firewall and point it at your DNS and time servers.", [
                Field("hostname", "Hostname", placeholder="FGT-HQ"),
                Field("dns1", "Primary DNS", default="1.1.1.1"),
                Field("dns2", "Secondary DNS", required=False, default="9.9.9.9"),
                Field("ntp", "NTP servers", required=False, default="pool.ntp.org",
                      help="Comma separated. Leave empty to use FortiGuard time servers."),
            ], self._w_basics, "System"),
            Wizard("address", "Address object", "A named host or network to use in policies.", [
                Field("name", "Name", placeholder="srv-web01"),
                Field("subnet", "IP or network", placeholder="192.168.10.20 or 192.168.10.0/24"),
                iface("interface", "Bound to interface", required=False, help="Optional. Leave empty for any."),
                Field("comment", "Comment", required=False),
            ], self._w_address, "Objects"),
            Wizard("policy", "Firewall policy", "Allow or deny traffic between two interfaces.", [
                Field("name", "Policy name", placeholder="LAN-to-WAN"),
                iface("srcintf", "From interface"),
                iface("dstintf", "To interface"),
                Field("srcaddr", "Source addresses", default="all", help="Address object names, comma separated. 'all' = any."),
                Field("dstaddr", "Destination addresses", default="all"),
                Field("service", "Services", "multiselect", default=["HTTPS"], options=[[s, s] for s in SERVICES]),
                Field("action", "Action", "select", default="accept", options=[["accept", "Accept"], ["deny", "Deny"]]),
                Field("nat", "NAT (masquerade to the outgoing interface)", "checkbox", required=False, default=False),
                Field("comment", "Comment", required=False),
            ], self._w_policy, "Policy"),
            Wizard("portforward", "Port forward (VIP)", "Publish an internal server on an outside port.", [
                Field("name", "Name", placeholder="vip-web01-https"),
                iface("extintf", "Outside interface"),
                Field("extip", "Outside IP", default="0.0.0.0", help="0.0.0.0 = the outside interface's own address."),
                Field("protocol", "Protocol", "select", default="tcp", options=[["tcp", "TCP"], ["udp", "UDP"]]),
                Field("extport", "Outside port", "number", placeholder="443"),
                Field("mappedip", "Internal server IP", placeholder="192.168.10.20"),
                Field("mappedport", "Internal port", "number", placeholder="443"),
                iface("dstintf", "Interface the server is on"),
            ], self._w_portforward, "Policy"),
            Wizard("adminaccess", "Admin access on an interface",
                   "Choose which management protocols answer on an interface. Turn off HTTP and Telnet everywhere, "
                   "and keep management off the WAN.", [
                iface("interface", "Interface"),
                Field("allow", "Allowed", "multiselect", default=["ping", "https", "ssh"],
                      options=[[a, a.upper() if len(a) <= 5 else a] for a in ACCESS]),
                Field("confirm_lockout", "I am not managing the FortiGate through this interface, or I kept HTTPS on it",
                      "checkbox", required=False, default=False),
            ], self._w_adminaccess, "Hardening"),
        ]

    def _w_basics(self, p, drv):
        host = v_hostname(p["hostname"])
        dns1 = v_ip(p["dns1"], "primary DNS")
        dns2 = v_ip(p["dns2"], "secondary DNS") if str(p.get("dns2", "")).strip() else ""
        ntp = v_list(p.get("ntp", ""), lambda s: v_text(s, 80, "NTP server", forbid=" \"'"), "NTP servers", 4)
        cur_g = self.api("GET", "/api/v2/cmdb/system/global").get("results", {})
        cur_d = self.api("GET", "/api/v2/cmdb/system/dns").get("results", {})
        cur_n = self.api("GET", "/api/v2/cmdb/system/ntp").get("results", {})
        steps = [Step("Set hostname", "PUT", "/api/v2/cmdb/system/global", {"hostname": host}),
                 Step("Set DNS servers", "PUT", "/api/v2/cmdb/system/dns",
                      {"primary": dns1, "secondary": dns2 or "0.0.0.0"})]
        undo = [Step("Restore hostname", "PUT", "/api/v2/cmdb/system/global", {"hostname": cur_g.get("hostname", "")}),
                Step("Restore DNS", "PUT", "/api/v2/cmdb/system/dns",
                     {"primary": cur_d.get("primary", ""), "secondary": cur_d.get("secondary", "")})]
        if ntp:
            steps.append(Step("Set NTP servers", "PUT", "/api/v2/cmdb/system/ntp",
                              {"ntpsync": "enable", "type": "custom",
                               "ntpserver": [{"id": i + 1, "server": s} for i, s in enumerate(ntp)]}))
            undo.append(Step("Restore NTP", "PUT", "/api/v2/cmdb/system/ntp",
                             {k: cur_n.get(k) for k in ("ntpsync", "type", "ntpserver") if k in cur_n}))
        return Plan(f"Hostname {host}, DNS {dns1}{' / ' + dns2 if dns2 else ''}"
                    + (f", NTP {', '.join(ntp)}" if ntp else ""), steps, undo)

    def _w_address(self, p, drv):
        name = v_name(p["name"], "name")
        net = v_cidr(p["subnet"], "IP or network")
        body = {"name": name, "type": "ipmask", "subnet": f"{net.network_address} {net.netmask}",
                "comment": v_text(p.get("comment"), 255, "comment")}
        if str(p.get("interface") or "").strip():
            body["associated-interface"] = v_iface(p["interface"])
        return Plan(f"Address object {name} = {net}",
                    [Step(f"Create address {name}", "POST", "/api/v2/cmdb/firewall/address", body)],
                    [Step(f"Delete address {name}", "DELETE", f"/api/v2/cmdb/firewall/address/{q(name)}")])

    def _names(self, v, what):
        return [{"name": n} for n in v_list(v or "all", lambda s: v_name(s, what) if s != "all" else s, what)]

    def _w_policy(self, p, drv):
        name = v_name(p["name"], "policy name")
        src, dst = v_iface(p["srcintf"]), v_iface(p["dstintf"])
        if src == dst:
            raise ValidationError("from and to interface are the same")
        svc = v_list(p.get("service") or ["ALL"], lambda s: v_choice(s, SERVICES, "service"), "services")
        action = v_choice(p.get("action", "accept"), ["accept", "deny"], "action")
        body = {"name": name, "srcintf": [{"name": src}], "dstintf": [{"name": dst}],
                "srcaddr": self._names(p.get("srcaddr"), "source address"),
                "dstaddr": self._names(p.get("dstaddr"), "destination address"),
                "service": [{"name": s} for s in svc], "action": action, "schedule": "always",
                "logtraffic": "all", "status": "enable",
                "comments": v_text(p.get("comment"), 1023, "comment")}
        if action == "accept":
            body["nat"] = "enable" if p.get("nat") in (True, "true", "on", "1") else "disable"
        notes = ["New policies are added at the end of the list. A broader policy above it can match first; "
                 "check the order in Policy & Objects afterwards."]
        if "ALL" in svc and action == "accept":
            notes.append("Service ALL allows every port. Prefer the specific services you need.")
        return Plan(f"{action.upper()} {src} → {dst} ({', '.join(svc)})",
                    [Step(f"Create policy {name}", "POST", "/api/v2/cmdb/firewall/policy", body,
                          capture={"policy_id": "mkey"})],
                    [Step(f"Delete policy {name}", "DELETE", "/api/v2/cmdb/firewall/policy/{policy_id}")],
                    notes)

    def _w_portforward(self, p, drv):
        name = v_name(p["name"], "name")
        ext, dst = v_iface(p["extintf"]), v_iface(p["dstintf"])
        extip = v_ipv4(p.get("extip") or "0.0.0.0", "outside IP")
        proto = v_choice(p.get("protocol", "tcp"), ["tcp", "udp"], "protocol")
        eport, mport = v_port(p["extport"], "outside port"), v_port(p["mappedport"], "internal port")
        mip = v_ipv4(p["mappedip"], "internal server IP")
        vip = {"name": name, "type": "static-nat", "extintf": ext, "extip": extip,
               "mappedip": [{"range": mip}], "portforward": "enable", "protocol": proto,
               "extport": str(eport), "mappedport": str(mport)}
        pol = {"name": f"{name}-in"[:35], "srcintf": [{"name": ext}], "dstintf": [{"name": dst}],
               "srcaddr": [{"name": "all"}], "dstaddr": [{"name": name}], "service": [{"name": "ALL"}],
               "action": "accept", "schedule": "always", "logtraffic": "all", "nat": "disable", "status": "enable",
               "comments": f"Port forward {proto}/{eport} to {mip}:{mport} (SentinelScan)"}
        return Plan(f"{ext} {proto}/{eport} → {mip}:{mport}",
                    [Step(f"Create VIP {name}", "POST", "/api/v2/cmdb/firewall/vip", vip),
                     Step("Create the allow policy for it", "POST", "/api/v2/cmdb/firewall/policy", pol,
                          capture={"policy_id": "mkey"})],
                    [Step("Delete the allow policy", "DELETE", "/api/v2/cmdb/firewall/policy/{policy_id}"),
                     Step(f"Delete VIP {name}", "DELETE", f"/api/v2/cmdb/firewall/vip/{q(name)}")],
                    ["This exposes an internal server to everyone who can reach the outside interface. "
                     "Restrict the policy's source addresses if you can."])

    def _w_adminaccess(self, p, drv):
        name = v_iface(p["interface"])
        allow = v_list(p.get("allow") or [], lambda s: v_choice(s, ACCESS, "protocol"), "allowed protocols")
        cur = next((i for i in (self.iface_cache or self.interfaces()) if i["name"] == name), None)
        if cur is None:
            raise ValidationError(f"interface {name} not found on the device")
        notes = []
        mine = cur.get("ip", "").split("/")[0] == self.address
        if mine and "https" not in allow and p.get("confirm_lockout") not in (True, "true", "on", "1"):
            raise ValidationError(f"You are connected to the FortiGate through {name} ({self.address}). "
                                  "Removing HTTPS there would cut this connection. Keep HTTPS, or tick the confirmation.")
        for bad in ("http", "telnet"):
            if bad in allow:
                notes.append(f"{bad.upper()} sends the admin password unencrypted. Use HTTPS / SSH instead.")
        if cur.get("role") == "wan" and ({"https", "ssh", "http", "telnet"} & set(allow)):
            notes.append("This is a WAN interface: management on it is reachable from the internet. "
                         "Restrict trusted hosts on the admin accounts, or use a VPN.")
        return Plan(f"{name}: allow {' '.join(allow) or 'nothing'} (was: {cur.get('allowaccess') or 'nothing'})",
                    [Step(f"Set allowaccess on {name}", "PUT", f"/api/v2/cmdb/system/interface/{q(name)}",
                          {"allowaccess": " ".join(allow)})],
                    [Step(f"Restore allowaccess on {name}", "PUT", f"/api/v2/cmdb/system/interface/{q(name)}",
                          {"allowaccess": cur.get("allowaccess", "")})],
                    notes)
