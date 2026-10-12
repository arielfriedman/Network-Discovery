#!/usr/bin/env python3
"""
Device lab: simulated FortiGate / Cisco / Palo Alto / Check Point devices on
127.0.0.1, so you can try every wizard without touching real equipment.

    cd panel && python3 -m devices.lab            # start all simulators
    cd panel && python3 -m devices.lab fortigate  # just one

Each simulator keeps its configuration in memory and answers the same API
calls the real device does, closely enough for the wizards. They are test
doubles, not emulators: firmware quirks are not reproduced.
"""
from __future__ import annotations

import json
import re
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

HOST = "127.0.0.1"
_CERT_DIR = Path(tempfile.gettempdir()) / "sentinel-lab-certs"


def lab_cert(name: str) -> tuple[str, str]:
    """A self-signed certificate per simulator, like a real appliance has."""
    _CERT_DIR.mkdir(mode=0o700, exist_ok=True)
    crt, key = _CERT_DIR / f"{name}.crt", _CERT_DIR / f"{name}.key"
    if not crt.exists():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                        "-subj", f"/CN={name}-lab", "-keyout", str(key), "-out", str(crt)],
                       check=True, capture_output=True)
    return str(crt), str(key)


def serve_https(handler_cls, port: int, name: str) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((HOST, port), handler_cls)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*lab_cert(name))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class JSONHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send_json(self, code: int, obj, ctype="application/json"):
        data = obj if isinstance(obj, bytes) else (obj.encode() if isinstance(obj, str) else json.dumps(obj).encode())
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return raw


# ── FortiGate 100F (FortiOS 7.4 REST API) ────────────────────────────────────
FGT_TOKEN = "lab-fortigate-token"


class FortiGateSim:
    def __init__(self):
        ports = [("mgmt", "192.168.1.99 255.255.255.0", "https ssh ping"),
                 ("wan1", "203.0.113.2 255.255.255.248", "ping"),
                 ("wan2", "0.0.0.0 0.0.0.0", ""), ("dmz", "10.10.10.1 255.255.255.0", "ping https ssh"),
                 ("ha1", "0.0.0.0 0.0.0.0", ""), ("ha2", "0.0.0.0 0.0.0.0", "")]
        ports += [(f"port{i}", "192.168.20.1 255.255.255.0" if i == 1 else "0.0.0.0 0.0.0.0",
                   "ping https ssh http" if i == 1 else "") for i in range(1, 21)]
        ports += [("x1", "0.0.0.0 0.0.0.0", ""), ("x2", "0.0.0.0 0.0.0.0", "")]
        self.interfaces = {n: {"name": n, "ip": ip, "allowaccess": acc, "status": "up", "type": "physical",
                               "alias": "", "description": "",
                               "role": "wan" if n.startswith("wan") else "dmz" if n == "dmz" else "lan"}
                           for n, ip, acc in ports}
        self.glob = {"hostname": "FGT100F-LAB", "timezone": "Asia/Jerusalem", "admintimeout": 5}
        self.dns = {"primary": "96.45.45.45", "secondary": "96.45.46.46"}
        self.ntp = {"ntpsync": "enable", "type": "fortiguard", "ntpserver": []}
        self.tables = {"address": {"all": {"name": "all", "subnet": "0.0.0.0 0.0.0.0"}},
                       "vip": {}, "policy": {}}
        self.next_policy = 1
        self.lock = threading.Lock()

    def config_text(self) -> str:
        out = ["#config-version=FG100F-7.04.4-FW-build2662-240514:opmode=0:vdom=0",
               "config system global", f'    set hostname "{self.glob["hostname"]}"', "end",
               "config system dns", f'    set primary {self.dns["primary"]}',
               f'    set secondary {self.dns["secondary"]}', "end", "config system interface"]
        for i in self.interfaces.values():
            out += [f'    edit "{i["name"]}"', f'        set ip {i["ip"]}',
                    f'        set allowaccess {i["allowaccess"]}' if i["allowaccess"] else "", "    next"]
        out.append("end")
        for t in ("address", "vip", "policy"):
            out.append(f"config firewall {t}")
            for k, v in self.tables[t].items():
                out.append(f'    edit "{k}"' if t != "policy" else f"    edit {k}")
                out += [f"        set {a} {json.dumps(b)}" for a, b in v.items() if a not in ("name", "policyid")]
                out.append("    next")
            out.append("end")
        return "\n".join(x for x in out if x != "") + "\n"


def fortigate_handler(sim: FortiGateSim):
    class H(JSONHandler):
        def _auth(self):
            if self.headers.get("Authorization") != f"Bearer {FGT_TOKEN}":
                self.send_json(401, {"http_status": 401, "status": "error"})
                return False
            return True

        def _route(self, method):
            if not self._auth():
                return
            u = urlparse(self.path)
            parts = [unquote(p) for p in u.path.split("/") if p]
            ok = lambda extra=None: self.send_json(200, {"http_method": method, "status": "success",
                                                         "http_status": 200, "vdom": "root", **(extra or {})})
            err = lambda code, msg: self.send_json(code, {"http_method": method, "status": "error",
                                                          "http_status": code, "error": -5, "cli_error": msg})
            p = "/".join(parts[2:])  # after api/v2
            with sim.lock:
                if p == "monitor/system/status" and method == "GET":
                    return self.send_json(200, {"status": "success", "serial": "FG100FTK20000001",
                                                "version": "v7.4.4", "build": 2662,
                                                "results": {"model_name": "FortiGate", "model_number": "100F",
                                                            "model": "FG100F", "hostname": sim.glob["hostname"]}})
                if p == "monitor/system/config/backup":
                    if method != "GET":
                        return err(405, "method not allowed")
                    return self.send_json(200, sim.config_text(), "text/plain")
                if p == "cmdb/system/interface" and method == "GET":
                    return ok({"results": list(sim.interfaces.values())})
                if p.startswith("cmdb/system/interface/") and method == "PUT":
                    name = parts[-1]
                    if name not in sim.interfaces:
                        return err(404, "entry not found")
                    body = self.body()
                    if "allowaccess" in body:
                        bad = set(body["allowaccess"].split()) - {"ping", "https", "ssh", "http", "telnet", "snmp",
                                                                   "fgfm", "radius-acct", "ftm", "speed-test"}
                        if bad:
                            return err(500, f"invalid allowaccess {bad}")
                    sim.interfaces[name].update(body)
                    return ok({"mkey": name})
                single = {"cmdb/system/global": sim.glob, "cmdb/system/dns": sim.dns, "cmdb/system/ntp": sim.ntp}
                if p in single:
                    if method == "GET":
                        return ok({"results": dict(single[p])})
                    if method == "PUT":
                        body = self.body()
                        if p.endswith("global") and "hostname" in body and not re.match(r"^[\w-]{1,35}$", body["hostname"]):
                            return err(500, "hostname invalid")
                        single[p].update(body)
                        return ok()
                m = re.match(r"^cmdb/firewall/(address|vip|policy)(?:/(.+))?$", p)
                if m:
                    t, key = m.group(1), m.group(2)
                    tbl = sim.tables[t]
                    if method == "GET":
                        return ok({"results": list(tbl.values()) if key is None else [tbl[key]] if key in tbl else []})
                    if method == "POST" and key is None:
                        body = self.body()
                        if t == "policy":
                            for ref in body.get("dstaddr", []) + body.get("srcaddr", []):
                                if ref["name"] not in sim.tables["address"] and ref["name"] not in sim.tables["vip"]:
                                    return err(424, f"entry not found in datasource: {ref['name']}")
                            for ref in body.get("srcintf", []) + body.get("dstintf", []):
                                if ref["name"] not in sim.interfaces:
                                    return err(424, f"interface not found: {ref['name']}")
                            pid = str(sim.next_policy); sim.next_policy += 1
                            tbl[pid] = {**body, "policyid": int(pid)}
                            return ok({"mkey": int(pid)})
                        name = body.get("name", "")
                        if not name or name in tbl:
                            return err(500, "entry already exists" if name else "name required")
                        tbl[name] = body
                        return ok({"mkey": name})
                    if method == "DELETE" and key is not None:
                        if key not in tbl:
                            return err(404, "entry not found")
                        if t in ("address", "vip"):
                            for pol in sim.tables["policy"].values():
                                if any(r["name"] == key for r in pol.get("dstaddr", []) + pol.get("srcaddr", [])):
                                    return err(500, "entry is used by a policy")
                        del tbl[key]
                        return ok({"mkey": key})
            return err(404, f"unknown path {p}")

        def do_GET(self): self._route("GET")
        def do_POST(self): self._route("POST")
        def do_PUT(self): self._route("PUT")
        def do_DELETE(self): self._route("DELETE")
    return H


def start_fortigate(port: int = 8443):
    sim = FortiGateSim()
    srv = serve_https(fortigate_handler(sim), port, "fortigate")
    return sim, srv, {"vendor": "fortinet", "family": "fortios", "model": "FG-100F", "address": HOST, "port": port,
                      "creds": {"token": FGT_TOKEN, "vdom": "root"}}


# name → start(port=None) returning (sim, server, connection info). Other vendors'
# simulators live in lab_<vendor>.py and add themselves with register().
SIMULATORS = {"fortigate": start_fortigate}


def register(name: str, start) -> None:
    SIMULATORS[name] = start


def _load_plugins() -> None:
    import importlib
    for f in sorted(Path(__file__).parent.glob("lab_*.py")):
        try:
            importlib.import_module(f"{__package__}.{f.stem}")
        except ImportError as e:
            print(f"  ({f.stem} not loaded: {e})")


def main(argv):
    _load_plugins()
    names = argv[1:] or list(SIMULATORS)
    print("SentinelScan device lab - simulated devices (Ctrl-C to stop)\n")
    for n in names:
        if n not in SIMULATORS:
            print(f"unknown simulator {n}; choose from {', '.join(SIMULATORS)}")
            return 2
        _, _, info = SIMULATORS[n]()
        creds = ", ".join(f"{k}={v}" for k, v in info["creds"].items())
        print(f"  {n:<17} {info['model']:<34} {info['address']} port {info['port']:<5}  {creds}")
    print("\nAdd them on the Devices page with the address and port above.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


if __name__ == "__main__":
    # Run through the package module, so lab_<vendor>.py plugins register into
    # the same SIMULATORS dict that main() reads (not into a second copy).
    import importlib
    sys.exit(importlib.import_module("devices.lab").main(sys.argv))
