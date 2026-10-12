"""
Check Point simulators for the device lab.

- checkpoint-spark: a Quantum Spark 1800 (R81.10.15) REST API (/web-api/[v1/]login, logout,
  run-clish-command) answering the clish commands the driver uses.
- checkpoint-mgmt: a Management Server (R81.20, Management API 1.9) with sessions: changes are
  visible only to the session that made them until publish; discard drops them.

Output formats of commands the vendor does not document (show dns, show ntp, …) are guesses.
"""
from __future__ import annotations

import base64
import binascii
import copy
import re
import threading
import uuid

from . import lab
from .lab import HOST, JSONHandler, serve_https

SPARK_USER, SPARK_PASSWORD = "admin", "lab-spark-password"
MGMT_USER, MGMT_PASSWORD, MGMT_API_KEY = "admin", "lab-mgmt-password", "lab-mgmt-api-key-0000000000"
MGMT_DOMAINS = {"", "SMC User", "Lab_Domain"}


# ── Quantum Spark 1800 ──────────────────────────────────────────────────────
class SparkSim:
    def __init__(self):
        self.hostname = "Spark1800-LAB"
        self.dns = {"mode": "internet", "primary": "8.8.8.8", "secondary": "", "tertiary": ""}
        self.ntp = {"primary": "ntp.checkpoint.com", "secondary": "ntp2.checkpoint.com", "active": "off"}
        self.rest_api = "on"
        self.interfaces = [("WAN", "203.0.113.10", "1/full"), ("DMZ", "", "off"),
                           ("LAN1", "192.168.1.1", "1/full")] + [(f"LAN{i}", "", "off") for i in range(2, 9)]
        self.sessions: set[str] = set()
        self.log: list[str] = []         # every clish command received
        self.lock = threading.Lock()

    def run(self, cmd: str) -> str:
        self.log.append(cmd)
        c = cmd.strip()
        if c == "show diag":
            return ("Current system info\n-----------------------------------\n"
                    "Current image name: R81.10.15_990173204_20_35\nCurrent image version: 173204\n"
                    "HW version : 1800\nSerial number : CP1800LAB0001\nHW MAC Address: 00:1C:7F:00:00:01\n"
                    "-----------------------------------\n")
        if c == "show software-version":
            return "R81.10.15 (990173204)\n"
        if c in ("show interfaces", "show interfaces all"):
            out = []
            for n, ip, st in self.interfaces:
                out += [f"name:                         {n}", f"ipv4-address:                 {ip}",
                        "ipv6-address:", f"status:                       {st}"]
                if c.endswith("all"):
                    out += ["mac-address:                  00:1C:7F:00:00:02", "description:"]
            return "\n".join(out) + "\n"
        if c == "show dns":
            return "".join(f"{k}: {self.dns[k]}\n" for k in ("mode", "primary", "secondary", "tertiary"))
        if c == "show ntp":
            return f"active: {self.ntp['active']}\nprimary: {self.ntp['primary']}\nsecondary: {self.ntp['secondary']}\n"
        if c == "show ntp servers":
            return f"primary: {self.ntp['primary']}\nsecondary: {self.ntp['secondary']}\n"
        if c == "show ntp active":
            return f"active: {self.ntp['active']}\n"
        if c == "show rest-api":
            return f"mode: {self.rest_api}\n"
        m = re.fullmatch(r"set (?:device-details )?hostname (\S+)", c)
        if m:
            if not re.fullmatch(r"[A-Za-z0-9-]{1,63}", m.group(1)):
                return "Error: invalid hostname\n"
            self.hostname = m.group(1)
            return f"set hostname: Setting hostname to '{self.hostname}'\nOK\n"
        m = re.fullmatch(r"set dns((?: (?:primary|secondary|tertiary) ipv4-address \S+)+)", c)
        if m:
            pairs = re.findall(r"(primary|secondary|tertiary) ipv4-address (\S+)", m.group(1))
            for _, ip in pairs:
                if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
                    return f"Error: invalid IPv4 address {ip}\n"
            for slot, ip in pairs:
                self.dns[slot] = ip
            return ""
        m = re.fullmatch(r"set dns mode (\S+)", c)
        if m:
            if m.group(1) not in ("global", "internet"):
                return "Error: mode must be global or internet\n"
            self.dns["mode"] = m.group(1)
            return ""
        m = re.fullmatch(r"set ntp server (primary|secondary) (\S+)", c)
        if m:
            self.ntp[m.group(1)] = m.group(2)
            return ""
        m = re.fullmatch(r"set ntp active (on|off)", c)
        if m:
            self.ntp["active"] = m.group(1)
            return ""
        return f"Error: Unknown command: {c[:60]}\n"


def spark_handler(sim: SparkSim):
    class H(JSONHandler):
        def do_POST(self):
            m = re.fullmatch(r"/web-api/(?:v1/)?([a-z-]+)", self.path)
            if not m:
                return self.send_json(404, {"message": "not found"})
            cmd, body = m.group(1), self.body()
            if cmd == "login":
                if not isinstance(body, dict) or body.get("user") != SPARK_USER or body.get("password") != SPARK_PASSWORD:
                    return self.send_json(401, {"message": "Authentication failed"})
                sid = uuid.uuid4().hex
                sim.sessions.add(sid)
                return self.send_json(200, {"sid": sid, "role": "ROLE.SUPER", "read-only": False,
                                            "api-server-version": "v1", "session-timeout": 10})
            sid = self.headers.get("x-chkp-sid", "")
            if sid not in sim.sessions:
                return self.send_json(401, {"message": "Invalid session id"})
            if cmd == "logout":
                sim.sessions.discard(sid)
                return self.send_json(200, {"message": "OK"})
            if cmd == "run-clish-command":
                try:
                    script = base64.b64decode(body.get("script", ""), validate=True).decode()
                except (binascii.Error, UnicodeDecodeError, AttributeError):
                    return self.send_json(400, {"message": "script must be base64"})
                if "\n" in script.strip() or not script.strip():
                    return self.send_json(400, {"message": "script must be a single clish command"})
                with sim.lock:
                    out = sim.run(script)
                return self.send_json(200, {"output": base64.b64encode(out.encode()).decode()})
            return self.send_json(404, {"message": f"unknown command {cmd}"})
    return H


def start_spark(port: int = 14434):
    sim = SparkSim()
    srv = serve_https(spark_handler(sim), port, "checkpoint-spark")
    return sim, srv, {"vendor": "checkpoint", "family": "spark", "model": "Quantum Spark 1600 / 1800",
                      "address": HOST, "port": port, "creds": {"username": SPARK_USER, "password": SPARK_PASSWORD}}


# ── Management Server R81.20 ────────────────────────────────────────────────
SERVICES = {"Any", "http", "https", "ssh", "ssh_version_2", "dns", "domain-udp", "ntp", "smtp", "icmp-proto", "ftp"}


class MgmtSim:
    def __init__(self):
        self.published = {
            "hosts": {}, "networks": {},
            "layers": {"Network": [{"type": "access-section", "name": "Lab rules", "uid": self._uid()},
                                   {"type": "access-rule", "uid": self._uid(), "name": "Cleanup rule",
                                    "source": ["Any"], "destination": ["Any"], "service": ["Any"],
                                    "action": "Drop", "track": {"type": "Log"}, "section": "Lab rules"}]},
        }
        self.gateways = [
            {"name": "mgmt-lab", "type": "checkpoint-host", "version": "R81.20", "ipv4-address": "10.0.0.5",
             "management-blades": {"network-policy-management": True}, "network-security-blades": {}},
            {"name": "gw-9100", "type": "simple-gateway", "version": "R81.20", "ipv4-address": "10.0.0.1",
             "network-security-blades": {"firewall": True}, "management-blades": {},
             "interfaces": [{"name": "Mgmt", "ipv4-address": "10.0.0.1", "ipv4-mask-length": 24, "topology": "internal"},
                            {"name": "eth1", "ipv4-address": "203.0.113.2", "ipv4-mask-length": 29, "topology": "external"},
                            {"name": "eth2", "ipv4-address": "192.168.10.1", "ipv4-mask-length": 24, "topology": "internal"}]},
            {"name": "cl-9200", "type": "CpmiGatewayCluster", "version": "R81.20", "ipv4-address": "10.0.1.1",
             "network-security-blades": {"firewall": True}, "management-blades": {}},
        ]
        self.packages = {"Standard"}
        self.sessions: dict[str, dict] = {}     # sid → {"user", "domain", "work": None | state copy}
        self.tasks: dict[str, dict] = {}
        self.fail_publish = ""                  # "", "error" (HTTP error) or "task" (task fails)
        self.fail_install = False
        self.installs: list[dict] = []
        self.lock = threading.Lock()

    @staticmethod
    def _uid():
        return str(uuid.uuid4())

    def state(self, sess, write=False):
        if sess["work"] is None:
            if not write:
                return self.published
            sess["work"] = copy.deepcopy(self.published)
            sess["changes"] = 0
        if write:
            sess["changes"] += 1
        return sess["work"]

    def task(self, ok=True, desc="", polls=1):
        tid = self._uid()
        self.tasks[tid] = {"ok": ok, "desc": desc, "polls": polls}
        return tid


class ApiError(Exception):
    def __init__(self, status, code, message, errors=None):
        super().__init__(message)
        self.status, self.code, self.message, self.errors = status, code, message, errors or []


def _page(items, body):
    off, lim = int(body.get("offset", 0)), int(body.get("limit", 50))
    part = items[off:off + lim]
    return {"objects": part, "from": off + 1 if part else 0, "to": off + len(part), "total": len(items)}


def mgmt_call(sim: MgmtSim, sess: dict, cmd: str, b: dict):
    st = lambda write=False: sim.state(sess, write)
    nf = lambda what, n: ApiError(404, "generic_err_object_not_found", f"Requested object [{n}] not found")

    def need(*keys):
        for k in keys:
            if k not in b:
                raise ApiError(400, "generic_err_missing_required_parameters", f"Missing parameter: [{k}]")

    def known(name):
        s = st()
        return name == "Any" or name in s["hosts"] or name in s["networks"]

    def name_free(name):
        s = st()
        if name in s["hosts"] or name in s["networks"]:
            raise ApiError(400, "err_validation_failed", "Validation failed with 1 error",
                           [{"message": f"More than one object named '{name}' exists."}])

    if cmd == "show-session":
        return {"uid": sess["sid_uid"], "user-name": sess["user"], "state": "open",
                "changes": sess.get("changes", 0) if sess["work"] is not None else 0,
                "domain": {"name": sess["domain"] or "SMC User", "domain-type": "domain" if sess["domain"] else "mds"}}
    if cmd == "show-api-versions":
        return {"current-version": "1.9", "supported-versions": ["1", "1.1", "1.5", "1.8", "1.9"]}
    if cmd == "show-gateways-and-servers":
        full = b.get("details-level") == "full"
        objs = [{k: v for k, v in g.items() if full or k in ("name", "type")} for g in sim.gateways]
        for o in objs:
            o.pop("interfaces", None)
            o["uid"] = "gw-" + o["name"]
        return _page(objs, b)
    if cmd == "show-simple-gateway":
        need("name")
        g = next((g for g in sim.gateways if g["name"] == b["name"] and g["type"] == "simple-gateway"), None)
        if not g:
            raise nf("gateway", b["name"])
        return copy.deepcopy(g)
    if cmd in ("show-host", "show-network"):
        need("name")
        tbl = st()["hosts" if cmd == "show-host" else "networks"]
        if b["name"] not in tbl:
            raise nf("object", b["name"])
        return tbl[b["name"]]
    if cmd in ("show-hosts", "show-networks"):
        return _page(list(st()["hosts" if cmd == "show-hosts" else "networks"].values()), b)
    if cmd == "add-host":
        need("name", "ip-address")
        name_free(b["name"])
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", str(b["ip-address"])):
            raise ApiError(400, "generic_err_invalid_parameter", "Invalid parameter for [ip-address]")
        obj = {"uid": sim._uid(), "name": b["name"], "type": "host", "ipv4-address": b["ip-address"],
               "comments": b.get("comments", "")}
        st(True)["hosts"][b["name"]] = obj
        return obj
    if cmd == "add-network":
        need("name", "subnet4", "mask-length4")
        name_free(b["name"])
        ml = b["mask-length4"]
        if not isinstance(ml, int) or not 0 <= ml <= 32:
            raise ApiError(400, "generic_err_invalid_parameter", "Invalid parameter for [mask-length4]")
        obj = {"uid": sim._uid(), "name": b["name"], "type": "network", "subnet4": b["subnet4"],
               "mask-length4": ml, "comments": b.get("comments", "")}
        st(True)["networks"][b["name"]] = obj
        return obj
    if cmd in ("delete-host", "delete-network"):
        need("name")
        tbl_name = "hosts" if cmd == "delete-host" else "networks"
        if b["name"] not in st()[tbl_name]:
            raise nf("object", b["name"])
        for layer in st()["layers"].values():
            for r in layer:
                if r["type"] == "access-rule" and b["name"] in r["source"] + r["destination"]:
                    raise ApiError(409, "err_validation_failed", "Validation failed with 1 error",
                                   [{"message": f"Object {b['name']} is used by rule '{r['name']}'"}])
        del st(True)[tbl_name][b["name"]]
        return {"message": "OK"}
    if cmd == "show-access-layer":
        need("name")
        if b["name"] not in st()["layers"]:
            raise nf("layer", b["name"])
        return {"name": b["name"], "uid": "layer-" + b["name"], "type": "access-layer"}
    if cmd == "add-access-rule":
        need("layer", "position")
        if b["layer"] not in st()["layers"]:
            raise nf("layer", b["layer"])
        for k in ("source", "destination"):
            for n in b.get(k, ["Any"]):
                if not known(n):
                    raise nf("object", n)
        for n in b.get("service", ["Any"]):
            if n not in SERVICES:
                raise nf("service", n)
        if str(b.get("action", "Drop")).lower() not in ("accept", "drop"):
            raise ApiError(400, "generic_err_invalid_parameter", "Invalid parameter for [action]")
        rules = st(True)["layers"][b["layer"]]
        rule = {"type": "access-rule", "uid": sim._uid(), "name": b.get("name", ""),
                "source": b.get("source", ["Any"]), "destination": b.get("destination", ["Any"]),
                "service": b.get("service", ["Any"]), "action": b.get("action", "Drop"),
                "track": b.get("track", {"type": "None"}), "comments": b.get("comments", "")}
        pos = b["position"]
        if pos == "top":
            first = next((i for i, r in enumerate(rules) if r["type"] == "access-rule"), len(rules))
            rule["section"] = rules[first].get("section") if first < len(rules) else None
            rules.insert(first if first < len(rules) else len(rules), rule)
        elif pos == "bottom":
            rule["section"] = rules[-1].get("section") or rules[-1]["name"] if rules else None
            rules.append(rule)
        elif isinstance(pos, dict) and "top" in pos:
            idx = next((i for i, r in enumerate(rules) if r["type"] == "access-section" and r["name"] == pos["top"]), None)
            if idx is None:
                raise nf("section", pos["top"])
            rule["section"] = pos["top"]
            rules.insert(idx + 1, rule)
        else:
            raise ApiError(400, "generic_err_invalid_parameter", "Invalid parameter for [position]")
        return {k: v for k, v in rule.items() if k != "section"}
    if cmd == "delete-access-rule":
        need("layer")
        if b["layer"] not in st()["layers"]:
            raise nf("layer", b["layer"])
        key = b.get("uid") or b.get("name")
        rules = st()["layers"][b["layer"]]
        idx = next((i for i, r in enumerate(rules) if r["type"] == "access-rule" and key in (r["uid"], r["name"])), None)
        if idx is None:
            raise nf("rule", key)
        del st(True)["layers"][b["layer"]][idx]
        return {"message": "OK"}
    if cmd == "show-access-rulebase":
        need("name")
        if b["name"] not in st()["layers"]:
            raise nf("layer", b["name"])
        items = st()["layers"][b["name"]]
        rules = [r for r in items if r["type"] == "access-rule"]
        off, lim = int(b.get("offset", 0)), int(b.get("limit", 50))
        part = rules[off:off + lim]
        out, sections = [], {}
        for n, r in enumerate(part, off + 1):
            rr = {k: v for k, v in r.items() if k != "section"}
            rr["rule-number"] = n
            if r.get("section"):
                if r["section"] not in sections:
                    sections[r["section"]] = {"type": "access-section", "name": r["section"], "rulebase": []}
                    out.append(sections[r["section"]])
                sections[r["section"]]["rulebase"].append(rr)
            else:
                out.append(rr)
        return {"uid": "layer-" + b["name"], "name": b["name"], "rulebase": out,
                "from": off + 1 if part else 0, "to": off + len(part), "total": len(rules)}
    if cmd == "publish":
        if sim.fail_publish == "error":
            raise ApiError(500, "generic_server_error", "Publish failed: database is locked by another session")
        if sim.fail_publish == "task":
            return {"task-id": sim.task(False, "Publish failed: validation error on object")}
        if sess["work"] is not None:
            sim.published = sess["work"]
            sess["work"] = None
        return {"task-id": sim.task(True, "Publish operation succeeded", polls=2)}
    if cmd == "discard":
        n = sess.get("changes", 0) if sess["work"] is not None else 0
        sess["work"] = None
        return {"number-of-discarded-changes": n, "message": "OK"}
    if cmd == "install-policy":
        need("policy-package", "targets")
        if b["policy-package"] not in sim.packages:
            raise nf("package", b["policy-package"])
        for t in b["targets"]:
            if not any(g["name"] == t and g["network-security-blades"].get("firewall") for g in sim.gateways):
                raise nf("gateway", t)
        if sess["work"] is not None:
            raise ApiError(400, "err_validation_failed", "Publish your changes before installing the policy")
        if sim.fail_install:
            return {"task-id": sim.task(False, "Policy installation failed on gw-9100: verification error")}
        sim.installs.append({"package": b["policy-package"], "targets": list(b["targets"]),
                             "rules": len([r for r in sim.published["layers"]["Network"] if r["type"] == "access-rule"])})
        return {"task-id": sim.task(True, "Policy installed", polls=2)}
    if cmd == "show-task":
        need("task-id")
        t = sim.tasks.get(b["task-id"])
        if not t:
            raise nf("task", b["task-id"])
        if t["polls"] > 1:
            t["polls"] -= 1
            return {"tasks": [{"task-id": b["task-id"], "status": "in progress", "progress-percentage": 50}]}
        status = "succeeded" if t["ok"] else "failed"
        return {"tasks": [{"task-id": b["task-id"], "status": status, "progress-percentage": 100,
                           "task-details": [{"statusDescription": t["desc"]}]}]}
    raise ApiError(404, "generic_err_command_not_found", f"Unknown command [{cmd}]")


def mgmt_handler(sim: MgmtSim):
    class H(JSONHandler):
        def do_POST(self):
            m = re.fullmatch(r"/web_api/(?:v[\d.]+/)?([a-z-]+)", self.path)
            if not m:
                return self.send_json(404, {"code": "generic_err_command_not_found", "message": "not found"})
            cmd, b = m.group(1), self.body()
            if not isinstance(b, dict):
                return self.send_json(400, {"code": "generic_err_invalid_syntax", "message": "Invalid JSON"})
            with sim.lock:
                if cmd == "login":
                    ok = (b.get("api-key") == MGMT_API_KEY) or (b.get("user") == MGMT_USER and
                                                               b.get("password") == MGMT_PASSWORD)
                    if not ok:
                        return self.send_json(400, {"code": "err_login_failed",
                                                    "message": "Authentication to server failed."})
                    if b.get("domain", "") not in MGMT_DOMAINS:
                        return self.send_json(400, {"code": "err_login_failed",
                                                    "message": f"Domain [{b['domain']}] not found"})
                    sid = uuid.uuid4().hex
                    sim.sessions[sid] = {"user": b.get("user") or "api-key-admin", "domain": b.get("domain", ""),
                                         "work": None, "sid_uid": str(uuid.uuid4()), "name": b.get("session-name")}
                    return self.send_json(200, {"sid": sid, "uid": sim.sessions[sid]["sid_uid"],
                                                "api-server-version": "1.9", "session-timeout": b.get("session-timeout", 600)})
                sess = sim.sessions.get(self.headers.get("X-chkp-sid", ""))
                if sess is None:
                    return self.send_json(403, {"code": "generic_err_wrong_session_id",
                                                "message": "Wrong session id [...]. Session may be expired."})
                if cmd == "logout":
                    sim.sessions.pop(self.headers.get("X-chkp-sid"), None)
                    return self.send_json(200, {"message": "OK"})
                try:
                    return self.send_json(200, mgmt_call(sim, sess, cmd, b))
                except ApiError as e:
                    out = {"code": e.code, "message": e.message}
                    if e.errors:
                        out["errors"] = e.errors
                    return self.send_json(e.status, out)
    return H


def start_mgmt(port: int = 10443):
    sim = MgmtSim()
    srv = serve_https(mgmt_handler(sim), port, "checkpoint-mgmt")
    return sim, srv, {"vendor": "checkpoint", "family": "mgmt", "model": "Management Server (R81.20 / R82)",
                      "address": HOST, "port": port, "creds": {"username": MGMT_USER, "password": MGMT_PASSWORD}}


lab.register("checkpoint-spark", start_spark)
lab.register("checkpoint-mgmt", start_mgmt)
