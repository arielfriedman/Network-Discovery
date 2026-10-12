"""
Check Point driver - two families, two different APIs.

Quantum Spark 1600 / 1800 / 1900 / 2000 (locally managed, family "spark")
    The appliance's own REST API on port 4434. Enable it once in clish:

        set rest-api mode on

    Log in with a Spark administrator (user name + password). The API has only
    login, logout, generate-report and run-clish-command, so every read and
    change is a single Gaia Clish command sent base64-encoded. Changes apply
    immediately; each wizard carries its own undo where the old value can be
    read back. The "backup" stored before a change is a snapshot of the
    relevant show commands, not a restorable backup file - make a real one in
    the WebUI (Device > System Operations > Backup) before larger changes.

Management Server (R81.20 / R82, family "mgmt") for Quantum Force and other gateways
    Connect to the Management Server, not to the gateway. Log in with a
    management administrator (user name + password) or an API key
    (SmartConsole > Manage & Settings > Permissions & Administrators >
    Administrators > Authentication method: API Key). On a Multi-Domain Server
    also enter the Domain. The Management API must accept your IP
    (SmartConsole > Manage & Settings > Blades > Management API > Advanced
    Settings), followed by 'api restart' on the server.

    Changes are made in a private session called "SentinelScan" and become
    visible to others only after Publish; if anything fails, the session is
    discarded. Gateways only enforce a change after Install Policy.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import time

from .base import (DeviceError, Driver, Field, Plan, PinnedHTTPS, Step, ValidationError, Wizard,
                   v_address, v_choice, v_cidr, v_hostname, v_ipv4, v_list, v_name, v_text)

SPARK_API = "/web-api/v1"       # versioned path, Admin Guide "RESTful API > Versioning" (p. 540)
MGMT_API = "/web_api"
SESSION_NAME = "SentinelScan"
TASK_TIMEOUT = 600              # seconds to wait for publish / install-policy
POLL_EVERY = 2
BACKUP_PAGE = 500

# A Spark clish command answered with one of these (at line start) failed. The Admin Guide
# shows "Error: missing argument ..." in its sample configuration log (p. 36).
SPARK_ERROR_RE = re.compile(r"^\s*(error|failed|invalid|unknown command|command not found)\b", re.I | re.M)
NOT_FOUND_CODES = {"generic_err_object_not_found", "err_object_not_found"}
SESSION_CODES = {"generic_err_wrong_session_id", "err_wrong_session_id", "generic_err_session_expired"}
PLACEHOLDER_RE = re.compile(r"^\{(\w+)\}$")
TRUE = (True, "true", "on", "1", 1)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _kv(text: str) -> list[tuple[str, str]]:
    """'key:   value' lines (the format of Spark show commands) → [(key, value)]."""
    out = []
    for line in (text or "").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out.append((k.strip().lower(), v.strip()))
    return out


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _fill_body(body, values: dict):
    """Put captured values (rule uid, …) into a body. Only whole-string placeholders like
    "{rule_uid}" are replaced; wizard input can never contain braces (validators forbid them)."""
    if isinstance(body, dict):
        return {k: _fill_body(v, values) for k, v in body.items()}
    if isinstance(body, list):
        return [_fill_body(v, values) for v in body]
    if isinstance(body, str):
        m = PLACEHOLDER_RE.match(body)
        if m:
            if m.group(1) not in values:
                raise DeviceError(f"value '{m.group(1)}' from an earlier step is missing")
            return values[m.group(1)]
    return body


def _obj_name(v: str, what: str) -> str:
    """A Check Point object name used in a rule; 'Any' is the built-in any-object."""
    s = str(v).strip()
    return "Any" if s.lower() == "any" else v_name(s, what)


class CheckPoint(Driver):
    vendor = "checkpoint"
    label = "Check Point"
    default_port = 443
    family_ports = {"spark": 4434, "mgmt": 443}
    auth_fields = [
        Field("username", "User name", required=False),
        Field("password", "Password", "password", required=False),
        Field("api_key", "API key", "password", required=False,
              help="Management Server only: use instead of user name and password."),
        Field("domain", "Domain", required=False, help="Multi-Domain Server only."),
    ]
    family_auth = {
        "spark": [
            Field("username", "User name", default="admin"),
            Field("password", "Password", "password",
                  help="A Spark administrator. The REST API must be on: clish 'set rest-api mode on'."),
        ],
        "mgmt": [
            Field("username", "User name", required=False,
                  help="A management administrator. Leave empty when you use an API key."),
            Field("password", "Password", "password", required=False),
            Field("api_key", "API key", "password", required=False,
                  help="Instead of user name and password (administrator with authentication method 'API Key')."),
            Field("domain", "Domain", required=False, help="Multi-Domain Server only: the Domain to log in to."),
        ],
    }

    def __init__(self, address, port, creds, pin, family=""):
        if family not in self.family_ports:
            family = "spark" if port == 4434 else "mgmt"
        super().__init__(address, port or self.family_ports[family], creds, pin, family)
        self.http = PinnedHTTPS(self.address, self.port, self.pin)
        self.sid = ""
        self.dirty = False              # mgmt: session holds unpublished changes
        self.pending_install: list[dict] = []
        self.api_version = ""

    @property
    def spark(self) -> bool:
        return self.family == "spark"

    # ── transport ───────────────────────────────────────────────────────────
    def probe_fingerprint(self) -> str:
        return self.http.fingerprint()

    def _post(self, path: str, body: dict | None, auth: bool = True):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if auth:
            headers["X-chkp-sid" if not self.spark else "x-chkp-sid"] = self.sid
        data = json.dumps(body if body is not None else {}).encode()
        status, _, resp = self.http.request("POST", path, data, headers)
        try:
            j = json.loads(resp or b"{}")
        except ValueError:
            j = {"message": resp[:200].decode(errors="replace")}
        return status, j if isinstance(j, (dict, list)) else {"message": str(j)}

    @staticmethod
    def _err_text(j) -> str:
        if not isinstance(j, dict):
            return str(j)[:300]
        parts = [str(j.get("message") or j.get("error") or "").strip()]
        for key in ("errors", "blocking-errors", "warnings"):
            for e in j.get(key) or []:
                msg = e.get("message") if isinstance(e, dict) else str(e)
                if msg:
                    parts.append(f"{'warning' if key == 'warnings' else 'error'}: {msg}")
        text = "; ".join(p for p in parts if p) or json.dumps(j)[:300]
        if j.get("code") in NOT_FOUND_CODES:
            text += " (object missing)"
        return text

    # Spark ------------------------------------------------------------------
    def _spark_login(self) -> None:
        user = v_text(self.creds.get("username") or "", 64, "user name")
        if not user or not self.creds.get("password"):
            raise DeviceError("Enter the Spark administrator's user name and password.")
        status, j = self._post(f"{SPARK_API}/login", {"user": user, "password": self.creds["password"]}, auth=False)
        if status in (400, 401, 403) or (status == 200 and not j.get("sid")):
            raise DeviceError(f"Spark refused the login (HTTP {status}): {self._err_text(j)}. "
                              "Check the user name and password, and that 'set rest-api mode on' was run.")
        if status != 200:
            raise DeviceError(f"Spark login failed: HTTP {status} - {self._err_text(j)}")
        if j.get("read-only"):
            raise DeviceError("This Spark administrator is read-only; the wizards need a read-write role.")
        self.sid = j["sid"]
        self.api_version = str(j.get("api-server-version", ""))

    def clish(self, command: str) -> str:
        """Run ONE clish command (the API runs a single command per call) and return its output."""
        if "\n" in command or "\r" in command:
            raise DeviceError("internal: one clish command per call")
        for attempt in (0, 1):
            status, j = self._post(f"{SPARK_API}/run-clish-command", {"script": _b64(command)})
            if status == 401 and attempt == 0:      # session timed out (default 10 min): log in again
                self._spark_login()
                continue
            break
        if status != 200:
            raise DeviceError(f"Spark: '{command}' failed: HTTP {status} - {self._err_text(j)}")
        try:
            out = base64.b64decode(j.get("output") or "", validate=False).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            raise DeviceError(f"Spark: '{command}' returned output that is not base64") from None
        return out

    # Management ----------------------------------------------------------------
    def _mgmt_login(self) -> None:
        body = {"session-name": SESSION_NAME, "session-description": "Changes made with the SentinelScan wizards",
                "session-timeout": 3600}
        key = (self.creds.get("api_key") or "").strip()
        user = (self.creds.get("username") or "").strip()
        if key:
            body["api-key"] = key
        elif user and self.creds.get("password"):
            body["user"] = v_text(user, 100, "user name")
            body["password"] = self.creds["password"]
        else:
            raise DeviceError("Enter a user name and password, or an API key.")
        dom = v_text(self.creds.get("domain") or "", 100, "domain")
        if dom:
            body["domain"] = dom
        status, j = self._post(f"{MGMT_API}/login", body, auth=False)
        if status != 200 or not j.get("sid"):
            hint = " Check the credentials, the Domain, and that the Management API accepts this IP." \
                if status in (400, 401, 403) else ""
            raise DeviceError(f"Management Server refused the login (HTTP {status}): {self._err_text(j)}.{hint}")
        self.sid = j["sid"]
        self.api_version = str(j.get("api-server-version", ""))
        self.dirty = False

    def mgmt(self, command: str, body: dict | None = None) -> dict:
        if not re.match(r"^[a-z][a-z0-9-]{1,60}$", command):
            raise DeviceError(f"internal: bad API command {command!r}")
        for attempt in (0, 1):
            status, j = self._post(f"{MGMT_API}/{command}", body or {})
            expired = status in (401, 403) and isinstance(j, dict) and j.get("code") in SESSION_CODES
            if expired and attempt == 0 and not self.dirty:
                self._mgmt_login()          # nothing unpublished would be lost
                continue
            break
        if expired:
            raise DeviceError("The Management API session expired with unpublished changes; they are lost. "
                              "Connect again and repeat the change.")
        if status != 200:
            raise DeviceError(f"{command}: HTTP {status} - {self._err_text(j)}")
        return j

    def _wait_task(self, task_id: str, what: str) -> dict:
        deadline = time.time() + TASK_TIMEOUT
        while True:
            j = self.mgmt("show-task", {"task-id": task_id, "details-level": "full"})
            tasks = j.get("tasks") or [{}]
            t = tasks[0]
            st = str(t.get("status", "")).lower()
            if st == "succeeded":
                return t
            if st in ("failed", "partially succeeded"):
                detail = "; ".join(
                    str(d.get("statusDescription") or d.get("message") or d.get("stagesInfo") or "")
                    for d in (t.get("task-details") or []) if isinstance(d, dict)).strip("; ")
                raise DeviceError(f"{what} {st}: {detail or t.get('comments') or 'see SmartConsole > Tasks'}")
            if time.time() > deadline:
                raise DeviceError(f"{what} did not finish within {TASK_TIMEOUT // 60} minutes "
                                  f"(task {task_id}); check SmartConsole > Tasks")
            time.sleep(POLL_EVERY)

    def _paged(self, command: str, body: dict, key: str = "objects") -> list:
        out, offset = [], 0
        while True:
            j = self.mgmt(command, {**body, "limit": BACKUP_PAGE, "offset": offset})
            items = j.get(key) or []
            out += items
            total, to = j.get("total", 0), j.get("to", 0)
            if not items or not to or to >= total:
                return out
            offset = to

    # ── connection ──────────────────────────────────────────────────────────
    def connect(self) -> None:
        if self.spark:
            self._spark_login()
        else:
            self._mgmt_login()
        self.facts_cache = self.facts()

    def close(self) -> None:
        if not self.sid:
            return
        try:
            if self.spark:
                self._post(f"{SPARK_API}/logout", {})
            else:
                if self.dirty:
                    self._post(f"{MGMT_API}/discard", {})
                self._post(f"{MGMT_API}/logout", {})
        except DeviceError:
            pass
        self.sid = ""

    # ── read ────────────────────────────────────────────────────────────────
    def facts(self) -> dict:
        return self._spark_facts() if self.spark else self._mgmt_facts()

    def interfaces(self) -> list[dict]:
        out = self._spark_interfaces() if self.spark else self._mgmt_gateways()
        self.iface_cache = out
        return out

    def backup(self) -> str:
        return self._spark_backup() if self.spark else self._mgmt_backup()

    # Spark: CLI Reference Guide R81.10.X "show diag", "show software-version", "show interfaces"
    def _spark_facts(self) -> dict:
        diag = dict(_kv(self.clish("show diag")))
        ver = self.clish("show software-version").strip().splitlines()
        return {"hostname": "",
                "model": "Quantum Spark" + (f" (HW {diag['hw version']})" if diag.get("hw version") else ""),
                "version": (ver[0].strip() if ver else "") or diag.get("current image name", ""),
                "serial": diag.get("serial number", ""),
                "image": diag.get("current image name", "")}

    def _spark_interfaces(self) -> list[dict]:
        # 'show interfaces all': blocks of name / ipv4-address / ipv6-address / status / mac-address / description
        out, cur = [], None
        for k, v in _kv(self.clish("show interfaces all")):
            if k == "name":
                cur = {"name": v, "ip": "", "status": "", "description": ""}
                out.append(cur)
            elif cur is not None and k == "ipv4-address":
                cur["ip"] = v
            elif cur is not None and k in ("status", "description", "mac-address"):
                cur[k] = v
        return [i for i in out if i["name"]]

    def _spark_backup(self) -> str:
        cmds = ["show diag", "show software-version", "show interfaces all", "show dns", "show ntp",
                "show ntp servers", "show ntp active", "show rest-api"]
        parts = ["# Check Point Quantum Spark settings snapshot (SentinelScan)",
                 "# Output of read-only clish commands. NOT a restorable backup file:",
                 "# for that use WebUI > Device > System Operations > Backup."]
        for c in cmds:
            try:
                parts += [f"\n### {c}", self.clish(c).rstrip()]
            except DeviceError as e:
                parts += [f"\n### {c}", f"(failed: {e})"]
        if not any(p.strip() for p in parts[3:] if not p.startswith("\n###") and not p.startswith("(failed")):
            raise DeviceError("Spark returned no output for any show command")
        return "\n".join(parts) + "\n"

    def _gateways_raw(self) -> list[dict]:
        return self._paged("show-gateways-and-servers", {"details-level": "full"})

    def _mgmt_facts(self) -> dict:
        s = self.mgmt("show-session", {})
        try:
            api = self.mgmt("show-api-versions", {}).get("current-version", self.api_version)
        except DeviceError:
            api = self.api_version
        objs = self._gateways_raw()
        mgmt = next((o for o in objs if (o.get("management-blades") or {}).get("network-policy-management")), None)
        gws = [o.get("name", "") for o in objs if (o.get("network-security-blades") or {}).get("firewall")]
        return {"hostname": (mgmt or {}).get("name", ""),
                "model": "Management Server" + (" (Multi-Domain)" if s.get("domain", {}).get("domain-type") == "domain"
                                                 else ""),
                "version": f"{(mgmt or {}).get('version', '')} (Management API {api})".strip(),
                "serial": "",
                "domain": (s.get("domain") or {}).get("name", ""),
                "gateways": gws}

    def _mgmt_gateways(self) -> list[dict]:
        """No interfaces of its own: the 'interfaces' of a Management Server are the gateways it
        manages (used as install-policy targets), each with its topology from show-simple-gateway."""
        out = []
        for o in self._gateways_raw():
            fw = (o.get("network-security-blades") or {}).get("firewall")
            row = {"name": o.get("name", ""), "ip": o.get("ipv4-address", ""),
                   "status": f"{o.get('type', '')} {o.get('version', '')}".strip(),
                   "role": "gateway" if fw else "management", "interfaces": []}
            if fw and o.get("type") == "simple-gateway":
                try:
                    g = self.mgmt("show-simple-gateway", {"name": row["name"]})
                    row["interfaces"] = [{"name": i.get("name", ""),
                                          "ip": f"{i.get('ipv4-address', '')}/{i.get('ipv4-mask-length', '')}"
                                          if i.get("ipv4-address") else "",
                                          "topology": i.get("topology", "")} for i in g.get("interfaces") or []]
                except DeviceError:
                    pass
            row["description"] = ("gateway" if fw else "management") + (
                ": " + ", ".join(f"{i['name']} {i['ip']}".strip() for i in row["interfaces"]) if row["interfaces"] else "")
            out.append(row)
        return out

    def _mgmt_backup(self, layer: str = "Network") -> str:
        snap = {"kind": "Check Point policy snapshot (SentinelScan)",
                "note": "JSON export of the access layer and network objects as published. Not a full "
                        "Management Server backup; use 'migrate_server export' or Gaia snapshots for that.",
                "taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "server": self.address, "layer": layer}
        try:
            snap["rulebase"] = self._paged("show-access-rulebase", {"name": layer, "details-level": "standard",
                                                                     "use-object-dictionary": False}, "rulebase")
        except DeviceError as e:
            raise DeviceError(f"policy snapshot of layer '{layer}' failed: {e}") from None
        snap["hosts"] = self._paged("show-hosts", {"details-level": "standard"})
        snap["networks"] = self._paged("show-networks", {"details-level": "standard"})
        return json.dumps(snap, indent=2, sort_keys=True) + "\n"

    # ── run a plan ──────────────────────────────────────────────────────────
    def execute(self, steps, values=None):
        values = dict(values or {})
        results = []
        for st in steps:
            try:
                if self.spark:
                    detail = self._exec_spark(st)
                else:
                    detail = self._exec_mgmt(st, values)
            except DeviceError as e:
                msg = str(e)
                skippable = st.path.rsplit("/", 1)[-1].startswith("delete-") and "missing" in msg
                if not self.spark and not skippable:
                    # never leave half a change (or a queued install) for a later publish
                    self.pending_install = []
                    if self.dirty:
                        try:
                            self.discard()
                            msg += " - unpublished session changes were discarded"
                        except DeviceError as e2:
                            msg += f" - discarding the session also failed: {e2}"
                results.append({"step": st.title, "ok": False, "detail": msg})
                break
            results.append({"step": st.title, "ok": True, "detail": detail})
        return results, values

    def _exec_spark(self, st: Step) -> str:
        if not st.cli:
            raise DeviceError("internal: Spark steps are clish commands")
        outs = []
        for line in st.cli:
            out = self.clish(line)
            if SPARK_ERROR_RE.search(out):
                raise DeviceError(f"'{line}': {out.strip()[:300]}")
            outs.append(out.strip())
        return " | ".join(o for o in outs if o)[:300] or "OK"

    def _exec_mgmt(self, st: Step, values: dict) -> str:
        command = st.path.rsplit("/", 1)[-1]
        body = _fill_body(st.body or {}, values)
        if st.extra.get("when") == "after publish":
            self.pending_install.append(body)       # install-policy runs in commit(), after publish
            return "queued: runs after publish"
        j = self.mgmt(command, body)
        if not command.startswith("show-"):
            self.dirty = True
        for key, src in st.capture.items():
            if src in j:
                values[key] = j[src]
        return "OK" + (f", uid {j['uid']}" if j.get("uid") else "")

    def commit(self) -> str:
        if self.spark:
            return ""
        installs, self.pending_install = self.pending_install, []
        j = self.mgmt("publish", {})
        if j.get("task-id"):
            self._wait_task(j["task-id"], "Publish")
        self.dirty = False
        msgs = ["published"]
        for body in installs:
            j = self.mgmt("install-policy", body)
            if j.get("task-id"):
                self._wait_task(j["task-id"], f"Install policy {body.get('policy-package')}")
            msgs.append(f"policy {body.get('policy-package')} installed on {', '.join(body.get('targets', []))}")
        return "; ".join(msgs)

    def discard(self) -> str:
        self.pending_install = []
        if self.spark:
            return ""
        j = self.mgmt("discard", {})
        self.dirty = False
        return f"discarded {j.get('number-of-discarded-changes', 0)} change(s)"

    # ── wizards ─────────────────────────────────────────────────────────────
    def wizards(self):
        spark, mgmt = ("spark",), ("mgmt",)
        gw = lambda name, label, **kw: Field(name, label, "select", source="interfaces", **kw)
        return [
            # Quantum Spark (clish over run-clish-command)
            Wizard("spark_hostname", "Hostname", "Rename the Spark appliance.", [
                Field("hostname", "New hostname", placeholder="Spark-HQ"),
                Field("current", "Current hostname (for undo)", required=False,
                      help="Spark has no documented clish command that shows the hostname. Enter the current "
                           "one (the clish prompt / WebUI header) to get an undo step."),
            ], self._w_spark_hostname, "System", spark),
            Wizard("spark_dns", "DNS servers", "Set the appliance's global DNS servers.", [
                Field("dns1", "Primary DNS", default="1.1.1.1"),
                Field("dns2", "Secondary DNS", required=False, default="9.9.9.9"),
                Field("dns3", "Tertiary DNS", required=False),
                Field("global_mode", "Use these instead of the DNS servers from the Internet provider "
                      "(set dns mode global)", "checkbox", required=False, default=True),
            ], self._w_spark_dns, "System", spark),
            Wizard("spark_ntp", "NTP servers", "Point the appliance at your time servers.", [
                Field("ntp1", "Primary NTP server", default="pool.ntp.org", help="IP address or host name."),
                Field("ntp2", "Secondary NTP server", required=False),
            ], self._w_spark_ntp, "System", spark),
            # Management Server (Management API, session + publish)
            Wizard("host", "Host object", "A named host to use in rules.", [
                Field("name", "Name", placeholder="srv-web01"),
                Field("ip", "IPv4 address", placeholder="192.168.10.20"),
                Field("comment", "Comment", required=False),
            ], self._w_host, "Objects", mgmt),
            Wizard("network", "Network object", "A named IPv4 network to use in rules.", [
                Field("name", "Name", placeholder="net-servers"),
                Field("subnet", "Network", placeholder="192.168.10.0/24"),
                Field("comment", "Comment", required=False),
            ], self._w_network, "Objects", mgmt),
            Wizard("rule", "Access rule", "Add a rule to an access layer, publish, and optionally install the policy.", [
                Field("name", "Rule name", placeholder="Web to servers"),
                Field("layer", "Access layer", default="Network"),
                Field("position", "Position", "select", default="bottom",
                      options=[["top", "Top of the layer"], ["bottom", "Bottom of the layer"],
                               ["section", "Top of a section"]]),
                Field("section", "Section name", required=False, help="Only for position 'Top of a section'."),
                Field("source", "Source", default="Any", help="Object names, comma separated. Any = any."),
                Field("destination", "Destination", default="Any"),
                Field("service", "Services", default="https", help="Service object names, e.g. https, ssh, http."),
                Field("action", "Action", "select", default="Accept", options=[["Accept", "Accept"], ["Drop", "Drop"]]),
                Field("comment", "Comment", required=False),
                Field("install", "Install the policy after publishing", "checkbox", required=False, default=False),
                Field("package", "Policy package", required=False, default="Standard"),
                gw("target", "Install on gateway", required=False),
            ], self._w_rule, "Policy", mgmt),
            Wizard("install", "Install policy", "Install a policy package on a gateway (pushes everything published).", [
                Field("package", "Policy package", default="Standard"),
                gw("target", "Gateway"),
            ], self._w_install, "Policy", mgmt),
        ]

    # Spark -----------------------------------------------------------------
    # Commands from: R81.10.X Spark Locally Managed Admin Guide (AG) and
    # R81.10.X Spark CLI Reference Guide (CLI), sc1.checkpoint.com/documents/SMB_R81.10.X/CLI/
    R82_NOTE = ("Commands are taken from the R81.10.X Spark documentation. R82.00.X firmware may differ; "
                "check the step output.")

    def _w_spark_hostname(self, p, drv):
        # AG p. 31 "Sample Configuration File" (set hostname DEMOgw01) and p. 36 sample log
        # ("set hostname Demo1 / Setting hostname to 'Demo1' / OK"). CLI has the equivalent
        # "set device-details hostname <hostname>" (letters, digits, '-').
        host = v_hostname(p["hostname"])
        cur = str(p.get("current") or "").strip()
        undo, notes = [], [self.R82_NOTE]
        if cur:
            cur = v_hostname(cur)
            undo = [Step(f"Restore hostname {cur}", cli=[f"set hostname {cur}"])]
        else:
            notes.append("No undo: enter the current hostname to get one.")
        return Plan(f"Hostname {host}" + (f" (was {cur})" if cur else ""),
                    [Step(f"Set hostname {host}", cli=[f"set hostname {host}"])], undo, notes)

    def _spark_dns_now(self) -> dict:
        # CLI "show dns" (output format not documented: parsed as key: value lines)
        cur = {"mode": ""}
        for k, v in _kv(self.clish("show dns")):
            for slot in ("primary", "secondary", "tertiary"):
                if slot in k and _is_ip(v) and ":" not in v:
                    cur.setdefault(slot, v)
            if "mode" in k and v.lower() in ("global", "internet"):
                cur["mode"] = v.lower()
        return cur

    def _dns_cmd(self, servers: dict) -> str:
        # CLI "set dns": set dns [primary ipv4-address <ip>] [secondary ipv4-address <ip>] [tertiary ipv4-address <ip>]
        return "set dns " + " ".join(f"{s} ipv4-address {servers[s]}"
                                     for s in ("primary", "secondary", "tertiary") if servers.get(s))

    def _w_spark_dns(self, p, drv):
        new = {"primary": v_ipv4(p["dns1"], "primary DNS")}
        for f, slot, label in (("dns2", "secondary", "secondary DNS"), ("dns3", "tertiary", "tertiary DNS")):
            if str(p.get(f) or "").strip():
                new[slot] = v_ipv4(p[f], label)
        use_global = p.get("global_mode", True) in TRUE
        cur = self._spark_dns_now()
        steps = [Step("Set DNS servers", cli=[self._dns_cmd(new)])]
        undo, notes = [], [self.R82_NOTE]
        if use_global and cur["mode"] != "global":
            # CLI "set dns mode <global|internet>"
            steps.append(Step("Use the global DNS servers", cli=["set dns mode global"]))
            if cur["mode"]:
                undo.append(Step(f"Restore DNS mode {cur['mode']}", cli=[f"set dns mode {cur['mode']}"]))
        if cur.get("primary"):
            undo.insert(0, Step("Restore DNS servers", cli=[self._dns_cmd(cur)]))
            if any(s in new and s not in cur for s in ("secondary", "tertiary")):
                notes.append("Undo restores the old servers but cannot clear the secondary / tertiary slot "
                             "(no documented clish command); clear it in the WebUI if needed.")
        else:
            notes.append("Could not read the current DNS servers from 'show dns', so there is no automatic undo. "
                         "The snapshot taken before apply has the old output.")
        if not use_global and cur["mode"] == "internet":
            notes.append("DNS mode is 'internet': the appliance uses the provider's DNS servers, not these.")
        return Plan(f"DNS {', '.join(new.values())}" + (f" (was {cur['primary']})" if cur.get("primary") else ""),
                    steps, undo, notes)

    def _spark_ntp_now(self) -> dict:
        # CLI "show ntp", "show ntp servers", "show ntp active" (formats not documented)
        cur = {}
        for cmd in ("show ntp servers", "show ntp"):
            try:
                for k, v in _kv(self.clish(cmd)):
                    for slot in ("primary", "secondary"):
                        if slot in k and v and " " not in v:
                            cur.setdefault(slot, v)
            except DeviceError:
                pass
        try:
            act = self.clish("show ntp active").lower()
            cur["active"] = "on" if re.search(r"\b(on|true|enabled?)\b", act) else \
                "off" if re.search(r"\b(off|false|disabled?)\b", act) else ""
        except DeviceError:
            cur["active"] = ""
        return cur

    def _w_spark_ntp(self, p, drv):
        # CLI "set ntp server primary <primary>", "set ntp server secondary <secondary>" (IP or host name),
        # "set ntp active {on | off}"; AG p. 31 sample uses "set ntp server primary 10.1.1.10".
        n1 = v_address(p["ntp1"])
        n2 = v_address(p["ntp2"]) if str(p.get("ntp2") or "").strip() else ""
        cur = self._spark_ntp_now()
        lines = [f"set ntp server primary {n1}"] + ([f"set ntp server secondary {n2}"] if n2 else [])
        steps = [Step("Set NTP servers", cli=lines), Step("Turn NTP on", cli=["set ntp active on"])]
        undo, notes = [], [self.R82_NOTE]
        old = []
        for slot in ("primary", "secondary"):
            if cur.get(slot):
                try:
                    old.append(f"set ntp server {slot} {v_address(cur[slot])}")
                except ValidationError:
                    pass
        if old:
            undo.append(Step("Restore NTP servers", cli=old))
        else:
            notes.append("Could not read the current NTP servers, so they have no automatic undo.")
        if cur.get("active") == "off":
            undo.append(Step("Turn NTP off again", cli=["set ntp active off"]))
        return Plan(f"NTP {n1}{' / ' + n2 if n2 else ''}", steps, undo, notes)

    # Management ------------------------------------------------------------------
    def _exists(self, command: str, name: str) -> bool:
        try:
            self.mgmt(command, {"name": name})
            return True
        except DeviceError as e:
            if "missing" in str(e):
                return False
            raise

    def _comment(self, p) -> str:
        return v_text(p.get("comment"), 1000, "comment", forbid="{}")

    PUBLISH_NOTE = "Changes are made in the session 'SentinelScan' and published together; on any failure " \
                   "the session is discarded. Gateways enforce them only after Install Policy."

    def _w_host(self, p, drv):
        name = v_name(p["name"], "name")
        ip = v_ipv4(p["ip"], "IPv4 address")
        if self._exists("show-host", name):
            raise ValidationError(f"a host named {name} already exists")
        body = {"name": name, "ip-address": ip, "comments": self._comment(p)}
        return Plan(f"Host {name} = {ip}",
                    [Step(f"Create host {name}", "POST", f"{MGMT_API}/add-host", body)],
                    [Step(f"Delete host {name}", "POST", f"{MGMT_API}/delete-host", {"name": name})],
                    [self.PUBLISH_NOTE], commit=True)

    def _w_network(self, p, drv):
        name = v_name(p["name"], "name")
        net = v_cidr(p["subnet"], "network")
        if net.prefixlen == 32:
            raise ValidationError("network: that is a single address; use a Host object, or give a prefix like /24")
        if self._exists("show-network", name):
            raise ValidationError(f"a network named {name} already exists")
        body = {"name": name, "subnet4": str(net.network_address), "mask-length4": net.prefixlen,
                "comments": self._comment(p)}
        return Plan(f"Network {name} = {net}",
                    [Step(f"Create network {name}", "POST", f"{MGMT_API}/add-network", body)],
                    [Step(f"Delete network {name}", "POST", f"{MGMT_API}/delete-network", {"name": name})],
                    [self.PUBLISH_NOTE], commit=True)

    def _install_body(self, package, target) -> dict:
        pkg = v_name(package or "Standard", "policy package")
        tgt = v_name(target, "gateway")
        known = self.iface_cache or self.interfaces()
        row = next((g for g in known if g["name"] == tgt), None)
        if row is None:
            raise ValidationError(f"gateway {tgt} is not managed by this server")
        if row.get("role") != "gateway":
            raise ValidationError(f"{tgt} is not a gateway (it has no firewall blade)")
        return {"policy-package": pkg, "targets": [tgt], "access": True, "threat-prevention": True}

    def _install_step(self, body) -> Step:
        return Step(f"Install policy {body['policy-package']} on {body['targets'][0]}", "POST",
                    f"{MGMT_API}/install-policy", body, extra={"when": "after publish"})

    def _w_rule(self, p, drv):
        name = v_text(p["name"], 100, "rule name", forbid="{}")
        if not name:
            raise ValidationError("rule name is required")
        layer = v_text(p.get("layer") or "Network", 100, "access layer", forbid="{}")
        pos = v_choice(p.get("position") or "bottom", ["top", "bottom", "section"], "position")
        if pos == "section":
            sec = v_text(p.get("section"), 100, "section name", forbid="{}")
            if not sec:
                raise ValidationError("section name: required for position 'Top of a section'")
            position = {"top": sec}
        else:
            position = pos
        src = v_list(p.get("source") or "Any", lambda s: _obj_name(s, "source"), "source", 32)
        dst = v_list(p.get("destination") or "Any", lambda s: _obj_name(s, "destination"), "destination", 32)
        svc = v_list(p.get("service") or "Any", lambda s: _obj_name(s, "service"), "services", 32)
        action = v_choice(p.get("action") or "Accept", ["Accept", "Drop"], "action")
        try:
            self.mgmt("show-access-layer", {"name": layer})
        except DeviceError as e:
            raise ValidationError(f"access layer '{layer}': {e}") from None
        body = {"layer": layer, "position": position, "name": name, "source": src, "destination": dst,
                "service": svc, "action": action, "track": {"type": "Log"}, "enabled": True,
                "comments": self._comment(p)}
        steps = [Step(f"Add rule '{name}' to {layer}", "POST", f"{MGMT_API}/add-access-rule", body,
                      capture={"rule_uid": "uid"})]
        undo = [Step(f"Delete rule '{name}'", "POST", f"{MGMT_API}/delete-access-rule",
                     {"layer": layer, "uid": "{rule_uid}"})]
        notes = [self.PUBLISH_NOTE]
        if p.get("install") in TRUE:
            if not str(p.get("target") or "").strip():
                raise ValidationError("choose the gateway to install the policy on")
            ib = self._install_body(p.get("package"), p["target"])
            steps.append(self._install_step(ib))
            undo.append(self._install_step(ib))
            notes.append("Install Policy pushes everything published in this package, not only this rule.")
        if action == "Accept" and src == ["Any"] and dst == ["Any"]:
            notes.append("Any → Any accept rule: this allows far more than you probably need.")
        if action == "Accept" and "Any" in svc:
            notes.append("Service Any allows every port. Prefer the specific services you need.")
        where = pos if pos != "section" else f"top of section {position['top']}"
        return Plan(f"{action} {', '.join(src)} → {', '.join(dst)} ({', '.join(svc)}) at {where} of {layer}",
                    steps, undo, notes, commit=True)

    def _w_install(self, p, drv):
        ib = self._install_body(p.get("package"), p["target"])
        return Plan(f"Install {ib['policy-package']} on {ib['targets'][0]}", [self._install_step(ib)], [],
                    ["Pushes everything published in this policy package (access and threat prevention) to the "
                     "gateway. There is no automatic undo; roll back with an earlier policy revision in SmartConsole."],
                    commit=True)
