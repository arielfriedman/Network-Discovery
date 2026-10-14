#!/usr/bin/env python3
"""
SentinelScan — control panel (stdlib only, no Flask)

Open a dashboard in the browser, choose WHAT and WHERE to scan (this host,
the network, or the cloud), click Start, watch live progress, and read the
results — all without touching the command line.

    python3 serve.py            # then open http://127.0.0.1:8765

Design goals: zero third-party dependencies (uses http.server), fully local
(binds to 127.0.0.1 only), and portable.
"""
from __future__ import annotations

import json
import os
import secrets
import re
import shutil
import signal
import threading
import time
import uuid
import webbrowser
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

# ── host engine (in-process) ────────────────────────────────────────────────
from config import Config
import scanner  # noqa: F401 — registers modules
from scanner import ScanSession, ScanOrchestrator, MODULE_REGISTRY
from reporters import generate_dashboard
import db
import db_backup
import actions as act
import action_targets as atg
import targets as tg
import creds as credmod        # discovery/lib/creds.py (path set up by targets)
from devices import manager as devmgr
from devices.base import DeviceError, PinMismatch, PinRequired

HOST, PORT = "127.0.0.1", 8765
APP_DIR = Path(__file__).resolve().parent
REPORTS = APP_DIR / "reports"
REPORTS.mkdir(exist_ok=True)
WEB = APP_DIR / "web"          # the browser pages
PAGES = {"/": "index.html", "/index.html": "index.html",
         "/history": "history.html", "/devices": "devices.html", "/actions": "actions.html"}
CTYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
          ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}
ND_DIR = APP_DIR.parent / "discovery"  # network/cloud tool, same repo
ND_SETTINGS = ND_DIR / "config" / "settings.conf"
CLOUD_PROVIDERS = ("aws", "azure", "gcp", "k8s", "digitalocean", "linode", "hetzner", "vultr",
                   "scaleway", "cloudflare", "ibm", "ovh", "alibaba", "oci")
MAX_BODY = 2 * 1024 * 1024             # target lists are the largest request

# Per-launch secret the panel's own pages send with every change request.
# Another website open in the same browser cannot read it, so it cannot make
# the panel start scans or change device configs (CSRF).
TOKEN = secrets.token_urlsafe(32)

# ── in-memory scan state ─────────────────────────────────────────────────────
SCANS: dict[str, dict] = {}
LOCK = threading.RLock()  # reentrant: emit() holds it while calling _log()


def _new_scan(scope: str, opts: dict) -> str:
    sid = uuid.uuid4().hex[:12]
    with LOCK:
        SCANS[sid] = {
            "id": sid, "scope": scope, "opts": opts, "status": "running",
            "pct": 0, "current": "Starting…", "log": [],
            "done": 0, "total": 0, "counts": {},
            "module": "", "activity": "", "tool": "", "cmd": "", "note": "",
            "cancel": None, "stopping": False,
            "result_html": None, "result_json": None,
            "started": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    return sid


# Credentials for a scan wait here between the request and the runner thread.
# They are never put in SCANS (whose contents feed the status API), the
# database or the activity log.
_CREDS: dict[str, dict] = {}


def parse_credentials(body: dict, scope: str) -> dict | None:
    """Validate the credential cards with the same rules discover.sh applies."""
    c = body.get("credentials")
    if not isinstance(c, dict) or scope not in ("network", "cloud"):
        return None
    sets = c.get("sets") if isinstance(c.get("sets"), list) else []
    allowed = {"ssh", "snmp"} if scope == "network" else set(credmod.TYPES) - credmod.HOST_TYPES
    for i, st in enumerate(sets, 1):
        if not isinstance(st, dict) or st.get("type") not in allowed:
            raise BadRequest(f"credential {i}: type not valid for a {scope} scan")
        try:
            credmod.validate(st, i)
        except credmod.Bad as e:
            raise BadRequest(str(e))
    v = c.get("vault") if isinstance(c.get("vault"), dict) else {}
    use = [str(x) for x in (v.get("use") or [])]
    if (use or any(st.get("save") for st in sets)) and not v.get("passphrase"):
        raise BadRequest("the vault passphrase is needed to use or remember saved credentials")
    if not sets and not use:
        return None
    return {"sets": sets, "vault": {"passphrase": str(v.get("passphrase") or ""), "use": use}}


def _send_secret(fd: int, data: bytes) -> None:
    """Write to the child's credential pipe from a thread (the pipe buffer is
    64 KB) and close it, so the child sees EOF."""
    def run():
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        except (BrokenPipeError, OSError):
            pass
    threading.Thread(target=run, daemon=True).start()


def _log(sid: str, msg: str) -> None:
    with LOCK:
        SCANS[sid]["log"].append(msg)
        SCANS[sid]["current"] = msg


def environment() -> dict:
    """What this machine can do right now — shown on the start page."""
    root = os.geteuid() == 0
    # sudo works without a password right now (unlocked in the panel's terminal).
    # Only the network scan uses it; the host scan runs as this user unless root.
    admin = root or subprocess.run(["sudo", "-n", "true"], stdin=subprocess.DEVNULL,
                                   capture_output=True).returncode == 0
    clouds = {name: bool(shutil.which(cmd)) for name, cmd in
              (("aws", "aws"), ("azure", "az"), ("gcp", "gcloud"), ("k8s", "kubectl"))}
    return {"admin": admin, "root": root, "clouds": clouds,
            "nd_tool": (ND_DIR / "discover.sh").exists(),
            "nmap": bool(shutil.which("nmap"))}


# ── scan runners ─────────────────────────────────────────────────────────────
def run_host_scan(sid: str, opts: dict) -> None:
    """In-process SentinelScan host audit."""
    try:
        mode = opts.get("mode", "workstation")
        scan_type = opts.get("scan_type", "quick")
        cfg = Config(mode=mode, scan_type=scan_type, target="127.0.0.1")
        session = ScanSession(sid, mode, scan_type, "localhost")
        total = len(MODULE_REGISTRY)

        def overall_pct(done: int, intra: int) -> int:
            # each module is 1/total of the bar; intra (0-100) fills its slice
            return min(99, int((done + intra / 100.0) / max(total, 1) * 100))

        def emit(event: str, data: dict) -> None:
            with LOCK:
                s = SCANS[sid]
                if event == "module_started":
                    s["module"] = data["display_name"]
                    s["activity"] = "starting…"; s["tool"] = ""; s["cmd"] = ""
                    s["pct"] = overall_pct(s["done"], 0)
                    _log(sid, f"[{data['index']}/{data['total']}] {data['display_name']}")
                elif event == "module_progress":
                    s["activity"] = data.get("message", "")
                    s["pct"] = overall_pct(s["done"], int(data.get("pct", 0)))
                elif event == "command":
                    s["tool"] = data.get("tool", "")
                    s["cmd"] = data.get("argv", "")
                    _log(sid, f"    $ {data.get('argv','')}")
                elif event == "module_done":
                    s["done"] += 1
                    s["tool"] = ""; s["cmd"] = ""
                    s["pct"] = overall_pct(s["done"], 0)
                    st = data.get("status")
                    if st == "skipped":
                        _log(sid, f"    → skipped ({data.get('detail','')})")
                    elif st == "error":
                        _log(sid, f"    → error: {data.get('detail','')}")
                    elif st == "cancelled":
                        _log(sid, "    → stopped")
                    else:
                        _log(sid, f"    → {data.get('finding_count',0)} finding(s)")

        db.scan_started(sid, "host", "127.0.0.1", mode, scan_type)
        orch = ScanOrchestrator(cfg, emit_fn=emit)
        with LOCK:
            SCANS[sid]["total"] = total
            SCANS[sid]["cancel"] = orch.cancel
        orch.run(session)

        d = session.to_dict()
        html = generate_dashboard(session)
        (REPORTS / f"{sid}.json").write_text(json.dumps(d, indent=2))
        (REPORTS / f"{sid}_dashboard.html").write_text(html)
        d["status"] = "cancelled" if session.status == "cancelled" else "complete"
        if db.save_host_scan(d, str(REPORTS / f"{sid}_dashboard.html")):
            _log(sid, "Saved to the database.")
        db.log("scan.complete" if d["status"] == "complete" else "scan.stop", sid,
               {"scope": "host", "findings": d["total_findings"], "risk": d["risk_score"]})
        with LOCK:
            s = SCANS[sid]
            s["counts"] = d["severity_counts"]; s["result_json"] = d
            s["result_html"] = html
            s["tool"] = ""; s["cmd"] = ""; s["activity"] = ""
            if session.status == "cancelled":
                s["status"] = "cancelled"
                s["current"] = (f"Stopped after {s['done']} of {total} checks — "
                                f"{d['total_findings']} findings so far")
            else:
                s["status"] = "complete"; s["pct"] = 100
                s["current"] = f"Done — {d['total_findings']} findings, risk {d['risk_score']}/100"
    except Exception as e:  # noqa: BLE001
        with LOCK:
            SCANS[sid]["status"] = "error"; SCANS[sid]["current"] = f"Error: {e}"
        _log(sid, f"ERROR: {e}")
        db.scan_ended(sid, "error")


# network-discovery stages → where the bar should be when each one starts
STAGE_PCT = {"Stage 0": 5, "Stage 1": 15, "Stage 2": 35, "Stage 3": 50,
             "Stage 4": 75, "Stage 5": 85, "Stage 6": 88,
             "Building report": 93, "Output": 97, "Done": 99}
ANSI = re.compile(r"\x1b\[[0-9;]*m")
WRAPPERS = {"as_root", "sudo", "timeout", "env", "nice", "stdbuf"}


def _tool_name(argv: str) -> str:
    """First real program in a command line, skipping sudo/timeout/etc."""
    for tok in argv.split():
        if tok in WRAPPERS or tok.startswith("-") or tok.isdigit() or "=" in tok:
            continue
        return os.path.basename(tok)
    return ""


def _kill_group(proc) -> None:
    """Stop discover.sh and everything it started (nmap, arp-scan, …)."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    for _ in range(30):
        if proc.poll() is not None:
            return
        time.sleep(0.1)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_shell_scan(sid: str, opts: dict) -> None:
    """Network / cloud scan — drives the network-discovery tool (discover.sh)
    with no terminal attached, so it can never stop and wait for typed input."""
    scope = opts.get("scope", "network")
    if not (ND_DIR / "discover.sh").exists():
        with LOCK:
            SCANS[sid]["status"] = "error"
            SCANS[sid]["current"] = f"network-discovery tool not found at {ND_DIR}"
        return

    args = ["bash", "discover.sh", "--yes", "--no-install"]
    # ND_PARENT_PID: discover.sh stops itself and its tools if the panel dies
    env = dict(os.environ, ND_PROGRESS="1", ND_NONINTERACTIVE="1", ND_PARENT_PID=str(os.getpid()))
    if scope == "cloud":
        args.append("--cloud-only")
        prov = opts.get("provider", "all")
        if prov != "all" and prov in CLOUD_PROVIDERS:
            env["CLOUD_PROVIDERS"] = prov
    else:
        args.append("--no-cloud")
        o = opts.get("options") or {}
        if o.get("ports", "off") == "off":
            args.append("--quick")
        elif o.get("ports") == "all":
            args.append("--deep")
        if o.get("vuln") and o.get("ports", "off") != "off":
            args.append("--vuln")
        if not o.get("names", True):
            args.append("--no-passive")
        if not o.get("wan", True):
            args.append("--no-wan")
        creds_doc = _CREDS.get(sid)
        if o.get("logins") or (creds_doc and creds_doc["sets"]):
            args.append("--auth")
        if opts.get("_targets"):
            tfile = REPORTS / f"{sid}-targets.txt"
            tg.write_file(tfile, opts["_targets"])
            args += ["--targets", str(tfile)]
            if o.get("pn"):
                args.append("--pn")
    creds_doc = _CREDS.pop(sid, None)
    pass_fds, cred_w, saved_meta = (), None, {}
    if creds_doc:
        r, cred_w = os.pipe()
        env["ND_CREDS_FD"] = str(r)
        pass_fds = (r,)
        saved_meta = {"CRED_" + credmod.slug(credmod.validate(st, i + 1)["name"]): st
                      for i, st in enumerate(creds_doc["sets"]) if st.get("save")}
        _log(sid, "Credentials: " + ", ".join(
            f"{st.get('name') or st['type']} ({st['type']})" for st in creds_doc["sets"])
            + (f"; {len(creds_doc['vault']['use'])} saved card(s) from the vault" if creds_doc["vault"]["use"] else ""))
    _log(sid, "$ " + " ".join(args))
    db.scan_started(sid, scope, None, None,
                    opts.get("scan_type") if scope == "network" else opts.get("provider", "all"),
                    options=opts.get("options"), target_spec=opts.get("target_spec"))

    try:
        proc = subprocess.Popen(
            args, cwd=str(ND_DIR), env=env, text=True, bufsize=1,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            # Own process group (so Stop can kill nmap & co.) but the same session:
            # sudo's per-terminal ticket from the panel's terminal still works.
            # ND_NONINTERACTIVE stops discover.sh from ever prompting there.
            process_group=0,
            pass_fds=pass_fds,
        )
    except Exception as e:  # noqa: BLE001
        if cred_w is not None:
            os.close(cred_w); os.close(pass_fds[0])
        with LOCK:
            SCANS[sid]["status"] = "error"; SCANS[sid]["current"] = f"Error: {e}"
        return
    if cred_w is not None:
        os.close(pass_fds[0])                       # the child has its own copy
        _send_secret(cred_w, json.dumps(creds_doc).encode())
        creds_doc = None
    with LOCK:
        SCANS[sid]["cancel"] = lambda: _kill_group(proc)

    run_dir, last_fail, nothing_cloud = None, "", False
    for raw in proc.stdout:
        line = ANSI.sub("", raw).rstrip()
        if not line.strip():
            continue
        with LOCK:
            s = SCANS[sid]
            if line.startswith("@@vault-saved "):
                key = line.split(" ", 1)[1].strip()
                st = saved_meta.get(key)
                if st:
                    db.save_credential(key, st.get("name") or key[5:], st["type"],
                                       [str(h) for h in (st.get("hosts") or [])])
                    _log(sid, f"Saved to the vault: {st.get('name') or key}")
                continue
            if line.startswith("@@cmd "):
                argv = line[6:]
                s["cmd"] = argv; s["tool"] = _tool_name(argv); s["cmd_since"] = time.time()
                _log(sid, f"    $ {argv}")
                continue
            if line.startswith("== "):
                title = line[3:].rstrip("= ").strip()
                s["module"] = title; s["activity"] = ""; s["cmd"] = ""; s["tool"] = ""
                for key, pct in STAGE_PCT.items():
                    if title.startswith(key):
                        s["pct"] = max(s["pct"], pct)
                _log(sid, f"[{title}]")
                continue
            m = re.match(r"\s*-> (.*)", line)
            if m:
                s["activity"] = m.group(1)
                nxt = min((p for p in STAGE_PCT.values() if p > s["pct"]), default=99)
                s["pct"] = min(nxt - 1, s["pct"] + 1)
            if "run directory:" in line:
                run_dir = Path(line.split("run directory:", 1)[1].strip())
            if "sudo not authorised" in line and scope == "network":
                s["note"] = ("Running without admin rights, so the ARP sweep and OS "
                             "detection are skipped. Everything else runs.")
            if "no cloud CLI installed" in line or "no cloud account reachable" in line:
                nothing_cloud = True
            if line.startswith("[FAIL]"):
                last_fail = line[6:].strip()
            _log(sid, line)
    proc.wait()
    (REPORTS / f"{sid}-targets.txt").unlink(missing_ok=True)

    with LOCK:
        s = SCANS[sid]
        s["tool"] = ""; s["cmd"] = ""; s["activity"] = ""
        dash = run_dir / "dashboard.html" if run_dir else None
        if s["stopping"]:
            s["status"] = "cancelled"
            s["current"] = "Stopped — the scan was ended before it finished."
        elif dash and dash.exists():
            s["status"] = "complete"; s["pct"] = 100
            s["result_html"] = dash.read_text(encoding="utf-8")
            if scope == "cloud" and nothing_cloud:
                s["current"] = ("Done — but no cloud account was reachable, so nothing "
                                "was collected. Install and sign in to a cloud CLI first.")
            else:
                s["current"] = "Done — network dashboard ready"
        else:
            s["status"] = "error"
            s["current"] = f"The scan failed: {last_fail or 'no dashboard was produced'}"
        final = s["status"]
    _store_shell_result(sid, scope, final, run_dir)


def _store_shell_result(sid: str, scope: str, status: str, run_dir) -> None:
    """Save a discovery run's findings.json to the database, or just mark how it ended."""
    fj = run_dir / "findings.json" if run_dir else None
    if status == "complete" and fj and fj.exists():
        try:
            data = json.loads(fj.read_text())
        except (OSError, ValueError):
            data = None
        if data is not None and db.save_network_scan(data, kind=scope, ref=sid,
                                                     report_path=str(run_dir / "dashboard.html")):
            _log(sid, "Saved to the database.")
    else:
        db.scan_ended(sid, status if status in ("cancelled", "error") else "error")
    db.log("scan.complete" if status == "complete" else "scan.stop" if status == "cancelled" else "scan.error",
           sid, {"scope": scope})


SCOPE_RUNNERS = {
    "host": run_host_scan,
    "network": run_shell_scan,
    "cloud": run_shell_scan,
}


class BadRequest(ValueError):
    def __init__(self, msg, detail=None):
        super().__init__(msg); self.detail = detail


def network_options(body: dict) -> dict:
    """The network checklist, from what the page sent. Older pages send only
    scan_type quick/full, which maps to ports off/top."""
    o = body.get("options") if isinstance(body.get("options"), dict) else {}
    ports = o.get("ports", "top" if body.get("scan_type") == "full" else "off")
    targets_mode = body.get("target_mode") == "targets"
    return {"names": bool(o.get("names", True)),
            "logins": bool(o.get("logins", False)),
            "ports": ports if ports in ("off", "top", "all") else "off",
            "vuln": bool(o.get("vuln", False)),
            "wan": bool(o.get("wan", not targets_mode)),
            "pn": bool(o.get("pn", False)) and targets_mode}


def _remove_report_files(deleted: list[dict]) -> int:
    """Delete the report files of deleted scans, but only inside this app's
    own report folders (panel/reports, discovery/reports)."""
    removed = 0
    for d in deleted:
        ref = re.sub(r"[^A-Za-z0-9_-]", "", d.get("scan_ref") or "")
        paths = [REPORTS / f"{ref}.json", REPORTS / f"{ref}_dashboard.html"] if ref else []
        rp = d.get("report_path")
        if rp:
            rp = Path(rp).resolve()
            nd_reports = (ND_DIR / "reports").resolve()
            if rp.parent.parent == nd_reports and rp.parent.name != "latest":
                paths.append(rp.parent)          # a whole discovery run folder
            elif rp.parent == REPORTS.resolve():
                paths.append(rp)
        for p in paths:
            try:
                if p.is_dir() and not p.is_symlink():
                    shutil.rmtree(p); removed += 1
                elif p.exists():
                    p.unlink(); removed += 1
            except OSError:
                pass
    return removed


def start_scan(scope: str, opts: dict, source_ip: str | None = None) -> str:
    opts = dict(opts); opts["scope"] = scope
    creds_doc = parse_credentials(opts, scope)
    opts.pop("credentials", None)                 # secrets never go further than this
    if scope == "network":
        opts["options"] = network_options(opts)
        opts["scan_type"] = "quick" if opts["options"]["ports"] == "off" else "full"
        if opts.get("target_mode") == "targets":
            r = tg.parse(opts.get("targets") if isinstance(opts.get("targets"), list) else [],
                         tg.allowed_prefixes(ND_SETTINGS))
            limits = [e["error"] for e in r["errors"] if not e["line"]]
            if limits:
                raise BadRequest("; ".join(limits), r["errors"])
            if not r["targets"]:
                raise BadRequest("no usable targets in the list", r["errors"])
            opts["_targets"] = r["targets"]
            opts["target_spec"] = {"mode": "targets", "counts": r["counts"], "addresses": r["addresses"],
                                   "files": sorted({t["source"] for t in r["targets"]}),
                                   "skipped": len(r["errors"])}
        else:
            opts["target_spec"] = {"mode": "network"}
    opts.pop("targets", None)                     # the raw list: big, and already parsed
    sid = _new_scan(scope, opts)
    if creds_doc:
        _CREDS[sid] = creds_doc
        opts["credentials"] = [{"type": st["type"], "name": st.get("name"), "hosts": st.get("hosts") or [],
                                "save": bool(st.get("save"))} for st in creds_doc["sets"]] \
            + [{"vault": k} for k in creds_doc["vault"]["use"]]   # names only, for the log
    db.log("scan.start", sid, {k: v for k, v in opts.items() if not k.startswith("_")}, source_ip)
    runner = SCOPE_RUNNERS.get(scope, run_host_scan)
    threading.Thread(target=runner, args=(sid, opts), daemon=True).start()
    return sid


def stop_scan(sid: str) -> bool:
    with LOCK:
        s = SCANS.get(sid)
        if not s or s["status"] != "running" or not s["cancel"]:
            return False
        s["stopping"] = True
        s["module"] = "Stopping…"; s["activity"] = "finishing the current step"
        cancel = s["cancel"]
    cancel()
    db.log("scan.stop", sid)
    return True


# ── HTTP handler ─────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self) -> bool:
        """Only answer to our own name: blocks DNS-rebinding attacks from web pages."""
        port = self.server.server_address[1]
        host = (self.headers.get("Host") or "").lower()
        if host in (f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"):
            return True
        self._send(403, {"error": "unexpected Host header"})
        return False

    def _write_ok(self) -> bool:
        port = self.server.server_address[1]
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
            self._send(403, {"error": "cross-origin request refused"})
            return False
        if not secrets.compare_digest(self.headers.get("X-Sentinel-Token", ""), TOKEN):
            self._send(403, {"error": "missing or wrong panel token - reload the page"})
            return False
        return True

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return {}
        try:
            b = json.loads(self.rfile.read(length) or "{}")
            return b if isinstance(b, dict) else {}
        except ValueError:
            return {}

    def _act(self, fn):
        try:
            return self._send(200, fn())
        except atg.NeedsTrust as e:
            return self._send(409, {"error": str(e), "needs_trust": e.fingerprint, "changed_from": e.changed_from})
        except (act.ActionError, ValueError, TypeError) as e:
            return self._send(400, {"error": str(e)})

    def _device_call(self, fn):
        """Run a device-manager call and map its errors to HTTP answers."""
        try:
            return self._send(200, fn())
        except PinMismatch as e:
            return self._send(409, {"error": str(e), "pin_mismatch": e.fingerprint, "kind": e.kind})
        except PinRequired as e:
            return self._send(409, {"error": str(e), "pin_required": e.fingerprint, "kind": e.kind})
        except DeviceError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def do_GET(self):
        if not self._host_ok():
            return
        path = urlparse(self.path).path
        if path.startswith("/api/devices"):
            return self._devices_get(path)
        if path in PAGES or path.startswith("/web/"):
            name = PAGES.get(path) or path[len("/web/"):]
            f = (WEB / name).resolve()
            if WEB.resolve() not in f.parents or not f.is_file():
                return self._send(404, {"error": "not found"})
            data = f.read_bytes()
            if f.suffix == ".html":
                data = data.replace(b"</head>", f'<meta name="sentinel-token" content="{TOKEN}">\n</head>'.encode(), 1)
            return self._send(200, data, CTYPES.get(f.suffix, "application/octet-stream"))
        if path == "/api/db/status":
            return self._send(200, db.status())
        if path == "/api/history":
            return self._send(200, {"db": db.ready(), "scans": db.list_scans(200)})
        if path.startswith("/api/history/"):
            got = db.get_scan(path.split("/")[3])
            return self._send(200 if got else 404, got or {"error": "not found"})
        if path == "/api/activity":
            return self._send(200, db.recent_activity(100))
        if path == "/api/actions":
            tid = re.search(r"[?&]target=([0-9a-f]{1,20})", self.path)
            return self._act(lambda: act.list_actions(tid.group(1) if tid else None))
        if path == "/api/actions/targets":
            return self._act(lambda: {"open": atg.list_open(), **atg.known()})
        if path == "/api/actions/runs":
            return self._act(lambda: {"runs": act.recent_runs(), "active": act.active_run()})
        if path == "/api/actions/export":
            return self._act(act.export_all)
        m = re.match(r"^/api/actions/runs/(\d+)$", path)
        if m:
            off = re.search(r"[?&]from=(\d+)", self.path)
            st = act.run_status(int(m.group(1)), int(off.group(1)) if off else 0)
            return self._send(200 if st else 404, st or {"error": "run not found (finished runs are listed in /api/actions/runs)"})
        if path == "/api/db/backups":
            return self._send(200, {"backups": db_backup.list_backups(), "keep": db_backup.keep_count(),
                                    "schedule": db_backup.schedule_status(), "db": db.ready()})
        if path.startswith("/api/db/backups/") and path.endswith("/download"):
            name = path.split("/")[4]
            f = db_backup.BACKUP_DIR / name
            if not db_backup.NAME_RE.match(name) or not f.is_file():
                return self._send(404, {"error": "no such backup"})
            data = f.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return None
        if path == "/api/credentials":
            return self._send(200, {"db": db.ready(), "credentials": db.list_credentials()})
        if path == "/api/env":
            return self._send(200, environment())
        if path.startswith("/api/scan/") and path.endswith("/status"):
            sid = path.split("/")[3]
            with LOCK:
                s = SCANS.get(sid)
                if not s:
                    return self._send(404, {"error": "not found"})
                return self._send(200, {
                    "id": s["id"], "scope": s["scope"], "status": s["status"],
                    "pct": s["pct"], "current": s["current"],
                    "module": s["module"], "activity": s["activity"],
                    "tool": s["tool"], "cmd": s["cmd"], "note": s["note"],
                    "cmd_secs": int(time.time() - s["cmd_since"]) if s["cmd"] and s.get("cmd_since") else None,
                    "stopping": s["stopping"],
                    "done": s["done"], "total": s["total"], "counts": s["counts"],
                    "log": s["log"][-80:], "has_result": bool(s["result_html"]),
                    "has_json": bool(s["result_json"]),
                })
        if path.startswith("/results/"):
            sid = path.split("/")[2]
            with LOCK:
                s = SCANS.get(sid)
            if not s or not s["result_html"]:
                return self._send(404, "<h1>No result yet</h1>", "text/html")
            return self._send(200, s["result_html"], "text/html; charset=utf-8")
        if path.startswith("/api/scan/") and path.endswith("/json"):
            sid = path.split("/")[3]
            with LOCK:
                s = SCANS.get(sid)
            if not s or not s["result_json"]:
                return self._send(404, {"error": "no json"})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", f'attachment; filename="scan_{sid}.json"')
            body = json.dumps(s["result_json"], indent=2).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
            return
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok() or not self._write_ok():
            return
        path = urlparse(self.path).path
        if path.startswith("/api/devices"):
            return self._devices_post(path, self._body())
        if path == "/api/scan/start":
            body = self._body()
            scope = body.get("scope", "host")
            try:
                sid = start_scan(scope, body, self.client_address[0])
            except BadRequest as e:
                return self._send(400, {"error": str(e), "errors": e.detail or []})
            return self._send(200, {"scan_id": sid})
        if path == "/api/history/delete":
            body = self._body()
            refs = body.get("refs") if isinstance(body.get("refs"), list) else None
            days = body.get("older_than_days")
            if refs is None and body.get("all") is not True and not isinstance(days, int):
                return self._send(400, {"error": "say which scans: refs, older_than_days, or all"})
            if isinstance(days, int) and days < 0:
                return self._send(400, {"error": "older_than_days must be 0 or more"})
            deleted = db.delete_scans([str(r)[:40] for r in refs] if refs is not None else None,
                                      days if isinstance(days, int) else None)
            files = _remove_report_files(deleted) if body.get("files") else 0
            db.log("history.delete", None, {"scans": len(deleted), "files_removed": files,
                                            "refs": [d["scan_ref"] for d in deleted][:50],
                                            "older_than_days": days, "all": body.get("all") is True},
                   self.client_address[0])
            return self._send(200, {"deleted": len(deleted), "files_removed": files})
        if path.startswith("/api/actions/"):
            b, what = self._body(), path[len("/api/actions/"):]
            ip = self.client_address[0]
            calls = {
                "save": lambda: act.save(b),
                "delete": lambda: act.delete(int(b.get("id") or 0)),
                "combine": lambda: act.combine(int(b.get("first") or 0), int(b.get("second") or 0), str(b.get("name") or "")),
                "parse": lambda: {"steps": act.parse_text(str(b.get("text") or "")),
                                  "dangerous": act.is_dangerous(act.parse_text(str(b.get("text") or "")))},
                "reorder": lambda: act.reorder([int(x) for x in (b.get("ids") or [])]),
                "restore": act.restore_builtins,
                "import": lambda: act.import_all(b.get("doc")),
                "run": lambda: act.start(int(b.get("id") or 0), b.get("confirm_dangerous") is True, ip,
                                         str(b.get("target") or "") or None),
                "targets/connect": lambda: atg.connect(b),
                "targets/disconnect": lambda: atg.disconnect(str(b.get("id") or "")),
                "targets/forget": lambda: atg.forget(str(b.get("host") or ""), int(b.get("port") or 22)),
            }
            m = re.match(r"^runs/(\d+)/stop$", what)
            if m:
                return self._act(lambda: act.stop(int(m.group(1))))
            if what not in calls:
                return self._send(404, {"error": "not found"})
            return self._act(calls[what])
        if path == "/api/db/backups/run":
            r = db_backup.run_backup()
            return self._send(200 if r["ok"] else 500, r if r["ok"] else {"error": r["error"]})
        if path == "/api/db/backups/schedule":
            r = db_backup.schedule(bool(self._body().get("enabled")))
            return self._send(200 if r.get("ok") else 500, r if r.get("ok") else {"error": r.get("error")})
        if path == "/api/credentials/forget":
            body = self._body()
            key, pw = str(body.get("vault_key") or ""), str(body.get("passphrase") or "")
            if not re.match(r"^CRED_[A-Za-z0-9_-]{1,64}$", key) or not pw:
                return self._send(400, {"error": "vault_key and passphrase are required"})
            r, w = os.pipe()
            try:
                p = subprocess.Popen(["bash", "vault.sh", "rm", key], cwd=str(ND_DIR), pass_fds=(r,),
                                     env=dict(os.environ, ND_VAULT_PASS_FD=str(r), NO_COLOR="1"),
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            finally:
                os.close(r)
            _send_secret(w, (pw + "\n").encode()); pw = ""
            out, _ = p.communicate(timeout=60)
            if p.returncode != 0 and "no such key" not in out:
                msg = ("wrong vault passphrase" if "passphrase was wrong" in out
                       else out.strip().splitlines()[-1] if out.strip() else "vault error")
                return self._send(400, {"error": msg})
            db.delete_credential(key)
            db.log("credential.forget", key, None, self.client_address[0])
            return self._send(200, {"forgotten": key})
        if path == "/api/targets/parse":
            body = self._body()
            r = tg.parse(body.get("targets") if isinstance(body.get("targets"), list) else [],
                         tg.allowed_prefixes(ND_SETTINGS))
            return self._send(200, {"counts": r["counts"], "addresses": r["addresses"],
                                    "total": len(r["targets"]), "errors": r["errors"][:200],
                                    "max_lines": tg.MAX_LINES, "max_addresses": tg.MAX_ADDRESSES})
        if path.startswith("/api/scan/") and path.endswith("/stop"):
            sid = path.split("/")[3]
            return self._send(200, {"stopped": stop_scan(sid)})
        return self._send(404, {"error": "not found"})

    # ── devices ─────────────────────────────────────────────────────────────
    def _devices_get(self, path):
        parts = path.strip("/").split("/")        # api devices [id|vendors|backups] [...]
        if path == "/api/devices":
            return self._device_call(lambda: {"devices": devmgr.list_devices()})
        if path == "/api/devices/vendors":
            return self._device_call(devmgr.vendors)
        if len(parts) == 5 and parts[2] == "backups" and parts[4] == "download":
            try:
                b = devmgr.get_backup(int(parts[3]))
            except (ValueError, DeviceError) as e:
                return self._send(404, {"error": str(e)})
            stamp = b["taken_at"][:19].replace(":", "").replace("T", "-")
            name = re.sub(r"[^A-Za-z0-9_.-]", "_", b["device_name"])
            data = b["config"].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{name}-{stamp}.conf"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers(); self.wfile.write(data)
            return
        try:
            dev = int(parts[2])
        except (IndexError, ValueError):
            return self._send(404, {"error": "not found"})
        what = parts[3] if len(parts) > 3 else ""
        calls = {"": devmgr.get_device, "overview": devmgr.overview, "wizards": devmgr.wizards,
                 "backups": devmgr.list_backups, "changes": devmgr.list_changes}
        if what not in calls:
            return self._send(404, {"error": "not found"})
        return self._device_call(lambda: _wrap(calls[what](dev)))

    def _devices_post(self, path, b):
        parts = path.strip("/").split("/")
        if path == "/api/devices":
            return self._device_call(lambda: {"id": devmgr.add_device(b)})
        if path == "/api/devices/apply":
            return self._device_call(lambda: devmgr.apply(str(b.get("plan_id", "")), bool(b.get("skip_backup"))))
        if len(parts) == 5 and parts[2] == "changes" and parts[4] == "rollback":
            return self._device_call(lambda: devmgr.rollback(int(parts[3])))
        try:
            dev = int(parts[2]); what = parts[3]
        except (IndexError, ValueError):
            return self._send(404, {"error": "not found"})
        calls = {
            "delete": lambda: devmgr.delete_device(dev) or {"ok": True},
            "probe": lambda: devmgr.probe(dev),
            "trust": lambda: devmgr.trust(dev, b.get("fingerprint", "")) or {"ok": True},
            "connect": lambda: {"facts": devmgr.connect(dev, b.get("creds") or {})},
            "disconnect": lambda: devmgr.disconnect(dev) or {"ok": True},
            "backup": lambda: devmgr.take_backup(dev, "manual"),
            "preview": lambda: devmgr.preview(dev, str(b.get("wizard", "")), b.get("params") or {}),
            "mode": lambda: devmgr.set_read_only(dev, b.get("read_only") is not False,
                                                 str(b.get("confirm_name") or "")),
        }
        if what not in calls:
            return self._send(404, {"error": "not found"})
        return self._device_call(calls[what])


def _wrap(v):
    return v if isinstance(v, dict) else {"items": v}


# ── control panel page ───────────────────────────────────────────────────────



def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}"
    print(f"SentinelScan control panel → {url}")
    print(f"  host engine: {len(MODULE_REGISTRY)} modules")
    print(f"  network/cloud tool: {ND_DIR}  ({'found' if (ND_DIR/'discover.sh').exists() else 'not found'})")
    if db.database_url():
        try:   # an update may bring new tables; apply them so saving keeps working
            new = db.migrate()
            print("  database: ready" + (f" (applied {', '.join(new)})" if new else ""))
            stale = db.mark_interrupted()
            act.mark_interrupted()
            if stale:
                print(f"  database: {stale} scan(s) from an earlier run marked interrupted")
        except Exception as e:  # noqa: BLE001
            print(f"  database: not available ({str(e).strip().splitlines()[0] if str(e).strip() else e})")
    else:
        print("  database: not configured (run install.sh); scans are not saved")
    print("  Ctrl-C to stop.")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
