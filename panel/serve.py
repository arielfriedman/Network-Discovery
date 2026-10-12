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
from devices import manager as devmgr
from devices.base import DeviceError, PinMismatch, PinRequired

HOST, PORT = "127.0.0.1", 8765
APP_DIR = Path(__file__).resolve().parent
REPORTS = APP_DIR / "reports"
REPORTS.mkdir(exist_ok=True)
WEB = APP_DIR / "web"          # the browser pages
PAGES = {"/": "index.html", "/index.html": "index.html",
         "/history": "history.html", "/devices": "devices.html"}
CTYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
          ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}
ND_DIR = APP_DIR.parent / "discovery"  # network/cloud tool, same repo

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


def _log(sid: str, msg: str) -> None:
    with LOCK:
        SCANS[sid]["log"].append(msg)
        SCANS[sid]["current"] = msg


def environment() -> dict:
    """What this machine can do right now — shown on the start page."""
    root = os.geteuid() == 0
    admin = root or subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0
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
    env = dict(os.environ, ND_PROGRESS="1")
    if scope == "cloud":
        args.append("--cloud-only")
        prov = opts.get("provider", "all")
        if prov != "all":
            env["CLOUD_PROVIDERS"] = prov
    else:
        args.append("--no-cloud")
        if opts.get("scan_type", "quick") == "quick":
            args.append("--quick")
    _log(sid, "$ " + " ".join(args))
    db.scan_started(sid, scope, None, None, opts.get("scan_type") if scope == "network" else opts.get("provider", "all"))

    try:
        proc = subprocess.Popen(
            args, cwd=str(ND_DIR), env=env, text=True, bufsize=1,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True,  # no controlling terminal → prompts can't block
        )
    except Exception as e:  # noqa: BLE001
        with LOCK:
            SCANS[sid]["status"] = "error"; SCANS[sid]["current"] = f"Error: {e}"
        return
    with LOCK:
        SCANS[sid]["cancel"] = lambda: _kill_group(proc)

    run_dir, last_fail, nothing_cloud = None, "", False
    for raw in proc.stdout:
        line = ANSI.sub("", raw).rstrip()
        if not line.strip():
            continue
        with LOCK:
            s = SCANS[sid]
            if line.startswith("@@cmd "):
                argv = line[6:]
                s["cmd"] = argv; s["tool"] = _tool_name(argv)
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


def start_scan(scope: str, opts: dict, source_ip: str | None = None) -> str:
    opts = dict(opts); opts["scope"] = scope
    sid = _new_scan(scope, opts)
    db.log("scan.start", sid, opts, source_ip)
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
        try:
            b = json.loads(self.rfile.read(length) or "{}")
            return b if isinstance(b, dict) else {}
        except ValueError:
            return {}

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
            sid = start_scan(scope, body, self.client_address[0])
            return self._send(200, {"scan_id": sid})
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
