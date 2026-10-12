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

HOST, PORT = "127.0.0.1", 8765
APP_DIR = Path(__file__).resolve().parent
REPORTS = APP_DIR / "reports"
REPORTS.mkdir(exist_ok=True)
ND_DIR = APP_DIR.parent / "discovery"  # network/cloud tool, same repo

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

        orch = ScanOrchestrator(cfg, emit_fn=emit)
        with LOCK:
            SCANS[sid]["total"] = total
            SCANS[sid]["cancel"] = orch.cancel
        orch.run(session)

        d = session.to_dict()
        html = generate_dashboard(session)
        (REPORTS / f"{sid}.json").write_text(json.dumps(d, indent=2))
        (REPORTS / f"{sid}_dashboard.html").write_text(html)
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


SCOPE_RUNNERS = {
    "host": run_host_scan,
    "network": run_shell_scan,
    "cloud": run_shell_scan,
}


def start_scan(scope: str, opts: dict) -> str:
    opts = dict(opts); opts["scope"] = scope
    sid = _new_scan(scope, opts)
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

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            return self._send(200, CONTROL_HTML, "text/html; charset=utf-8")
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
        path = urlparse(self.path).path
        if path == "/api/scan/start":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or "{}")
            except Exception:
                body = {}
            scope = body.get("scope", "host")
            sid = start_scan(scope, body)
            return self._send(200, {"scan_id": sid})
        if path.startswith("/api/scan/") and path.endswith("/stop"):
            sid = path.split("/")[3]
            return self._send(200, {"stopped": stop_scan(sid)})
        return self._send(404, {"error": "not found"})


# ── control panel page ───────────────────────────────────────────────────────
CONTROL_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelScan</title>
<style>
  :root{color-scheme:light;--plane:#f9f9f7;--surface-1:#fcfcfb;--text-primary:#0b0b0b;
    --text-secondary:#52514e;--text-muted:#898781;--border:rgba(11,11,11,0.10);
    --series-1:#2a78d6;--series-1-soft:#cde2fb;--good:#0ca30c;--warning:#fab219;
    --serious:#ec835a;--critical:#d03b3b;--radius:10px;}
  @media (prefers-color-scheme:dark){:root:where(:not([data-theme=light])){color-scheme:dark;
    --plane:#0d0d0d;--surface-1:#1a1a19;--text-primary:#fff;--text-secondary:#c3c2b7;
    --text-muted:#898781;--border:rgba(255,255,255,0.10);--series-1:#3987e5;--series-1-soft:#184f95;}}
  :root[data-theme=dark]{color-scheme:dark;--plane:#0d0d0d;--surface-1:#1a1a19;--text-primary:#fff;
    --text-secondary:#c3c2b7;--text-muted:#898781;--border:rgba(255,255,255,0.10);
    --series-1:#3987e5;--series-1-soft:#184f95;}
  *{box-sizing:border-box}
  body{margin:0;padding:0 16px 64px;background:var(--plane);color:var(--text-primary);
    font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
  .wrap{max-width:900px;margin:0 auto}
  header{padding:28px 0 8px}
  h1{margin:0 0 4px;font-size:24px;letter-spacing:-.01em}
  .sub{color:var(--text-secondary);font-size:13.5px}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:var(--text-muted);
    margin:26px 0 12px;font-weight:600}
  .scopes{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
  .scope{background:var(--surface-1);border:1px solid var(--border);border-radius:var(--radius);
    padding:16px 18px;cursor:pointer;transition:border-color .12s}
  .scope:hover{border-color:var(--series-1)}
  .scope.on{border-color:var(--series-1);box-shadow:0 0 0 1px var(--series-1) inset}
  .scope .t{font-weight:600;font-size:15px;margin-bottom:3px}
  .scope .d{color:var(--text-muted);font-size:12.5px}
  .opts{background:var(--surface-1);border:1px solid var(--border);border-radius:var(--radius);
    padding:16px 18px;margin-top:14px;display:flex;flex-wrap:wrap;gap:14px}
  .field{display:flex;flex-direction:column;gap:4px}
  .field label{font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted)}
  select,input{background:var(--plane);color:var(--text-primary);border:1px solid var(--border);
    border-radius:8px;padding:8px 11px;font:inherit;font-size:13.5px;min-width:150px}
  .go{margin-top:18px;display:flex;gap:12px;align-items:center}
  button.start{background:var(--series-1);color:#fff;border:none;border-radius:8px;
    padding:11px 22px;font:inherit;font-size:14px;font-weight:600;cursor:pointer}
  button.start:disabled{opacity:.5;cursor:default}
  button.theme{background:var(--surface-1);color:var(--text-secondary);border:1px solid var(--border);
    border-radius:999px;padding:7px 14px;font:inherit;font-size:13px;cursor:pointer;float:right}
  /* progress */
  #run{display:none;margin-top:8px}
  .bar{height:12px;border-radius:6px;background:var(--series-1-soft);overflow:hidden;margin:6px 0 4px}
  .bar>span{display:block;height:100%;background:var(--series-1);width:0;transition:width .4s}
  .status{font-size:14px;margin-bottom:8px}
  .now{background:var(--surface-1);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px}
  .now-top{display:flex;justify-content:space-between;align-items:baseline;gap:12px}
  .now-mod{font-size:16px;font-weight:650}
  .now-pct{font-size:16px;font-weight:650;color:var(--series-1);font-variant-numeric:tabular-nums}
  .now-act{color:var(--text-secondary);font-size:13.5px;margin-top:2px;min-height:18px}
  .now-cmd{margin-top:10px;display:flex;align-items:center;gap:8px;background:var(--plane);
    border:1px solid var(--border);border-radius:7px;padding:7px 11px;
    font:12.5px/1.4 ui-monospace,Menlo,Consolas,monospace;color:var(--text-primary);
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .dotpulse{flex:none;width:8px;height:8px;border-radius:50%;background:var(--good);animation:pulse 1s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
  .log-h{color:var(--text-muted);font-size:12px;margin:14px 0 6px;text-transform:uppercase;letter-spacing:.04em}
  .log{background:var(--surface-1);border:1px solid var(--border);border-radius:8px;
    padding:12px 14px;height:260px;overflow:auto;font:12.5px/1.5 ui-monospace,Menlo,Consolas,monospace;
    color:var(--text-secondary);white-space:pre-wrap}
  .done-bar{display:none;margin-top:14px;gap:10px}
  .done-bar a,.done-bar button{background:var(--series-1);color:#fff;border:none;border-radius:8px;
    padding:10px 18px;font:inherit;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block}
  .done-bar .ghost{background:var(--surface-1);color:var(--text-secondary);border:1px solid var(--border)}
  iframe{width:100%;height:80vh;border:1px solid var(--border);border-radius:var(--radius);margin-top:16px;background:var(--plane)}
  .ready{margin-top:12px;font-size:13px;color:var(--text-secondary);display:flex;flex-direction:column;gap:4px}
  .ready code{background:var(--surface-1);border:1px solid var(--border);border-radius:5px;padding:1px 6px;font-size:12px}
  .ready .ok{color:var(--good);font-weight:700}.ready .warn{color:var(--serious);font-weight:700}
  .ready .bad{color:var(--critical);font-weight:700}.muted{color:var(--text-muted)}
  button.stop{background:var(--surface-1);color:var(--critical);border:1px solid var(--critical);border-radius:8px;
    padding:9px 18px;font:inherit;font-size:14px;font-weight:600;cursor:pointer}
  button.stop:disabled{opacity:.6;cursor:default}
  .note{margin-top:10px;background:var(--surface-1);border:1px solid var(--border);border-left:3px solid var(--warning);
    border-radius:8px;padding:9px 12px;font-size:13px;color:var(--text-secondary)}
</style></head>
<body><div class="wrap">
  <button class="theme" id="themeBtn">Toggle theme</button>
  <header><h1>SentinelScan</h1>
    <div class="sub">Choose what to scan, then start. Everything runs locally on this machine.</div>
  </header>

  <div id="setup">
    <h2>What do you want to scan?</h2>
    <div class="scopes" id="scopes">
      <div class="scope on" data-scope="host">
        <div class="t">This host</div>
        <div class="d">Audit this machine's own security: ports, firewall, SSH, hardening, users, updates and more.</div></div>
      <div class="scope" data-scope="network">
        <div class="t">The network</div>
        <div class="d">Find the devices and services on your LAN, using the network-discovery tool.</div></div>
      <div class="scope" data-scope="cloud">
        <div class="t">The cloud</div>
        <div class="d">List AWS, Azure, GCP and Kubernetes resources. Needs a cloud CLI that is signed in.</div></div>
    </div>

    <div class="opts" id="opts"></div>
    <div class="ready" id="ready"></div>

    <div class="go">
      <button class="start" id="startBtn">Start scan</button>
    </div>
  </div>

  <div id="run">
    <h2 id="runTitle">Scanning</h2>
    <div class="now" id="now">
      <div class="now-top">
        <span class="now-mod" id="nowMod">Starting…</span>
        <span class="now-pct" id="nowPct">0%</span>
      </div>
      <div class="now-act" id="nowAct"></div>
      <div class="now-cmd" id="nowCmd"><span class="dotpulse"></span><span id="nowCmdText">preparing…</span></div>
    </div>
    <div class="bar"><span id="barFill"></span></div>
    <div class="note" id="noteBox" style="display:none"></div>
    <div class="go" id="stopRow"><button class="stop" id="stopBtn">Stop scan</button></div>
    <div class="log-h">Live activity log: every check and command as it runs</div>
    <div class="log" id="logBox"></div>
    <div class="done-bar" id="doneBar">
      <a id="viewBtn" href="#">Open dashboard</a>
      <a id="jsonBtn" class="ghost" href="#">Download JSON</a>
      <button class="ghost" id="againBtn">New scan</button>
    </div>
    <iframe id="frame" style="display:none"></iframe>
  </div>
</div>
<script>
(function(){
  const $=id=>document.getElementById(id);
  try{const t=localStorage.getItem("sentinel-theme");if(t)document.documentElement.setAttribute("data-theme",t);}catch(e){}
  $("themeBtn").onclick=()=>{const c=document.documentElement.getAttribute("data-theme");
    const dark=c?c==="dark":matchMedia("(prefers-color-scheme:dark)").matches;const n=dark?"light":"dark";
    document.documentElement.setAttribute("data-theme",n);try{localStorage.setItem("sentinel-theme",n);}catch(e){}};

  let scope="host", ENV=null;
  const PROV={all:"All installed",aws:"AWS",azure:"Azure",gcp:"Google Cloud",k8s:"Kubernetes"};
  function opts(){
    if(scope==="host") return [["mode","Mode",[["workstation","Workstation (this PC / laptop)"],["server","Server (hosts services)"]]],
                               ["scan_type","Depth",[["quick","Quick"],["full","Full (all ports, slower)"]]]];
    if(scope==="network") return [["scan_type","Depth",[["quick","Quick (find devices, minutes)"],["full","Full (per-device port scan, can take hours)"]]]];
    return [["provider","Provider",Object.keys(PROV).map(k=>
      [k, PROV[k]+(k!=="all"&&ENV&&!ENV.clouds[k]?" (not installed)":"")])]];
  }
  function renderOpts(){
    $("opts").innerHTML=opts().map(([k,label,vals])=>
      `<div class="field"><label>${label}</label><select data-k="${k}">`+
      vals.map(([v,t])=>`<option value="${v}">${t}</option>`).join("")+`</select></div>`).join("");
    renderReady();
  }
  function renderReady(){
    const box=$("ready"); let lines=[], ok=true;
    if(!ENV){ box.innerHTML='<span class="muted">Checking this machine…</span>'; return; }
    const admin=ENV.admin
      ? '<span class="ok">✓</span> Admin rights available.'
      : '<span class="warn">!</span> No admin rights. Scans run, but checks that need root see less. To include them, stop the panel and start it with <code>sudo python3 serve.py</code>.';
    if(scope==="host"){ lines.push('<span class="ok">✓</span> Ready.'); lines.push(admin); }
    if(scope==="network"){
      if(!ENV.nd_tool){ ok=false; lines.push('<span class="bad">✗</span> network-discovery tool not found in <code>discovery/</code> next to the panel.'); }
      else lines.push('<span class="ok">✓</span> network-discovery tool found.');
      lines.push(ENV.admin?admin:'<span class="warn">!</span> No admin rights: the ARP sweep and OS detection will be skipped. Device and port discovery still run.');
    }
    if(scope==="cloud"){
      const have=Object.keys(ENV.clouds).filter(k=>ENV.clouds[k]);
      if(!have.length){ lines.push('<span class="bad">✗</span> No cloud tool is installed (aws, az, gcloud, kubectl), so a cloud scan will find nothing. Install one and sign in first.'); }
      else lines.push('<span class="ok">✓</span> Installed: '+have.map(k=>PROV[k]).join(", ")+'. They must also be signed in.');
    }
    box.innerHTML=lines.map(l=>`<div>${l}</div>`).join("");
    $("startBtn").disabled=!ok;
  }
  document.querySelectorAll(".scope").forEach(el=>el.onclick=()=>{
    document.querySelectorAll(".scope").forEach(s=>s.classList.remove("on"));
    el.classList.add("on"); scope=el.dataset.scope; renderOpts();
  });
  renderOpts();
  fetch("/api/env").then(r=>r.json()).then(e=>{ENV=e; renderOpts();}).catch(()=>{});

  let pollTimer=null, curId=null;
  $("startBtn").onclick=async()=>{
    const o={scope};
    $("opts").querySelectorAll("select").forEach(s=>o[s.dataset.k]=s.value);
    $("startBtn").disabled=true;
    const r=await fetch("/api/scan/start",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});
    const j=await r.json(); curId=j.scan_id;
    $("setup").style.display="none"; $("run").style.display="block";
    $("runTitle").textContent="Scanning";
    $("doneBar").style.display="none"; $("frame").style.display="none";
    $("noteBox").style.display="none"; $("nowCmd").style.display="flex";
    $("stopRow").style.display="flex"; $("stopBtn").disabled=false; $("stopBtn").textContent="Stop scan";
    $("barFill").style.width="0%"; $("logBox").textContent="";
    poll();
  };
  $("stopBtn").onclick=async()=>{
    if(!curId) return;
    $("stopBtn").disabled=true; $("stopBtn").textContent="Stopping…";
    await fetch(`/api/scan/${curId}/stop`,{method:"POST"});
  };
  async function poll(){
    if(!curId)return;
    let s;
    try{ s=await (await fetch(`/api/scan/${curId}/status`)).json(); }
    catch(e){ $("nowMod").textContent="Lost contact with the panel. Is serve.py still running?"; pollTimer=setTimeout(poll,2000); return; }
    $("barFill").style.width=(s.pct||0)+"%";
    $("nowPct").textContent=(s.pct||0)+"%";
    $("nowMod").textContent=s.module||s.current||s.status;
    $("nowAct").textContent=s.activity||"";
    $("nowCmdText").textContent=s.cmd||(s.status==="running"?"working…":"");
    if(s.note){ $("noteBox").textContent=s.note; $("noteBox").style.display="block"; }
    $("logBox").textContent=(s.log||[]).join("\n"); $("logBox").scrollTop=1e9;
    if(s.status==="running"){ pollTimer=setTimeout(poll,1000); return; }

    // finished: complete, cancelled (stopped) or error
    $("stopRow").style.display="none"; $("nowCmd").style.display="none"; $("nowAct").textContent="";
    $("runTitle").textContent = s.status==="complete"?"Finished":s.status==="cancelled"?"Stopped":"Failed";
    $("nowMod").textContent=s.current||s.status;
    if(s.status==="complete"){ $("nowPct").textContent="100%"; $("barFill").style.width="100%"; }
    $("doneBar").style.display="flex";
    $("viewBtn").style.display=s.has_result?"inline-block":"none";
    $("jsonBtn").style.display=s.has_json?"inline-block":"none";
    if(s.has_result){
      $("viewBtn").href=`/results/${curId}`; $("viewBtn").target="_blank";
      $("jsonBtn").href=`/api/scan/${curId}/json`;
      $("frame").src=`/results/${curId}`; $("frame").style.display="block";
    }
  }
  $("againBtn").onclick=()=>{ if(pollTimer)clearTimeout(pollTimer); curId=null;
    $("run").style.display="none"; $("setup").style.display="block"; renderReady(); };
})();
</script>
</body></html>"""


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
