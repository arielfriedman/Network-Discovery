#!/usr/bin/env python3
"""
SentinelScan — main.py  (reconstructed CLI entry point)

Runs a host security scan and writes:
    reports/<scan_id>.json            the raw findings (shared schema)
    reports/<scan_id>_dashboard.html  the dashboard (open in a browser)

Usage:
    python3 main.py                       # server / quick scan of localhost
    python3 main.py --mode workstation
    python3 main.py --type full
    python3 main.py --target 127.0.0.1
    python3 main.py --open                # also open the dashboard when done

Every check runs on this host and reads only local state; nothing leaves the
machine. Some modules (open ports, firewall, hardening) see more when run with
sudo, but the scan works unprivileged too — those checks simply report less.
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
import webbrowser
from pathlib import Path

from config import Config
import scanner  # noqa: F401  — triggers module registration
from scanner import ScanSession, ScanOrchestrator, MODULE_REGISTRY
from reporters import generate_dashboard


def _cli_emit(event: str, data: dict) -> None:
    """Console progress. Keeps output readable without a browser/websocket."""
    if event == "module_started":
        print(f"  [{data['index']:>2}/{data['total']}] {data['display_name']} …", flush=True)
    elif event == "module_done":
        st = data.get("status", "done")
        if st == "skipped":
            print(f"        skipped ({data.get('detail','')})")
        elif st == "error":
            print(f"        ERROR: {data.get('detail','')}")
        else:
            print(f"        {data.get('finding_count',0)} finding(s) in {data.get('elapsed_s',0)}s")


def main() -> int:
    ap = argparse.ArgumentParser(description="SentinelScan — host security audit")
    ap.add_argument("--mode", choices=["workstation", "server"], default="server")
    ap.add_argument("--type", dest="scan_type", choices=["quick", "full"], default="quick")
    ap.add_argument("--target", default="127.0.0.1")
    ap.add_argument("--offline", action="store_true", help="skip anything needing the internet")
    ap.add_argument("--debug", action="store_true", help="print tracebacks from failing modules")
    ap.add_argument("--open", action="store_true", help="open the dashboard when the scan finishes")
    args = ap.parse_args()

    cfg = Config(mode=args.mode, scan_type=args.scan_type, target=args.target,
                 debug=args.debug, offline=args.offline)

    print(f"SentinelScan — {cfg.os_type} ({cfg.os_version})")
    print(f"Mode: {args.mode} · Scan: {args.scan_type} · Target: {args.target}")
    print(f"Modules registered: {len(MODULE_REGISTRY)} · "
          f"Tools found: {len(cfg.tool_paths)} · Missing: {len(cfg.missing_tools)}")
    if not MODULE_REGISTRY:
        print("No scan modules registered — aborting.", file=sys.stderr)
        return 2
    print("-" * 60)

    scan_id = uuid.uuid4().hex[:12]
    session = ScanSession(scan_id, args.mode, args.scan_type, args.target)
    ScanOrchestrator(cfg, emit_fn=_cli_emit).run(session)

    print("-" * 60)
    c = session.severity_counts
    print(f"Done in {session.elapsed_s}s — {session.total_findings} findings "
          f"(risk {session.risk_score}/100)")
    print(f"  CRITICAL {c['CRITICAL']}  HIGH {c['HIGH']}  MEDIUM {c['MEDIUM']}  "
          f"LOW {c['LOW']}  INFO {c['INFO']}")

    reports_dir = cfg.reports_dir
    json_path = reports_dir / f"{scan_id}.json"
    html_path = reports_dir / f"{scan_id}_dashboard.html"
    json_path.write_text(json.dumps(session.to_dict(), indent=2), encoding="utf-8")
    generate_dashboard(session, str(html_path))

    print(f"\nJSON     : {json_path}")
    print(f"Dashboard: {html_path}")

    if args.open:
        try:
            webbrowser.open(html_path.as_uri())
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
