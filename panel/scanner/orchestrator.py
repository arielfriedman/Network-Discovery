"""
SentinelScan — scanner/orchestrator.py  (reconstructed)

Provides:
    register_module            — decorator every module applies to itself
    MODULE_REGISTRY            — the list it fills
    ScanSession                — holds one scan's findings + module results
    ScanOrchestrator           — runs the applicable modules against a session

The ScanSession.to_dict() shape is fixed by web_server_phase7.py (_load/_save,
/history) and by the reporters. ScanOrchestrator's construction
(ScanOrchestrator(cfg, emit_fn=...).run(session) / .cancel()) is fixed by
web_server_phase7.api_scan_start().
"""
from __future__ import annotations

import time
import traceback
from datetime import datetime
from typing import Callable, List, Optional

from .base import Finding, Severity, ScanCancelled

# ─── module registry ───────────────────────────────────────────────────────────
MODULE_REGISTRY: List[type] = []


def register_module(cls):
    """Class decorator: register a ScanModule subclass. Returns the class unchanged."""
    if cls not in MODULE_REGISTRY:
        MODULE_REGISTRY.append(cls)
    return cls


# ─── scan session ──────────────────────────────────────────────────────────────
class ScanSession:
    SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def __init__(self, scan_id: str, mode: str, scan_type: str, target: str):
        self.scan_id = scan_id
        self.mode = mode                 # "workstation" | "server"
        self.scan_type = scan_type       # "quick" | "full"
        self.target = target
        self.status = "pending"          # pending -> running -> complete | cancelled | error
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.started_iso = datetime.now().isoformat(timespec="seconds")
        self.findings: List[Finding] = []
        self.modules: List[dict] = []    # {name, display_name, status, finding_count, elapsed_s}

    # -- derived ----------------------------------------------------------------
    @property
    def elapsed_s(self) -> float:
        end = self.end_time if self.end_time is not None else time.time()
        return round(end - self.start_time, 1)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def severity_counts(self) -> dict:
        counts = {s: 0 for s in self.SEVERITIES}
        for f in self.findings:
            key = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            if key in counts:
                counts[key] += 1
        return counts

    @property
    def risk_score(self) -> int:
        total = self.total_findings
        if total == 0:
            return 0
        raw = sum(
            (f.severity.weight if isinstance(f.severity, Severity) else 0)
            for f in self.findings
        )
        return min(100, round(raw / (total * 10) * 100))

    # -- serialisation ----------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "kind": "host",                    # shared-schema discriminator
            "mode": self.mode,
            "scan_type": self.scan_type,
            "target": self.target,
            "status": self.status,
            "started": self.started_iso,
            "elapsed_s": self.elapsed_s,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "risk_score": self.risk_score,
            "modules": self.modules,
            "findings": [f.to_dict() for f in sorted(
                self.findings,
                key=lambda f: f.severity.sort_order if isinstance(f.severity, Severity) else 9,
            )],
        }


# ─── orchestrator ──────────────────────────────────────────────────────────────
class ScanOrchestrator:
    def __init__(self, config, emit_fn: Optional[Callable[[str, dict], None]] = None):
        self.config = config
        self.emit_fn = emit_fn
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True
        # modules check this on every progress update / command and stop at once
        self.config.cancelled = True

    def _emit(self, event: str, data: dict) -> None:
        if self.emit_fn:
            try:
                self.emit_fn(event, data)
            except Exception:
                pass

    def _applicable(self, mod_cls, session) -> Optional[str]:
        """Return None if the module should run, else a reason string for skipping."""
        os_type = getattr(self.config, "os_type", "linux")
        if os_type not in getattr(mod_cls, "applies_to_os", ["linux", "windows", "macos"]):
            return f"not for {os_type}"
        if session.mode not in getattr(mod_cls, "applies_to_mode", ["workstation", "server"]):
            return f"not in {session.mode} mode"
        for tool in getattr(mod_cls, "requires_tools", []) or []:
            if not self.config.has_tool(tool):
                return f"missing tool: {tool}"
        return None

    def run(self, session) -> None:
        session.status = "running"
        session.start_time = time.time()
        modules = list(MODULE_REGISTRY)
        total = len(modules)
        self._emit("scan_started", {"scan_id": session.scan_id, "module_count": total})

        for idx, mod_cls in enumerate(modules):
            if self._cancelled:
                session.status = "cancelled"
                break

            display = getattr(mod_cls, "display_name", getattr(mod_cls, "name", mod_cls.__name__))
            name = getattr(mod_cls, "name", mod_cls.__name__)
            self._emit("module_started", {
                "scan_id": session.scan_id, "module": name,
                "display_name": display, "index": idx + 1, "total": total,
            })

            skip_reason = self._applicable(mod_cls, session)
            if skip_reason:
                session.modules.append({
                    "name": name, "display_name": display,
                    "status": "skipped", "finding_count": 0,
                    "elapsed_s": 0.0, "detail": skip_reason,
                })
                self._emit("module_done", {"scan_id": session.scan_id, "module": name,
                                           "status": "skipped", "detail": skip_reason})
                continue

            t0 = time.time()
            count = 0
            status = "done"
            detail = ""
            try:
                module = mod_cls(self.config, emit_fn=self.emit_fn)
                for finding in module.run():
                    if self._cancelled:
                        status = "cancelled"
                        break
                    if finding is not None:
                        session.findings.append(finding)
                        count += 1
            except ScanCancelled:
                status = "cancelled"
                detail = "stopped by user"
            except Exception as e:  # a broken module must not kill the scan
                status = "error"
                detail = f"{type(e).__name__}: {e}"
                if getattr(self.config, "debug", False):
                    traceback.print_exc()

            elapsed = round(time.time() - t0, 1)
            session.modules.append({
                "name": name, "display_name": display,
                "status": status, "finding_count": count,
                "elapsed_s": elapsed, "detail": detail,
            })
            self._emit("module_done", {
                "scan_id": session.scan_id, "module": name, "status": status,
                "finding_count": count, "elapsed_s": elapsed, "detail": detail,
            })
            if status == "cancelled":
                session.status = "cancelled"
                break

        session.end_time = time.time()
        if session.status == "running":
            session.status = "complete"
        self._emit("scan_complete", {
            "scan_id": session.scan_id, "status": session.status,
            "total_findings": session.total_findings,
            "severity_counts": session.severity_counts,
            "risk_score": session.risk_score,
            "elapsed_s": session.elapsed_s,
        })
