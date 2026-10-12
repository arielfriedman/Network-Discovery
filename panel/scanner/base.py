"""
SentinelScan — scanner/base.py  (reconstructed)

Defines the three primitives every scan module imports:

    from .base import ScanModule, Finding, Severity

The contract here is reverse-engineered from how the 14 scan modules and the
three reporters use it — it is not a redesign. Anything a module calls on
`self` (run_command, _emit_progress) or on a Finding/Severity is implemented to
match that exact usage.
"""
from __future__ import annotations

import enum
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Callable


# ─── Cancellation ──────────────────────────────────────────────────────────────
class ScanCancelled(BaseException):
    """
    Raised inside a module when the user presses Stop. Derives from
    BaseException (like KeyboardInterrupt) so the modules' own broad
    `except Exception` blocks cannot swallow it; the orchestrator catches it.
    """


# ─── Severity ──────────────────────────────────────────────────────────────────
class Severity(str, enum.Enum):
    """
    String-valued enum so that:
      - f.severity.value           -> "CRITICAL" (used by the reporters)
      - Severity("CRITICAL")       -> Severity.CRITICAL (used by web_server._load)
      - f.severity.sort_order      -> 0..4, CRITICAL first (reporter sorting)
    """
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def sort_order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]

    @property
    def weight(self) -> int:
        return {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}[self.value]


# ─── Finding ───────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    title: str
    severity: Severity
    category: str
    description: str = ""
    affected_component: str = ""
    remediation: str = ""
    workaround: str = ""
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: "f" + uuid.uuid4().hex[:8])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "category": self.category,
            "description": self.description,
            "affected_component": self.affected_component,
            "remediation": self.remediation,
            "workaround": self.workaround,
            "cvss_score": self.cvss_score,
            "cve_ids": list(self.cve_ids or []),
            "references": list(self.references or []),
        }


# ─── ScanModule base ───────────────────────────────────────────────────────────
class ScanModule:
    """
    Base class for every scan module. Subclasses set the class attributes below,
    are decorated with @register_module, and implement `run(self) -> Iterator[Finding]`.

    Modules rely on exactly two helpers from this base:
      self._emit_progress(pct, message)         — progress reporting (196 call sites)
      self.run_command(args, timeout=N)         — subprocess wrapper (136 call sites)
                                                  returns (stdout, stderr, returncode)
    """
    # Defaults — subclasses override.
    name: str = "module"
    display_name: str = "Scan Module"
    category: str = "General"
    description: str = ""
    applies_to_os: List[str] = ["linux", "windows", "macos"]
    applies_to_mode: List[str] = ["workstation", "server"]
    requires_tools: List[str] = []

    def __init__(self, config, emit_fn: Optional[Callable[[str, dict], None]] = None):
        self.config = config
        self._emit_fn = emit_fn
        self._last_pct = 0

    # -- progress ---------------------------------------------------------------
    def _check_cancelled(self) -> None:
        if getattr(self.config, "cancelled", False):
            raise ScanCancelled()

    def _emit_progress(self, pct: int, message: str = "") -> None:
        self._check_cancelled()
        try:
            self._last_pct = int(pct)
        except Exception:
            self._last_pct = 0
        if self._emit_fn:
            try:
                self._emit_fn("module_progress", {
                    "module": self.name,
                    "display_name": self.display_name,
                    "pct": self._last_pct,
                    "message": message,
                })
            except Exception:
                pass

    # -- subprocess -------------------------------------------------------------
    def run_command(self, args, timeout: int = 30):
        """
        Run a command and return (stdout, stderr, returncode) as (str, str, int).

        `args` is always a list (verified across all modules). Never uses a shell.
        On timeout or launch failure, returns ("", "<reason>", -1) so callers that
        do `stdout, _, rc = self.run_command(...)` keep working and simply see an
        empty stdout / non-zero rc.

        Each invocation is announced via a "command" event so the UI can show
        exactly which external tool is running right now.
        """
        self._check_cancelled()
        if self._emit_fn and isinstance(args, (list, tuple)) and args:
            try:
                self._emit_fn("command", {
                    "module": self.name,
                    "tool": str(args[0]),
                    "argv": " ".join(str(a) for a in args),
                })
            except Exception:
                pass
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return proc.stdout or "", proc.stderr or "", proc.returncode
        except subprocess.TimeoutExpired:
            return "", f"timeout after {timeout}s", -1
        except FileNotFoundError:
            return "", "command not found", -1
        except Exception as e:  # noqa: BLE001 — modules expect a tuple, never a raise
            return "", str(e), -1

    # -- to be overridden -------------------------------------------------------
    def run(self) -> Iterator[Finding]:  # pragma: no cover
        raise NotImplementedError(f"{self.__class__.__name__} must implement run()")
