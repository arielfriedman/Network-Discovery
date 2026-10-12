"""
SentinelScan — scanner package.

Importing this package makes the orchestrator primitives available and imports
every scan module so that each one's @register_module decorator runs and fills
MODULE_REGISTRY. Import order matters: base -> orchestrator -> modules.

A module that fails to import (e.g. a syntax issue in one file) must not take the
whole scanner down — it is skipped with a warning and the others still load.
"""
from __future__ import annotations

import importlib
import warnings

from .base import Finding, Severity, ScanModule            # noqa: F401
from .orchestrator import (                                # noqa: F401
    register_module, MODULE_REGISTRY, ScanSession, ScanOrchestrator,
)

# The 14 scan modules, in a sensible display order.
_MODULES = [
    "ports", "firewall", "updates", "users", "av_status",
    "hardening", "permissions", "ssh_config", "rootkits",
    "ssl_tls", "network", "log_audit", "docker", "software_cve",
]

for _m in _MODULES:
    try:
        importlib.import_module(f".{_m}", __name__)
    except Exception as e:  # noqa: BLE001
        warnings.warn(f"scanner module '{_m}' failed to load and was skipped: {e}")

__all__ = [
    "Finding", "Severity", "ScanModule",
    "register_module", "MODULE_REGISTRY", "ScanSession", "ScanOrchestrator",
]
