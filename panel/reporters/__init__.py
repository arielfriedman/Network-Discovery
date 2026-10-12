"""SentinelScan reporters package.

Each import is guarded so a missing optional dependency (e.g. reportlab for the
PDF reporters) cannot break the always-available HTML dashboard path.
"""
from __future__ import annotations

# Always available — no third-party dependencies.
from .dashboard import generate_dashboard   # noqa: F401
from .html_report import generate_html      # noqa: F401

# PDF reporters need reportlab; degrade gracefully if it is not installed.
try:
    from .pdf_report import generate_pdf, generate_pdf_bytes, REPORTLAB_AVAILABLE  # noqa: F401
except Exception:  # noqa: BLE001
    REPORTLAB_AVAILABLE = False

    def generate_pdf(*a, **k):  # type: ignore
        raise RuntimeError("reportlab not installed — pip install reportlab")

    def generate_pdf_bytes(*a, **k):  # type: ignore
        raise RuntimeError("reportlab not installed — pip install reportlab")

try:
    from .executive import generate_executive_pdf  # noqa: F401
except Exception:  # noqa: BLE001
    def generate_executive_pdf(*a, **k):  # type: ignore
        raise RuntimeError("reportlab not installed — pip install reportlab")

__all__ = [
    "generate_dashboard", "generate_html",
    "generate_pdf", "generate_pdf_bytes", "generate_executive_pdf",
    "REPORTLAB_AVAILABLE",
]
