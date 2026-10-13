"""
Target lists for the network scan. The rules live in one place,
discovery/lib/targets_util.py (discover.sh --targets uses the same code), so
the panel and the command line accept and refuse exactly the same lines.
Validation always runs here on the server, whatever the browser checked.
"""
from __future__ import annotations

import sys
from pathlib import Path

_LIB = Path(__file__).resolve().parent.parent / "discovery" / "lib"
if str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))

from targets_util import (MAX_ADDRESSES, MAX_LINES, allowed_prefixes,  # noqa: E402,F401
                          classify, normalize_mac, parse)


def write_file(path: Path, targets: list[dict]) -> None:
    """kind<TAB>value<TAB>source - read by discover.sh --targets."""
    path.write_text("".join(f"{t['kind']}\t{t['value']}\t{t['source']}\n" for t in targets))
    path.chmod(0o600)
