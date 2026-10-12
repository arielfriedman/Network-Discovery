"""
SentinelScan — config.py  (reconstructed)

Platform detection, external-tool discovery, and paths. The attribute surface is
fixed by what the modules, orchestrator, reporters and web_server read:

  os_type, os_version, offline_mode, missing_tools, tool_paths, default_target,
  default_scan_mode, default_scan_type, current_target, nvd_api_key, debug,
  app_dir, reports_dir, tool(name), has_tool(name), to_dict()
"""
from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import Dict, List, Optional

# Tools the scan modules invoke by name. Discovery is best-effort; every module
# degrades gracefully when a tool is absent (ports.py falls back to sockets, etc.).
KNOWN_TOOLS = [
    "nmap", "lynis", "rkhunter", "chkrootkit", "clamscan", "freshclam",
    "ufw", "firewall-cmd", "iptables", "nft", "ss", "netstat",
    "openssl", "smbclient", "showmount", "docker", "podman",
    "apt", "apt-get", "dnf", "yum", "pacman", "zypper",
    "sshd", "auditctl", "sysctl", "getent", "pip", "pip3", "npm", "pip-audit",
]


class Config:
    def __init__(self, mode: str = "server", scan_type: str = "quick",
                 target: str = "127.0.0.1", debug: bool = False,
                 offline: bool = False, nvd_api_key: Optional[str] = None):
        # -- platform -----------------------------------------------------------
        sysname = platform.system().lower()
        self.os_type = ("windows" if sysname.startswith("win")
                        else "macos" if sysname == "darwin"
                        else "linux")
        self.os_version = self._detect_os_version()

        # -- scan defaults ------------------------------------------------------
        self.default_scan_mode = mode          # "workstation" | "server"
        self.default_scan_type = scan_type     # "quick" | "full"
        self.default_target = target
        self.current_target = target

        # -- environment --------------------------------------------------------
        self.offline_mode = offline
        self.debug = debug
        self.nvd_api_key = nvd_api_key or os.environ.get("NVD_API_KEY")

        # -- paths --------------------------------------------------------------
        self.app_dir = Path(__file__).resolve().parent
        self.reports_dir = self.app_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # -- tool discovery -----------------------------------------------------
        self.tool_paths: Dict[str, str] = {}
        self.missing_tools: List[str] = []
        self._discover_tools()

    # -- helpers ----------------------------------------------------------------
    def _detect_os_version(self) -> str:
        try:
            if self.os_type == "linux":
                data = {}
                p = Path("/etc/os-release")
                if p.exists():
                    for line in p.read_text().splitlines():
                        if "=" in line:
                            k, _, v = line.partition("=")
                            data[k] = v.strip().strip('"')
                    return data.get("PRETTY_NAME") or data.get("NAME", "Linux")
                return "Linux"
            if self.os_type == "macos":
                return "macOS " + platform.mac_ver()[0]
            return platform.platform()
        except Exception:
            return platform.system()

    def _discover_tools(self) -> None:
        for tool in KNOWN_TOOLS:
            path = shutil.which(tool)
            if path:
                self.tool_paths[tool] = path
            else:
                self.missing_tools.append(tool)

    # -- API used by modules ----------------------------------------------------
    def tool(self, name: str) -> Optional[str]:
        """Absolute path of a tool, or None if not installed."""
        return self.tool_paths.get(name)

    def has_tool(self, name: str) -> bool:
        return name in self.tool_paths

    def to_dict(self) -> dict:
        return {
            "os_type": self.os_type,
            "os_version": self.os_version,
            "mode": self.default_scan_mode,
            "scan_type": self.default_scan_type,
            "target": self.current_target,
            "offline_mode": self.offline_mode,
            "installed_tools": sorted(self.tool_paths.keys()),
            "missing_tools": self.missing_tools,
        }
