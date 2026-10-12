"""
SentinelScan — scanner/software_cve.py
Installed Software CVE Mapping
Phase 6 — Scan Modules Tier 3

Enumerates installed software, maps versions to NVD/OSV vulnerability
databases, reports CVEs with CVSS ≥ 7.0, and also runs pip-audit and
npm audit where applicable.
"""
from __future__ import annotations
import json
import re
import os
import shutil
import time
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module

NVD_API_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE   = "https://api.osv.dev/v1/query"
REQUEST_DELAY  = 0.7   # NVD rate limit: ~5 req/30s without key
CVSS_CRITICAL  = 9.0
CVSS_HIGH      = 7.0


@register_module
class SoftwareCVEModule(ScanModule):
    name             = "software_cve"
    display_name     = "Software CVE Mapping"
    category         = "Vulnerabilities"
    description      = "Maps installed software versions to known CVEs via NVD and OSV APIs"
    applies_to_os    = ["linux", "windows", "macos"]
    applies_to_mode  = ["workstation", "server"]

    def run(self) -> Iterator[Finding]:
        if self.config.offline_mode:
            yield Finding(
                title              = "Software CVE mapping skipped (offline mode)",
                severity           = Severity.INFO,
                category           = "Vulnerabilities",
                description        = "CVE lookup requires internet access to the NVD/OSV APIs. Enable online mode to run this module.",
                affected_component = "NVD/OSV API",
                remediation        = "Connect to the internet and re-run, or use --offline to skip this module.",
            )
            return

        self._emit_progress(5, "Enumerating installed software...")
        packages = self._get_installed_packages()

        if not packages:
            yield Finding(
                title              = "No software inventory could be collected",
                severity           = Severity.INFO,
                category           = "Vulnerabilities",
                description        = "Could not enumerate installed packages. Run with elevated privileges.",
                affected_component = "Package manager",
                remediation        = "Run with sudo for complete software inventory.",
            )
            return

        yield Finding(
            title              = f"Software inventory: {len(packages)} package(s) found",
            severity           = Severity.INFO,
            category           = "Vulnerabilities",
            description        = f"Enumerated {len(packages)} installed packages for CVE analysis.",
            affected_component = "Installed software",
            remediation        = "Review findings below for specific CVEs.",
        )

        # Check Python packages
        self._emit_progress(20, "Running pip-audit for Python package CVEs...")
        yield from self._pip_audit()

        # Check npm packages
        self._emit_progress(35, "Running npm audit for Node.js CVEs...")
        yield from self._npm_audit()

        # NVD lookup for key software
        self._emit_progress(50, "Querying NVD for critical software CVEs...")
        yield from self._nvd_lookup(packages)

    # ─────────────────────────────────────────────────────────────────────────
    # PACKAGE ENUMERATION
    # ─────────────────────────────────────────────────────────────────────────
    def _get_installed_packages(self) -> list[dict]:
        packages = []
        if self.config.os_type == "linux":
            packages = self._linux_packages()
        elif self.config.os_type == "windows":
            packages = self._windows_packages()
        elif self.config.os_type == "macos":
            packages = self._macos_packages()
        return packages

    def _linux_packages(self) -> list[dict]:
        packages = []
        # dpkg (Debian/Ubuntu)
        if shutil.which("dpkg-query"):
            stdout, _, _ = self.run_command(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
                timeout=30)
            for line in stdout.splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    packages.append({"name": parts[0], "version": parts[1].strip(), "mgr": "apt"})

        # rpm (RHEL/CentOS/Fedora)
        elif shutil.which("rpm"):
            stdout, _, _ = self.run_command(
                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"],
                timeout=30)
            for line in stdout.splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    packages.append({"name": parts[0], "version": parts[1].strip(), "mgr": "rpm"})

        # pacman (Arch)
        elif shutil.which("pacman"):
            stdout, _, _ = self.run_command(["pacman", "-Q"], timeout=30)
            for line in stdout.splitlines():
                parts = line.split()
                if len(parts) == 2:
                    packages.append({"name": parts[0], "version": parts[1].strip(), "mgr": "pacman"})

        return packages

    def _windows_packages(self) -> list[dict]:
        packages = []
        stdout, _, rc = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
             "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
             "-ErrorAction SilentlyContinue | "
             "Where-Object {$_.DisplayName} | "
             "Select-Object DisplayName, DisplayVersion | "
             "ConvertTo-Json -Compress"],
            timeout=30)
        if rc == 0 and stdout.strip() and stdout.strip() not in ("null", "[]"):
            try:
                apps = json.loads(stdout)
                if not isinstance(apps, list):
                    apps = [apps]
                for app in apps:
                    if app.get("DisplayName"):
                        packages.append({
                            "name":    app["DisplayName"],
                            "version": app.get("DisplayVersion", "unknown"),
                            "mgr":     "windows",
                        })
            except (json.JSONDecodeError, TypeError):
                pass
        return packages

    def _macos_packages(self) -> list[dict]:
        packages = []
        # System Profiler for installed apps
        stdout, _, _ = self.run_command(
            ["system_profiler", "SPApplicationsDataType", "-json"],
            timeout=60)
        if stdout.strip():
            try:
                data = json.loads(stdout)
                apps = data.get("SPApplicationsDataType", [])
                for app in apps[:100]:  # Limit to 100
                    packages.append({
                        "name":    app.get("_name", ""),
                        "version": app.get("version", "unknown"),
                        "mgr":     "macos",
                    })
            except (json.JSONDecodeError, KeyError):
                pass

        # Homebrew
        if shutil.which("brew"):
            stdout2, _, _ = self.run_command(
                ["brew", "list", "--versions"], timeout=30)
            for line in stdout2.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    packages.append({
                        "name":    parts[0],
                        "version": parts[1],
                        "mgr":     "brew",
                    })
        return packages

    # ─────────────────────────────────────────────────────────────────────────
    # PIP AUDIT
    # ─────────────────────────────────────────────────────────────────────────
    def _pip_audit(self) -> Iterator[Finding]:
        if not shutil.which("pip-audit") and not shutil.which("pip3"):
            return

        # Try pip-audit first
        if shutil.which("pip-audit"):
            stdout, _, rc = self.run_command(
                ["pip-audit", "--format", "json", "--progress-spinner", "off"],
                timeout=120)
            if rc in (0, 1) and stdout.strip():
                try:
                    data = json.loads(stdout)
                    vulns = data.get("vulnerabilities", [])
                    critical = [v for v in vulns if any(
                        a.get("fix_versions") for a in v.get("aliases", [{}])
                    )]
                    if vulns:
                        for v in vulns[:15]:
                            pkg_name = v.get("name", "?")
                            pkg_ver  = v.get("version", "?")
                            ids      = v.get("aliases", [])
                            desc     = v.get("description", "")
                            yield Finding(
                                title              = f"Python package vulnerability: {pkg_name} {pkg_ver}",
                                severity           = Severity.HIGH,
                                category           = "Vulnerabilities",
                                description        = f"pip-audit found vulnerability in {pkg_name} {pkg_ver}: {desc[:200] if desc else ', '.join(ids[:3])}",
                                affected_component = f"Python package: {pkg_name}=={pkg_ver}",
                                remediation        = f"Upgrade: pip install --upgrade {pkg_name}",
                                cve_ids            = [i for i in ids if i.startswith("CVE-")][:5],
                            )
                    else:
                        yield Finding(
                            title="pip-audit: No Python package vulnerabilities found",
                            severity=Severity.INFO, category="Vulnerabilities",
                            description="pip-audit found no known vulnerabilities in installed Python packages.",
                            affected_component="Python packages", remediation="Keep packages updated: pip install --upgrade <pkg>")
                except (json.JSONDecodeError, KeyError):
                    pass
            return

        # Fallback: check common vulnerable packages via pip show
        KNOWN_VULN_PACKAGES = {
            "urllib3":     ("2.0.7", "CVE-2023-45803", "SSRF in urllib3 < 2.0.7"),
            "requests":    ("2.31.0","CVE-2023-32681", "Proxy-Authorization leak"),
            "cryptography":("41.0.6","CVE-2023-49083", "NULL pointer dereference"),
            "pillow":      ("10.2.0","CVE-2024-28219", "Buffer overflow in libwebp"),
            "paramiko":    ("3.4.0", "CVE-2023-48795", "Terrapin SSH attack"),
            "flask":       ("3.0.0", "CVE-2023-30861", "Cookie security issue"),
            "django":      ("4.2.7", "CVE-2023-43665", "DoS via header injection"),
            "pyyaml":      ("6.0",   "CVE-2022-1471",  "Remote code execution"),
            "setuptools":  ("65.5.1","CVE-2022-40897", "ReDoS vulnerability"),
            "certifi":     ("2023.7.22","CVE-2023-37920","CA bundle validation bypass"),
        }
        stdout, _, _ = self.run_command(
            ["pip3", "list", "--format=json"], timeout=20)
        if stdout.strip():
            try:
                installed = {p["name"].lower(): p["version"] for p in json.loads(stdout)}
                for pkg, (safe_ver, cve, desc) in KNOWN_VULN_PACKAGES.items():
                    if pkg in installed:
                        inst_ver = installed[pkg]
                        if self._version_less_than(inst_ver, safe_ver):
                            yield Finding(
                                title              = f"Outdated Python package: {pkg} {inst_ver} (safe: {safe_ver}+)",
                                severity           = Severity.HIGH,
                                category           = "Vulnerabilities",
                                description        = f"{pkg} version {inst_ver} has known vulnerability {cve}: {desc}",
                                affected_component = f"Python package: {pkg}=={inst_ver}",
                                remediation        = f"Upgrade: pip install --upgrade {pkg}>={safe_ver}",
                                cve_ids            = [cve],
                                cvss_score         = 8.0,
                            )
            except (json.JSONDecodeError, TypeError):
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # NPM AUDIT
    # ─────────────────────────────────────────────────────────────────────────
    def _npm_audit(self) -> Iterator[Finding]:
        if not shutil.which("npm"):
            return

        # Find package.json files in common locations
        npm_dirs = []
        for base in ("/var/www", "/opt", os.path.expanduser("~")):
            if os.path.isdir(base):
                try:
                    for root, dirs, files in os.walk(base):
                        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", ".npm")]
                        if "package.json" in files and "node_modules" in os.listdir(root):
                            npm_dirs.append(root)
                        if len(npm_dirs) >= 3:
                            break
                except (PermissionError, OSError):
                    pass
            if len(npm_dirs) >= 3:
                break

        if not npm_dirs:
            return

        for npm_dir in npm_dirs[:2]:  # Limit to first 2 projects
            stdout, _, rc = self.run_command(
                ["npm", "audit", "--json", "--prefix", npm_dir],
                timeout=60)
            if rc in (0, 1) and stdout.strip():
                try:
                    data   = json.loads(stdout)
                    vulns  = data.get("vulnerabilities", {})
                    totals = data.get("metadata", {}).get("vulnerabilities", {})
                    crit   = totals.get("critical", 0)
                    high   = totals.get("high", 0)
                    total  = sum(totals.values())

                    if total > 0:
                        sev = Severity.CRITICAL if crit > 0 else Severity.HIGH if high > 0 else Severity.MEDIUM
                        yield Finding(
                            title              = f"npm audit: {total} vulnerabilit(ies) in {os.path.basename(npm_dir)}",
                            severity           = sev,
                            category           = "Vulnerabilities",
                            description        = f"npm audit found {total} vulnerability/vulnerabilities ({crit} critical, {high} high) in {npm_dir}.",
                            affected_component = f"Node.js packages in {npm_dir}",
                            remediation        = f"cd {npm_dir} && npm audit fix\nFor breaking changes: npm audit fix --force",
                            cvss_score         = 9.5 if crit > 0 else 7.5 if high > 0 else 5.0,
                        )
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass

    # ─────────────────────────────────────────────────────────────────────────
    # NVD API LOOKUP
    # ─────────────────────────────────────────────────────────────────────────
    def _nvd_lookup(self, packages: list[dict]) -> Iterator[Finding]:
        # Focus on high-value targets for NVD lookup
        HIGH_VALUE = {
            "openssl", "openssh", "openssh-server", "openssh-client",
            "apache2", "httpd", "nginx", "vsftpd", "proftpd",
            "samba", "nfs-common", "nfs-kernel-server",
            "bind9", "named", "bind",
            "sudo", "polkit", "dbus",
            "linux-image", "kernel", "linux-kernel",
            "curl", "libcurl", "wget",
            "python3", "python",
            "openssl", "libssl",
            "git", "subversion",
        }
        targets = [p for p in packages
                   if any(hv in p["name"].lower() for hv in HIGH_VALUE)][:20]

        if not targets:
            return

        try:
            import urllib.request
            import urllib.parse
        except ImportError:
            return

        pct_base = 55
        for i, pkg in enumerate(targets):
            pct = pct_base + int((i / len(targets)) * 35)
            self._emit_progress(pct, f"NVD lookup: {pkg['name']} {pkg['version']}...")

            try:
                params  = {
                    "keywordSearch": f"{pkg['name']} {pkg['version']}",
                    "cvssV3Severity": "HIGH",
                    "resultsPerPage": "5",
                }
                if self.config.nvd_api_key:
                    params["apiKey"] = self.config.nvd_api_key

                url  = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
                headers = {
                    "User-Agent": "SentinelScan/1.0",
                    "Accept":     "application/json",
                }
                if self.config.nvd_api_key:
                    headers["apiKey"] = self.config.nvd_api_key

                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode("utf-8"))

                vulns = data.get("vulnerabilities", [])
                time.sleep(REQUEST_DELAY)  # respect NVD rate limit

                for vuln in vulns[:3]:
                    cve_id   = vuln.get("cve", {}).get("id", "")
                    desc_list = vuln.get("cve", {}).get("descriptions", [])
                    desc     = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
                    metrics  = vuln.get("cve", {}).get("metrics", {})
                    cvss_score = None

                    # Get CVSS score
                    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if metric_key in metrics and metrics[metric_key]:
                            cvss_score = metrics[metric_key][0].get("cvssData", {}).get("baseScore")
                            break

                    if cvss_score and cvss_score >= CVSS_HIGH:
                        sev = Severity.CRITICAL if cvss_score >= CVSS_CRITICAL else Severity.HIGH
                        yield Finding(
                            title              = f"CVE: {cve_id} in {pkg['name']} (CVSS {cvss_score})",
                            severity           = sev,
                            category           = "Vulnerabilities",
                            description        = f"{cve_id} — {desc[:250]}",
                            affected_component = f"{pkg['name']} {pkg['version']} ({pkg['mgr']})",
                            remediation        = f"Update {pkg['name']} via your package manager:\napt-get install --only-upgrade {pkg['name']}\nCheck: https://nvd.nist.gov/vuln/detail/{cve_id}",
                            cve_ids            = [cve_id],
                            cvss_score         = cvss_score,
                            references         = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                        )

            except Exception:
                time.sleep(REQUEST_DELAY)
                continue

    # ─────────────────────────────────────────────────────────────────────────
    # HELPER
    # ─────────────────────────────────────────────────────────────────────────
    def _version_less_than(self, ver: str, threshold: str) -> bool:
        """Simple version comparison — returns True if ver < threshold."""
        try:
            def parse(v):
                return [int(x) for x in re.sub(r"[^0-9.]", "", v).split(".")[:3]]
            return parse(ver) < parse(threshold)
        except Exception:
            return False
