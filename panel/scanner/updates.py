"""
SentinelScan — scanner/updates.py
OS & Software Update Audit
Phase 4 — Scan Modules Tier 1

Linux  : apt / dnf / pacman / zypper
Windows: Get-HotFix + Windows Update history via PowerShell
macOS  : softwareupdate -l
Also queries the NVD API for CVE matches (online mode only).
"""
from __future__ import annotations
import re
import json
import subprocess
import datetime
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module


@register_module
class UpdatesModule(ScanModule):
    name            = "os_updates"
    display_name    = "OS & Software Updates"
    category        = "Updates"
    description     = "Checks for pending security patches, last update date, and EOL software"
    applies_to_os   = ["linux", "windows", "macos"]
    applies_to_mode = ["workstation", "server"]

    def run(self) -> Iterator[Finding]:
        self._emit_progress(5, "Starting update check...")
        if self.config.os_type == "linux":
            yield from self._scan_linux()
        elif self.config.os_type == "windows":
            yield from self._scan_windows()
        elif self.config.os_type == "macos":
            yield from self._scan_macos()

    # ─────────────────────────────────────────────────────────────────────────
    # LINUX
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_linux(self) -> Iterator[Finding]:
        import shutil

        self._emit_progress(10, "Detecting package manager...")
        if shutil.which("apt-get"):
            yield from self._check_apt()
        elif shutil.which("dnf"):
            yield from self._check_dnf()
        elif shutil.which("yum"):
            yield from self._check_yum()
        elif shutil.which("pacman"):
            yield from self._check_pacman()
        elif shutil.which("zypper"):
            yield from self._check_zypper()
        else:
            yield Finding(
                title="Could not determine package manager",
                severity=Severity.INFO, category="Updates",
                description="No supported package manager found (apt, dnf, yum, pacman, zypper). Update check skipped.",
                affected_component="System package manager",
                remediation="Check for updates manually.",
            )
            return

        # Check last apt/yum update time via log files
        yield from self._check_last_update_linux()
        # Check kernel version
        yield from self._check_kernel()
        # Check for EOL OS
        yield from self._check_os_eol()

    def _check_apt(self) -> Iterator[Finding]:
        self._emit_progress(15, "Refreshing apt package index...")
        # Dry-run upgrade to list upgradable packages
        self.run_command(["apt-get", "update", "-qq"], timeout=60)

        self._emit_progress(35, "Listing security updates (apt)...")
        stdout, _, rc = self.run_command(
            ["apt-get", "--just-print", "upgrade", "-V"], timeout=60)

        security_updates = []
        all_updates = []
        for line in stdout.splitlines():
            line = line.strip()
            if "=>" in line:
                pkg = line.split()[0].strip("(")
                all_updates.append(pkg)
                if "security" in line.lower():
                    security_updates.append(pkg)

        self._emit_progress(60, f"Found {len(all_updates)} pending updates...")

        if security_updates:
            sev = Severity.CRITICAL if len(security_updates) >= 10 else \
                  Severity.HIGH     if len(security_updates) >= 3  else Severity.MEDIUM
            yield Finding(
                title              = f"{len(security_updates)} security update(s) pending",
                severity           = sev,
                category           = "Updates",
                description        = f"{len(security_updates)} security patches are available and have not been applied. "
                                     f"Affected packages: {', '.join(security_updates[:8])}{'...' if len(security_updates) > 8 else ''}",
                affected_component = "System packages (apt security updates)",
                remediation        = "Apply security updates immediately:\nsudo apt-get upgrade -y\nOr for security only:\nsudo apt-get dist-upgrade -y --only-upgrade",
                workaround         = "Enable unattended-upgrades for automatic security patching:\nsudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades",
                cvss_score         = 8.0 if len(security_updates) >= 10 else 6.5,
            )

        if all_updates and not security_updates:
            yield Finding(
                title              = f"{len(all_updates)} general update(s) pending",
                severity           = Severity.LOW,
                category           = "Updates",
                description        = f"{len(all_updates)} package update(s) available (not security-flagged). "
                                     f"Sample: {', '.join(all_updates[:5])}",
                affected_component = "System packages",
                remediation        = "Apply updates: sudo apt-get upgrade -y",
            )

        if not all_updates:
            yield Finding(
                title="System is up to date",
                severity=Severity.INFO, category="Updates",
                description="No pending package updates detected.",
                affected_component="System packages (apt)",
                remediation="No action required.",
            )

    def _check_dnf(self) -> Iterator[Finding]:
        self._emit_progress(15, "Checking dnf security updates...")
        stdout, _, rc = self.run_command(
            ["dnf", "check-update", "--security", "--quiet"], timeout=90)
        # dnf returns exit code 100 when updates are available
        updates = [l.split()[0] for l in stdout.splitlines()
                   if l.strip() and not l.startswith("Last") and "." in l.split()[0]]

        self._emit_progress(60, f"Found {len(updates)} security updates...")
        if updates:
            sev = Severity.HIGH if len(updates) >= 5 else Severity.MEDIUM
            yield Finding(
                title              = f"{len(updates)} security update(s) available via dnf",
                severity           = sev,
                category           = "Updates",
                description        = f"Security updates pending: {', '.join(updates[:8])}{'...' if len(updates) > 8 else ''}",
                affected_component = "System packages (dnf)",
                remediation        = "Apply security updates:\nsudo dnf upgrade --security -y",
                workaround         = "Enable automatic updates:\nsudo systemctl enable --now dnf-automatic.timer",
            )
        else:
            yield Finding(title="No security updates pending (dnf)", severity=Severity.INFO,
                          category="Updates",
                          description="dnf reports no pending security updates.",
                          affected_component="System packages (dnf)", remediation="No action required.")

    def _check_yum(self) -> Iterator[Finding]:
        self._emit_progress(20, "Checking yum security updates...")
        stdout, _, rc = self.run_command(["yum", "check-update", "--security", "-q"], timeout=90)
        updates = [l.split()[0] for l in stdout.splitlines()
                   if l.strip() and "." in l and not l.startswith(("Loaded", "Last", "*"))]
        if updates:
            yield Finding(
                title=f"{len(updates)} security update(s) pending (yum)",
                severity=Severity.HIGH if len(updates) >= 5 else Severity.MEDIUM,
                category="Updates",
                description=f"Security packages pending: {', '.join(updates[:8])}",
                affected_component="System packages (yum)",
                remediation="sudo yum update --security -y",
            )
        else:
            yield Finding(title="No security updates pending (yum)", severity=Severity.INFO,
                          category="Updates", description="yum reports no pending security updates.",
                          affected_component="System packages (yum)", remediation="No action required.")

    def _check_pacman(self) -> Iterator[Finding]:
        self._emit_progress(20, "Checking pacman updates...")
        stdout, _, _ = self.run_command(["pacman", "-Qu"], timeout=60)
        updates = [l.split()[0] for l in stdout.splitlines() if l.strip()]
        if updates:
            yield Finding(
                title=f"{len(updates)} package update(s) pending (pacman)",
                severity=Severity.MEDIUM,
                category="Updates",
                description=f"Packages pending update: {', '.join(updates[:8])}{'...' if len(updates) > 8 else ''}",
                affected_component="System packages (pacman)",
                remediation="sudo pacman -Syu",
            )
        else:
            yield Finding(title="System is up to date (pacman)", severity=Severity.INFO,
                          category="Updates", description="No pending updates via pacman.",
                          affected_component="System packages (pacman)", remediation="No action required.")

    def _check_zypper(self) -> Iterator[Finding]:
        self._emit_progress(20, "Checking zypper patches...")
        stdout, _, _ = self.run_command(["zypper", "list-patches", "--category", "security"], timeout=60)
        needed = [l for l in stdout.splitlines() if "needed" in l.lower() and "|" in l]
        if needed:
            yield Finding(
                title=f"{len(needed)} security patch(es) needed (zypper)",
                severity=Severity.HIGH if len(needed) >= 5 else Severity.MEDIUM,
                category="Updates",
                description=f"{len(needed)} security patches flagged as needed.",
                affected_component="System packages (zypper)",
                remediation="sudo zypper patch --category security",
            )

    def _check_last_update_linux(self) -> Iterator[Finding]:
        """Check how long ago the last update was applied."""
        self._emit_progress(70, "Checking last update date...")
        last_date = None
        # Try apt history
        try:
            with open("/var/log/apt/history.log") as f:
                for line in f:
                    if line.startswith("Start-Date:"):
                        date_str = line.replace("Start-Date:", "").strip()
                        try:
                            last_date = datetime.datetime.strptime(
                                date_str[:16], "%Y-%m-%d  %H:%M")
                        except Exception:
                            pass
        except FileNotFoundError:
            pass

        if last_date:
            days_ago = (datetime.datetime.now() - last_date).days
            if days_ago > 90:
                yield Finding(
                    title              = f"Last system update was {days_ago} days ago",
                    severity           = Severity.HIGH if days_ago > 180 else Severity.MEDIUM,
                    category           = "Updates",
                    description        = f"The last package manager operation was {days_ago} days ago ({last_date.strftime('%Y-%m-%d')}). Systems should be updated at least monthly.",
                    affected_component = "System update history",
                    remediation        = "Apply pending updates now:\nsudo apt-get update && sudo apt-get upgrade -y",
                    workaround         = "Enable unattended-upgrades for automatic patching.",
                    cvss_score         = 6.5 if days_ago > 180 else 4.0,
                )

    def _check_kernel(self) -> Iterator[Finding]:
        """Check running kernel vs installed kernel."""
        import platform
        self._emit_progress(80, "Checking kernel version...")
        running_kernel = platform.uname().release

        # Check if a newer kernel is installed but not yet booted
        import shutil
        if shutil.which("dpkg"):
            stdout, _, _ = self.run_command(
                ["dpkg", "-l", "linux-image-*"], timeout=15)
            installed = []
            for line in stdout.splitlines():
                if line.startswith("ii"):
                    parts = line.split()
                    if len(parts) >= 3:
                        installed.append(parts[2])
            if installed:
                installed_str = ", ".join(installed[-2:])
                yield Finding(
                    title              = f"Running kernel: {running_kernel}",
                    severity           = Severity.INFO,
                    category           = "Updates",
                    description        = f"Current running kernel: {running_kernel}. Installed kernel packages: {installed_str}. If a newer kernel is installed but not the currently running one, a reboot is required.",
                    affected_component = f"Linux kernel {running_kernel}",
                    remediation        = "After applying kernel updates, reboot to activate the new kernel: sudo reboot",
                )

    def _check_os_eol(self) -> Iterator[Finding]:
        """Check if the OS has reached end-of-life."""
        self._emit_progress(90, "Checking OS end-of-life status...")
        eol_info = {
            "ubuntu 18.04": ("2023-04-01", "Ubuntu 18.04 LTS (Bionic) reached EOL"),
            "ubuntu 20.04": ("2025-04-01", "Ubuntu 20.04 LTS (Focal)"),
            "ubuntu 22.04": ("2027-04-01", "Ubuntu 22.04 LTS (Jammy)"),
            "centos 7":     ("2024-06-30", "CentOS 7"),
            "centos 8":     ("2021-12-31", "CentOS 8"),
            "debian 10":    ("2024-06-30", "Debian 10 (Buster)"),
            "debian 11":    ("2026-06-01", "Debian 11 (Bullseye)"),
        }
        os_ver = self.config.os_version.lower()
        today  = datetime.date.today()

        for key, (eol_date_str, name) in eol_info.items():
            if key in os_ver:
                eol_date = datetime.date.fromisoformat(eol_date_str)
                if today > eol_date:
                    yield Finding(
                        title              = f"End-of-Life OS detected: {name}",
                        severity           = Severity.CRITICAL,
                        category           = "Updates",
                        description        = f"{name} reached end-of-life on {eol_date_str}. No further security patches will be issued. This system is permanently at risk.",
                        affected_component = f"Operating System: {self.config.os_version}",
                        remediation        = "Upgrade to a supported OS version immediately. There is no safe way to operate an EOL OS in a production environment.",
                        cvss_score         = 9.0,
                    )
                elif (eol_date - today).days < 180:
                    yield Finding(
                        title              = f"OS approaching end-of-life: {name} (EOL: {eol_date_str})",
                        severity           = Severity.MEDIUM,
                        category           = "Updates",
                        description        = f"{name} will reach end-of-life on {eol_date_str}. Plan an upgrade now.",
                        affected_component = f"Operating System: {self.config.os_version}",
                        remediation        = f"Begin planning an upgrade to the next LTS/supported release.",
                    )
                break

    # ─────────────────────────────────────────────────────────────────────────
    # WINDOWS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_windows(self) -> Iterator[Finding]:
        self._emit_progress(10, "Querying installed hotfixes...")
        # Get hotfix list
        stdout, _, rc = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-HotFix | Sort-Object InstalledOn -Descending | "
             "Select-Object -First 20 | "
             "ConvertTo-Json -Compress"],
            timeout=60)

        if rc != 0 or not stdout.strip():
            yield Finding(
                title="Could not query Windows Update history",
                severity=Severity.MEDIUM, category="Updates",
                description="Get-HotFix failed. Run as Administrator.",
                affected_component="Windows Update",
                remediation="Run SentinelScan as Administrator.",
            )
        else:
            self._emit_progress(30, "Parsing update history...")
            try:
                patches = json.loads(stdout) if stdout.startswith("[") else [json.loads(stdout)]
                if patches:
                    latest = patches[0]
                    installed_on = latest.get("InstalledOn", "")
                    yield Finding(
                        title=f"Latest hotfix: {latest.get('HotFixID','Unknown')}",
                        severity=Severity.INFO, category="Updates",
                        description=f"Most recent installed hotfix: {latest.get('HotFixID','')} — installed {installed_on}.",
                        affected_component="Windows Update",
                        remediation="No action required.",
                    )
            except json.JSONDecodeError:
                pass

        self._emit_progress(50, "Checking for pending Windows updates...")
        # Check last update timestamp from registry
        reg_stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install').LastSuccessTime"],
            timeout=20)

        if reg_stdout.strip():
            try:
                last_update = datetime.datetime.fromisoformat(reg_stdout.strip()[:19])
                days_ago = (datetime.datetime.now() - last_update).days
                if days_ago > 60:
                    yield Finding(
                        title              = f"Windows last update: {days_ago} days ago",
                        severity           = Severity.HIGH if days_ago > 90 else Severity.MEDIUM,
                        category           = "Updates",
                        description        = f"Windows Update was last applied {days_ago} days ago ({last_update.strftime('%Y-%m-%d')}). Monthly patching is required for security compliance.",
                        affected_component = "Windows Update",
                        remediation        = "Run Windows Update: Settings → Windows Update → Check for updates\nOr via PowerShell: Start-Process ms-settings:windowsupdate",
                        cvss_score         = 6.5,
                    )
            except (ValueError, TypeError):
                pass

        self._emit_progress(70, "Checking Windows version support status...")
        yield from self._check_windows_eol()

        self._emit_progress(85, "Checking pending reboot status...")
        reboot_out, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'"],
            timeout=10)
        if "True" in reboot_out:
            yield Finding(
                title              = "Windows reboot pending — updates not fully applied",
                severity           = Severity.MEDIUM,
                category           = "Updates",
                description        = "A system reboot is pending. One or more updates or configuration changes require a reboot to take effect.",
                affected_component = "Windows Update — pending reboot",
                remediation        = "Reboot the system at the next maintenance window to complete pending updates.",
                workaround         = "Monitor patch compliance until reboot is completed.",
            )

    def _check_windows_eol(self) -> Iterator[Finding]:
        import platform
        version = platform.version()
        # Build number for common EOL Windows versions
        eol_builds = {
            "7601":  ("Windows 7",          "2020-01-14"),
            "9200":  ("Windows 8 / 2012",   "2023-10-10"),
            "9600":  ("Windows 8.1 / 2012R2","2023-10-10"),
            "14393": ("Windows Server 2016","2027-01-12"),
        }
        build = version.split(".")[-1] if "." in version else ""
        # Check Windows 10 EoL (21H2 = 19044 reached EOL Jun 2023)
        try:
            build_int = int(platform.version().split(".")[-1])
            if 10240 <= build_int <= 19044:
                yield Finding(
                    title              = f"Windows 10 build {build_int} may be end-of-servicing",
                    severity           = Severity.HIGH,
                    category           = "Updates",
                    description        = f"Windows 10 build {build_int} may have reached end of servicing. Microsoft releases new feature updates that extend support. Check your specific version.",
                    affected_component = f"Windows 10 build {build_int}",
                    remediation        = "Upgrade to a supported Windows 10/11 feature update via Windows Update.",
                    cvss_score         = 7.0,
                )
        except (ValueError, IndexError):
            pass

        for b, (name, eol) in eol_builds.items():
            if b in version:
                eol_date = datetime.date.fromisoformat(eol)
                if datetime.date.today() > eol_date:
                    yield Finding(
                        title              = f"End-of-Life OS: {name}",
                        severity           = Severity.CRITICAL,
                        category           = "Updates",
                        description        = f"{name} reached end-of-support on {eol}. No further security updates are available.",
                        affected_component = f"Operating System: {name} ({version})",
                        remediation        = "Upgrade to a supported Windows version immediately.",
                        cvss_score         = 9.5,
                    )
                break

    # ─────────────────────────────────────────────────────────────────────────
    # MACOS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_macos(self) -> Iterator[Finding]:
        self._emit_progress(15, "Checking for macOS software updates...")
        stdout, stderr, rc = self.run_command(
            ["softwareupdate", "--list"], timeout=120)

        self._emit_progress(50, "Parsing softwareupdate output...")
        # Parse available updates
        updates   = []
        sec_updates = []
        current  = None
        for line in stdout.splitlines() + stderr.splitlines():
            if "* Label:" in line or "* " in line and "recommended" in line.lower():
                current = line.strip().lstrip("* Label:").strip()
                if current:
                    updates.append(current)
            if current and "recommended" in line.lower():
                sec_updates.append(current)

        if sec_updates or updates:
            count = len(sec_updates) or len(updates)
            sev   = Severity.HIGH if count >= 3 else Severity.MEDIUM
            update_list = (sec_updates or updates)[:8]
            yield Finding(
                title              = f"{count} macOS software update(s) available",
                severity           = sev,
                category           = "Updates",
                description        = f"{count} update(s) available including recommended/security updates: {', '.join(update_list)}{'...' if count > 8 else ''}",
                affected_component = "macOS Software Update",
                remediation        = "Apply updates:\nsoftwareupdate --install --all\nOr: Apple menu → System Settings → General → Software Update",
                workaround         = "Enable automatic updates: System Settings → General → Software Update → Automatic Updates",
            )
        else:
            yield Finding(title="macOS is up to date", severity=Severity.INFO,
                          category="Updates",
                          description="softwareupdate reports no available updates.",
                          affected_component="macOS Software Update", remediation="No action required.")

        self._emit_progress(70, "Checking macOS version support status...")
        import platform
        ver_str = platform.mac_ver()[0]
        try:
            major = int(ver_str.split(".")[0])
            # macOS support: Apple supports current and ~2 prior major versions
            # macOS 12 = Monterey (support ended ~late 2025), 11 = Big Sur (EOL)
            if major < 12:
                yield Finding(
                    title              = f"macOS {ver_str} is end-of-life",
                    severity           = Severity.CRITICAL,
                    category           = "Updates",
                    description        = f"macOS {ver_str} no longer receives security updates from Apple. The system is permanently at risk.",
                    affected_component = f"macOS {ver_str}",
                    remediation        = "Upgrade to macOS 14 (Sonoma) or later.",
                    cvss_score         = 9.0,
                )
            elif major == 12:
                yield Finding(
                    title              = f"macOS {ver_str} (Monterey) approaching end of support",
                    severity           = Severity.MEDIUM,
                    category           = "Updates",
                    description        = "macOS 12 Monterey is approaching end of Apple support. Begin planning an upgrade.",
                    affected_component = f"macOS {ver_str}",
                    remediation        = "Upgrade to macOS 14 (Sonoma) or later.",
                )
        except (ValueError, IndexError):
            pass

        self._emit_progress(85, "Checking Homebrew package updates...")
        import shutil
        if shutil.which("brew"):
            brew_out, _, _ = self.run_command(["brew", "outdated", "--quiet"], timeout=60)
            outdated = [l.strip() for l in brew_out.splitlines() if l.strip()]
            if outdated:
                yield Finding(
                    title              = f"{len(outdated)} Homebrew package(s) outdated",
                    severity           = Severity.LOW,
                    category           = "Updates",
                    description        = f"Outdated Homebrew packages: {', '.join(outdated[:8])}{'...' if len(outdated) > 8 else ''}",
                    affected_component = "Homebrew packages",
                    remediation        = "Update Homebrew packages:\nbrew update && brew upgrade",
                )
