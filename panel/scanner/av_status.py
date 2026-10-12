"""
SentinelScan — scanner/av_status.py
Antivirus / EDR Status Audit
Phase 4 — Scan Modules Tier 1

Windows : Windows Defender via Get-MpComputerStatus + WMI Security Center
Linux   : ClamAV, rkhunter, chkrootkit status
macOS   : XProtect, Gatekeeper, MRT, and third-party AV via launchctl
"""
from __future__ import annotations
import datetime
import json
import re
import shutil
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module


@register_module
class AVStatusModule(ScanModule):
    name            = "av_status"
    display_name    = "Antivirus / EDR Status"
    category        = "AV / EDR"
    description     = "Checks antivirus and endpoint protection status, definition age, and real-time protection"
    applies_to_os   = ["linux", "windows", "macos"]
    applies_to_mode = ["workstation", "server"]

    def run(self) -> Iterator[Finding]:
        self._emit_progress(5, "Checking endpoint protection status...")
        if self.config.os_type == "windows":
            yield from self._scan_windows()
        elif self.config.os_type == "linux":
            yield from self._scan_linux()
        elif self.config.os_type == "macos":
            yield from self._scan_macos()

    # ─────────────────────────────────────────────────────────────────────────
    # WINDOWS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_windows(self) -> Iterator[Finding]:
        self._emit_progress(10, "Querying Windows Defender status...")
        yield from self._check_windows_defender()
        yield from self._check_wmi_security_center()
        yield from self._check_defender_exclusions()
        yield from self._check_tamper_protection()

    def _check_windows_defender(self) -> Iterator[Finding]:
        stdout, _, rc = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-MpComputerStatus | ConvertTo-Json -Compress"],
            timeout=30)

        if rc != 0 or not stdout.strip():
            yield Finding(
                title              = "Cannot query Windows Defender status",
                severity           = Severity.MEDIUM,
                category           = "AV / EDR",
                description        = "Get-MpComputerStatus failed. This may indicate Defender is not installed or the process lacks admin rights.",
                affected_component = "Windows Defender",
                remediation        = "Run SentinelScan as Administrator. Check that Windows Security Center is running.",
            )
            return

        try:
            d = json.loads(stdout)
        except json.JSONDecodeError:
            return

        self._emit_progress(35, "Analysing Defender state...")

        # Real-time protection
        rtp = d.get("RealTimeProtectionEnabled", False)
        if not rtp:
            yield Finding(
                title              = "Windows Defender: Real-Time Protection is DISABLED",
                severity           = Severity.CRITICAL,
                category           = "AV / EDR",
                description        = "Real-time malware protection is not active. Files, downloads, and processes are not being scanned.",
                affected_component = "Windows Defender — Real-Time Protection",
                remediation        = "Enable real-time protection:\nSet-MpPreference -DisableRealtimeMonitoring $false\nOr: Windows Security → Virus & Threat Protection → Real-time protection → On",
                cvss_score         = 8.5,
            )
        else:
            yield Finding(title="Windows Defender: Real-Time Protection ON",
                          severity=Severity.INFO, category="AV / EDR",
                          description="Real-time malware protection is active.",
                          affected_component="Windows Defender", remediation="No action required.")

        # Antivirus enabled
        av_enabled = d.get("AntivirusEnabled", False)
        if not av_enabled:
            yield Finding(
                title              = "Windows Defender antivirus is DISABLED",
                severity           = Severity.CRITICAL,
                category           = "AV / EDR",
                description        = "Windows Defender antivirus engine is disabled. The system has no active malware detection.",
                affected_component = "Windows Defender antivirus",
                remediation        = "Re-enable Defender:\nStart-Service WinDefend\nSet-MpPreference -DisableAntiSpyware $false",
                cvss_score         = 9.0,
            )

        # Definition update age
        sig_date_str = d.get("AntivirusSignatureLastUpdated", "")
        try:
            # PowerShell returns date as "/Date(timestamp)/" format
            match = re.search(r"/Date\((\d+)", sig_date_str)
            if match:
                ts = int(match.group(1)) / 1000
                sig_date = datetime.datetime.fromtimestamp(ts)
                days_old = (datetime.datetime.now() - sig_date).days
                if days_old > 7:
                    yield Finding(
                        title              = f"Defender definitions are {days_old} day(s) old",
                        severity           = Severity.HIGH if days_old > 14 else Severity.MEDIUM,
                        category           = "AV / EDR",
                        description        = f"Antivirus signature definitions were last updated {days_old} days ago ({sig_date.strftime('%Y-%m-%d')}). Definitions should be updated at least daily.",
                        affected_component = "Windows Defender — virus definitions",
                        remediation        = "Update definitions now:\nUpdate-MpSignature\nOr: Windows Security → Virus & Threat Protection → Check for updates",
                        workaround         = "Enable automatic Windows Update to keep definitions current.",
                        cvss_score         = 6.0 if days_old > 14 else 4.0,
                    )
                else:
                    yield Finding(title=f"Defender definitions up to date ({days_old} day(s) old)",
                                  severity=Severity.INFO, category="AV / EDR",
                                  description=f"Definitions last updated: {sig_date.strftime('%Y-%m-%d')}",
                                  affected_component="Windows Defender definitions",
                                  remediation="No action required.")
        except Exception:
            pass

        # Quick scan age
        last_scan_str = d.get("QuickScanAge", -1)
        try:
            scan_days = int(last_scan_str)
            if scan_days > 7:
                yield Finding(
                    title              = f"Last Defender quick scan was {scan_days} day(s) ago",
                    severity           = Severity.LOW,
                    category           = "AV / EDR",
                    description        = f"Windows Defender last performed a quick scan {scan_days} days ago. Weekly scans are recommended.",
                    affected_component = "Windows Defender — scheduled scans",
                    remediation        = "Trigger a scan: Start-MpScan -ScanType QuickScan\nEnable scheduled scans: Windows Security → Virus & Threat Protection → Scan options",
                )
        except (ValueError, TypeError):
            pass

        # AMSIEnabled
        amsi = d.get("AmsiBehaviorMonitorEnabled", True)
        if not amsi:
            yield Finding(
                title              = "AMSI (Anti-Malware Scan Interface) is disabled",
                severity           = Severity.HIGH,
                category           = "AV / EDR",
                description        = "AMSI provides in-memory scan coverage for scripting engines (PowerShell, VBScript). Disabling it is a common attacker technique.",
                affected_component = "Windows Defender AMSI",
                remediation        = "Re-enable AMSI via Group Policy or registry. Investigate why it was disabled.",
                cvss_score         = 7.5,
            )

    def _check_wmi_security_center(self) -> Iterator[Finding]:
        """Check Security Center for third-party AV products."""
        self._emit_progress(55, "Checking Security Center for third-party AV...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | "
             "Select-Object displayName,productState | ConvertTo-Json -Compress"],
            timeout=20)

        if stdout and stdout.strip() not in ("", "null"):
            try:
                products = json.loads(stdout)
                if not isinstance(products, list):
                    products = [products]
                av_names = [p.get("displayName", "Unknown") for p in products if p]
                if av_names:
                    yield Finding(
                        title              = f"AV products registered with Security Center: {', '.join(av_names)}",
                        severity           = Severity.INFO,
                        category           = "AV / EDR",
                        description        = f"The following antivirus products are registered: {', '.join(av_names)}. Verify they are current and active.",
                        affected_component = "Windows Security Center",
                        remediation        = "Verify each product is updated and real-time protection is enabled.",
                    )
            except json.JSONDecodeError:
                pass

    def _check_defender_exclusions(self) -> Iterator[Finding]:
        """Flag if Defender has exclusions set (potential blind spots)."""
        self._emit_progress(70, "Checking Defender exclusions...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-MpPreference).ExclusionPath | ConvertTo-Json -Compress"],
            timeout=15)
        if stdout.strip() and stdout.strip() not in ("null", "[]", '""'):
            try:
                exclusions = json.loads(stdout)
                if exclusions:
                    ex_list = exclusions if isinstance(exclusions, list) else [exclusions]
                    yield Finding(
                        title              = f"Windows Defender has {len(ex_list)} path exclusion(s)",
                        severity           = Severity.MEDIUM,
                        category           = "AV / EDR",
                        description        = f"Defender excludes the following paths from scanning: {', '.join(str(e) for e in ex_list[:5])}. Exclusions are a common attacker persistence technique.",
                        affected_component = "Windows Defender exclusions",
                        remediation        = "Review and minimise exclusions. Remove any non-essential paths:\nRemove-MpPreference -ExclusionPath '<path>'",
                        cvss_score         = 5.5,
                    )
            except (json.JSONDecodeError, TypeError):
                pass

    def _check_tamper_protection(self) -> Iterator[Finding]:
        """Check if Defender Tamper Protection is enabled."""
        self._emit_progress(80, "Checking Tamper Protection status...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-MpComputerStatus).IsTamperProtected"],
            timeout=15)
        if "False" in stdout:
            yield Finding(
                title              = "Windows Defender Tamper Protection is DISABLED",
                severity           = Severity.HIGH,
                category           = "AV / EDR",
                description        = "Tamper Protection prevents malware and attackers from disabling Windows Defender. Without it, malware can trivially turn off AV.",
                affected_component = "Windows Defender — Tamper Protection",
                remediation        = "Enable Tamper Protection: Windows Security → Virus & Threat Protection → Virus & threat protection settings → Tamper Protection → On",
                cvss_score         = 7.0,
            )

    # ─────────────────────────────────────────────────────────────────────────
    # LINUX
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_linux(self) -> Iterator[Finding]:
        self._emit_progress(10, "Checking Linux endpoint protection tools...")
        found_any = False

        # ClamAV
        if shutil.which("clamscan") or shutil.which("clamd"):
            found_any = True
            yield from self._check_clamav()

        # rkhunter
        if shutil.which("rkhunter"):
            found_any = True
            yield from self._check_rkhunter()

        # chkrootkit
        if shutil.which("chkrootkit"):
            found_any = True
            yield from self._check_chkrootkit()

        # AIDE (file integrity)
        if shutil.which("aide"):
            found_any = True
            yield Finding(title="AIDE file integrity monitor detected",
                          severity=Severity.INFO, category="AV / EDR",
                          description="AIDE (Advanced Intrusion Detection Environment) is installed for file integrity monitoring.",
                          affected_component="AIDE",
                          remediation="Ensure aide --check is run regularly. Consider adding to cron.")

        # Check for commercial EDR agents
        edr_procs = ["falcon-sensor", "cbdaemon", "elastic-agent", "osqueryd",
                     "wazuh-agent", "sentinelone", "cortex-xdr"]
        stdout, _, _ = self.run_command(["ps", "aux"], timeout=10)
        found_edr = [p for p in edr_procs if p in stdout]
        if found_edr:
            found_any = True
            yield Finding(
                title              = f"EDR/SIEM agent(s) detected: {', '.join(found_edr)}",
                severity           = Severity.INFO,
                category           = "AV / EDR",
                description        = f"Enterprise endpoint detection agents running: {', '.join(found_edr)}",
                affected_component = f"EDR agents: {', '.join(found_edr)}",
                remediation        = "Ensure agents are healthy and reporting to the management console.",
            )

        if not found_any:
            yield Finding(
                title              = "No antivirus or endpoint protection detected",
                severity           = Severity.HIGH,
                category           = "AV / EDR",
                description        = "No AV, rootkit scanner, or EDR agent was detected. Linux servers are targeted by malware and rootkits, particularly after a compromise.",
                affected_component = "Linux endpoint protection",
                remediation        = "Install ClamAV for on-demand scanning:\nsudo apt install clamav clamav-daemon\nAnd rkhunter for rootkit detection:\nsudo apt install rkhunter\nFor enterprise environments, deploy an EDR agent (Wazuh, Elastic, CrowdStrike Falcon).",
                cvss_score         = 7.0,
            )

    def _check_clamav(self) -> Iterator[Finding]:
        self._emit_progress(30, "Checking ClamAV status...")
        # Check freshclam / database age
        db_paths = [
            "/var/lib/clamav/main.cvd", "/var/lib/clamav/daily.cvd",
            "/var/lib/clamav/daily.cld", "/usr/share/clamav/main.cvd"
        ]
        import os
        db_found = False
        for db_path in db_paths:
            if os.path.exists(db_path):
                db_found = True
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(db_path))
                days_old = (datetime.datetime.now() - mtime).days
                if days_old > 3:
                    yield Finding(
                        title              = f"ClamAV virus database is {days_old} day(s) old",
                        severity           = Severity.MEDIUM if days_old <= 7 else Severity.HIGH,
                        category           = "AV / EDR",
                        description        = f"ClamAV database file {db_path} was last updated {days_old} days ago.",
                        affected_component = f"ClamAV database: {db_path}",
                        remediation        = "Update ClamAV signatures:\nsudo freshclam\nEnable automatic updates: sudo systemctl enable --now clamav-freshclam",
                    )
                else:
                    yield Finding(title=f"ClamAV database up to date ({days_old} day(s) old)",
                                  severity=Severity.INFO, category="AV / EDR",
                                  description=f"ClamAV signatures last updated {mtime.strftime('%Y-%m-%d')}.",
                                  affected_component="ClamAV", remediation="No action required.")
                break

        # Check if clamd daemon is running
        stdout, _, _ = self.run_command(["systemctl", "is-active", "clamav-daemon"], timeout=5)
        if stdout.strip().lower() != "active":
            yield Finding(
                title              = "ClamAV daemon (clamd) is not running",
                severity           = Severity.LOW,
                category           = "AV / EDR",
                description        = "ClamAV is installed but the daemon is not active. Real-time scanning is not available.",
                affected_component = "clamd service",
                remediation        = "Enable clamd:\nsudo systemctl enable --now clamav-daemon",
            )

    def _check_rkhunter(self) -> Iterator[Finding]:
        self._emit_progress(50, "Checking rkhunter database age...")
        import os
        db_path = "/var/lib/rkhunter/db/rkhunter.dat"
        if os.path.exists(db_path):
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(db_path))
            days_old = (datetime.datetime.now() - mtime).days
            if days_old > 30:
                yield Finding(
                    title              = f"rkhunter database is {days_old} day(s) old",
                    severity           = Severity.LOW,
                    category           = "AV / EDR",
                    description        = "rkhunter's rootkit detection database has not been updated recently.",
                    affected_component = "rkhunter database",
                    remediation        = "Update rkhunter:\nsudo rkhunter --update\nSchedule weekly: add 'rkhunter --update' to cron",
                )
            else:
                yield Finding(title=f"rkhunter database current ({days_old} day(s) old)",
                              severity=Severity.INFO, category="AV / EDR",
                              description="rkhunter database is up to date.",
                              affected_component="rkhunter", remediation="No action required.")

    def _check_chkrootkit(self) -> Iterator[Finding]:
        self._emit_progress(65, "Running chkrootkit scan (quick)...")
        stdout, _, rc = self.run_command(["chkrootkit", "-q"], timeout=60)
        infected = [l for l in stdout.splitlines() if "INFECTED" in l or "Possible" in l]
        if infected:
            yield Finding(
                title              = f"chkrootkit: {len(infected)} suspicious finding(s)",
                severity           = Severity.CRITICAL,
                category           = "AV / EDR",
                description        = f"chkrootkit detected potentially suspicious indicators: {'; '.join(infected[:3])}. Note: chkrootkit can produce false positives — verify manually.",
                affected_component = "System binaries / kernel (chkrootkit)",
                remediation        = "Boot from a trusted live USB and verify the file system independently. Compare checksums of suspicious binaries against known-good versions.",
                workaround         = "Isolate the system from the network pending investigation.",
                cvss_score         = 9.5,
            )
        elif rc == 0:
            yield Finding(title="chkrootkit: No infections detected",
                          severity=Severity.INFO, category="AV / EDR",
                          description="chkrootkit quick scan found no infected files.",
                          affected_component="chkrootkit", remediation="Run full scan periodically.")

    # ─────────────────────────────────────────────────────────────────────────
    # MACOS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_macos(self) -> Iterator[Finding]:
        self._emit_progress(10, "Checking macOS built-in security features...")
        yield from self._check_xprotect()
        yield from self._check_gatekeeper()
        yield from self._check_mrt()
        yield from self._check_macos_edr()

    def _check_xprotect(self) -> Iterator[Finding]:
        self._emit_progress(20, "Checking XProtect definition age...")
        import os
        xp_paths = [
            "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist",
            "/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist",
        ]
        for xp_path in xp_paths:
            if os.path.exists(xp_path):
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(xp_path))
                days_old = (datetime.datetime.now() - mtime).days
                if days_old > 30:
                    yield Finding(
                        title              = f"XProtect definitions are {days_old} day(s) old",
                        severity           = Severity.MEDIUM,
                        category           = "AV / EDR",
                        description        = f"macOS XProtect malware definitions were last updated {days_old} days ago. XProtect updates should be delivered automatically.",
                        affected_component = "XProtect (macOS built-in AV)",
                        remediation        = "Ensure automatic updates are enabled: System Settings → General → Software Update → Automatic Updates → Install Security Responses and System Files",
                    )
                else:
                    yield Finding(title=f"XProtect definitions current ({days_old} day(s) old)",
                                  severity=Severity.INFO, category="AV / EDR",
                                  description=f"XProtect last updated {mtime.strftime('%Y-%m-%d')}.",
                                  affected_component="XProtect", remediation="No action required.")
                return

        yield Finding(title="XProtect definition file not found",
                      severity=Severity.LOW, category="AV / EDR",
                      description="Could not locate XProtect definition file to check its age.",
                      affected_component="XProtect",
                      remediation="Run: softwareupdate --install-rosetta (or check SIP settings)")

    def _check_gatekeeper(self) -> Iterator[Finding]:
        self._emit_progress(45, "Checking Gatekeeper status...")
        stdout, _, _ = self.run_command(["spctl", "--status"], timeout=10)
        if "disabled" in stdout.lower():
            yield Finding(
                title              = "Gatekeeper is DISABLED",
                severity           = Severity.HIGH,
                category           = "AV / EDR",
                description        = "Gatekeeper prevents unsigned and unnotarised applications from running. Disabling it allows any software to execute without verification.",
                affected_component = "macOS Gatekeeper",
                remediation        = "Re-enable Gatekeeper:\nsudo spctl --master-enable\nOr: System Settings → Privacy & Security → Allow applications downloaded from: App Store and identified developers",
                cvss_score         = 7.5,
            )
        else:
            yield Finding(title="Gatekeeper is enabled",
                          severity=Severity.INFO, category="AV / EDR",
                          description="Gatekeeper enforces code signing for downloaded applications.",
                          affected_component="Gatekeeper", remediation="No action required.")

    def _check_mrt(self) -> Iterator[Finding]:
        """Check Malware Removal Tool (MRT) is present."""
        import os
        mrt_paths = [
            "/Library/Apple/System/Library/CoreServices/MRT.app",
            "/System/Library/CoreServices/MRT.app",
        ]
        self._emit_progress(65, "Checking MRT (Malware Removal Tool)...")
        for path in mrt_paths:
            if os.path.exists(path):
                yield Finding(title="MRT (Malware Removal Tool) is present",
                              severity=Severity.INFO, category="AV / EDR",
                              description="macOS MRT actively removes known malware when detected.",
                              affected_component="MRT", remediation="No action required.")
                return
        yield Finding(title="MRT not found at expected path",
                      severity=Severity.LOW, category="AV / EDR",
                      description="MRT.app not found. This may indicate SIP is modified or an unusual macOS installation.",
                      affected_component="MRT",
                      remediation="Check SIP status and run Software Update.")

    def _check_macos_edr(self) -> Iterator[Finding]:
        """Check for third-party AV/EDR agents."""
        self._emit_progress(80, "Checking for third-party security agents...")
        edr_indicators = {
            "com.crowdstrike.falcon.Agent":   "CrowdStrike Falcon",
            "com.carbonblack.daemon":         "VMware Carbon Black",
            "com.sentinelone.agent":          "SentinelOne",
            "com.cylance.CylanceSvc":         "Cylance",
            "com.elastic.agent":              "Elastic Agent",
            "com.jamf.management.daemon":     "Jamf MDM",
        }
        found_edr = []
        stdout, _, _ = self.run_command(
            ["launchctl", "list"], timeout=20)
        for identifier, product in edr_indicators.items():
            if identifier in stdout:
                found_edr.append(product)

        # Also check for ClamAV on macOS (via Homebrew)
        if shutil.which("clamscan"):
            found_edr.append("ClamAV")

        if found_edr:
            yield Finding(
                title              = f"Third-party security agent(s) active: {', '.join(found_edr)}",
                severity           = Severity.INFO,
                category           = "AV / EDR",
                description        = f"Detected: {', '.join(found_edr)}. Verify agents are healthy and up to date in their management consoles.",
                affected_component = f"Third-party EDR: {', '.join(found_edr)}",
                remediation        = "Check agent status in the respective management console.",
            )
        else:
            yield Finding(
                title              = "No third-party AV/EDR detected on macOS",
                severity           = Severity.MEDIUM,
                category           = "AV / EDR",
                description        = "No third-party antivirus or EDR agent was found. macOS has built-in protections (XProtect, Gatekeeper, MRT) but enterprise environments benefit from a managed EDR solution.",
                affected_component = "macOS endpoint protection",
                remediation        = "Consider deploying an EDR solution for managed endpoints: CrowdStrike Falcon, SentinelOne, Elastic Agent, or ClamAV for open-source coverage.",
            )
