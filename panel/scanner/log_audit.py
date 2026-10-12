"""
SentinelScan — scanner/log_audit.py
Security Event Log Audit
Phase 6 — Scan Modules Tier 3

Linux  : /var/log/auth.log, /var/log/secure, journalctl
Windows: Windows Event Log (Get-WinEvent) — IDs 4625, 4624, 4720, 4728, 4732, 4688
macOS  : /var/log/system.log + unified log (log show)

Looks back 24 hours by default (quick) or 7 days (full).
"""
from __future__ import annotations
import re
import datetime
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module

# Windows Event IDs of interest
WIN_EVENT_IDS = {
    4625: ("Failed logon",             "An account failed to log on"),
    4624: ("Successful logon",         "An account was successfully logged on"),
    4648: ("Explicit credential logon","Logon attempted using explicit credentials"),
    4720: ("Account created",          "A user account was created"),
    4722: ("Account enabled",          "A user account was enabled"),
    4723: ("Password change attempt",  "An attempt was made to change an account password"),
    4724: ("Password reset",           "An attempt was made to reset an account password"),
    4728: ("Added to global group",    "Member added to security-enabled global group"),
    4732: ("Added to local group",     "Member added to security-enabled local group"),
    4756: ("Added to universal group", "Member added to universal security group"),
    4688: ("Process creation",         "A new process has been created"),
    4697: ("Service installed",        "A service was installed in the system"),
    4698: ("Scheduled task created",   "A scheduled task was created"),
    4702: ("Scheduled task modified",  "A scheduled task was modified"),
    4719: ("Audit policy changed",     "System audit policy was changed"),
    4765: ("SID history added",        "SID History was added to an account"),
    7034: ("Service crashed",          "A service terminated unexpectedly"),
    7045: ("New service installed",    "A new service was installed"),
}

# Suspicious process names (Windows 4688 events)
SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "wce.exe", "fgdump.exe",
    "gsecdump.exe", "pwdump.exe", "quarks-pwdump.exe",
    "meterpreter", "empire", "cobalt", "cobaltstrike",
    "psexec.exe", "psexesvc.exe",
    "wmic.exe", "powershell.exe", "cmd.exe",  # flag high-frequency
    "net.exe", "net1.exe", "nltest.exe", "whoami.exe",
    "nmap.exe", "masscan.exe", "nc.exe", "ncat.exe",
}

# Failed login thresholds
BRUTE_FORCE_THRESHOLD_10MIN = 5
BRUTE_FORCE_THRESHOLD_1HR   = 20
BRUTE_FORCE_THRESHOLD_24HR  = 50


@register_module
class LogAuditModule(ScanModule):
    name             = "log_audit"
    display_name     = "Security Log Audit"
    category         = "Logs"
    description      = "Analyses security logs for failed logins, account changes, and suspicious activity"
    applies_to_os    = ["linux", "windows", "macos"]
    applies_to_mode  = ["workstation", "server"]

    def run(self) -> Iterator[Finding]:
        self._emit_progress(5, "Starting security log audit...")
        lookback_hours = 24 if self.config.default_scan_type == "quick" else 168  # 7 days

        if self.config.os_type == "linux":
            yield from self._scan_linux(lookback_hours)
        elif self.config.os_type == "windows":
            yield from self._scan_windows(lookback_hours)
        elif self.config.os_type == "macos":
            yield from self._scan_macos(lookback_hours)

    # ─────────────────────────────────────────────────────────────────────────
    # LINUX
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_linux(self, hours: int) -> Iterator[Finding]:
        yield from self._check_linux_auth_log(hours)
        yield from self._check_linux_sudo_log(hours)
        yield from self._check_linux_last_logins()
        yield from self._check_linux_wtmp_anomalies()

    def _check_linux_auth_log(self, hours: int) -> Iterator[Finding]:
        self._emit_progress(10, "Parsing authentication logs...")
        log_paths = [
            "/var/log/auth.log",
            "/var/log/secure",       # RHEL/CentOS
            "/var/log/audit/audit.log",
        ]
        log_path = next((p for p in log_paths if os.path.exists(p)), None)

        failed_users   = defaultdict(int)
        failed_ips     = defaultdict(int)
        root_attempts  = 0
        invalid_users  = []
        sudo_events    = []
        breakin_attempts = 0

        if log_path:
            # Use journalctl for structured data if available
            import shutil
            if shutil.which("journalctl"):
                stdout, _, _ = self.run_command(
                    ["journalctl", "-u", "ssh", "--since",
                     f"{hours} hours ago", "--no-pager", "-q"],
                    timeout=30)
            else:
                try:
                    # Read last portion of auth.log
                    stdout = self._read_recent_log(log_path, hours)
                except Exception:
                    stdout = ""

            self._emit_progress(25, "Analysing failed authentication events...")

            for line in stdout.splitlines():
                if "Failed password" in line or "authentication failure" in line.lower():
                    # Extract username
                    user_match = re.search(r"for (?:invalid user )?(\S+) from", line)
                    ip_match   = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                    if user_match:
                        user = user_match.group(1)
                        failed_users[user] += 1
                        if user == "root":
                            root_attempts += 1
                    if ip_match:
                        failed_ips[ip_match.group(1)] += 1

                if "Invalid user" in line:
                    user_match = re.search(r"Invalid user (\S+)", line)
                    if user_match:
                        invalid_users.append(user_match.group(1))

                if "POSSIBLE BREAK-IN ATTEMPT" in line:
                    breakin_attempts += 1

                if "sudo:" in line and ("COMMAND" in line or "sudo" in line.lower()):
                    cmd_match = re.search(r"COMMAND=(.+?)$", line)
                    if cmd_match:
                        sudo_events.append(cmd_match.group(1).strip()[:80])
        else:
            yield Finding(
                title              = "Authentication log not accessible",
                severity           = Severity.MEDIUM,
                category           = "Logs",
                description        = "Could not read authentication logs. Run with sudo for full log access.",
                affected_component = "/var/log/auth.log or /var/log/secure",
                remediation        = "Run SentinelScan with sudo: sudo ./launch.sh",
            )
            return

        self._emit_progress(40, "Generating log findings...")

        # Failed login summary
        total_failures = sum(failed_users.values())
        if total_failures > BRUTE_FORCE_THRESHOLD_24HR:
            top_ips = sorted(failed_ips.items(), key=lambda x: x[1], reverse=True)[:5]
            yield Finding(
                title              = f"High volume of failed SSH logins: {total_failures} in {hours}h",
                severity           = Severity.HIGH,
                category           = "Logs",
                description        = f"{total_failures} failed authentication attempts in the last {hours} hours. Top source IPs: {', '.join(f'{ip}({n})' for ip, n in top_ips)}. This indicates active brute-force or credential stuffing.",
                affected_component = "SSH authentication (auth.log)",
                remediation        = "Install fail2ban:\nsudo apt install fail2ban\nOr use firewall to block offending IPs:\nufw deny from <ip> to any port 22",
                workaround         = "Change SSH to a non-standard port as a temporary measure.",
                cvss_score         = 6.5,
            )

        # Root login attempts
        if root_attempts > 0:
            yield Finding(
                title              = f"{root_attempts} direct root SSH login attempt(s) in {hours}h",
                severity           = Severity.HIGH if root_attempts > 10 else Severity.MEDIUM,
                category           = "Logs",
                description        = f"{root_attempts} attempts to authenticate directly as root over SSH. Ensure PermitRootLogin is set to 'no' in sshd_config.",
                affected_component = "SSH root login (auth.log)",
                remediation        = "Set PermitRootLogin no in /etc/ssh/sshd_config\nRestart sshd: sudo systemctl restart sshd",
            )

        # Per-user brute force
        heavy_hitters = {u: c for u, c in failed_users.items() if c >= 10}
        if heavy_hitters:
            yield Finding(
                title              = f"Targeted brute-force against: {', '.join(heavy_hitters.keys())}",
                severity           = Severity.HIGH,
                category           = "Logs",
                description        = f"Specific accounts targeted heavily: {', '.join(f'{u}({c})' for u, c in heavy_hitters.items())}",
                affected_component = f"User accounts: {', '.join(heavy_hitters.keys())}",
                remediation        = "Ensure accounts have strong passwords. Consider account lockout policy via PAM:\nfaillog -m 5 -l 600 -u <username>",
            )

        # Unusual usernames attempted
        unique_invalid = list(set(invalid_users))[:10]
        if len(unique_invalid) > 5:
            yield Finding(
                title              = f"{len(set(invalid_users))} distinct invalid usernames tried (user enumeration)",
                severity           = Severity.MEDIUM,
                category           = "Logs",
                description        = f"Many non-existent usernames tried: {', '.join(unique_invalid[:8])}{'...' if len(unique_invalid) > 8 else ''}",
                affected_component = "SSH user enumeration (auth.log)",
                remediation        = "Enable fail2ban with the sshd jail. Use AllowUsers in sshd_config to limit valid users.",
            )

        # Break-in attempts
        if breakin_attempts > 0:
            yield Finding(
                title              = f"{breakin_attempts} 'POSSIBLE BREAK-IN ATTEMPT' log entr(ies)",
                severity           = Severity.HIGH,
                category           = "Logs",
                description        = "Syslog recorded POSSIBLE BREAK-IN ATTEMPT messages, typically caused by reverse DNS mismatch or failed authentication followed by connection reset.",
                affected_component = "auth.log — break-in detection",
                remediation        = "Investigate source IPs. Add IPs to fail2ban blocklist.",
            )

        # Sudo usage
        if len(sudo_events) > 50:
            yield Finding(
                title              = f"High sudo activity: {len(sudo_events)} sudo commands in {hours}h",
                severity           = Severity.LOW,
                category           = "Logs",
                description        = f"{len(sudo_events)} sudo commands executed. Sample: {'; '.join(sudo_events[:3])}",
                affected_component = "sudo activity (auth.log)",
                remediation        = "Review sudo usage is authorised. Consider using more restrictive sudo rules.",
            )

        if total_failures == 0 and root_attempts == 0:
            yield Finding(
                title              = f"No failed authentication events in last {hours}h",
                severity           = Severity.INFO,
                category           = "Logs",
                description        = f"Authentication logs show no failed login attempts in the last {hours} hours.",
                affected_component = log_path,
                remediation        = "No action required.",
            )

    def _check_linux_sudo_log(self, hours: int) -> Iterator[Finding]:
        self._emit_progress(55, "Checking sudo log for privilege escalations...")
        import shutil
        if not shutil.which("journalctl"):
            return
        stdout, _, _ = self.run_command(
            ["journalctl", "_COMM=sudo", "--since", f"{hours} hours ago",
             "--no-pager", "-q"],
            timeout=20)
        escalations = [l for l in stdout.splitlines() if "COMMAND" in l and "/bin/su" in l.lower()]
        if escalations:
            yield Finding(
                title              = f"{len(escalations)} sudo su / su - command(s) in {hours}h",
                severity           = Severity.MEDIUM,
                category           = "Logs",
                description        = f"sudo su or su - commands (shell escalations) found: {'; '.join(e[:80] for e in escalations[:3])}",
                affected_component = "sudo log — su escalations",
                remediation        = "Review if these escalations are authorised. Consider disabling sudo su if users should not need full shells.",
            )

    def _check_linux_last_logins(self) -> Iterator[Finding]:
        self._emit_progress(65, "Checking recent successful logins (last)...")
        stdout, _, _ = self.run_command(["last", "-n", "20", "-w"], timeout=10)
        unusual_logins = []
        for line in stdout.splitlines():
            if not line.strip() or line.startswith("wtmp"):
                continue
            # Flag logins from external IPs (not localhost)
            ip_match = re.search(r"\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s", line)
            if ip_match:
                ip = ip_match.group(1)
                if not ip.startswith(("127.", "10.", "192.168.", "172.")):
                    unusual_logins.append(line.strip()[:100])

        if unusual_logins:
            yield Finding(
                title              = f"{len(unusual_logins)} login(s) from external IP addresses",
                severity           = Severity.HIGH,
                category           = "Logs",
                description        = f"Successful logins from public IP addresses: {'; '.join(unusual_logins[:4])}",
                affected_component = "SSH login history (wtmp)",
                remediation        = "Verify each login is authorised. Consider restricting SSH to VPN/trusted IP ranges.",
                cvss_score         = 6.0,
            )

    def _check_linux_wtmp_anomalies(self) -> Iterator[Finding]:
        self._emit_progress(73, "Checking for wtmp/btmp anomalies...")
        import shutil
        if not shutil.which("lastb"):
            return
        stdout, _, _ = self.run_command(["lastb", "-n", "10", "-w"], timeout=10)
        bad_count = len([l for l in stdout.splitlines()
                         if l.strip() and not l.startswith("btmp")])
        if bad_count > 0:
            yield Finding(
                title              = f"{bad_count} bad login(s) in btmp (failed su/local logins)",
                severity           = Severity.LOW,
                category           = "Logs",
                description        = f"lastb shows {bad_count} failed local/su login attempts. These are separate from SSH failures.",
                affected_component = "/var/log/btmp",
                remediation        = "Review with: sudo lastb | head -20. Investigate root-targeted entries.",
            )

    def _read_recent_log(self, path: str, hours: int) -> str:
        """Read the last N bytes of a log file efficiently."""
        MAX_BYTES = 5 * 1024 * 1024  # 5MB
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                if size > MAX_BYTES:
                    f.seek(size - MAX_BYTES)
                return f.read().decode("utf-8", errors="replace")
        except (PermissionError, FileNotFoundError):
            return ""

    # ─────────────────────────────────────────────────────────────────────────
    # WINDOWS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_windows(self, hours: int) -> Iterator[Finding]:
        self._emit_progress(10, "Querying Windows Security event log...")
        since = (datetime.datetime.now() - datetime.timedelta(hours=hours)).strftime(
            "%Y-%m-%d %H:%M:%S")

        yield from self._windows_failed_logons(since, hours)
        yield from self._windows_account_changes(since, hours)
        yield from self._windows_new_services(since, hours)
        yield from self._windows_audit_policy_changes(since, hours)
        yield from self._windows_log_cleared(hours)

    def _windows_failed_logons(self, since: str, hours: int) -> Iterator[Finding]:
        self._emit_progress(20, "Checking failed logon events (4625)...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             f"$events = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625; StartTime='{since}'}} -ErrorAction SilentlyContinue; "
             "$events | Group-Object {$_.Properties[5].Value} | Sort-Object Count -Descending | "
             "Select-Object -First 10 Name, Count | ConvertTo-Json -Compress"],
            timeout=30)

        if stdout.strip() and stdout.strip() not in ("null", "[]"):
            try:
                groups = json.loads(stdout)
                if not isinstance(groups, list):
                    groups = [groups]
                total = sum(g.get("Count", 0) for g in groups)
                if total >= BRUTE_FORCE_THRESHOLD_24HR:
                    top = [f"{g.get('Name','?')}({g.get('Count',0)})" for g in groups[:5]]
                    yield Finding(
                        title              = f"{total} failed logon event(s) (Event 4625) in {hours}h",
                        severity           = Severity.HIGH if total >= 100 else Severity.MEDIUM,
                        category           = "Logs",
                        description        = f"{total} failed Windows logon events in the last {hours} hours. Top accounts targeted: {', '.join(top)}",
                        affected_component = "Windows Security Event Log — Event 4625",
                        remediation        = "Enable Account Lockout Policy:\nComputer Config → Windows Settings → Security Settings → Account Policies → Account Lockout Policy\nSet threshold: 5 attempts, lockout duration: 15 min",
                        cvss_score         = 6.5,
                    )
                elif total > 0:
                    yield Finding(
                        title              = f"{total} failed logon(s) in {hours}h",
                        severity           = Severity.LOW,
                        category           = "Logs",
                        description        = f"{total} failed Windows logon events — normal background level.",
                        affected_component = "Windows Security Event Log — Event 4625",
                        remediation        = "No immediate action required. Monitor for increases.",
                    )
                else:
                    yield Finding(title=f"No failed logon events in {hours}h", severity=Severity.INFO,
                                  category="Logs", description="Windows Security log shows no failed logons.",
                                  affected_component="Event 4625", remediation="No action required.")
            except (json.JSONDecodeError, TypeError):
                pass

    def _windows_account_changes(self, since: str, hours: int) -> Iterator[Finding]:
        self._emit_progress(40, "Checking account management events...")
        # New user accounts (4720), group membership changes (4728, 4732)
        for event_id, desc in [(4720, "user account created"), (4728, "added to admin group"),
                                (4732, "added to local group")]:
            stdout, _, _ = self.run_command(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-WinEvent -FilterHashtable @{{LogName='Security'; Id={event_id}; StartTime='{since}'}} "
                 f"-ErrorAction SilentlyContinue | Measure-Object).Count"],
                timeout=15)
            try:
                count = int(stdout.strip())
                if count > 0:
                    severity = Severity.HIGH if event_id in (4720, 4728) else Severity.MEDIUM
                    yield Finding(
                        title              = f"{count} Event {event_id} ({desc}) in {hours}h",
                        severity           = severity,
                        category           = "Logs",
                        description        = f"{count} '{desc}' event(s) recorded in the last {hours} hours. Verify these account changes were authorised.",
                        affected_component = f"Windows Security Event Log — Event {event_id}",
                        remediation        = f"Review in Event Viewer: Security log, filter for Event ID {event_id}.\nDisable unauthorised accounts: Disable-LocalUser -Name '<n>'",
                        cvss_score         = 7.5 if event_id in (4720, 4728) else 5.5,
                    )
            except (ValueError, TypeError):
                pass

    def _windows_new_services(self, since: str, hours: int) -> Iterator[Finding]:
        self._emit_progress(60, "Checking for new service installations (Event 7045)...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             f"Get-WinEvent -FilterHashtable @{{LogName='System'; Id=7045; StartTime='{since}'}} "
             f"-ErrorAction SilentlyContinue | Select-Object TimeCreated, "
             f"@{{N='ServiceName';E={{$_.Properties[0].Value}}}} | ConvertTo-Json -Compress"],
            timeout=15)
        if stdout.strip() and stdout.strip() not in ("null", "[]"):
            try:
                events = json.loads(stdout)
                if not isinstance(events, list):
                    events = [events]
                svcs = [e.get("ServiceName", "?") for e in events]
                yield Finding(
                    title              = f"{len(svcs)} new service(s) installed (Event 7045) in {hours}h",
                    severity           = Severity.HIGH,
                    category           = "Logs",
                    description        = f"New Windows services installed: {', '.join(svcs[:5])}. Service installation is a common persistence technique.",
                    affected_component = "Windows Event Log — Event 7045",
                    remediation        = "Verify each service is legitimate:\nGet-Service '<name>' | Select-Object *\nRemove if unauthorised: sc delete '<name>'",
                    cvss_score         = 7.5,
                )
            except (json.JSONDecodeError, TypeError):
                pass

    def _windows_audit_policy_changes(self, since: str, hours: int) -> Iterator[Finding]:
        self._emit_progress(75, "Checking for audit policy changes (Event 4719)...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4719; StartTime='{since}'}} "
             f"-ErrorAction SilentlyContinue | Measure-Object).Count"],
            timeout=10)
        try:
            count = int(stdout.strip())
            if count > 0:
                yield Finding(
                    title              = f"{count} audit policy change(s) (Event 4719) in {hours}h",
                    severity           = Severity.HIGH,
                    category           = "Logs",
                    description        = f"{count} audit policy change event(s) recorded. Attackers modify audit policies to hide their activities.",
                    affected_component = "Windows Security Event Log — Event 4719",
                    remediation        = "Review changes in Event Viewer. Restore audit policy via GPO.\n auditpol /set /category:* /success:enable /failure:enable",
                    cvss_score         = 8.0,
                )
        except (ValueError, TypeError):
            pass

    def _windows_log_cleared(self, hours: int) -> Iterator[Finding]:
        self._emit_progress(85, "Checking for event log clearing (Event 1102/104)...")
        for event_id, log in [(1102, "Security"), (104, "System")]:
            stdout, _, _ = self.run_command(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-WinEvent -FilterHashtable @{{LogName='{log}'; Id={event_id}}} "
                 f"-ErrorAction SilentlyContinue | Select-Object -First 5 | Measure-Object).Count"],
                timeout=10)
            try:
                count = int(stdout.strip())
                if count > 0:
                    yield Finding(
                        title              = f"Event log cleared {count} time(s): {log} log (Event {event_id})",
                        severity           = Severity.CRITICAL,
                        category           = "Logs",
                        description        = f"The {log} event log has been cleared {count} time(s). Attackers clear logs to remove evidence of compromise.",
                        affected_component = f"Windows {log} Event Log — Event {event_id}",
                        remediation        = "INCIDENT RESPONSE: Log clearing is a high-confidence indicator of compromise. Preserve remaining logs. Check for other indicators.",
                        cvss_score         = 9.0,
                    )
            except (ValueError, TypeError):
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # MACOS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_macos(self, hours: int) -> Iterator[Finding]:
        self._emit_progress(10, "Checking macOS security logs...")
        yield from self._macos_failed_logins(hours)
        yield from self._macos_sudo_log(hours)
        yield from self._macos_system_log(hours)

    def _macos_failed_logins(self, hours: int) -> Iterator[Finding]:
        self._emit_progress(20, "Parsing macOS authentication failures...")
        stdout, _, _ = self.run_command(
            ["log", "show", "--style", "syslog",
             "--predicate", "process == 'sshd' AND eventMessage CONTAINS 'Failed'",
             f"--last", f"{hours}h", "--info"],
            timeout=30)
        failures = [l for l in stdout.splitlines() if "Failed" in l]
        if len(failures) > BRUTE_FORCE_THRESHOLD_24HR:
            # Count IPs
            ip_counts: dict[str, int] = defaultdict(int)
            for line in failures:
                m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    ip_counts[m.group(1)] += 1
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            yield Finding(
                title              = f"{len(failures)} SSH authentication failures in {hours}h",
                severity           = Severity.HIGH,
                category           = "Logs",
                description        = f"{len(failures)} failed SSH authentications. Top source IPs: {', '.join(f'{ip}({n})' for ip, n in top_ips)}",
                affected_component = "macOS SSH authentication log",
                remediation        = "Install and configure fail2ban or BlockBlock.\nAlternatively restrict SSH source IPs in /etc/pf.conf.",
            )
        elif len(failures) > 0:
            yield Finding(
                title              = f"{len(failures)} SSH failure(s) in {hours}h",
                severity           = Severity.LOW,
                category           = "Logs",
                description        = "Low level of SSH authentication failures.",
                affected_component = "macOS SSH log",
                remediation        = "Monitor for increases. No immediate action required.",
            )
        else:
            yield Finding(title=f"No SSH failures in {hours}h", severity=Severity.INFO,
                          category="Logs", description="macOS SSH log shows no failed authentications.",
                          affected_component="macOS SSH", remediation="No action required.")

    def _macos_sudo_log(self, hours: int) -> Iterator[Finding]:
        self._emit_progress(50, "Checking macOS sudo activity...")
        stdout, _, _ = self.run_command(
            ["log", "show", "--style", "syslog",
             "--predicate", "process == 'sudo'",
             f"--last", f"{hours}h"],
            timeout=20)
        sudo_lines = [l for l in stdout.splitlines() if "COMMAND" in l]
        if len(sudo_lines) > 100:
            yield Finding(
                title              = f"High sudo activity: {len(sudo_lines)} commands in {hours}h",
                severity           = Severity.LOW,
                category           = "Logs",
                description        = f"{len(sudo_lines)} sudo commands in the last {hours} hours. Sample: {'; '.join(l[-60:] for l in sudo_lines[:3])}",
                affected_component = "macOS sudo log",
                remediation        = "Review sudo activity. Ensure all escalations are authorised.",
            )

    def _macos_system_log(self, hours: int) -> Iterator[Finding]:
        self._emit_progress(70, "Scanning macOS system log for anomalies...")
        SUSPICIOUS_PATTERNS = [
            "unauthorized", "kernel exploit", "privilege escalation",
            "rootkit", "malware", "segfault", "cannot execute",
        ]
        stdout, _, _ = self.run_command(
            ["log", "show", "--style", "syslog", "--level", "error",
             "--last", f"{hours}h", "--predicate",
             "eventMessage CONTAINS[c] 'error' OR eventMessage CONTAINS[c] 'denied'"],
            timeout=30)
        for pattern in SUSPICIOUS_PATTERNS:
            matches = [l for l in stdout.splitlines() if pattern.lower() in l.lower()]
            if matches:
                yield Finding(
                    title              = f"macOS system log: '{pattern}' appeared {len(matches)} time(s)",
                    severity           = Severity.MEDIUM,
                    category           = "Logs",
                    description        = f"System log entries containing '{pattern}': {matches[0][:120]}",
                    affected_component = "macOS unified log",
                    remediation        = f"Investigate: log show --predicate \"eventMessage CONTAINS '{pattern}'\" --last {hours}h",
                )
