"""
SentinelScan — scanner/hardening.py
OS Hardening & CIS Benchmark Audit
Phase 5 — Scan Modules Tier 2

Linux  : lynis --audit-system (if available) + direct sysctl/config checks
Windows: PowerShell security baseline — audit policy, NLA, SMBv1, AppLocker, etc.
macOS  : lynis + FileVault + screen lock + Gatekeeper + SIP + privacy controls
"""
from __future__ import annotations
import re
import os
import shutil
from pathlib import Path
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module


@register_module
class HardeningModule(ScanModule):
    name             = "hardening"
    display_name     = "Hardening Checks"
    category         = "Hardening"
    description      = "CIS Benchmark compliance, kernel parameters, login policy, and service hardening"
    applies_to_os    = ["linux", "windows", "macos"]
    applies_to_mode  = ["workstation", "server"]
    full_scan_only   = False

    def run(self) -> Iterator[Finding]:
        self._emit_progress(5, "Starting hardening audit...")
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
        if shutil.which("lynis"):
            yield from self._run_lynis()
        else:
            self._emit_progress(10, "lynis not found — running manual sysctl/config checks")

        yield from self._check_sysctl()
        yield from self._check_login_banner()
        yield from self._check_services()
        yield from self._check_auditd()
        yield from self._check_umask()
        yield from self._check_cron_permissions()
        yield from self._check_limits_conf()

    # ── lynis ─────────────────────────────────────────────────────────────────
    def _run_lynis(self) -> Iterator[Finding]:
        self._emit_progress(10, "Running lynis system audit (this may take a minute)...")
        stdout, stderr, rc = self.run_command(
            ["lynis", "audit", "system", "--quick", "--no-colors", "--quiet"],
            timeout=300)

        combined = stdout + stderr
        self._emit_progress(55, "Parsing lynis output...")

        # Extract warnings and suggestions from lynis output
        warnings    = re.findall(r"\[WARNING\]\s*(.+)", combined)
        suggestions = re.findall(r"Suggestion.*?:\s*(.+?)(?:\n|$)", combined, re.MULTILINE)
        hardening_idx_match = re.search(r"Hardening index\s*:\s*(\d+)", combined)
        hardening_idx = int(hardening_idx_match.group(1)) if hardening_idx_match else None

        if hardening_idx is not None:
            sev = Severity.HIGH   if hardening_idx < 50 else \
                  Severity.MEDIUM if hardening_idx < 70 else \
                  Severity.LOW    if hardening_idx < 85 else Severity.INFO
            yield Finding(
                title              = f"lynis Hardening Index: {hardening_idx}/100",
                severity           = sev,
                category           = "Hardening",
                description        = f"lynis system hardening score is {hardening_idx}/100. "
                                     f"{'Critical hardening gaps detected.' if hardening_idx < 50 else 'Improvements recommended.' if hardening_idx < 70 else 'System is reasonably hardened.' if hardening_idx < 85 else 'System is well hardened.'}",
                affected_component = "Overall system hardening (lynis)",
                remediation        = "Address lynis suggestions in order of priority. Re-run lynis after changes to track progress.",
            )

        # Map known lynis test IDs to better descriptions
        lynis_map = {
            "AUTH-9228": ("No password set for single-user mode", Severity.HIGH,
                          "Set root password: passwd root"),
            "AUTH-9308": ("No password aging configured", Severity.MEDIUM,
                          "Edit /etc/login.defs: PASS_MAX_DAYS 90"),
            "BOOT-5122": ("GRUB not password protected", Severity.MEDIUM,
                          "Set GRUB password: grub-mkpasswd-pbkdf2"),
            "KRNL-5820": ("core dumps not restricted", Severity.MEDIUM,
                          "Add to sysctl.conf: fs.suid_dumpable = 0"),
            "MAIL-8818": ("Postfix is not installed or configured", Severity.INFO,
                          "Install Postfix for local mail handling if required."),
            "NETW-3200": ("No active firewall detected", Severity.HIGH,
                          "sudo ufw enable or sudo systemctl enable --now firewalld"),
            "PKGS-7370": ("Vulnerable packages found", Severity.HIGH,
                          "sudo apt-get upgrade or dnf upgrade"),
            "STRG-1840": ("USB storage not disabled", Severity.LOW,
                          "Add to /etc/modprobe.d/blacklist.conf: blacklist usb-storage"),
        }

        for test_id, (desc, sev, fix) in lynis_map.items():
            if test_id in combined:
                yield Finding(
                    title              = f"lynis {test_id}: {desc}",
                    severity           = sev,
                    category           = "Hardening",
                    description        = f"lynis test {test_id} flagged: {desc}",
                    affected_component = f"lynis test {test_id}",
                    remediation        = fix,
                )

        # Emit top warnings as findings
        for w in warnings[:8]:
            w = w.strip()
            if w and len(w) > 5:
                yield Finding(
                    title              = f"lynis WARNING: {w[:80]}",
                    severity           = Severity.HIGH,
                    category           = "Hardening",
                    description        = f"lynis reported a warning: {w}",
                    affected_component = "lynis audit",
                    remediation        = "Review the full lynis report: sudo lynis audit system --report-file /tmp/lynis-report.dat",
                )

    # ── sysctl ────────────────────────────────────────────────────────────────
    def _check_sysctl(self) -> Iterator[Finding]:
        self._emit_progress(60, "Checking kernel sysctl parameters...")

        SYSCTL_CHECKS = [
            # (parameter, expected_value, severity, title, description, remediation)
            ("net.ipv4.ip_forward",             "0", Severity.MEDIUM,
             "IP forwarding is enabled",
             "IP forwarding allows the host to route packets between interfaces — a server acting as a router. Enable only if this is an intentional router/gateway.",
             "Disable: sysctl -w net.ipv4.ip_forward=0\nPersist: echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.conf"),

            ("net.ipv4.conf.all.send_redirects", "0", Severity.MEDIUM,
             "ICMP redirects are being sent",
             "Sending ICMP redirects exposes routing topology information and can be abused for man-in-the-middle attacks.",
             "echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf && sysctl -p"),

            ("net.ipv4.conf.all.accept_redirects", "0", Severity.MEDIUM,
             "ICMP redirects are accepted",
             "Accepting ICMP redirects can allow an attacker to redirect traffic through a malicious router.",
             "echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf && sysctl -p"),

            ("net.ipv4.conf.all.accept_source_route", "0", Severity.MEDIUM,
             "Source routing is accepted",
             "Source routing allows the sender to specify the route. This is rarely needed and is a vector for spoofing attacks.",
             "echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.conf && sysctl -p"),

            ("net.ipv4.tcp_syncookies",          "1", Severity.MEDIUM,
             "TCP SYN cookies are disabled",
             "SYN cookies protect against SYN flood denial-of-service attacks.",
             "echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.conf && sysctl -p"),

            ("kernel.randomize_va_space",         "2", Severity.HIGH,
             "ASLR (Address Space Layout Randomisation) is not fully enabled",
             "ASLR randomises memory addresses making exploitation significantly harder. Value 2 = full randomisation.",
             "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf && sysctl -p"),

            ("fs.suid_dumpable",                 "0", Severity.MEDIUM,
             "Core dumps from SUID programs are allowed",
             "Core dumps from SUID programs can contain sensitive data including credentials from memory.",
             "echo 'fs.suid_dumpable = 0' >> /etc/sysctl.conf && sysctl -p"),

            ("kernel.dmesg_restrict",            "1", Severity.LOW,
             "dmesg is readable by non-root users",
             "dmesg output can reveal kernel addresses, hardware info, and version details useful for exploitation.",
             "echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.conf && sysctl -p"),

            ("net.ipv6.conf.all.disable_ipv6",   None, Severity.INFO,
             "IPv6 status",
             "Check whether IPv6 is intentionally enabled or should be disabled.",
             "To disable: echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf"),
        ]

        for param, expected, sev, title, desc, fix in SYSCTL_CHECKS:
            if expected is None:
                continue
            stdout, _, rc = self.run_command(["sysctl", "-n", param], timeout=5)
            actual = stdout.strip()
            if rc == 0 and actual != expected:
                yield Finding(
                    title              = f"sysctl: {title} ({param}={actual}, expected={expected})",
                    severity           = sev,
                    category           = "Hardening",
                    description        = f"Kernel parameter {param} is set to {actual} but should be {expected}. {desc}",
                    affected_component = f"kernel sysctl — {param}",
                    remediation        = fix,
                )

    # ── Login banner ───────────────────────────────────────────────────────────
    def _check_login_banner(self) -> Iterator[Finding]:
        self._emit_progress(72, "Checking login banners...")
        banner_files = ["/etc/issue", "/etc/issue.net", "/etc/motd"]
        for bf in banner_files:
            try:
                content = Path(bf).read_text().strip()
                if not content or len(content) < 10:
                    yield Finding(
                        title              = f"Login banner is empty or missing: {bf}",
                        severity           = Severity.LOW,
                        category           = "Hardening",
                        description        = f"{bf} is empty. Pre-login banners are required by PCI-DSS, HIPAA, and most enterprise compliance frameworks to establish legal notice.",
                        affected_component = bf,
                        remediation        = f"Add an authorised-use-only notice to {bf}:\necho 'Authorised access only. All activity is monitored.' > {bf}",
                        workaround         = "Low priority for workstations; higher priority for servers.",
                    )
            except FileNotFoundError:
                pass

    # ── Services ──────────────────────────────────────────────────────────────
    def _check_services(self) -> Iterator[Finding]:
        self._emit_progress(78, "Checking unnecessary services...")
        RISKY_SERVICES = [
            ("xinetd",     Severity.HIGH,   "xinetd is a legacy super-server that manages many insecure services."),
            ("telnet",     Severity.CRITICAL,"Telnet service exposes cleartext credentials."),
            ("rsh",        Severity.CRITICAL,"rsh allows remote execution without encryption."),
            ("rlogin",     Severity.CRITICAL,"rlogin is an unencrypted remote login service."),
            ("rexec",      Severity.CRITICAL,"rexec executes remote commands without encryption."),
            ("tftp",       Severity.HIGH,   "TFTP has no authentication and transfers files in plaintext."),
            ("nis",        Severity.HIGH,   "NIS (YP) transmits user credentials in cleartext."),
            ("nfs-server", Severity.MEDIUM, "NFS server — ensure exports are restricted and no_root_squash is not set broadly."),
            ("vsftpd",     Severity.HIGH,   "FTP server transmits credentials in plaintext."),
            ("proftpd",    Severity.HIGH,   "FTP server transmits credentials in plaintext."),
            ("sendmail",   Severity.MEDIUM, "Sendmail is a legacy MTA with a long history of vulnerabilities."),
        ]
        for svc, sev, desc in RISKY_SERVICES:
            stdout, _, _ = self.run_command(
                ["systemctl", "is-active", svc], timeout=5)
            if stdout.strip().lower() == "active":
                yield Finding(
                    title              = f"Risky service is running: {svc}",
                    severity           = sev,
                    category           = "Hardening",
                    description        = f"Service '{svc}' is active. {desc}",
                    affected_component = f"systemd service: {svc}",
                    remediation        = f"Disable and stop the service:\nsudo systemctl disable --now {svc}",
                )

    # ── auditd ────────────────────────────────────────────────────────────────
    def _check_auditd(self) -> Iterator[Finding]:
        self._emit_progress(83, "Checking auditd...")
        stdout, _, _ = self.run_command(["systemctl", "is-active", "auditd"], timeout=5)
        if stdout.strip().lower() != "active":
            yield Finding(
                title              = "auditd is not running",
                severity           = Severity.MEDIUM,
                category           = "Hardening",
                description        = "The Linux audit daemon (auditd) is not active. auditd records security-relevant system events required for incident response and compliance.",
                affected_component = "auditd service",
                remediation        = "Enable auditd:\nsudo systemctl enable --now auditd\nConfigure rules in /etc/audit/rules.d/",
            )

        # Check audit rules exist
        rules_out, _, _ = self.run_command(["auditctl", "-l"], timeout=5)
        if not rules_out.strip() or "No rules" in rules_out:
            yield Finding(
                title              = "No auditd rules configured",
                severity           = Severity.MEDIUM,
                category           = "Hardening",
                description        = "auditd is installed but no audit rules are defined. Without rules, critical events (file access, privilege escalation, user creation) are not logged.",
                affected_component = "auditd rules",
                remediation        = "Add CIS-recommended rules:\nwget https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -O /etc/audit/rules.d/audit.rules\nsudo service auditd restart",
            )

    # ── umask ─────────────────────────────────────────────────────────────────
    def _check_umask(self) -> Iterator[Finding]:
        self._emit_progress(87, "Checking system umask...")
        stdout, _, _ = self.run_command(["bash", "-c", "umask"], timeout=5)
        umask = stdout.strip()
        if umask and umask not in ("0022", "0027", "0077", "022", "027", "077"):
            yield Finding(
                title              = f"System umask may be too permissive: {umask}",
                severity           = Severity.LOW,
                category           = "Hardening",
                description        = f"Default umask is {umask}. A umask of 0027 (rwxr-x---) or 0077 (rwx------) is recommended for security-sensitive systems.",
                affected_component = f"System umask: {umask}",
                remediation        = "Set in /etc/profile and /etc/bash.bashrc:\numask 027",
            )

    # ── /etc/cron permissions ─────────────────────────────────────────────────
    def _check_cron_permissions(self) -> Iterator[Finding]:
        self._emit_progress(90, "Checking cron directory permissions...")
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                     "/etc/cron.weekly", "/etc/crontab"]
        for cp in cron_dirs:
            if os.path.exists(cp):
                mode = oct(os.stat(cp).st_mode)[-3:]
                if mode[-1] not in ("0", "0"):
                    # World-writable check
                    if int(mode[-1]) & 2:
                        yield Finding(
                            title              = f"Cron path is world-writable: {cp} (mode {mode})",
                            severity           = Severity.HIGH,
                            category           = "Hardening",
                            description        = f"{cp} has world-writable permissions ({mode}). Any user can add or modify cron jobs to gain persistent code execution.",
                            affected_component = cp,
                            remediation        = f"Fix permissions:\nchmod 700 {cp}\nchown root:root {cp}",
                            cvss_score         = 7.8,
                        )

    # ── /etc/security/limits.conf ─────────────────────────────────────────────
    def _check_limits_conf(self) -> Iterator[Finding]:
        limits_path = "/etc/security/limits.conf"
        if not os.path.exists(limits_path):
            return
        content = Path(limits_path).read_text()
        if "core" not in content:
            yield Finding(
                title              = "Core dump limits not configured in limits.conf",
                severity           = Severity.LOW,
                category           = "Hardening",
                description        = "Core dump limits are not restricted in /etc/security/limits.conf. Core dumps can expose sensitive data.",
                affected_component = "/etc/security/limits.conf",
                remediation        = "Add to /etc/security/limits.conf:\n* hard core 0\n* soft core 0",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # WINDOWS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_windows(self) -> Iterator[Finding]:
        self._emit_progress(10, "Running Windows security baseline checks...")
        yield from self._check_smb_v1()
        yield from self._check_nla_rdp()
        yield from self._check_audit_policy()
        yield from self._check_windows_update_settings()
        yield from self._check_uac_settings()
        yield from self._check_powershell_version()
        yield from self._check_laps()
        yield from self._check_bitlocker()
        yield from self._check_windows_event_log_sizes()
        yield from self._check_screen_lock()
        yield from self._check_windows_defender_settings()

    def _check_smb_v1(self) -> Iterator[Finding]:
        self._emit_progress(15, "Checking SMBv1 status...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-SmbServerConfiguration).EnableSMB1Protocol"],
            timeout=15)
        if "True" in stdout:
            yield Finding(
                title              = "SMBv1 is ENABLED",
                severity           = Severity.CRITICAL,
                category           = "Hardening",
                description        = "SMBv1 is the protocol exploited by EternalBlue/WannaCry. It must be disabled on all systems.",
                affected_component = "Windows SMBv1 protocol",
                remediation        = "Disable SMBv1 immediately:\nSet-SmbServerConfiguration -EnableSMB1Protocol $false -Force\nAlso via Group Policy: Computer Configuration → Administrative Templates → Network → Lanman Workstation",
                cvss_score         = 9.8,
                cve_ids            = ["CVE-2017-0144", "CVE-2017-0145"],
            )
        else:
            yield Finding(title="SMBv1 is disabled", severity=Severity.INFO,
                          category="Hardening",
                          description="SMBv1 (EternalBlue vector) is correctly disabled.",
                          affected_component="Windows SMBv1", remediation="No action required.")

    def _check_nla_rdp(self) -> Iterator[Finding]:
        self._emit_progress(22, "Checking RDP Network Level Authentication...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthenticationRequired"],
            timeout=10)
        val = stdout.strip()
        if val == "0":
            yield Finding(
                title              = "RDP: Network Level Authentication (NLA) is DISABLED",
                severity           = Severity.HIGH,
                category           = "Hardening",
                description        = "NLA requires authentication before the RDP session is fully established, protecting against pre-auth exploits like BlueKeep.",
                affected_component = "RDP — NLA (UserAuthenticationRequired)",
                remediation        = "Enable NLA via Registry:\nSet-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' UserAuthenticationRequired 1\nOr: Computer Properties → Remote → Allow connections only from computers running Remote Desktop with Network Level Authentication",
                cvss_score         = 7.5,
                cve_ids            = ["CVE-2019-0708"],
            )

    def _check_audit_policy(self) -> Iterator[Finding]:
        self._emit_progress(30, "Checking Windows audit policy...")
        stdout, _, _ = self.run_command(
            ["auditpol", "/get", "/category:*"], timeout=15)
        if not stdout:
            return
        no_auditing = []
        for line in stdout.splitlines():
            if "No Auditing" in line and ":" in line:
                category = line.split(":")[0].strip()
                if category and category not in ("Setting Value", "System", ""):
                    no_auditing.append(category)

        important = ["Logon", "Account Logon", "Object Access", "Privilege Use",
                     "Policy Change", "Account Management"]
        missing = [c for c in no_auditing if any(i in c for i in important)]

        if missing:
            yield Finding(
                title              = f"Audit policy disabled for: {', '.join(missing[:4])}",
                severity           = Severity.HIGH,
                category           = "Hardening",
                description        = f"No Auditing is configured for critical categories: {', '.join(missing)}. Without audit logging, attacks and policy violations go undetected.",
                affected_component = "Windows Audit Policy",
                remediation        = "Configure via Group Policy: Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration\nOr command line: auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
            )

    def _check_windows_update_settings(self) -> Iterator[Finding]:
        self._emit_progress(38, "Checking Windows Update configuration...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -ErrorAction SilentlyContinue).NoAutoUpdate"],
            timeout=10)
        if stdout.strip() == "1":
            yield Finding(
                title              = "Automatic Windows Updates are DISABLED via Group Policy",
                severity           = Severity.HIGH,
                category           = "Hardening",
                description        = "A Group Policy setting is blocking automatic Windows Updates. Security patches will not be applied automatically.",
                affected_component = "Windows Update — Group Policy",
                remediation        = "Review Group Policy: gpedit.msc → Computer Configuration → Administrative Templates → Windows Components → Windows Update → Configure Automatic Updates",
            )

    def _check_uac_settings(self) -> Iterator[Finding]:
        self._emit_progress(44, "Checking UAC configuration...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA"],
            timeout=10)
        if stdout.strip() == "0":
            yield Finding(
                title              = "User Account Control (UAC) is DISABLED",
                severity           = Severity.CRITICAL,
                category           = "Hardening",
                description        = "UAC is disabled. All processes run with full administrative privileges without prompting. This eliminates a critical defence against privilege escalation.",
                affected_component = "Windows UAC (User Account Control)",
                remediation        = "Enable UAC:\nSet-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1\nReboot required.",
                cvss_score         = 8.0,
            )

        # Check UAC prompt level (should not be 0 = no prompt)
        prompt_out, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').ConsentPromptBehaviorAdmin"],
            timeout=10)
        if prompt_out.strip() == "0":
            yield Finding(
                title              = "UAC set to 'Elevate without prompting' for admins",
                severity           = Severity.HIGH,
                category           = "Hardening",
                description        = "UAC consent prompt for administrators is set to 0 (no prompt). Admin applications silently elevate, removing a key audit trail.",
                affected_component = "Windows UAC — ConsentPromptBehaviorAdmin",
                remediation        = "Set to prompt for credentials (value 1):\nSet-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' ConsentPromptBehaviorAdmin 1",
            )

    def _check_powershell_version(self) -> Iterator[Finding]:
        self._emit_progress(50, "Checking PowerShell version and logging...")
        # Check if PS v2 is available (security concern — bypasses constrained language mode)
        ps2_out, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue).State"],
            timeout=20)
        if "Enabled" in ps2_out:
            yield Finding(
                title              = "PowerShell v2 engine is ENABLED",
                severity           = Severity.HIGH,
                category           = "Hardening",
                description        = "PowerShell v2 is enabled and can be used to bypass security controls like Script Block Logging, AMSI, and Constrained Language Mode by downgrading: powershell -Version 2",
                affected_component = "PowerShell v2 Windows Feature",
                remediation        = "Disable PS v2:\nDisable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root",
                cvss_score         = 7.5,
            )

        # Check Script Block Logging
        sbl_out, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging"],
            timeout=10)
        if sbl_out.strip() != "1":
            yield Finding(
                title              = "PowerShell Script Block Logging is disabled",
                severity           = Severity.MEDIUM,
                category           = "Hardening",
                description        = "Script Block Logging records all PowerShell code that executes, including obfuscated/decoded scripts. It is essential for detecting malicious PowerShell activity.",
                affected_component = "PowerShell Script Block Logging",
                remediation        = "Enable via Group Policy: Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging\nOr registry: Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' EnableScriptBlockLogging 1",
            )

    def _check_laps(self) -> Iterator[Finding]:
        self._emit_progress(58, "Checking LAPS deployment...")
        laps_out, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-Command Get-LapsADPassword -ErrorAction SilentlyContinue"],
            timeout=10)
        laps_reg, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Test-Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd'"],
            timeout=10)
        if "False" in laps_reg and not laps_out.strip():
            yield Finding(
                title              = "LAPS (Local Administrator Password Solution) not detected",
                severity           = Severity.MEDIUM,
                category           = "Hardening",
                description        = "LAPS automatically manages unique local administrator passwords per machine, preventing lateral movement via shared local admin credentials.",
                affected_component = "Windows LAPS",
                remediation        = "Deploy Microsoft LAPS from the Microsoft Download Center or enable Windows LAPS (built into Windows 11/Server 2022):\nhttps://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview",
            )

    def _check_bitlocker(self) -> Iterator[Finding]:
        self._emit_progress(64, "Checking BitLocker status...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "manage-bde -status C: 2>$null | Select-String 'Protection Status'"],
            timeout=20)
        if stdout and "Protection On" not in stdout:
            yield Finding(
                title              = "BitLocker is NOT enabled on drive C:",
                severity           = Severity.HIGH if self.config.default_scan_mode == "workstation" else Severity.MEDIUM,
                category           = "Hardening",
                description        = "BitLocker full-disk encryption is not active on the system drive. Physical theft or forensic access exposes all data.",
                affected_component = "BitLocker — drive C:",
                remediation        = "Enable BitLocker:\nEnable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly\nStore recovery key in Active Directory.",
                cvss_score         = 7.5,
            )

    def _check_windows_event_log_sizes(self) -> Iterator[Finding]:
        self._emit_progress(72, "Checking event log retention settings...")
        logs_to_check = {
            "Security":    100 * 1024 * 1024,   # 100 MB minimum
            "Application": 50  * 1024 * 1024,
            "System":      50  * 1024 * 1024,
        }
        for log_name, min_size in logs_to_check.items():
            stdout, _, _ = self.run_command(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-EventLog -List | Where-Object {{$_.Log -eq '{log_name}'}}).MaximumKilobytes * 1024"],
                timeout=10)
            try:
                current = int(stdout.strip())
                if current < min_size:
                    yield Finding(
                        title              = f"Event Log '{log_name}' size too small: {current // 1024 // 1024}MB (min {min_size // 1024 // 1024}MB)",
                        severity           = Severity.LOW,
                        category           = "Hardening",
                        description        = f"The {log_name} event log is configured to only {current // 1024 // 1024}MB. Logs may be overwritten before incidents are investigated.",
                        affected_component = f"Windows Event Log — {log_name}",
                        remediation        = f"Increase log size:\nLimit-EventLog -LogName {log_name} -MaximumSize {min_size // 1024}KB",
                    )
            except ValueError:
                pass

    def _check_screen_lock(self) -> Iterator[Finding]:
        self._emit_progress(80, "Checking screen lock policy...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop').ScreenSaveTimeOut"],
            timeout=10)
        try:
            timeout_secs = int(stdout.strip())
            if timeout_secs > 900 or timeout_secs == 0:
                yield Finding(
                    title              = f"Screen lock timeout is too long or disabled ({timeout_secs}s)",
                    severity           = Severity.MEDIUM,
                    category           = "Hardening",
                    description        = f"Screen saver/lock timeout is set to {timeout_secs} seconds ({timeout_secs // 60} min). Recommended maximum is 15 minutes for workstations.",
                    affected_component = "Windows screen lock policy",
                    remediation        = "Set screen lock via Group Policy:\nComputer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Interactive Logon: Machine Inactivity Limit = 900",
                )
        except (ValueError, TypeError):
            pass

    def _check_windows_defender_settings(self) -> Iterator[Finding]:
        self._emit_progress(88, "Checking additional Defender settings...")
        cloud_out, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-MpPreference).MAPSReporting"],
            timeout=10)
        if cloud_out.strip() == "0":
            yield Finding(
                title              = "Windows Defender cloud-based protection is disabled",
                severity           = Severity.MEDIUM,
                category           = "Hardening",
                description        = "Cloud-delivered protection provides near-real-time detection of new threats. Disabling it reduces detection capability.",
                affected_component = "Windows Defender cloud protection (MAPS)",
                remediation        = "Enable cloud protection:\nSet-MpPreference -MAPSReporting Advanced",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # MACOS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_macos(self) -> Iterator[Finding]:
        self._emit_progress(10, "Running macOS hardening checks...")
        if shutil.which("lynis"):
            yield from self._run_lynis()
        yield from self._check_filevault()
        yield from self._check_macos_screen_lock()
        yield from self._check_macos_firewall_stealth()
        yield from self._check_macos_remote_services()
        yield from self._check_macos_sharing()
        yield from self._check_macos_privacy()

    def _check_filevault(self) -> Iterator[Finding]:
        self._emit_progress(30, "Checking FileVault status...")
        stdout, _, _ = self.run_command(["fdesetup", "status"], timeout=10)
        if "Off" in stdout or "disabled" in stdout.lower():
            yield Finding(
                title              = "FileVault disk encryption is DISABLED",
                severity           = Severity.HIGH,
                category           = "Hardening",
                description        = "FileVault is not enabled. All data on disk is unencrypted. Physical theft provides immediate access to all data.",
                affected_component = "macOS FileVault",
                remediation        = "Enable FileVault:\nsudo fdesetup enable\nOr: System Settings → Privacy & Security → FileVault → Turn On\nStore recovery key securely.",
                cvss_score         = 7.5,
            )
        else:
            yield Finding(title="FileVault is enabled", severity=Severity.INFO,
                          category="Hardening",
                          description="Full-disk encryption (FileVault) is active.",
                          affected_component="FileVault", remediation="No action required.")

    def _check_macos_screen_lock(self) -> Iterator[Finding]:
        self._emit_progress(45, "Checking screen lock settings...")
        stdout, _, _ = self.run_command(
            ["defaults", "read", "com.apple.screensaver", "idleTime"], timeout=5)
        try:
            idle_secs = int(stdout.strip())
            if idle_secs == 0 or idle_secs > 900:
                yield Finding(
                    title              = f"Screen lock idle time is {idle_secs}s ({idle_secs // 60} min)",
                    severity           = Severity.MEDIUM,
                    category           = "Hardening",
                    description        = "Screen lock timeout is too long or disabled. Unattended machines can be accessed physically.",
                    affected_component = "macOS screensaver idle time",
                    remediation        = "Reduce idle time:\ndefaults write com.apple.screensaver idleTime 600\nOr: System Settings → Screen Saver → Start after: 10 minutes",
                )
        except (ValueError, TypeError):
            pass

        # Check require password immediately
        pw_delay, _, _ = self.run_command(
            ["defaults", "read", "com.apple.screensaver", "askForPasswordDelay"], timeout=5)
        try:
            delay = int(pw_delay.strip())
            if delay > 0:
                yield Finding(
                    title              = f"Password not required immediately on wake (delay: {delay}s)",
                    severity           = Severity.MEDIUM,
                    category           = "Hardening",
                    description        = "macOS allows access without password for a period after screen lock activates.",
                    affected_component = "macOS screen lock — askForPasswordDelay",
                    remediation        = "Set immediate password requirement:\ndefaults write com.apple.screensaver askForPasswordDelay 0",
                )
        except (ValueError, TypeError):
            pass

    def _check_macos_firewall_stealth(self) -> Iterator[Finding]:
        pass  # Covered in firewall.py

    def _check_macos_remote_services(self) -> Iterator[Finding]:
        self._emit_progress(60, "Checking remote access services...")
        services = {
            "com.apple.screensharing":  ("Screen Sharing", Severity.HIGH),
            "com.apple.RemoteDesktop":  ("Apple Remote Desktop", Severity.HIGH),
            "com.apple.tftpd":          ("TFTP daemon", Severity.CRITICAL),
            "com.apple.telnetd":        ("Telnet daemon", Severity.CRITICAL),
            "com.apple.ftpd":           ("FTP daemon", Severity.HIGH),
        }
        stdout, _, _ = self.run_command(["launchctl", "list"], timeout=15)
        for svc_id, (name, sev) in services.items():
            if svc_id in stdout:
                yield Finding(
                    title              = f"Remote service active: {name}",
                    severity           = sev,
                    category           = "Hardening",
                    description        = f"The {name} service is running. Disable if not required.",
                    affected_component = f"launchd: {svc_id}",
                    remediation        = f"Disable in System Settings → Sharing\nOr: launchctl unload -w /System/Library/LaunchDaemons/{svc_id}.plist",
                )

    def _check_macos_sharing(self) -> Iterator[Finding]:
        self._emit_progress(75, "Checking macOS sharing preferences...")
        sharing_prefs = {
            "com.apple.smb.server.preferences": ("SMB File Sharing", Severity.MEDIUM),
        }
        for plist, (name, sev) in sharing_prefs.items():
            stdout, _, _ = self.run_command(
                ["defaults", "read", f"/Library/Preferences/{plist}", "NetBIOSName"],
                timeout=5)
            if stdout.strip() and "does not exist" not in stdout:
                yield Finding(
                    title              = f"macOS {name} is enabled",
                    severity           = sev,
                    category           = "Hardening",
                    description        = f"{name} is active. Disable if not required for network file sharing.",
                    affected_component = f"macOS {name}",
                    remediation        = f"Disable in System Settings → General → Sharing → {name} → Off",
                )

    def _check_macos_privacy(self) -> Iterator[Finding]:
        self._emit_progress(87, "Checking macOS diagnostic data settings...")
        stdout, _, _ = self.run_command(
            ["defaults", "read", "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist",
             "AutoSubmit"], timeout=5)
        # Just report as informational
        yield Finding(
            title              = "macOS diagnostic data submission check",
            severity           = Severity.INFO,
            category           = "Hardening",
            description        = "Review System Settings → Privacy & Security → Analytics & Improvements to ensure diagnostic data sharing aligns with your privacy policy.",
            affected_component = "macOS Privacy — diagnostics",
            remediation        = "Disable analytics: System Settings → Privacy & Security → Analytics & Improvements → uncheck all options.",
        )
