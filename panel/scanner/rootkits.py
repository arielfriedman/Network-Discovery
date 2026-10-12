"""
SentinelScan — scanner/rootkits.py
Rootkit Detection & Persistence Audit
Phase 5 — Scan Modules Tier 2

Linux  : rkhunter --check, chkrootkit, hidden processes (/proc),
         unusual kernel modules, unexpected LD_PRELOAD, /proc/net anomalies
macOS  : LaunchAgents/Daemons persistence, hidden files, kernel extensions,
         unexpected startup items
Windows: Autoruns via PowerShell, suspicious scheduled tasks, hidden services,
         unusual startup registry keys, DLL hijacking indicators
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module


@register_module
class RootkitModule(ScanModule):
    name             = "rootkits"
    display_name     = "Rootkit & Persistence Detection"
    category         = "Rootkits"
    description      = "Detects rootkits, hidden processes, and suspicious persistence mechanisms"
    applies_to_os    = ["linux", "windows", "macos"]
    applies_to_mode  = ["workstation", "server"]

    # Known-safe kernel modules (won't flag these)
    KNOWN_MODULES = {
        "ext4", "xfs", "btrfs", "vfat", "iso9660", "nfs", "cifs",
        "virtio_net", "virtio_blk", "virtio_scsi", "vmw_vmci",
        "nvidia", "nouveau", "i915", "amdgpu", "radeon",
        "e1000", "e1000e", "igb", "ixgbe", "r8169", "rtl8xxxu",
        "usbhid", "hid_generic", "bluetooth", "bnep",
        "dm_mod", "dm_crypt", "md_mod", "raid1", "raid5",
        "tcp_cubic", "tcp_bbr", "iptable_filter", "nf_conntrack",
        "overlay", "br_netfilter", "veth", "dummy", "tun", "tap",
        "vboxdrv", "vboxnetflt", "vmhgfs", "vmxnet3",
    }

    def run(self) -> Iterator[Finding]:
        self._emit_progress(5, "Starting rootkit detection...")
        if self.config.os_type == "linux":
            yield from self._scan_linux()
        elif self.config.os_type == "macos":
            yield from self._scan_macos()
        elif self.config.os_type == "windows":
            yield from self._scan_windows()

    # ─────────────────────────────────────────────────────────────────────────
    # LINUX
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_linux(self) -> Iterator[Finding]:
        yield from self._rkhunter_scan()
        yield from self._chkrootkit_scan()
        yield from self._check_hidden_processes()
        yield from self._check_kernel_modules()
        yield from self._check_ld_preload()
        yield from self._check_proc_net_anomalies()
        yield from self._check_cron_persistence()
        yield from self._check_rc_local()
        yield from self._check_systemd_persistence()

    # ── rkhunter ──────────────────────────────────────────────────────────────
    def _rkhunter_scan(self) -> Iterator[Finding]:
        import shutil
        if not shutil.which("rkhunter"):
            yield Finding(title="rkhunter not installed",
                          severity=Severity.INFO, category="Rootkits",
                          description="rkhunter is not installed. Install it for rootkit detection.",
                          affected_component="rkhunter",
                          remediation="sudo apt install rkhunter  or  sudo dnf install rkhunter")
            return

        self._emit_progress(10, "Running rkhunter check (this may take a moment)...")
        stdout, stderr, rc = self.run_command(
            ["rkhunter", "--check", "--skip-keypress", "--report-warnings-only",
             "--disable SUSPSCAN,HIDDEN_PROCS,DELETED_FILES,PACKET_CAP_LIB",
             "--rwo"],
            timeout=300)

        combined = stdout + stderr
        self._emit_progress(35, "Parsing rkhunter output...")

        warnings   = re.findall(r"Warning:\s*(.+)", combined)
        found_rootkits = re.findall(r"Rootkit '([^']+)'.+?: (?:INFECTED|Found)", combined, re.IGNORECASE)

        if found_rootkits:
            yield Finding(
                title              = f"rkhunter: ROOTKIT DETECTED — {', '.join(found_rootkits)}",
                severity           = Severity.CRITICAL,
                category           = "Rootkits",
                description        = f"rkhunter has detected indicators of rootkit(s): {', '.join(found_rootkits)}. This is a serious security incident.",
                affected_component = "System binaries / kernel",
                remediation        = "IMMEDIATE ACTION REQUIRED:\n1. Isolate this system from the network NOW\n2. Boot from a trusted live USB\n3. Verify system binaries using known-good checksums\n4. Preserve forensic evidence before remediation\n5. Rebuild from a known-good image",
                workaround         = "Do not trust any tool running on a potentially compromised system.",
                cvss_score         = 10.0,
            )

        for w in warnings[:10]:
            w = w.strip()
            if not w or len(w) < 5:
                continue
            # Filter out known-false positives
            if any(fp in w.lower() for fp in ["prelink", "hidden_procs", "suspscan"]):
                continue
            yield Finding(
                title              = f"rkhunter warning: {w[:80]}",
                severity           = Severity.HIGH,
                category           = "Rootkits",
                description        = f"rkhunter reported: {w}",
                affected_component = "rkhunter check",
                remediation        = "Investigate with: sudo rkhunter --check --rwo\nUpdate DB: sudo rkhunter --update\nVerify false positive: sudo rkhunter --propupd (only after confirming file is legitimate)",
            )

        if not warnings and not found_rootkits:
            yield Finding(title="rkhunter: No warnings or rootkit indicators",
                          severity=Severity.INFO, category="Rootkits",
                          description="rkhunter completed with no warnings.",
                          affected_component="rkhunter", remediation="Keep rkhunter updated: sudo rkhunter --update")

    # ── chkrootkit ────────────────────────────────────────────────────────────
    def _chkrootkit_scan(self) -> Iterator[Finding]:
        import shutil
        if not shutil.which("chkrootkit"):
            return

        self._emit_progress(40, "Running chkrootkit...")
        stdout, _, rc = self.run_command(["chkrootkit"], timeout=120)
        infected = [l.strip() for l in stdout.splitlines()
                    if ("INFECTED" in l or "Suspect" in l or "Vulnerable" in l)
                    and "nothing found" not in l.lower()
                    and "not infected" not in l.lower()]

        if infected:
            yield Finding(
                title              = f"chkrootkit: {len(infected)} suspicious indicator(s)",
                severity           = Severity.CRITICAL,
                category           = "Rootkits",
                description        = f"chkrootkit detected suspicious indicators: {'; '.join(infected[:4])}. Note: chkrootkit can produce false positives on modern kernels — cross-validate with rkhunter.",
                affected_component = "System binaries (chkrootkit)",
                remediation        = "Cross-validate with rkhunter. If confirmed: isolate, preserve forensics, rebuild from trusted image.",
                cvss_score         = 9.5,
            )

    # ── Hidden processes ──────────────────────────────────────────────────────
    def _check_hidden_processes(self) -> Iterator[Finding]:
        self._emit_progress(50, "Checking for hidden processes via /proc...")
        # Compare ps output with /proc directory entries
        stdout, _, _ = self.run_command(["ps", "-eo", "pid"], timeout=10)
        ps_pids = set()
        for line in stdout.splitlines():
            line = line.strip()
            if line.isdigit():
                ps_pids.add(int(line))

        # Get PIDs from /proc
        try:
            proc_pids = set()
            for entry in os.scandir("/proc"):
                if entry.name.isdigit():
                    proc_pids.add(int(entry.name))

            # PIDs in /proc but not in ps could indicate hidden processes
            hidden_candidates = proc_pids - ps_pids
            # Filter out kernel threads (typically < 10 PID offset noise)
            suspicious = [p for p in hidden_candidates if p > 2]

            if len(suspicious) > 5:
                yield Finding(
                    title              = f"{len(suspicious)} potential hidden process(es) detected",
                    severity           = Severity.HIGH,
                    category           = "Rootkits",
                    description        = f"Processes visible in /proc but not in ps output: {suspicious[:8]}. This can indicate a rootkit hiding running processes, though some discrepancy is normal due to short-lived processes.",
                    affected_component = "/proc vs ps output comparison",
                    remediation        = "Investigate specific PIDs: ls -la /proc/<pid>/ && cat /proc/<pid>/cmdline\nRun rkhunter and check dmesg for anomalies.",
                    cvss_score         = 7.5,
                )
        except (PermissionError, FileNotFoundError):
            pass

    # ── Kernel modules ────────────────────────────────────────────────────────
    def _check_kernel_modules(self) -> Iterator[Finding]:
        self._emit_progress(57, "Checking kernel modules for suspicious entries...")
        stdout, _, _ = self.run_command(["lsmod"], timeout=10)
        suspicious_mods = []

        # Patterns that suggest malicious or uncommon modules
        suspicious_patterns = [
            r"^hide_", r"^hid[a-z]{1,3}$", r"^r?kit", r"^bd_",
            r"diamorphine", r"reptile", r"azazel", r"necurs",
        ]
        for line in stdout.splitlines()[1:]:  # Skip header
            mod_name = line.split()[0].lower() if line.split() else ""
            if not mod_name:
                continue
            for pattern in suspicious_patterns:
                if re.match(pattern, mod_name):
                    suspicious_mods.append(mod_name)
                    break

        if suspicious_mods:
            yield Finding(
                title              = f"Suspicious kernel module(s) detected: {', '.join(suspicious_mods)}",
                severity           = Severity.CRITICAL,
                category           = "Rootkits",
                description        = f"Loaded kernel modules matching known rootkit/backdoor names: {', '.join(suspicious_mods)}. Kernel-level rootkits have full system access.",
                affected_component = "Linux kernel modules",
                remediation        = "CRITICAL: This may indicate a kernel-level compromise.\n1. Isolate system immediately\n2. Boot from live USB\n3. Perform forensic analysis\n4. Rebuild from known-good image",
                cvss_score         = 10.0,
            )

        # Also check for modules in unusual locations
        stdout2, _, _ = self.run_command(
            ["find", "/dev", "/tmp", "/var/tmp", "-name", "*.ko", "-type", "f"],
            timeout=15)
        if stdout2.strip():
            mods = [l.strip() for l in stdout2.splitlines() if l.strip()]
            yield Finding(
                title              = f"Kernel module file(s) found in non-standard location(s): {', '.join(mods)}",
                severity           = Severity.CRITICAL,
                category           = "Rootkits",
                description        = f".ko kernel module files in unexpected locations: {', '.join(mods)}. Legitimate kernel modules are in /lib/modules/.",
                affected_component = "Kernel module files",
                remediation        = "Investigate and remove if malicious. These should not exist in /dev, /tmp, or /var/tmp.",
                cvss_score         = 9.0,
            )

    # ── LD_PRELOAD ────────────────────────────────────────────────────────────
    def _check_ld_preload(self) -> Iterator[Finding]:
        self._emit_progress(63, "Checking LD_PRELOAD and /etc/ld.so.preload...")
        preload_path = "/etc/ld.so.preload"
        if os.path.exists(preload_path):
            try:
                content = Path(preload_path).read_text().strip()
                if content:
                    libs = [l.strip() for l in content.splitlines() if l.strip()]
                    yield Finding(
                        title              = f"/etc/ld.so.preload has {len(libs)} entr(ies): {', '.join(libs)}",
                        severity           = Severity.CRITICAL,
                        category           = "Rootkits",
                        description        = f"/etc/ld.so.preload forces shared libraries to be loaded into EVERY process. This is a common rootkit persistence mechanism. Libraries: {', '.join(libs)}",
                        affected_component = "/etc/ld.so.preload",
                        remediation        = "Investigate each library immediately:\nfile {lib}\nldd {lib}\nls -la {lib}\nIf not legitimate: remove from /etc/ld.so.preload and delete the file.",
                        cvss_score         = 9.8,
                    )
            except PermissionError:
                pass

    # ── /proc/net anomalies ───────────────────────────────────────────────────
    def _check_proc_net_anomalies(self) -> Iterator[Finding]:
        self._emit_progress(70, "Checking for unexpected network listeners...")
        stdout, _, _ = self.run_command(
            ["ss", "-tlnp"], timeout=10)
        # Look for listeners on unusual ports bound to all interfaces
        unusual_ports = []
        for line in stdout.splitlines():
            if "LISTEN" not in line:
                continue
            # Extract port
            m = re.search(r":(\d+)\s", line)
            if m:
                port = int(m.group(1))
                # Flag high ports on all interfaces that aren't common service ports
                if port > 10000 and "0.0.0.0" in line or ":::*" in line:
                    if port not in {27017, 9200, 5432, 3306, 6379}:
                        unusual_ports.append(port)

        if unusual_ports:
            yield Finding(
                title              = f"Unusual high-port listeners bound to all interfaces: {', '.join(str(p) for p in unusual_ports[:6])}",
                severity           = Severity.MEDIUM,
                category           = "Rootkits",
                description        = f"Network services listening on high ports (>10000) bound to all interfaces: {unusual_ports[:6]}. Investigate whether these are authorised.",
                affected_component = "Network listeners",
                remediation        = "Investigate with: lsof -i :<port>  or  ss -tlnp | grep :<port>\nKill or restrict if unauthorised.",
            )

    # ── Cron persistence ──────────────────────────────────────────────────────
    def _check_cron_persistence(self) -> Iterator[Finding]:
        self._emit_progress(75, "Checking crontabs for suspicious entries...")
        cron_locations = [
            "/var/spool/cron/crontabs",
            "/var/spool/cron",
            "/etc/cron.d",
        ]
        SUSPICIOUS_PATTERNS = [
            r"base64\s+-d",
            r"python.*-c.*exec",
            r"perl.*-e",
            r"ruby.*-e",
            r"bash\s+-i",
            r"nc\s+-e",
            r"wget\s+.*(sh|bash|py|pl)\s*\|",
            r"curl\s+.*\|\s*(bash|sh)",
            r"/tmp/",
            r"/dev/shm/",
        ]
        suspicious_crons = []
        for base in cron_locations:
            if not os.path.isdir(base):
                continue
            try:
                for entry in os.scandir(base):
                    try:
                        content = Path(entry.path).read_text(errors="replace")
                        for pattern in SUSPICIOUS_PATTERNS:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                suspicious_crons.append(f"{entry.path}: {matches[0][:60]}")
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                continue

        if suspicious_crons:
            yield Finding(
                title              = f"{len(suspicious_crons)} suspicious cron entr(ies) detected",
                severity           = Severity.CRITICAL,
                category           = "Rootkits",
                description        = f"Crontab entries with suspicious patterns (base64 decode, reverse shells, downloading scripts): {'; '.join(suspicious_crons[:3])}",
                affected_component = "System crontabs",
                remediation        = "Immediately investigate and remove suspicious entries.\ncrontab -e (for user crons)\nReview /etc/cron.d/ contents.\nConsider this a potential active incident.",
                cvss_score         = 9.5,
            )

    # ── /etc/rc.local ─────────────────────────────────────────────────────────
    def _check_rc_local(self) -> Iterator[Finding]:
        rc_path = "/etc/rc.local"
        if not os.path.exists(rc_path):
            return
        try:
            content = Path(rc_path).read_text()
            real_lines = [l for l in content.splitlines()
                          if l.strip() and not l.strip().startswith("#")
                          and l.strip() != "exit 0"]
            if real_lines:
                yield Finding(
                    title              = f"/etc/rc.local contains {len(real_lines)} command(s)",
                    severity           = Severity.MEDIUM,
                    category           = "Rootkits",
                    description        = f"/etc/rc.local runs commands at boot. Entries: {'; '.join(real_lines[:3])}",
                    affected_component = "/etc/rc.local",
                    remediation        = "Review /etc/rc.local. Remove any entries that are not explicitly authorised startup commands.",
                )
        except PermissionError:
            pass

    # ── Systemd persistence ───────────────────────────────────────────────────
    def _check_systemd_persistence(self) -> Iterator[Finding]:
        self._emit_progress(82, "Checking systemd units for persistence...")
        suspicious_unit_dirs = [
            "/etc/systemd/system",
            "/usr/local/lib/systemd/system",
            "/run/systemd/system",
        ]
        KNOWN_SUSPICIOUS = re.compile(
            r"(ExecStart.*(/tmp|/dev/shm|/var/tmp))|"
            r"(ExecStart.*(wget|curl|nc|bash -i|base64))|"
            r"(ExecStart.*\|.*sh)",
            re.IGNORECASE
        )
        suspicious_units = []
        for udir in suspicious_unit_dirs:
            if not os.path.isdir(udir):
                continue
            try:
                for entry in os.scandir(udir):
                    if not entry.name.endswith((".service", ".timer", ".socket")):
                        continue
                    try:
                        content = Path(entry.path).read_text(errors="replace")
                        if KNOWN_SUSPICIOUS.search(content):
                            suspicious_units.append(entry.name)
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                continue

        if suspicious_units:
            yield Finding(
                title              = f"Suspicious systemd unit(s): {', '.join(suspicious_units)}",
                severity           = Severity.CRITICAL,
                category           = "Rootkits",
                description        = f"Systemd unit files with suspicious ExecStart commands (temp dir execution, reverse shells, downloaders): {', '.join(suspicious_units)}",
                affected_component = f"systemd units: {', '.join(suspicious_units)}",
                remediation        = "Investigate with: systemctl cat <unit>\nDisable: systemctl disable --now <unit>\nRemove unit file and reload: systemctl daemon-reload",
                cvss_score         = 9.5,
            )

    # ─────────────────────────────────────────────────────────────────────────
    # MACOS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_macos(self) -> Iterator[Finding]:
        yield from self._check_launch_agents()
        yield from self._check_launch_daemons()
        yield from self._check_macos_kexts()
        yield from self._check_macos_hidden_files()
        yield from self._check_macos_login_items()
        yield from self._check_macos_cron()

    def _check_launch_agents(self) -> Iterator[Finding]:
        self._emit_progress(15, "Scanning LaunchAgents for persistence...")
        agent_dirs = [
            "/Library/LaunchAgents",
            "/System/Library/LaunchAgents",
        ]
        # Add user-specific LaunchAgents
        try:
            import pwd
            agent_dirs += [f"{p.pw_dir}/Library/LaunchAgents" for p in pwd.getpwall()
                           if p.pw_uid >= 500 and os.path.isdir(f"{p.pw_dir}/Library/LaunchAgents")]
        except Exception:
            pass

        yield from self._scan_plist_directory(agent_dirs, "LaunchAgent")

    def _check_launch_daemons(self) -> Iterator[Finding]:
        self._emit_progress(35, "Scanning LaunchDaemons for persistence...")
        daemon_dirs = ["/Library/LaunchDaemons", "/System/Library/LaunchDaemons"]
        yield from self._scan_plist_directory(daemon_dirs, "LaunchDaemon")

    def _scan_plist_directory(self, dirs: list, item_type: str) -> Iterator[Finding]:
        SUSPICIOUS_PLIST = re.compile(
            r"(ProgramArguments.*(/tmp|/var/tmp|/dev))|"
            r"(python.*-c.*exec|curl.*\|.*bash|wget.*\|.*sh|nc\s+-e)",
            re.IGNORECASE | re.DOTALL
        )
        suspicious = []
        for d in dirs:
            if not os.path.isdir(d):
                continue
            # Only flag non-system (non-Apple) items
            if "/System/Library" in d:
                continue
            try:
                for entry in os.scandir(d):
                    if not entry.name.endswith(".plist"):
                        continue
                    # Skip known-good Apple plists
                    if entry.name.startswith("com.apple."):
                        continue
                    try:
                        content = Path(entry.path).read_text(errors="replace")
                        if SUSPICIOUS_PLIST.search(content):
                            suspicious.append(entry.name)
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                continue

        if suspicious:
            yield Finding(
                title              = f"Suspicious {item_type} plist(s): {', '.join(suspicious)}",
                severity           = Severity.HIGH,
                category           = "Rootkits",
                description        = f"LaunchAgent/Daemon plists with suspicious program arguments (temp dir execution, download/execute patterns): {', '.join(suspicious)}",
                affected_component = f"macOS {item_type}s: {', '.join(suspicious)}",
                remediation        = "Investigate with: plutil -p <plist>\nDisable: launchctl unload -w <plist_path>\nRemove if malicious.",
                cvss_score         = 8.5,
            )

    def _check_macos_kexts(self) -> Iterator[Finding]:
        self._emit_progress(55, "Checking kernel extensions...")
        stdout, _, _ = self.run_command(["kextstat"], timeout=15)
        non_apple = [l.strip() for l in stdout.splitlines()
                     if l.strip() and "com.apple" not in l and "Index" not in l
                     and not l.startswith("Index")]
        if non_apple:
            yield Finding(
                title              = f"{len(non_apple)} third-party kernel extension(s) loaded",
                severity           = Severity.INFO,
                category           = "Rootkits",
                description        = f"Third-party kexts: {'; '.join(l.split()[-1] for l in non_apple[:4] if l.split())}. Verify all loaded kexts are from trusted sources.",
                affected_component = "macOS Kernel Extensions",
                remediation        = "Review with: kextstat | grep -v com.apple\nUnload with: sudo kextunload -b <bundle_id>",
            )

    def _check_macos_hidden_files(self) -> Iterator[Finding]:
        self._emit_progress(68, "Checking for hidden files in key locations...")
        check_dirs = ["/", "/usr", "/Library"]
        hidden_files = []
        for d in check_dirs:
            try:
                for entry in os.scandir(d):
                    if entry.name.startswith(".") and entry.name not in (
                        ".DS_Store", ".localized", ".file", ".vol", ".Spotlight-V100",
                        ".fseventsd", ".Trashes", ".DocumentRevisions-V100",
                    ):
                        hidden_files.append(entry.path)
            except (PermissionError, OSError):
                continue
        if hidden_files:
            yield Finding(
                title              = f"{len(hidden_files)} hidden file(s)/directory/directories in system root locations",
                severity           = Severity.MEDIUM,
                category           = "Rootkits",
                description        = f"Hidden items in system directories: {', '.join(hidden_files[:6])}",
                affected_component = "macOS filesystem — hidden items",
                remediation        = "Investigate each. Legitimate hidden files in / are rare. Check with: ls -la /  and  file <path>",
            )

    def _check_macos_login_items(self) -> Iterator[Finding]:
        self._emit_progress(80, "Checking login items via osascript...")
        stdout, _, _ = self.run_command(
            ["osascript", "-e",
             'tell application "System Events" to get the name of every login item'],
            timeout=10)
        if stdout.strip():
            items = [i.strip() for i in stdout.split(",") if i.strip()]
            yield Finding(
                title              = f"{len(items)} macOS Login Item(s): {', '.join(items)}",
                severity           = Severity.INFO,
                category           = "Rootkits",
                description        = f"The following applications launch at login: {', '.join(items)}. Verify all are intentional.",
                affected_component = "macOS Login Items",
                remediation        = "Review in System Settings → General → Login Items. Remove anything unexpected.",
            )

    def _check_macos_cron(self) -> Iterator[Finding]:
        self._emit_progress(88, "Checking macOS crontabs...")
        stdout, _, _ = self.run_command(["crontab", "-l"], timeout=10)
        lines = [l for l in stdout.splitlines() if l.strip() and not l.startswith("#")]
        if lines:
            yield Finding(
                title              = f"User crontab has {len(lines)} entr(ies)",
                severity           = Severity.INFO,
                category           = "Rootkits",
                description        = f"Cron entries for current user: {'; '.join(lines[:3])}. Review for unauthorised persistence.",
                affected_component = "macOS crontab",
                remediation        = "Review: crontab -l\nRemove if unexpected: crontab -e",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # WINDOWS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_windows(self) -> Iterator[Finding]:
        yield from self._check_autorun_registry()
        yield from self._check_suspicious_scheduled_tasks()
        yield from self._check_hidden_services()
        yield from self._check_windows_startup_dirs()
        yield from self._check_wmi_subscriptions()

    def _check_autorun_registry(self) -> Iterator[Finding]:
        self._emit_progress(15, "Checking autorun registry keys...")
        AUTORUN_KEYS = [
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ]
        SUSPICIOUS_PATTERNS = re.compile(
            r"(cmd\.exe.*\/c|powershell.*-enc|wscript|cscript|"
            r"mshta|regsvr32|rundll32.*\.txt|\\Temp\\|\\AppData\\Roaming\\[^\\]+\.exe)",
            re.IGNORECASE
        )
        suspicious_entries = []
        for key in AUTORUN_KEYS:
            stdout, _, _ = self.run_command(
                ["powershell", "-NoProfile", "-Command",
                 f"Get-ItemProperty -Path '{key}' -ErrorAction SilentlyContinue | "
                 "ConvertTo-Json -Compress"],
                timeout=10)
            if not stdout.strip() or stdout.strip() in ("null", "{}"):
                continue
            if SUSPICIOUS_PATTERNS.search(stdout):
                import json
                try:
                    data = json.loads(stdout)
                    for k, v in data.items():
                        if k.startswith("PS") or k in ("PSPath", "PSParentPath", "PSChildName",
                                                         "PSProvider", "PSDrive"):
                            continue
                        if isinstance(v, str) and SUSPICIOUS_PATTERNS.search(v):
                            suspicious_entries.append(f"{k}: {v[:80]}")
                except (json.JSONDecodeError, TypeError):
                    suspicious_entries.append(f"{key}: (suspicious content)")

        if suspicious_entries:
            yield Finding(
                title              = f"{len(suspicious_entries)} suspicious autorun registry entr(ies)",
                severity           = Severity.CRITICAL,
                category           = "Rootkits",
                description        = f"Registry autorun entries with suspicious patterns: {'; '.join(suspicious_entries[:3])}",
                affected_component = "Windows Registry autorun keys",
                remediation        = "Remove suspicious entries via regedit or PowerShell:\nRemove-ItemProperty -Path '<key>' -Name '<name>'\nInvestigate the binary/script being launched.",
                cvss_score         = 9.0,
            )
        else:
            yield Finding(title="No suspicious autorun registry entries detected",
                          severity=Severity.INFO, category="Rootkits",
                          description="HKLM/HKCU Run keys checked — no obviously malicious entries found.",
                          affected_component="Windows autorun registry keys",
                          remediation="Periodic review recommended.")

    def _check_suspicious_scheduled_tasks(self) -> Iterator[Finding]:
        self._emit_progress(35, "Checking scheduled tasks for persistence...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -and "
             "$_.TaskPath -notlike '\\Microsoft\\*'} | "
             "Select-Object TaskName, TaskPath, @{N='Action';E={$_.Actions.Execute}} | "
             "ConvertTo-Json -Compress"],
            timeout=30)

        if not stdout.strip() or stdout.strip() in ("null", "[]"):
            return

        SUSPICIOUS_TASK = re.compile(
            r"(powershell.*-enc|cmd.*\/c.*\|.*|mshta|regsvr32|"
            r"wscript|cscript|\\Temp\\|\\AppData\\Roaming\\.*\.exe|"
            r"base64|\.ps1.*-.*bypass)",
            re.IGNORECASE
        )
        suspicious_tasks = []
        try:
            import json
            tasks = json.loads(stdout)
            if not isinstance(tasks, list):
                tasks = [tasks]
            for task in tasks:
                action = str(task.get("Action", ""))
                name   = task.get("TaskName", "?")
                if action and SUSPICIOUS_TASK.search(action):
                    suspicious_tasks.append(f"{name}: {action[:70]}")
        except (json.JSONDecodeError, TypeError):
            pass

        if suspicious_tasks:
            yield Finding(
                title              = f"{len(suspicious_tasks)} suspicious scheduled task(s)",
                severity           = Severity.CRITICAL,
                category           = "Rootkits",
                description        = f"Non-Microsoft scheduled tasks with suspicious actions: {'; '.join(suspicious_tasks[:3])}",
                affected_component = "Windows Scheduled Tasks",
                remediation        = "Investigate and remove:\nUnregister-ScheduledTask -TaskName '<name>' -Confirm:$false\nCheck Task Scheduler GUI: taskschd.msc",
                cvss_score         = 9.0,
            )

    def _check_hidden_services(self) -> Iterator[Finding]:
        self._emit_progress(55, "Checking for services with suspicious characteristics...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-Service | Where-Object {$_.StartType -ne 'Disabled'} | "
             "Select-Object Name, DisplayName, Status, StartType | "
             "ConvertTo-Json -Compress"],
            timeout=20)

        # Cross-reference with WMI for any services visible in WMI but not Get-Service
        wmi_out, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-WmiObject Win32_Service | Measure-Object | Select -Expand Count"],
            timeout=15)
        try:
            import json
            services = json.loads(stdout) if stdout.strip() not in ("null", "[]") else []
            if not isinstance(services, list):
                services = [services]
            get_svc_count = len(services)
            wmi_count = int(wmi_out.strip()) if wmi_out.strip().isdigit() else 0
            diff = wmi_count - get_svc_count
            if diff > 5:
                yield Finding(
                    title              = f"{diff} service(s) visible via WMI but not Get-Service (possible DKOM)",
                    severity           = Severity.HIGH,
                    category           = "Rootkits",
                    description        = f"WMI reports {wmi_count} services while Get-Service sees {get_svc_count}. A large discrepancy may indicate a kernel-level rootkit using DKOM to hide services.",
                    affected_component = "Windows services (DKOM detection)",
                    remediation        = "Use an offline scanning tool (Windows Defender Offline, Malwarebytes) to scan from outside the potentially compromised OS.",
                    cvss_score         = 7.5,
                )
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    def _check_windows_startup_dirs(self) -> Iterator[Finding]:
        self._emit_progress(72, "Checking startup directories...")
        startup_dirs = [
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
        SUSPICIOUS_EXT = {".exe", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr"}
        suspicious_files = []
        for d in startup_dirs:
            if not os.path.isdir(d):
                continue
            for entry in os.scandir(d):
                ext = os.path.splitext(entry.name)[1].lower()
                if ext in SUSPICIOUS_EXT and entry.name.lower() not in (
                    "desktop.ini", "thumbs.db"
                ):
                    suspicious_files.append(entry.path)

        if suspicious_files:
            yield Finding(
                title              = f"{len(suspicious_files)} executable(s) in Windows startup folder(s)",
                severity           = Severity.HIGH,
                category           = "Rootkits",
                description        = f"Startup folder items: {', '.join(suspicious_files[:5])}. Review all entries for legitimacy.",
                affected_component = "Windows Startup folders",
                remediation        = "Review and remove suspicious files:\nExplore startup folder: shell:startup\nRemove any unrecognised files.",
                cvss_score         = 7.5,
            )

    def _check_wmi_subscriptions(self) -> Iterator[Finding]:
        self._emit_progress(85, "Checking WMI event subscriptions (common persistence mechanism)...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-WMIObject -Namespace root\\subscription -Class __EventFilter | "
             "Select-Object Name, Query | ConvertTo-Json -Compress"],
            timeout=20)
        if stdout.strip() and stdout.strip() not in ("null", "[]", ""):
            try:
                import json
                subs = json.loads(stdout)
                if not isinstance(subs, list):
                    subs = [subs]
                if subs:
                    names = [s.get("Name", "?") for s in subs]
                    yield Finding(
                        title              = f"{len(subs)} WMI event subscription(s) found",
                        severity           = Severity.HIGH,
                        category           = "Rootkits",
                        description        = f"WMI Event Subscriptions are a well-known APT persistence mechanism. Found: {', '.join(names)}. Investigate all subscriptions.",
                        affected_component = "WMI Event Subscriptions (root\\subscription)",
                        remediation        = "Investigate and remove subscriptions:\nGet-WMIObject -Namespace root\\subscription -Class __EventFilter | Remove-WmiObject\nGet-WMIObject -Namespace root\\subscription -Class __EventConsumer | Remove-WmiObject\nGet-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding | Remove-WmiObject",
                        cvss_score         = 8.5,
                    )
            except (json.JSONDecodeError, TypeError):
                pass
        else:
            yield Finding(title="No WMI event subscriptions found",
                          severity=Severity.INFO, category="Rootkits",
                          description="No WMI persistence subscriptions detected.",
                          affected_component="WMI event subscriptions",
                          remediation="No action required.")
