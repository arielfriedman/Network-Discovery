"""
SentinelScan — scanner/permissions.py
File System Permissions & ACL Audit
Phase 5 — Scan Modules Tier 2

Linux/macOS: SUID/SGID binaries, world-writable paths, /tmp noexec,
             sticky bit on shared dirs, unowned files
Windows    : icacls weak ACL checks on sensitive folders/registry,
             world-writable paths in system directories
"""
from __future__ import annotations
import os
import stat
import subprocess
from pathlib import Path
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module


@register_module
class PermissionsModule(ScanModule):
    name             = "permissions"
    display_name     = "File Permissions Audit"
    category         = "Permissions"
    description      = "SUID/SGID binaries, world-writable paths, ACL misconfigurations"
    applies_to_os    = ["linux", "windows", "macos"]
    applies_to_mode  = ["workstation", "server"]

    # Known-safe SUID binaries on Linux (common legitimate ones)
    KNOWN_SAFE_SUID = {
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
        "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd",
        "/usr/bin/pkexec", "/usr/bin/fusermount", "/usr/bin/fusermount3",
        "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/ssh-agent",
        "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/sbin/pppd", "/bin/ping", "/bin/su", "/bin/mount", "/bin/umount",
        "/sbin/mount.nfs", "/usr/bin/at", "/usr/bin/crontab",
        "/usr/bin/wall", "/usr/bin/write", "/usr/bin/expiry",
    }

    def run(self) -> Iterator[Finding]:
        self._emit_progress(5, "Starting permissions audit...")
        if self.config.os_type in ("linux", "macos"):
            yield from self._scan_unix()
        elif self.config.os_type == "windows":
            yield from self._scan_windows()

    # ─────────────────────────────────────────────────────────────────────────
    # LINUX / MACOS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_unix(self) -> Iterator[Finding]:
        yield from self._check_suid_sgid()
        yield from self._check_world_writable_dirs()
        yield from self._check_world_writable_sensitive()
        yield from self._check_tmp_noexec()
        yield from self._check_sticky_bit()
        yield from self._check_unowned_files()
        if self.config.os_type == "linux":
            yield from self._check_passwd_file_perms()

    def _check_suid_sgid(self) -> Iterator[Finding]:
        self._emit_progress(10, "Searching for SUID/SGID binaries...")
        # Search common binary directories
        search_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin",
                        "/usr/local/bin", "/usr/local/sbin"]
        if self.config.os_type == "macos":
            search_paths += ["/Applications"]

        unusual_suid = []
        unusual_sgid = []

        for search_dir in search_paths:
            if not os.path.isdir(search_dir):
                continue
            try:
                for entry in os.scandir(search_dir):
                    try:
                        st = entry.stat(follow_symlinks=False)
                        mode = st.st_mode
                        if stat.S_ISREG(mode):
                            path = entry.path
                            if (mode & stat.S_ISUID) and path not in self.KNOWN_SAFE_SUID:
                                unusual_suid.append(path)
                            if (mode & stat.S_ISGID):
                                unusual_sgid.append(path)
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                continue

        self._emit_progress(35, f"Found {len(unusual_suid)} unusual SUID, {len(unusual_sgid)} SGID binaries")

        if unusual_suid:
            yield Finding(
                title              = f"{len(unusual_suid)} unexpected SUID binary/binaries found",
                severity           = Severity.HIGH,
                category           = "Permissions",
                description        = f"SUID binaries run with the owner's privileges regardless of who executes them. Unexpected SUID binaries are a common persistence/privilege-escalation technique. Found: {', '.join(unusual_suid[:6])}{'...' if len(unusual_suid) > 6 else ''}",
                affected_component = f"SUID binaries: {', '.join(unusual_suid[:4])}",
                remediation        = f"Verify each binary is legitimate:\nls -la {' '.join(unusual_suid[:3])}\nRemove SUID if not needed:\nchmod u-s <binary>",
                cvss_score         = 7.8,
            )
        else:
            yield Finding(title="No unexpected SUID binaries in standard paths",
                          severity=Severity.INFO, category="Permissions",
                          description="All SUID binaries in system paths are in the expected set.",
                          affected_component="SUID binaries", remediation="No action required.")

        # Also run find for comprehensive SUID search in full mode
        if self.config.default_scan_type == "full":
            self._emit_progress(40, "Running full filesystem SUID search...")
            stdout, _, _ = self.run_command(
                ["find", "/", "-xdev", "-perm", "/4000", "-type", "f",
                 "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"],
                timeout=120)
            all_suid = [l.strip() for l in stdout.splitlines() if l.strip()]
            full_unusual = [p for p in all_suid if p not in self.KNOWN_SAFE_SUID]
            if full_unusual:
                yield Finding(
                    title              = f"Full scan: {len(full_unusual)} SUID binary/binaries outside standard paths",
                    severity           = Severity.HIGH,
                    category           = "Permissions",
                    description        = f"Additional SUID binaries found in non-standard locations: {', '.join(full_unusual[:8])}",
                    affected_component = "SUID binaries (full filesystem scan)",
                    remediation        = "Investigate each. Remove SUID bit from any that are not required: chmod u-s <binary>",
                    cvss_score         = 7.8,
                )

    def _check_world_writable_dirs(self) -> Iterator[Finding]:
        self._emit_progress(48, "Checking world-writable directories in sensitive paths...")
        sensitive_dirs = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
                          "/usr/lib", "/lib", "/boot"]
        if self.config.os_type == "macos":
            sensitive_dirs += ["/usr/local/bin", "/usr/local/lib"]

        ww_paths = []
        for sdir in sensitive_dirs:
            if not os.path.isdir(sdir):
                continue
            try:
                for entry in os.scandir(sdir):
                    try:
                        mode = entry.stat(follow_symlinks=False).st_mode
                        if stat.S_ISDIR(mode) and (mode & stat.S_IWOTH):
                            ww_paths.append(entry.path)
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                continue

        if ww_paths:
            yield Finding(
                title              = f"{len(ww_paths)} world-writable directory/directories in sensitive system paths",
                severity           = Severity.HIGH,
                category           = "Permissions",
                description        = f"World-writable directories allow any user to create, modify, or delete files. In system paths this enables library injection and privilege escalation. Paths: {', '.join(ww_paths[:6])}",
                affected_component = f"World-writable dirs: {', '.join(ww_paths[:3])}",
                remediation        = f"Fix permissions:\nchmod o-w {' '.join(ww_paths[:3])}\nchown root:root {' '.join(ww_paths[:3])}",
                cvss_score         = 8.0,
            )

    def _check_world_writable_sensitive(self) -> Iterator[Finding]:
        self._emit_progress(55, "Checking world-writable sensitive configuration files...")
        sensitive_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
            "/etc/crontab", "/etc/ssh/sshd_config", "/etc/fstab",
            "/etc/iptables/rules.v4", "/etc/apt/sources.list",
        ]
        writable = []
        for fp in sensitive_files:
            try:
                mode = os.stat(fp).st_mode
                if mode & stat.S_IWOTH or mode & stat.S_IWGRP:
                    writable.append((fp, oct(mode)[-4:]))
            except (FileNotFoundError, PermissionError):
                continue

        if writable:
            for fp, mode in writable:
                yield Finding(
                    title              = f"Sensitive file is group/world-writable: {fp} (mode {mode})",
                    severity           = Severity.CRITICAL,
                    category           = "Permissions",
                    description        = f"{fp} has permissions {mode} allowing group or world write access. Modification of this file could allow privilege escalation or persistent backdoors.",
                    affected_component = f"File permissions: {fp}",
                    remediation        = f"Fix immediately:\nchmod 600 {fp}\nchown root:root {fp}",
                    cvss_score         = 9.0,
                )
        else:
            yield Finding(title="Critical config files have correct permissions",
                          severity=Severity.INFO, category="Permissions",
                          description="Checked /etc/passwd, /etc/shadow, /etc/sudoers and other sensitive files — all have appropriate permissions.",
                          affected_component="Sensitive configuration files",
                          remediation="No action required.")

    def _check_tmp_noexec(self) -> Iterator[Finding]:
        self._emit_progress(63, "Checking /tmp mount options...")
        # Check /proc/mounts or /etc/fstab
        try:
            with open("/proc/mounts") as f:
                mounts = f.read()
            tmp_line = [l for l in mounts.splitlines() if " /tmp " in l]
            if tmp_line:
                if "noexec" not in tmp_line[0]:
                    yield Finding(
                        title              = "/tmp is mounted WITHOUT noexec option",
                        severity           = Severity.MEDIUM,
                        category           = "Permissions",
                        description        = "/tmp allows execution of files. Attackers commonly upload and execute malicious binaries from /tmp. The noexec mount option prevents this.",
                        affected_component = "/tmp mount options",
                        remediation        = "Add noexec to /tmp in /etc/fstab:\ntmpfs /tmp tmpfs defaults,nosuid,nodev,noexec 0 0\nThen: sudo mount -o remount /tmp",
                    )
                if "nosuid" not in tmp_line[0]:
                    yield Finding(
                        title              = "/tmp is mounted WITHOUT nosuid option",
                        severity           = Severity.MEDIUM,
                        category           = "Permissions",
                        description        = "/tmp lacks the nosuid mount option. SUID binaries placed in /tmp can be used for privilege escalation.",
                        affected_component = "/tmp mount options (nosuid)",
                        remediation        = "Add nosuid to /tmp in /etc/fstab and remount.",
                    )
        except (FileNotFoundError, PermissionError):
            pass

    def _check_sticky_bit(self) -> Iterator[Finding]:
        self._emit_progress(70, "Checking sticky bit on shared directories...")
        shared_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
        for d in shared_dirs:
            if os.path.isdir(d):
                mode = os.stat(d).st_mode
                if not (mode & stat.S_ISVTX):
                    yield Finding(
                        title              = f"Sticky bit not set on shared directory: {d}",
                        severity           = Severity.MEDIUM,
                        category           = "Permissions",
                        description        = f"{d} is world-writable without the sticky bit. Without sticky bit, any user can delete files owned by other users.",
                        affected_component = f"Directory permissions: {d}",
                        remediation        = f"Set sticky bit:\nchmod +t {d}\nchmod 1777 {d}",
                    )

    def _check_unowned_files(self) -> Iterator[Finding]:
        self._emit_progress(77, "Checking for unowned files in system paths...")
        # Limit to /etc for quick scan to avoid long runtime
        stdout, _, _ = self.run_command(
            ["find", "/etc", "-xdev", "-nouser", "-o", "-nogroup"],
            timeout=30)
        unowned = [l.strip() for l in stdout.splitlines() if l.strip()]
        if unowned:
            yield Finding(
                title              = f"{len(unowned)} unowned file(s) found in /etc",
                severity           = Severity.MEDIUM,
                category           = "Permissions",
                description        = f"Files with no valid owner or group may indicate deleted accounts, package residue, or post-compromise file drops: {', '.join(unowned[:5])}",
                affected_component = "Unowned files in /etc",
                remediation        = f"Assign correct ownership:\nchown root:root {' '.join(unowned[:3])}\nOr remove if not needed.",
            )

    def _check_passwd_file_perms(self) -> Iterator[Finding]:
        self._emit_progress(85, "Verifying critical file permissions...")
        EXPECTED = {
            "/etc/passwd":       (0o644, "644"),
            "/etc/group":        (0o644, "644"),
            "/etc/shadow":       (0o640, "640"),  # or 000 on some distros
            "/etc/gshadow":      (0o640, "640"),
            "/etc/ssh/sshd_config": (0o600, "600"),
            "/boot/grub/grub.cfg":  (0o600, "600"),
        }
        for fp, (expected_mode, expected_str) in EXPECTED.items():
            try:
                actual_mode = os.stat(fp).st_mode & 0o777
                if actual_mode > expected_mode:
                    actual_str = oct(actual_mode)[-3:]
                    yield Finding(
                        title              = f"Permissions too open on {fp}: {actual_str} (expected {expected_str})",
                        severity           = Severity.HIGH if fp in ("/etc/shadow", "/etc/gshadow") else Severity.MEDIUM,
                        category           = "Permissions",
                        description        = f"{fp} has permissions {actual_str} but should be at most {expected_str}.",
                        affected_component = f"File: {fp}",
                        remediation        = f"chmod {expected_str} {fp}",
                    )
            except (FileNotFoundError, PermissionError):
                continue

    # ─────────────────────────────────────────────────────────────────────────
    # WINDOWS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_windows(self) -> Iterator[Finding]:
        self._emit_progress(10, "Checking Windows filesystem permissions...")
        yield from self._check_windows_weak_folder_acls()
        yield from self._check_windows_registry_permissions()
        yield from self._check_windows_service_binary_perms()
        yield from self._check_windows_unquoted_paths()

    def _check_windows_weak_folder_acls(self) -> Iterator[Finding]:
        self._emit_progress(20, "Checking system folder ACLs...")
        SENSITIVE_PATHS = [
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ]
        for path in SENSITIVE_PATHS:
            if not os.path.exists(path):
                continue
            stdout, _, _ = self.run_command(
                ["icacls", path], timeout=15)
            if stdout and "Everyone:(OI)(CI)(F)" in stdout:
                yield Finding(
                    title              = f"World-writable ACL on system path: {path}",
                    severity           = Severity.CRITICAL,
                    category           = "Permissions",
                    description        = f"{path} grants Everyone full control. Any user can replace system binaries, enabling DLL hijacking and privilege escalation.",
                    affected_component = f"Windows ACL: {path}",
                    remediation        = f"Fix ACL:\nicacls \"{path}\" /reset /T\nicacls \"{path}\" /inheritance:r\nicacls \"{path}\" /grant Administrators:(OI)(CI)(F) SYSTEM:(OI)(CI)(F)",
                    cvss_score         = 9.5,
                )
            # Check for writable by Users group
            if "BUILTIN\\Users:(OI)(CI)(M)" in stdout or "BUILTIN\\Users:(OI)(CI)(F)" in stdout:
                yield Finding(
                    title              = f"Users group has Modify/Full access to: {path}",
                    severity           = Severity.HIGH,
                    category           = "Permissions",
                    description        = f"The Users group has Modify or Full access to {path}. Standard users can modify system binaries or drop malicious files.",
                    affected_component = f"Windows ACL: {path}",
                    remediation        = f"Remove Users modify access:\nicacls \"{path}\" /remove:g \"BUILTIN\\Users\"",
                    cvss_score         = 7.8,
                )

    def _check_windows_registry_permissions(self) -> Iterator[Finding]:
        self._emit_progress(45, "Checking sensitive registry key permissions...")
        REG_KEYS = [
            r"HKLM\SAM",
            r"HKLM\SECURITY",
            r"HKLM\SYSTEM\CurrentControlSet\Services",
        ]
        for key in REG_KEYS:
            stdout, _, _ = self.run_command(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-Acl -Path 'Registry::{key}' -ErrorAction SilentlyContinue).Access | "
                 f"Where-Object {{$_.IdentityReference -like '*Users*' -and $_.RegistryRights -match 'Write|FullControl'}} | "
                 f"Select-Object -First 1 | ConvertTo-Json -Compress"],
                timeout=15)
            if stdout.strip() and stdout.strip() not in ("null", ""):
                yield Finding(
                    title              = f"Users group has write access to registry key: {key}",
                    severity           = Severity.HIGH,
                    category           = "Permissions",
                    description        = f"Standard users have write access to {key}. This can allow service manipulation or credential access.",
                    affected_component = f"Registry: {key}",
                    remediation        = f"Review and restrict ACL:\nGet-Acl 'Registry::{key}' | fl *\nUse regedit.msc → Permissions to remove Users write access.",
                    cvss_score         = 7.5,
                )

    def _check_windows_service_binary_perms(self) -> Iterator[Finding]:
        self._emit_progress(60, "Checking service binary permissions for privilege escalation...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-WmiObject Win32_Service | Where-Object {$_.PathName -and $_.PathName -notlike '*svchost*'} | "
             "Select-Object -First 20 -Expand PathName"],
            timeout=20)
        weak_perms = []
        for line in stdout.splitlines():
            binary = line.strip().strip('"').split()[0] if line.strip() else ""
            if not binary or not os.path.exists(binary):
                continue
            icacls_out, _, _ = self.run_command(["icacls", binary], timeout=10)
            if icacls_out and ("Users:(M)" in icacls_out or "Users:(F)" in icacls_out or
                               "Everyone:(F)" in icacls_out or "Everyone:(M)" in icacls_out):
                weak_perms.append(binary)

        if weak_perms:
            yield Finding(
                title              = f"{len(weak_perms)} service binary/binaries writable by standard users",
                severity           = Severity.CRITICAL,
                category           = "Permissions",
                description        = f"Service binaries writable by non-privileged users: {', '.join(weak_perms[:4])}. Replacing these binaries causes them to run as SYSTEM.",
                affected_component = f"Service binaries: {', '.join(weak_perms[:3])}",
                remediation        = f"Fix permissions on each binary:\nicacls \"{weak_perms[0]}\" /reset\nicacls \"{weak_perms[0]}\" /inheritance:r /grant SYSTEM:(F) Administrators:(F)",
                cvss_score         = 9.0,
            )

    def _check_windows_unquoted_paths(self) -> Iterator[Finding]:
        self._emit_progress(78, "Checking for unquoted service paths...")
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-WmiObject Win32_Service | Where-Object { "
             "$_.PathName -match '^[^\"]+\\s+[^\"]+' -and "
             "$_.PathName -notlike '\"*' } | "
             "Select-Object Name, PathName | ConvertTo-Json -Compress"],
            timeout=20)
        if not stdout.strip() or stdout.strip() in ("null", "[]"):
            yield Finding(title="No unquoted service paths found", severity=Severity.INFO,
                          category="Permissions",
                          description="All Windows service binary paths are properly quoted.",
                          affected_component="Windows service paths",
                          remediation="No action required.")
            return

        import json
        try:
            services = json.loads(stdout)
            if not isinstance(services, list):
                services = [services]
            if services:
                names = [s.get("Name","?") for s in services[:5]]
                yield Finding(
                    title              = f"{len(services)} service(s) with unquoted executable paths",
                    severity           = Severity.HIGH,
                    category           = "Permissions",
                    description        = f"Services with unquoted paths containing spaces: {', '.join(names)}. Windows path-parsing allows placing a malicious binary at an earlier path component to hijack service execution.",
                    affected_component = f"Windows services: {', '.join(names)}",
                    remediation        = "Wrap service paths in quotes:\nsc config <ServiceName> binpath= '\"C:\\Path With Spaces\\service.exe\"'",
                    cvss_score         = 7.8,
                )
        except (json.JSONDecodeError, TypeError):
            pass
