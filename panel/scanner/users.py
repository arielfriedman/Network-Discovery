"""
SentinelScan — scanner/users.py
User & Account Security Audit
Phase 4 — Scan Modules Tier 1

Linux  : /etc/passwd, /etc/shadow, /etc/sudoers, lastlog
Windows: Get-LocalUser, net user, PowerShell security policy
macOS  : dscl, dscacheutil, /etc/sudoers
"""
from __future__ import annotations
import re
import datetime
from pathlib import Path
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module


@register_module
class UsersModule(ScanModule):
    name            = "user_audit"
    display_name    = "User & Account Audit"
    category        = "Users"
    description     = "Audits local user accounts, password policy, and privilege assignments"
    applies_to_os   = ["linux", "windows", "macos"]
    applies_to_mode = ["workstation", "server"]

    def run(self) -> Iterator[Finding]:
        self._emit_progress(5, "Starting user audit...")
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
        yield from self._check_passwd()
        yield from self._check_shadow()
        yield from self._check_sudo_group()
        yield from self._check_sudoers()
        yield from self._check_passwd_policy_linux()
        yield from self._check_root_login()
        yield from self._check_inactive_users()

    def _check_passwd(self) -> Iterator[Finding]:
        self._emit_progress(10, "Parsing /etc/passwd...")
        try:
            content = Path("/etc/passwd").read_text()
        except PermissionError:
            yield Finding(title="Cannot read /etc/passwd", severity=Severity.INFO,
                          category="Users", description="Permission denied reading /etc/passwd.",
                          affected_component="/etc/passwd",
                          remediation="Run with sudo for full user audit.")
            return

        shell_users = []
        uid0_users  = []
        for line in content.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username, _, uid, _, _, _, shell = parts[:7]
            uid = int(uid) if uid.isdigit() else -1

            # UID 0 non-root users
            if uid == 0 and username != "root":
                uid0_users.append(username)

            # Non-system users (UID >= 1000) with valid login shells
            if uid >= 1000 and shell not in ("/usr/sbin/nologin", "/bin/false",
                                              "/sbin/nologin", "/dev/null", ""):
                shell_users.append((username, shell))

        if uid0_users:
            yield Finding(
                title              = f"Non-root account(s) with UID 0: {', '.join(uid0_users)}",
                severity           = Severity.CRITICAL,
                category           = "Users",
                description        = f"Account(s) with UID 0 bypass all file permission checks and effectively have root access: {', '.join(uid0_users)}",
                affected_component = f"/etc/passwd — UID 0 accounts: {', '.join(uid0_users)}",
                remediation        = f"Remove or reassign UID for these accounts:\nusermod -u <new_uid> {uid0_users[0]}\nInvestigate whether this was an authorised change.",
                cvss_score         = 9.8,
            )

        yield Finding(
            title              = f"{len(shell_users)} interactive user account(s) found",
            severity           = Severity.INFO,
            category           = "Users",
            description        = f"Accounts with login shells (UID >= 1000): {', '.join(u for u, _ in shell_users)}",
            affected_component = "/etc/passwd",
            remediation        = "Review the list. Disable accounts that are no longer active: passwd -l <username>",
        )

    def _check_shadow(self) -> Iterator[Finding]:
        self._emit_progress(25, "Checking /etc/shadow for empty passwords...")
        try:
            content = Path("/etc/shadow").read_text()
        except PermissionError:
            yield Finding(title="Cannot read /etc/shadow (requires root)",
                          severity=Severity.INFO, category="Users",
                          description="Run with sudo to audit password hashes.",
                          affected_component="/etc/shadow",
                          remediation="Run SentinelScan with sudo for full password audit.")
            return
        except FileNotFoundError:
            return

        empty_pw_users = []
        no_expiry_users = []
        today_days = (datetime.date.today() - datetime.date(1970, 1, 1)).days

        for line in content.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 8:
                continue
            username  = parts[0]
            pw_hash   = parts[1]
            last_chg  = parts[2]
            max_days  = parts[4]

            # Empty password (! means locked, * means no password login)
            if pw_hash not in ("!", "*", "!!", "x") and pw_hash == "":
                empty_pw_users.append(username)

            # Password set to never expire (max_days empty or 99999)
            if max_days in ("99999", "", "0") and pw_hash not in ("!", "*", "!!"):
                no_expiry_users.append(username)

        if empty_pw_users:
            yield Finding(
                title              = f"Account(s) with EMPTY passwords: {', '.join(empty_pw_users)}",
                severity           = Severity.CRITICAL,
                category           = "Users",
                description        = f"The following accounts have no password set, allowing anyone to log in: {', '.join(empty_pw_users)}",
                affected_component = f"/etc/shadow — empty passwords: {', '.join(empty_pw_users)}",
                remediation        = f"Set a strong password or lock the account:\npasswd {empty_pw_users[0]}\nOr lock: passwd -l {empty_pw_users[0]}",
                cvss_score         = 9.8,
            )

        if len(no_expiry_users) > 3:
            yield Finding(
                title              = f"{len(no_expiry_users)} account(s) have passwords set to never expire",
                severity           = Severity.LOW,
                category           = "Users",
                description        = f"Password expiry is not configured for {len(no_expiry_users)} accounts: {', '.join(no_expiry_users[:5])}{'...' if len(no_expiry_users) > 5 else ''}",
                affected_component = "/etc/shadow — password expiry",
                remediation        = "Set maximum password age:\nchage -M 90 <username>\nOr system-wide in /etc/login.defs: PASS_MAX_DAYS 90",
            )

    def _check_sudo_group(self) -> Iterator[Finding]:
        self._emit_progress(40, "Checking sudo group membership...")
        stdout, _, _ = self.run_command(["getent", "group", "sudo"])
        if not stdout:
            stdout, _, _ = self.run_command(["getent", "group", "wheel"])

        if stdout:
            parts   = stdout.strip().split(":")
            members = [m for m in parts[-1].split(",") if m.strip()]
            if members:
                yield Finding(
                    title              = f"Sudo/wheel group members: {', '.join(members)}",
                    severity           = Severity.INFO,
                    category           = "Users",
                    description        = f"The following accounts have sudo/admin privileges: {', '.join(members)}. Verify each is intentional.",
                    affected_component = "sudo / wheel group membership",
                    remediation        = "Remove any accounts that should not have sudo:\ngpasswd -d <username> sudo",
                )

    def _check_sudoers(self) -> Iterator[Finding]:
        self._emit_progress(50, "Auditing sudoers file...")
        try:
            content = Path("/etc/sudoers").read_text()
        except (PermissionError, FileNotFoundError):
            return

        # Check for NOPASSWD entries
        nopasswd = re.findall(r"^[^#].*NOPASSWD.*", content, re.MULTILINE)
        if nopasswd:
            yield Finding(
                title              = f"sudoers: NOPASSWD entries found ({len(nopasswd)})",
                severity           = Severity.HIGH,
                category           = "Users",
                description        = f"NOPASSWD sudo rules allow privilege escalation without a password prompt. Entries: {'; '.join(nopasswd[:3])}",
                affected_component = "/etc/sudoers — NOPASSWD rules",
                remediation        = "Remove NOPASSWD entries unless absolutely required for automation. Use specific command restrictions:\nuser ALL=(ALL) NOPASSWD: /specific/command/only",
                cvss_score         = 7.2,
            )

        # Check for ALL=(ALL) ALL (unrestricted sudo)
        all_all = re.findall(r"^[^#\s].*ALL=\(ALL\).*ALL\b", content, re.MULTILINE)
        if len(all_all) > 1:  # root and one user is expected
            yield Finding(
                title              = f"sudoers: {len(all_all)} unrestricted ALL=(ALL) ALL entries",
                severity           = Severity.MEDIUM,
                category           = "Users",
                description        = f"Multiple accounts have unrestricted sudo access: {'; '.join(all_all[:3])}. Limit sudo to specific commands where possible.",
                affected_component = "/etc/sudoers",
                remediation        = "Restrict sudo to specific commands rather than ALL. Use visudo to edit safely.",
            )

    def _check_passwd_policy_linux(self) -> Iterator[Finding]:
        self._emit_progress(60, "Checking password policy (login.defs)...")
        try:
            content = Path("/etc/login.defs").read_text()
        except FileNotFoundError:
            return

        values = {}
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    values[parts[0]] = parts[1]

        pass_max = int(values.get("PASS_MAX_DAYS", "99999"))
        pass_min_len = int(values.get("PASS_MIN_LEN", "0"))

        if pass_max >= 180:
            yield Finding(
                title              = f"Password maximum age not enforced (PASS_MAX_DAYS={pass_max})",
                severity           = Severity.MEDIUM,
                category           = "Users",
                description        = "Passwords are set to never expire or have an excessively long maximum age. This increases risk from stolen credentials.",
                affected_component = "/etc/login.defs — PASS_MAX_DAYS",
                remediation        = "Set in /etc/login.defs:\nPASS_MAX_DAYS   90\nPASS_MIN_DAYS   1\nPASS_WARN_AGE   14",
            )

        if pass_min_len < 8:
            yield Finding(
                title              = f"Minimum password length too short (PASS_MIN_LEN={pass_min_len})",
                severity           = Severity.MEDIUM,
                category           = "Users",
                description        = f"The system's minimum password length is {pass_min_len} characters. NIST SP 800-63B recommends at least 8 characters, ideally 12+.",
                affected_component = "/etc/login.defs — PASS_MIN_LEN",
                remediation        = "Edit /etc/login.defs: PASS_MIN_LEN 12\nAlso configure PAM pwquality: minlen=12 in /etc/security/pwquality.conf",
            )

    def _check_root_login(self) -> Iterator[Finding]:
        """Check if root account is locked or has a login shell."""
        self._emit_progress(70, "Checking root account configuration...")
        stdout, _, _ = self.run_command(["passwd", "-S", "root"])
        if stdout:
            # P = password set, L = locked, NP = no password
            status = stdout.split()[1] if len(stdout.split()) > 1 else ""
            if status == "NP":
                yield Finding(
                    title              = "Root account has NO PASSWORD",
                    severity           = Severity.CRITICAL,
                    category           = "Users",
                    description        = "The root account has no password set, allowing direct root login with no authentication.",
                    affected_component = "root account",
                    remediation        = "Set a strong root password: passwd root\nOr lock root and use sudo only: passwd -l root",
                    cvss_score         = 9.8,
                )

    def _check_inactive_users(self) -> Iterator[Finding]:
        self._emit_progress(80, "Checking for inactive accounts...")
        stdout, _, rc = self.run_command(["lastlog", "-b", "90"], timeout=20)
        if rc != 0:
            return
        inactive = []
        for line in stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 1 and "Never logged in" not in line and \
               "**Never logged in**" not in line:
                continue
            if len(parts) >= 1 and "**Never logged in**" in line:
                username = parts[0]
                if username not in ("root", "daemon", "bin", "sys", "www-data",
                                     "nobody", "sync", "games", "man", "mail"):
                    inactive.append(username)
        if inactive:
            yield Finding(
                title              = f"{len(inactive)} account(s) have never logged in",
                severity           = Severity.LOW,
                category           = "Users",
                description        = f"The following accounts have never logged in and may be unused: {', '.join(inactive[:8])}",
                affected_component = "Local user accounts",
                remediation        = "Disable unused accounts:\npasswd -l <username>  (locks password)\nOr remove: userdel <username>",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # WINDOWS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_windows(self) -> Iterator[Finding]:
        self._emit_progress(10, "Enumerating local users via PowerShell...")
        stdout, _, rc = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,"
             "PasswordNeverExpires,LastLogon,Description | ConvertTo-Json -Compress"],
            timeout=30)

        if rc != 0 or not stdout.strip():
            yield Finding(title="Could not enumerate local users (requires Admin)",
                          severity=Severity.INFO, category="Users",
                          description="Get-LocalUser failed. Run as Administrator.",
                          affected_component="Local Users",
                          remediation="Run SentinelScan as Administrator.")
            return

        import json
        self._emit_progress(30, "Analysing user accounts...")
        try:
            raw = json.loads(stdout)
            users = raw if isinstance(raw, list) else [raw]
        except json.JSONDecodeError:
            return

        enabled_admins = []
        no_pw_users    = []
        never_exp_users = []
        enabled_count  = sum(1 for u in users if u.get("Enabled"))

        for user in users:
            name    = user.get("Name", "?")
            enabled = user.get("Enabled", False)
            pw_req  = user.get("PasswordRequired", True)
            pw_nevr = user.get("PasswordNeverExpires", False)

            if enabled and not pw_req:
                no_pw_users.append(name)
            if enabled and pw_nevr:
                never_exp_users.append(name)

        # Get admin group members
        adm_out, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-LocalGroupMember -Group 'Administrators' | Select-Object -Expand Name"],
            timeout=20)
        if adm_out:
            enabled_admins = [l.strip().split("\\")[-1] for l in adm_out.splitlines() if l.strip()]

        self._emit_progress(55, "Checking for security policy issues...")

        if no_pw_users:
            yield Finding(
                title              = f"Account(s) with no password required: {', '.join(no_pw_users)}",
                severity           = Severity.CRITICAL,
                category           = "Users",
                description        = f"The following Windows accounts do not require a password: {', '.join(no_pw_users)}",
                affected_component = f"Local accounts: {', '.join(no_pw_users)}",
                remediation        = "Require passwords:\nnet user <username> * (prompts for password)\nOr via Computer Management → Local Users and Groups",
                cvss_score         = 9.1,
            )

        if len(enabled_admins) > 2:
            yield Finding(
                title              = f"{len(enabled_admins)} Administrator group members",
                severity           = Severity.MEDIUM if len(enabled_admins) <= 4 else Severity.HIGH,
                category           = "Users",
                description        = f"Administrator group has {len(enabled_admins)} members: {', '.join(enabled_admins)}. Principle of least privilege requires minimising admin accounts.",
                affected_component = "Local Administrators group",
                remediation        = "Remove non-essential users from the Administrators group:\nnet localgroup Administrators <username> /delete",
            )

        if never_exp_users:
            yield Finding(
                title              = f"{len(never_exp_users)} account(s) with passwords set to never expire",
                severity           = Severity.LOW,
                category           = "Users",
                description        = f"Accounts with non-expiring passwords: {', '.join(never_exp_users[:5])}",
                affected_component = "Local user password expiry",
                remediation        = "Set password expiry:\nnet accounts /maxpwage:90\nOr per-user: Set-LocalUser -Name <name> -PasswordNeverExpires $false",
            )

        yield Finding(title=f"{enabled_count} active local user account(s)",
                      severity=Severity.INFO, category="Users",
                      description=f"Local accounts found: {', '.join(u.get('Name','?') for u in users if u.get('Enabled'))}",
                      affected_component="Local Users",
                      remediation="Review and disable accounts no longer in use.")

        self._emit_progress(75, "Checking password policy...")
        yield from self._check_windows_password_policy()

        self._emit_progress(90, "Checking guest account...")
        guest_out, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "(Get-LocalUser -Name 'Guest').Enabled"], timeout=10)
        if "True" in guest_out:
            yield Finding(
                title              = "Guest account is ENABLED",
                severity           = Severity.HIGH,
                category           = "Users",
                description        = "The Windows Guest account is enabled. This allows unauthenticated local access.",
                affected_component = "Guest account",
                remediation        = "Disable the Guest account:\nnet user guest /active:no",
                cvss_score         = 7.0,
            )

    def _check_windows_password_policy(self) -> Iterator[Finding]:
        stdout, _, _ = self.run_command(["net", "accounts"], timeout=10)
        if not stdout:
            return
        values = {}
        for line in stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                values[k.strip()] = v.strip()

        min_len = values.get("Minimum password length", "0")
        try:
            min_len_int = int(min_len)
            if min_len_int < 8:
                yield Finding(
                    title              = f"Minimum password length is {min_len_int} characters",
                    severity           = Severity.MEDIUM,
                    category           = "Users",
                    description        = f"Windows password policy requires only {min_len_int} character(s). Minimum should be 12.",
                    affected_component = "Windows password policy",
                    remediation        = "Set via Group Policy: Computer Configuration → Windows Settings → Security Settings → Account Policies → Password Policy → Minimum password length = 12\nOr: net accounts /minpwlen:12",
                )
        except ValueError:
            pass

        max_age = values.get("Maximum password age (days)", "0")
        try:
            if int(max_age) == 0 or int(max_age) > 180:
                yield Finding(
                    title              = f"Password maximum age: {max_age} days (weak policy)",
                    severity           = Severity.MEDIUM,
                    category           = "Users",
                    description        = f"Windows password policy has a maximum age of {max_age} days. Should be set to 90 days.",
                    affected_component = "Windows password policy — maximum age",
                    remediation        = "net accounts /maxpwage:90",
                )
        except ValueError:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # MACOS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_macos(self) -> Iterator[Finding]:
        self._emit_progress(10, "Listing local users via dscl...")
        stdout, _, _ = self.run_command(["dscl", ".", "list", "/Users"], timeout=20)

        all_users = [u.strip() for u in stdout.splitlines()
                     if u.strip() and not u.strip().startswith("_") and u.strip() != "nobody"]
        human_users = [u for u in all_users if not u.startswith("_")]

        self._emit_progress(25, "Checking admin group membership...")
        adm_out, _, _ = self.run_command(
            ["dscl", ".", "read", "/Groups/admin", "GroupMembership"], timeout=15)
        admins = []
        if adm_out:
            for line in adm_out.splitlines():
                if "GroupMembership:" in line:
                    admins = line.replace("GroupMembership:", "").split()

        if admins:
            yield Finding(
                title              = f"Admin group members: {', '.join(admins)}",
                severity           = Severity.INFO if len(admins) <= 2 else Severity.MEDIUM,
                category           = "Users",
                description        = f"The following accounts are in the admin group: {', '.join(admins)}.",
                affected_component = "macOS admin group",
                remediation        = "Remove non-essential accounts from admin group:\ndscl . -delete /Groups/admin GroupMembership <username>",
            )

        self._emit_progress(45, "Checking for password policy...")
        pwpol_out, _, _ = self.run_command(
            ["pwpolicy", "-getaccountpolicies"], timeout=15)
        if not pwpol_out or "No global account policies" in pwpol_out:
            yield Finding(
                title              = "No macOS global password policy configured",
                severity           = Severity.MEDIUM,
                category           = "Users",
                description        = "No system-wide password policy is set. Without a policy, users may set weak or empty passwords.",
                affected_component = "macOS password policy (pwpolicy)",
                remediation        = "Configure password policy via MDM (recommended) or:\nsudo pwpolicy setaccountpolicies /path/to/policy.plist\nFor workgroups managed by Intune/Jamf, push the policy via MDM.",
            )

        self._emit_progress(65, "Checking SIP and secure boot status...")
        sip_out, _, _ = self.run_command(["csrutil", "status"], timeout=10)
        if "disabled" in sip_out.lower():
            yield Finding(
                title              = "System Integrity Protection (SIP) is DISABLED",
                severity           = Severity.HIGH,
                category           = "Users",
                description        = "SIP prevents modification of protected system files and directories. Disabling it significantly increases the attack surface.",
                affected_component = "macOS SIP (System Integrity Protection)",
                remediation        = "Re-enable SIP:\n1. Reboot into Recovery Mode (hold Cmd+R)\n2. Open Terminal\n3. Run: csrutil enable\n4. Reboot",
                cvss_score         = 7.0,
            )
        else:
            yield Finding(title="SIP is enabled", severity=Severity.INFO,
                          category="Users",
                          description="System Integrity Protection is active.",
                          affected_component="macOS SIP", remediation="No action required.")

        self._emit_progress(80, "Checking auto-login setting...")
        autologin_out, _, _ = self.run_command(
            ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"],
            timeout=10)
        if autologin_out.strip() and "does not exist" not in autologin_out:
            yield Finding(
                title              = f"Auto-login is enabled for user: {autologin_out.strip()}",
                severity           = Severity.HIGH,
                category           = "Users",
                description        = "macOS is configured to automatically log in a user without requiring a password at boot. Physical access grants immediate access.",
                affected_component = "macOS auto-login setting",
                remediation        = "Disable auto-login: System Settings → General → Login Options → Automatic login → Off\nOr: sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser",
                cvss_score         = 7.5,
            )

        yield Finding(
            title=f"{len(human_users)} local user account(s) found",
            severity=Severity.INFO, category="Users",
            description=f"Local accounts: {', '.join(human_users)}",
            affected_component="macOS local users",
            remediation="Disable inactive accounts: dscl . -create /Users/<name> AuthenticationAuthority ';DisabledUser;'",
        )
