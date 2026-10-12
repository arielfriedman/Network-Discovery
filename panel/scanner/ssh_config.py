"""
SentinelScan — scanner/ssh_config.py
SSH Server Configuration Audit
Phase 5 — Scan Modules Tier 2

Parses /etc/ssh/sshd_config (Linux/macOS) for insecure settings.
Also audits authorized_keys files for unexpected entries, key algorithm
strength, and known-bad host key types. Applies to workstations running
sshd and to all servers.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module


# ─── SSHD_CONFIG CHECKS ───────────────────────────────────────────────────────
# (directive, dangerous_values, recommended_value, severity, description, fix)
SSHD_CHECKS = [
    ("PermitRootLogin",        {"yes"},         "no",                  Severity.CRITICAL,
     "Direct root login over SSH is allowed. An attacker who obtains the root password or key gains immediate full control with no audit trail.",
     "PermitRootLogin no\nOr: PermitRootLogin prohibit-password (keys only, no password)"),

    ("PasswordAuthentication", {"yes"},         "no",                  Severity.HIGH,
     "Password-based SSH authentication is enabled. Passwords are vulnerable to brute-force, credential stuffing, and phishing attacks.",
     "PasswordAuthentication no\n(Ensure all users have SSH keys configured first)"),

    ("PermitEmptyPasswords",   {"yes"},         "no",                  Severity.CRITICAL,
     "SSH connections with empty passwords are permitted. Any account without a password can be accessed remotely.",
     "PermitEmptyPasswords no"),

    ("Protocol",               {"1", "1,2"},    "2",                   Severity.CRITICAL,
     "SSH Protocol version 1 is enabled. SSHv1 has known cryptographic weaknesses and must not be used.",
     "Protocol 2"),

    ("X11Forwarding",          {"yes"},         "no",                  Severity.MEDIUM,
     "X11 forwarding is enabled. This can allow attackers who have a session to capture keystrokes and display contents from other applications.",
     "X11Forwarding no"),

    ("AllowAgentForwarding",   {"yes"},         "no",                  Severity.MEDIUM,
     "SSH agent forwarding is enabled. An attacker who compromises an intermediate host can use the forwarded agent to authenticate further.",
     "AllowAgentForwarding no"),

    ("AllowTcpForwarding",     {"yes", "all"},  "no",                  Severity.MEDIUM,
     "TCP forwarding allows the SSH connection to be used as a tunnel to reach internal services that should not be externally accessible.",
     "AllowTcpForwarding no\n(Unless explicitly required for jump host / bastion)"),

    ("UseDNS",                 {"yes"},         "no",                  Severity.LOW,
     "SSH performs reverse DNS lookups on connecting clients, adding latency and a dependency on DNS infrastructure.",
     "UseDNS no"),

    ("IgnoreRhosts",           {"no"},          "yes",                 Severity.HIGH,
     "Rhosts authentication is not ignored. .rhosts and /etc/hosts.equiv provide host-based authentication without passwords.",
     "IgnoreRhosts yes"),

    ("HostbasedAuthentication", {"yes"},        "no",                  Severity.HIGH,
     "Host-based authentication allows login based solely on the client's hostname, which can be spoofed.",
     "HostbasedAuthentication no"),

    ("GSSAPIAuthentication",   {"yes"},         "no",                  Severity.LOW,
     "GSSAPI authentication is enabled. Disable if Kerberos is not in use to reduce attack surface.",
     "GSSAPIAuthentication no  # (only if Kerberos is not in use)"),

    ("StrictModes",            {"no"},          "yes",                 Severity.HIGH,
     "StrictModes is disabled. SSH will not check file permissions on user home directories and key files, allowing login from accounts with insecure permissions.",
     "StrictModes yes"),

    ("UsePrivilegeSeparation", {"no"},          "yes",                 Severity.HIGH,
     "Privilege separation is disabled. This reduces isolation between SSH processes.",
     "UsePrivilegeSeparation yes  # (or 'sandbox' for stronger isolation)"),

    ("ClientAliveCountMax",    {"0"},           "3",                   Severity.INFO,
     "ClientAliveCountMax 0 means SSH never disconnects idle sessions, which could leave unattended sessions open.",
     "ClientAliveCountMax 3"),

    ("LoginGraceTime",         {"0"},           "60",                  Severity.MEDIUM,
     "LoginGraceTime 0 means there is no timeout for login attempts, enabling unlimited slow brute force.",
     "LoginGraceTime 60"),

    ("MaxAuthTries",           {"0"},           "3",                   Severity.MEDIUM,
     "MaxAuthTries is 0, meaning unlimited authentication attempts per connection — brute force is unrestricted.",
     "MaxAuthTries 3"),
]

# Weak cipher/algorithm patterns
WEAK_CIPHERS    = ["arcfour", "blowfish", "cast128", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                   "3des-cbc", "des"]
WEAK_MACS       = ["hmac-md5", "hmac-sha1", "umac-64"]
WEAK_KEX        = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                   "diffie-hellman-group-exchange-sha1", "ecdh-sha2-nistp256"]
WEAK_HOST_KEYS  = ["ssh-dss", "ssh-dsa"]


@register_module
class SSHConfigModule(ScanModule):
    name             = "ssh_config"
    display_name     = "SSH Configuration Audit"
    category         = "SSH"
    description      = "Audits sshd_config for insecure settings, weak algorithms, and key policy"
    applies_to_os    = ["linux", "macos"]
    applies_to_mode  = ["workstation", "server"]

    def run(self) -> Iterator[Finding]:
        self._emit_progress(5, "Locating SSH configuration...")

        sshd_config_paths = [
            "/etc/ssh/sshd_config",
            "/private/etc/ssh/sshd_config",   # macOS alternate
        ]
        config_path = None
        for p in sshd_config_paths:
            if os.path.isfile(p):
                config_path = p
                break

        # Check if SSH daemon is even running
        sshd_running = self._is_sshd_running()

        if not config_path:
            if sshd_running:
                yield Finding(
                    title              = "sshd is running but sshd_config not found",
                    severity           = Severity.MEDIUM,
                    category           = "SSH",
                    description        = "SSH daemon is active but the config file could not be read. Run with elevated privileges.",
                    affected_component = "/etc/ssh/sshd_config",
                    remediation        = "Run with sudo to read /etc/ssh/sshd_config.",
                )
            else:
                yield Finding(
                    title              = "SSH daemon not detected",
                    severity           = Severity.INFO,
                    category           = "SSH",
                    description        = "sshd does not appear to be running and no sshd_config was found.",
                    affected_component = "sshd",
                    remediation        = "No action required if SSH access is not needed.",
                )
            return

        self._emit_progress(15, f"Parsing {config_path}...")
        try:
            raw = Path(config_path).read_text(errors="replace")
        except PermissionError:
            yield Finding(
                title="Cannot read sshd_config (requires root)",
                severity=Severity.INFO, category="SSH",
                description=f"Permission denied reading {config_path}. Run with sudo.",
                affected_component=config_path,
                remediation="Run SentinelScan with sudo.",
            )
            return

        # Parse config into a dict (last value wins, case-insensitive keys)
        config = self._parse_sshd_config(raw)

        self._emit_progress(30, "Checking security directives...")
        yield from self._check_directives(config, config_path)

        self._emit_progress(55, "Checking cryptographic algorithms...")
        yield from self._check_algorithms(config)

        self._emit_progress(70, "Checking port and network settings...")
        yield from self._check_port_and_network(config)

        self._emit_progress(80, "Checking authorized_keys files...")
        yield from self._check_authorized_keys()

        self._emit_progress(90, "Checking host key types...")
        yield from self._check_host_keys()

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _is_sshd_running(self) -> bool:
        stdout, _, _ = self.run_command(["pgrep", "-x", "sshd"], timeout=5)
        return bool(stdout.strip())

    def _parse_sshd_config(self, text: str) -> dict[str, str]:
        config: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                config[parts[0].lower()] = parts[1].strip().lower()
        return config

    # ── Directive checks ──────────────────────────────────────────────────────
    def _check_directives(self, config: dict, config_path: str) -> Iterator[Finding]:
        for directive, bad_vals, recommended, severity, description, fix in SSHD_CHECKS:
            key = directive.lower()
            value = config.get(key, "")

            # Check for dangerous explicit values
            if value in {v.lower() for v in bad_vals}:
                yield Finding(
                    title              = f"sshd_config: {directive} = {value} (insecure)",
                    severity           = severity,
                    category           = "SSH",
                    description        = f"{directive} is set to '{value}'. {description}",
                    affected_component = f"{config_path} → {directive}",
                    remediation        = f"Edit {config_path}:\n{directive} {recommended}\nThen restart: sudo systemctl restart sshd",
                )
            # Warn if MaxAuthTries > 6 or missing
            elif directive == "MaxAuthTries":
                try:
                    v = int(value) if value else 6
                    if v > 6:
                        yield Finding(
                            title              = f"sshd_config: MaxAuthTries is high ({v})",
                            severity           = Severity.MEDIUM,
                            category           = "SSH",
                            description        = f"MaxAuthTries {v} allows too many authentication attempts per connection, facilitating brute force.",
                            affected_component = f"{config_path} → MaxAuthTries",
                            remediation        = f"Edit {config_path}: MaxAuthTries 3\nRestart sshd.",
                        )
                except ValueError:
                    pass
            # Warn if LoginGraceTime is very long
            elif directive == "LoginGraceTime":
                try:
                    t = int(re.sub(r"[^0-9]", "", value)) if value else 120
                    if t > 120:
                        yield Finding(
                            title              = f"sshd_config: LoginGraceTime is {t}s (should be ≤ 60s)",
                            severity           = Severity.LOW,
                            category           = "SSH",
                            description        = f"LoginGraceTime {t}s is too long. Longer grace periods enable slow brute-force attacks.",
                            affected_component = f"{config_path} → LoginGraceTime",
                            remediation        = f"Edit {config_path}: LoginGraceTime 60",
                        )
                except ValueError:
                    pass

        # Check ClientAliveInterval is set (session timeout)
        if not config.get("clientaliveinterval") or config.get("clientaliveinterval") == "0":
            yield Finding(
                title              = "No SSH idle session timeout configured",
                severity           = Severity.LOW,
                category           = "SSH",
                description        = "ClientAliveInterval is not set. Idle SSH sessions remain open indefinitely, increasing the window for session hijacking.",
                affected_component = "sshd_config → ClientAliveInterval",
                remediation        = "Add to sshd_config:\nClientAliveInterval 300\nClientAliveCountMax 3\nThis disconnects idle sessions after 15 minutes.",
            )

        # Warn if AllowUsers / AllowGroups not set (server mode)
        if self.config.default_scan_mode == "server":
            if not config.get("allowusers") and not config.get("allowgroups"):
                yield Finding(
                    title              = "No AllowUsers or AllowGroups restriction in sshd_config",
                    severity           = Severity.MEDIUM,
                    category           = "SSH",
                    description        = "Any local user account can potentially authenticate via SSH. Restricting SSH to specific users/groups limits lateral movement.",
                    affected_component = "sshd_config → AllowUsers / AllowGroups",
                    remediation        = "Add to sshd_config:\nAllowGroups sshusers\nThen: groupadd sshusers && usermod -aG sshusers <username>\nRestart sshd.",
                )

        # Check if Banner is set
        if not config.get("banner"):
            yield Finding(
                title              = "No SSH login banner configured",
                severity           = Severity.LOW,
                category           = "SSH",
                description        = "No pre-authentication banner is shown to SSH clients. Banners establish legal notice and are required by many compliance frameworks.",
                affected_component = "sshd_config → Banner",
                remediation        = "Create /etc/ssh/banner.txt with your authorised-use notice, then:\nBanner /etc/ssh/banner.txt",
            )

    # ── Algorithm checks ──────────────────────────────────────────────────────
    def _check_algorithms(self, config: dict) -> Iterator[Finding]:
        # Check Ciphers line
        ciphers_val = config.get("ciphers", "")
        if ciphers_val:
            found_weak = [c for c in WEAK_CIPHERS if c in ciphers_val]
            if found_weak:
                yield Finding(
                    title              = f"sshd_config: Weak ciphers enabled: {', '.join(found_weak)}",
                    severity           = Severity.HIGH,
                    category           = "SSH",
                    description        = f"Weak or deprecated cipher algorithms are explicitly allowed: {', '.join(found_weak)}. These can be forced by a MITM downgrade.",
                    affected_component = "sshd_config → Ciphers",
                    remediation        = "Use only strong ciphers:\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
                    cvss_score         = 6.5,
                )

        # Check MACs
        macs_val = config.get("macs", "")
        if macs_val:
            found_weak_macs = [m for m in WEAK_MACS if m in macs_val]
            if found_weak_macs:
                yield Finding(
                    title              = f"sshd_config: Weak MACs enabled: {', '.join(found_weak_macs)}",
                    severity           = Severity.HIGH,
                    category           = "SSH",
                    description        = f"Weak MAC algorithms allowed: {', '.join(found_weak_macs)}. HMAC-MD5 and HMAC-SHA1 are cryptographically broken.",
                    affected_component = "sshd_config → MACs",
                    remediation        = "Use only ETM MACs:\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com",
                    cvss_score         = 6.5,
                )

        # Check KexAlgorithms
        kex_val = config.get("kexalgorithms", "")
        if kex_val:
            found_weak_kex = [k for k in WEAK_KEX if k in kex_val]
            if found_weak_kex:
                yield Finding(
                    title              = f"sshd_config: Weak KEX algorithms: {', '.join(found_weak_kex)}",
                    severity           = Severity.HIGH,
                    category           = "SSH",
                    description        = f"Weak key exchange algorithms allowed: {', '.join(found_weak_kex)}. DH group 1/14 are vulnerable to Logjam.",
                    affected_component = "sshd_config → KexAlgorithms",
                    remediation        = "Use only strong KEX:\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512",
                    cvss_score         = 6.8,
                    cve_ids            = ["CVE-2015-4000"],
                )

    # ── Port and network ──────────────────────────────────────────────────────
    def _check_port_and_network(self, config: dict) -> Iterator[Finding]:
        port_val = config.get("port", "22")
        try:
            port = int(port_val)
            if port == 22:
                yield Finding(
                    title              = "SSH is running on default port 22",
                    severity           = Severity.LOW,
                    category           = "SSH",
                    description        = "Using the default SSH port 22 makes the service an immediate target for automated scanners and brute-force bots.",
                    affected_component = "sshd_config → Port",
                    remediation        = "Consider moving SSH to a non-standard port (e.g., 2222, 22222):\nPort 2222\n(Update firewall rules accordingly — this is security-through-obscurity but reduces noise.)",
                )
        except ValueError:
            pass

    # ── authorized_keys ───────────────────────────────────────────────────────
    def _check_authorized_keys(self) -> Iterator[Finding]:
        auth_keys_found = []

        # Check root's authorized_keys
        root_ak = Path("/root/.ssh/authorized_keys")
        if root_ak.exists():
            try:
                lines = [l for l in root_ak.read_text().splitlines()
                         if l.strip() and not l.strip().startswith("#")]
                if lines:
                    yield Finding(
                        title              = f"root has {len(lines)} authorized SSH key(s)",
                        severity           = Severity.HIGH,
                        category           = "SSH",
                        description        = f"/root/.ssh/authorized_keys contains {len(lines)} key(s). Even if PermitRootLogin is 'prohibit-password', these keys allow passwordless root access.",
                        affected_component = "/root/.ssh/authorized_keys",
                        remediation        = "Review and remove all but essential keys. Prefer sudo from a regular account over direct root SSH keys.",
                    )
            except PermissionError:
                pass

        # Scan home directories for authorized_keys
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        uid = int(parts[2]) if parts[2].isdigit() else -1
                        home = parts[5]
                        if uid >= 1000 and home and home.startswith("/home"):
                            ak_path = Path(home) / ".ssh" / "authorized_keys"
                            if ak_path.exists():
                                auth_keys_found.append((parts[0], str(ak_path)))
        except (FileNotFoundError, PermissionError):
            pass

        if len(auth_keys_found) > 0:
            yield Finding(
                title              = f"authorized_keys files found for {len(auth_keys_found)} user(s)",
                severity           = Severity.INFO,
                category           = "SSH",
                description        = f"SSH authorized_keys present for: {', '.join(u for u, _ in auth_keys_found[:5])}. Review periodically to ensure no stale or unauthorised keys exist.",
                affected_component = "SSH authorized_keys",
                remediation        = "Audit each authorized_keys file and remove stale/unauthorised entries. Consider centralised key management.",
            )

    # ── Host keys ─────────────────────────────────────────────────────────────
    def _check_host_keys(self) -> Iterator[Finding]:
        dsa_key = "/etc/ssh/ssh_host_dsa_key"
        if os.path.exists(dsa_key):
            yield Finding(
                title              = "Weak DSA host key present: ssh_host_dsa_key",
                severity           = Severity.HIGH,
                category           = "SSH",
                description        = "DSA (ssh-dss) host keys are limited to 1024 bits and are cryptographically weak. They should be removed.",
                affected_component = "/etc/ssh/ssh_host_dsa_key",
                remediation        = "Remove DSA host key and regenerate:\nrm /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub\nAdd to sshd_config: HostKey /etc/ssh/ssh_host_ed25519_key\nRestart sshd.",
                cvss_score         = 6.5,
            )

        ed25519_key = "/etc/ssh/ssh_host_ed25519_key"
        if not os.path.exists(ed25519_key):
            yield Finding(
                title              = "Ed25519 host key not present",
                severity           = Severity.LOW,
                category           = "SSH",
                description        = "The modern Ed25519 host key type is not configured. Ed25519 provides the strongest security and fastest authentication.",
                affected_component = "/etc/ssh/ssh_host_ed25519_key",
                remediation        = "Generate Ed25519 host key:\nssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''\nAdd to sshd_config: HostKey /etc/ssh/ssh_host_ed25519_key",
            )
        else:
            yield Finding(title="Ed25519 host key is present",
                          severity=Severity.INFO, category="SSH",
                          description="The modern Ed25519 host key algorithm is configured.",
                          affected_component="SSH host keys", remediation="No action required.")
