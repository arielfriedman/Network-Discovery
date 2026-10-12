"""
SentinelScan — scanner/network.py
Network Shares & Exposed Services Audit
Phase 6 — Scan Modules Tier 3

Checks SMB (signing, anonymous access), NFS exports, LDAP null bind,
DNS zone transfer, exposed management interfaces, and network
configuration weaknesses across Linux, Windows, and macOS.
"""
from __future__ import annotations
import socket
import shutil
import re
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module


@register_module
class NetworkSharesModule(ScanModule):
    name             = "network_shares"
    display_name     = "Network Shares & Services"
    category         = "Network"
    description      = "SMB shares, NFS exports, LDAP null bind, DNS zone transfer, exposed management ports"
    applies_to_os    = ["linux", "windows", "macos"]
    applies_to_mode  = ["workstation", "server"]

    def run(self) -> Iterator[Finding]:
        target = getattr(self.config, "current_target", "127.0.0.1")
        self._emit_progress(5, "Starting network services audit...")

        yield from self._check_smb(target)
        yield from self._check_nfs(target)
        yield from self._check_ldap(target)
        yield from self._check_dns_zone_transfer(target)
        yield from self._check_exposed_management(target)
        yield from self._check_local_shares()
        yield from self._check_network_interfaces()

    # ─────────────────────────────────────────────────────────────────────────
    # SMB / SAMBA
    # ─────────────────────────────────────────────────────────────────────────
    def _check_smb(self, target: str) -> Iterator[Finding]:
        self._emit_progress(10, "Checking SMB service...")

        # Check if 445 is open
        if not self._port_open(target, 445):
            return

        yield Finding(
            title              = f"SMB service detected on {target}:445",
            severity           = Severity.INFO,
            category           = "Network",
            description        = "SMB (Server Message Block) service is listening on port 445.",
            affected_component = f"{target}:445",
            remediation        = "Ensure SMB is required. Block port 445 from untrusted networks.",
        )

        # Anonymous share enumeration via smbclient
        if shutil.which("smbclient"):
            yield from self._smb_anonymous_enum(target)
        elif self.config.os_type == "windows":
            yield from self._smb_windows_check(target)

        # SMB signing check via nmap script (if available)
        if self.config.has_tool("nmap"):
            yield from self._smb_signing_check(target)

    def _smb_anonymous_enum(self, target: str) -> Iterator[Finding]:
        self._emit_progress(18, "Attempting anonymous SMB enumeration...")
        stdout, _, rc = self.run_command(
            ["smbclient", "-L", target, "-N", "--option=client min protocol=SMB2"],
            timeout=15)

        if rc == 0 and ("Sharename" in stdout or "WORKGROUP" in stdout.upper()):
            shares = re.findall(r"^\s+(\S+)\s+Disk", stdout, re.MULTILINE)
            if shares:
                yield Finding(
                    title              = f"Anonymous SMB share enumeration successful: {', '.join(shares)}",
                    severity           = Severity.HIGH,
                    category           = "Network",
                    description        = f"SMB shares are accessible without authentication: {', '.join(shares)}. This exposes file system content to any network user.",
                    affected_component = f"SMB shares on {target}: {', '.join(shares)}",
                    remediation        = "Disable anonymous (null session) access:\nLinux/Samba: Set 'restrict anonymous = 2' in smb.conf\nWindows: Computer Config → Policies → Windows Settings → Security → Local Policies → Security Options → Network access: Do not allow anonymous enumeration",
                    cvss_score         = 7.5,
                )
            else:
                yield Finding(
                    title              = "SMB server responded to anonymous listing (no shares exposed)",
                    severity           = Severity.LOW,
                    category           = "Network",
                    description        = "SMB server responded to anonymous connection but did not expose shares.",
                    affected_component = f"SMB on {target}",
                    remediation        = "Consider restricting anonymous connections: restrict anonymous = 2 in smb.conf.",
                )
        elif "NT_STATUS_ACCESS_DENIED" in stdout or "NT_STATUS_LOGON_FAILURE" in stdout:
            yield Finding(
                title              = "SMB anonymous access correctly denied",
                severity           = Severity.INFO,
                category           = "Network",
                description        = "SMB correctly rejects anonymous (unauthenticated) connections.",
                affected_component = f"SMB on {target}",
                remediation        = "No action required.",
            )

        # Check for IPC$ null session
        stdout2, _, rc2 = self.run_command(
            ["smbclient", f"\\\\{target}\\IPC$", "-N", "-c", "exit"],
            timeout=10)
        if rc2 == 0:
            yield Finding(
                title              = "SMB IPC$ accessible anonymously (null session)",
                severity           = Severity.HIGH,
                category           = "Network",
                description        = "The IPC$ share accepts null sessions. This allows attackers to enumerate users, groups, and policies without credentials.",
                affected_component = f"SMB IPC$ on {target}",
                remediation        = "Windows: Security Options → Network access: Restrict anonymous access to Named Pipes and Shares\nSamba: restrict anonymous = 2",
                cvss_score         = 6.5,
            )

    def _smb_windows_check(self, target: str) -> Iterator[Finding]:
        # Windows: check local SMB configuration
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature,EnableSMB1Protocol,RejectUnencryptedAccess | ConvertTo-Json -Compress"],
            timeout=15)
        if stdout.strip():
            import json
            try:
                cfg = json.loads(stdout)
                if not cfg.get("RequireSecuritySignature", True):
                    yield Finding(
                        title              = "SMB signing is NOT required on this server",
                        severity           = Severity.HIGH,
                        category           = "Network",
                        description        = "SMB message signing is not enforced. Attackers can perform SMB relay attacks (NTLM relay) to authenticate as other users.",
                        affected_component = "Windows SMB Server — RequireSecuritySignature",
                        remediation        = "Require SMB signing:\nSet-SmbServerConfiguration -RequireSecuritySignature $true -Force\nOr via GPO: Computer Config → Windows Settings → Security Settings → Local Policies → Security Options → Microsoft network server: Digitally sign communications (always)",
                        cvss_score         = 7.5,
                    )
                if cfg.get("EnableSMB1Protocol", False):
                    yield Finding(
                        title              = "SMBv1 is ENABLED",
                        severity           = Severity.CRITICAL,
                        category           = "Network",
                        description        = "SMBv1 is enabled (EternalBlue/WannaCry vector).",
                        affected_component = "Windows SMBv1",
                        remediation        = "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                        cvss_score         = 9.8,
                        cve_ids            = ["CVE-2017-0144"],
                    )
            except (json.JSONDecodeError, TypeError):
                pass

    def _smb_signing_check(self, target: str) -> Iterator[Finding]:
        self._emit_progress(25, "Checking SMB signing via nmap...")
        stdout, _, rc = self.run_command(
            [self.config.tool("nmap"), "--script", "smb2-security-mode",
             "-p", "445", target, "--open"],
            timeout=30)
        if "Message signing enabled but not required" in stdout:
            yield Finding(
                title              = "SMB signing enabled but NOT required",
                severity           = Severity.HIGH,
                category           = "Network",
                description        = "SMB signing is available but not enforced. NTLM relay attacks can redirect authenticated SMB sessions to other services.",
                affected_component = f"SMB signing policy on {target}",
                remediation        = "Enforce SMB signing:\nWindows: Set-SmbServerConfiguration -RequireSecuritySignature $true\nSamba: server signing = mandatory",
                cvss_score         = 7.5,
            )
        elif "Message signing enabled and required" in stdout:
            yield Finding(
                title              = "SMB signing is required",
                severity           = Severity.INFO,
                category           = "Network",
                description        = "SMB message signing is correctly enforced.",
                affected_component = f"SMB signing on {target}",
                remediation        = "No action required.",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # NFS
    # ─────────────────────────────────────────────────────────────────────────
    def _check_nfs(self, target: str) -> Iterator[Finding]:
        self._emit_progress(35, "Checking NFS exports...")
        if not self._port_open(target, 2049) and not shutil.which("showmount"):
            return

        if not shutil.which("showmount"):
            if self._port_open(target, 2049):
                yield Finding(
                    title              = f"NFS port 2049 open on {target} (showmount not available)",
                    severity           = Severity.INFO,
                    category           = "Network",
                    description        = "NFS service detected but showmount is not installed to enumerate exports.",
                    affected_component = f"NFS on {target}:2049",
                    remediation        = "Install showmount: sudo apt install nfs-common",
                )
            return

        stdout, _, rc = self.run_command(
            ["showmount", "-e", target], timeout=10)

        if rc != 0 or not stdout.strip():
            return

        exports = re.findall(r"^(/[^\s]+)\s+(.+)", stdout, re.MULTILINE)
        if exports:
            yield Finding(
                title              = f"NFS exports accessible: {', '.join(e[0] for e in exports[:4])}",
                severity           = Severity.HIGH,
                category           = "Network",
                description        = f"NFS exports visible: {', '.join(f'{e[0]} ({e[1].strip()})' for e in exports[:4])}. Anyone on the listed networks can mount these filesystems.",
                affected_component = f"NFS exports on {target}",
                remediation        = "Restrict exports in /etc/exports:\n/sensitive/path  192.168.1.0/24(rw,sync,no_subtree_check)\nAvoid: /path *(rw)  — this exports to the entire internet.",
                cvss_score         = 7.5,
            )

            # Check for no_root_squash
            for export_path, export_opts in exports:
                if "no_root_squash" in export_opts.lower():
                    yield Finding(
                        title              = f"NFS export with no_root_squash: {export_path}",
                        severity           = Severity.CRITICAL,
                        category           = "Network",
                        description        = f"The NFS export {export_path} has no_root_squash set. Remote root users have root access to the mounted filesystem — this is equivalent to giving remote root access.",
                        affected_component = f"NFS export: {export_path}",
                        remediation        = f"Remove no_root_squash from /etc/exports:\n{export_path}  <network>(rw,sync,no_subtree_check,root_squash)\nReload: exportfs -ra",
                        cvss_score         = 9.8,
                    )

            # World-accessible exports (*)
            for export_path, export_opts in exports:
                if "*" in export_opts:
                    yield Finding(
                        title              = f"NFS export accessible to ALL hosts: {export_path}",
                        severity           = Severity.CRITICAL,
                        category           = "Network",
                        description        = f"NFS export {export_path} is accessible to all hosts (*). Anyone on the internet can mount this filesystem.",
                        affected_component = f"NFS export: {export_path} (*)",
                        remediation        = "Immediately restrict to specific trusted IP ranges in /etc/exports.",
                        cvss_score         = 9.8,
                    )

    # ─────────────────────────────────────────────────────────────────────────
    # LDAP
    # ─────────────────────────────────────────────────────────────────────────
    def _check_ldap(self, target: str) -> Iterator[Finding]:
        self._emit_progress(47, "Checking LDAP null bind...")
        if not self._port_open(target, 389) and not self._port_open(target, 636):
            return

        # Attempt LDAP null bind using Python ldap3 or ldap module
        try:
            import ldap3
            conn = ldap3.Connection(
                ldap3.Server(target, port=389, get_info=ldap3.ALL),
                auto_bind=True,
                authentication=ldap3.ANONYMOUS,
            )
            if conn.bound:
                yield Finding(
                    title              = f"LDAP null bind allowed on {target}:389",
                    severity           = Severity.HIGH,
                    category           = "Network",
                    description        = "LDAP accepts anonymous (null) bind. An unauthenticated attacker can enumerate directory entries, users, groups, and organisational structure.",
                    affected_component = f"LDAP on {target}:389",
                    remediation        = "Disable anonymous LDAP binds:\nOpenLDAP: olcAllows: none (remove bind_v2)\nActive Directory: deny anonymous access via Group Policy",
                    cvss_score         = 6.5,
                )
                conn.unbind()
        except ImportError:
            # Fallback: use ldapsearch CLI
            if shutil.which("ldapsearch"):
                stdout, _, rc = self.run_command(
                    ["ldapsearch", "-x", "-H", f"ldap://{target}",
                     "-b", "", "-s", "base"], timeout=8)
                if rc == 0 and "namingContexts" in stdout:
                    yield Finding(
                        title              = f"LDAP null bind successful on {target}:389",
                        severity           = Severity.HIGH,
                        category           = "Network",
                        description        = "Anonymous LDAP bind succeeded. Directory information is exposed without credentials.",
                        affected_component = f"LDAP on {target}:389",
                        remediation        = "Restrict anonymous LDAP binds in directory server configuration.",
                        cvss_score         = 6.5,
                    )
            elif self._port_open(target, 389):
                yield Finding(
                    title              = f"LDAP port 389 open on {target}",
                    severity           = Severity.INFO,
                    category           = "Network",
                    description        = "LDAP service detected. Install ldap3 (pip) or ldap-utils to test for null bind.",
                    affected_component = f"LDAP on {target}:389",
                    remediation        = "Verify anonymous access is disabled in your LDAP server configuration.",
                )
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # DNS ZONE TRANSFER
    # ─────────────────────────────────────────────────────────────────────────
    def _check_dns_zone_transfer(self, target: str) -> Iterator[Finding]:
        if not self._port_open(target, 53):
            return

        self._emit_progress(55, "Testing DNS zone transfer...")
        # Get domain from hostname if possible
        try:
            hostname = socket.getfqdn(target)
            domain   = ".".join(hostname.split(".")[-2:]) if "." in hostname else hostname
        except Exception:
            domain = target

        if shutil.which("dig"):
            stdout, _, rc = self.run_command(
                ["dig", "@" + target, domain, "AXFR"], timeout=10)
            if rc == 0 and "Transfer failed" not in stdout and len(stdout.split("\n")) > 5:
                record_count = len([l for l in stdout.splitlines()
                                    if l and not l.startswith(";") and "\t" in l])
                if record_count > 3:
                    yield Finding(
                        title              = f"DNS zone transfer allowed from {target} (AXFR)",
                        severity           = Severity.HIGH,
                        category           = "Network",
                        description        = f"DNS zone transfer (AXFR) succeeded, exposing {record_count} DNS records. This reveals complete network topology to attackers.",
                        affected_component = f"DNS server {target}",
                        remediation        = "Restrict zone transfers to authorised secondaries only:\nBIND: allow-transfer { secondary-ip; };\nWindows DNS: Properties → Zone Transfers → Only to listed servers",
                        cvss_score         = 7.5,
                    )
        elif shutil.which("nslookup"):
            yield Finding(
                title              = f"DNS port 53 open on {target}",
                severity           = Severity.INFO,
                category           = "Network",
                description        = "DNS service detected. Install dig to test zone transfer security.",
                affected_component = f"DNS on {target}:53",
                remediation        = "Verify zone transfers are restricted to authorised secondary DNS servers only.",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # EXPOSED MANAGEMENT INTERFACES
    # ─────────────────────────────────────────────────────────────────────────
    def _check_exposed_management(self, target: str) -> Iterator[Finding]:
        self._emit_progress(63, "Checking for exposed management interfaces...")
        MGMT_PORTS = {
            8080:  ("HTTP management UI", Severity.MEDIUM),
            8888:  ("Jupyter Notebook", Severity.HIGH),
            9090:  ("Prometheus/Cockpit", Severity.MEDIUM),
            3000:  ("Grafana / Node app", Severity.MEDIUM),
            5000:  ("Flask dev server", Severity.HIGH),
            8161:  ("ActiveMQ web console", Severity.HIGH),
            15672: ("RabbitMQ management", Severity.HIGH),
            9200:  ("Elasticsearch HTTP", Severity.CRITICAL),
            5601:  ("Kibana", Severity.HIGH),
            4848:  ("GlassFish admin", Severity.HIGH),
            7474:  ("Neo4j browser", Severity.HIGH),
            2181:  ("Zookeeper", Severity.HIGH),
            9092:  ("Kafka", Severity.HIGH),
            6379:  ("Redis", Severity.CRITICAL),
            11211: ("Memcached", Severity.HIGH),
            27017: ("MongoDB", Severity.CRITICAL),
            5432:  ("PostgreSQL", Severity.HIGH),
            3306:  ("MySQL/MariaDB", Severity.HIGH),
            1433:  ("MSSQL", Severity.HIGH),
            8500:  ("Consul UI", Severity.HIGH),
            8200:  ("Vault", Severity.HIGH),
            2379:  ("etcd", Severity.CRITICAL),
            10250: ("Kubernetes kubelet API", Severity.CRITICAL),
            6443:  ("Kubernetes API server", Severity.HIGH),
        }
        # Only check a subset in quick mode
        if self.config.default_scan_type == "quick":
            check_ports = {p: v for p, v in MGMT_PORTS.items() if v[1] in (Severity.CRITICAL, Severity.HIGH)}
        else:
            check_ports = MGMT_PORTS

        for port, (service, severity) in check_ports.items():
            if self._port_open(target, port):
                yield Finding(
                    title              = f"Management/database service exposed: {service} on {target}:{port}",
                    severity           = severity,
                    category           = "Network",
                    description        = f"{service} is accessible on {target}:{port}. Management interfaces and databases should never be exposed to untrusted networks.",
                    affected_component = f"{service} on {target}:{port}",
                    remediation        = f"Bind {service} to localhost only (127.0.0.1) or restrict via firewall. Use SSH tunnelling for admin access:\nssh -L {port}:localhost:{port} admin@server",
                    cvss_score         = 9.5 if severity == Severity.CRITICAL else 7.5,
                )

    # ─────────────────────────────────────────────────────────────────────────
    # LOCAL SHARE AUDIT
    # ─────────────────────────────────────────────────────────────────────────
    def _check_local_shares(self) -> Iterator[Finding]:
        self._emit_progress(78, "Auditing local file shares...")
        if self.config.os_type == "windows":
            yield from self._windows_local_shares()
        elif self.config.os_type == "linux":
            yield from self._linux_nfs_exports()

    def _windows_local_shares(self) -> Iterator[Finding]:
        stdout, _, _ = self.run_command(
            ["powershell", "-NoProfile", "-Command",
             "Get-SmbShare | Select-Object Name, Path, Description | ConvertTo-Json -Compress"],
            timeout=15)
        if not stdout.strip() or stdout.strip() in ("null", "[]"):
            return
        import json
        try:
            shares = json.loads(stdout)
            if not isinstance(shares, list):
                shares = [shares]
            # Filter out IPC$ and ADMIN$ (normal)
            custom_shares = [s for s in shares
                             if s.get("Name", "").upper() not in ("IPC$", "ADMIN$", "C$", "D$", "E$")]
            if custom_shares:
                names = [s.get("Name", "?") for s in custom_shares]
                paths = [s.get("Path", "?") for s in custom_shares]
                yield Finding(
                    title              = f"{len(custom_shares)} custom SMB share(s) configured: {', '.join(names)}",
                    severity           = Severity.MEDIUM,
                    category           = "Network",
                    description        = f"Custom network shares: {', '.join(f'{n} → {p}' for n, p in zip(names, paths))}. Verify each share has appropriate ACLs and is required.",
                    affected_component = f"Windows SMB shares: {', '.join(names)}",
                    remediation        = "Review share permissions: Get-SmbShareAccess -Name '<share>'\nRemove unnecessary shares: Remove-SmbShare -Name '<share>' -Force",
                )

            # Check for Everyone or Guest access
            for share in shares:
                name = share.get("Name", "?")
                acl_out, _, _ = self.run_command(
                    ["powershell", "-NoProfile", "-Command",
                     f"Get-SmbShareAccess -Name '{name}' | Where-Object {{$_.AccountName -match 'Everyone|Guest|Authenticated Users'}} | ConvertTo-Json -Compress"],
                    timeout=10)
                if acl_out.strip() and acl_out.strip() not in ("null", "[]"):
                    yield Finding(
                        title              = f"SMB share '{name}' accessible by Everyone/Guest",
                        severity           = Severity.HIGH,
                        category           = "Network",
                        description        = f"Share '{name}' has broad access permissions. Guest or Everyone access allows unauthenticated users to access files.",
                        affected_component = f"SMB share ACL: {name}",
                        remediation        = f"Restrict share access:\nGrant-SmbShareAccess -Name '{name}' -AccountName 'DOMAIN\\AuthorizedGroup' -AccessRight Full -Force\nRevoke-SmbShareAccess -Name '{name}' -AccountName 'Everyone' -Force",
                        cvss_score         = 7.0,
                    )
        except (json.JSONDecodeError, TypeError):
            pass

    def _linux_nfs_exports(self) -> Iterator[Finding]:
        import os
        if not os.path.exists("/etc/exports"):
            return
        try:
            from pathlib import Path
            content = Path("/etc/exports").read_text()
            exports = [l.strip() for l in content.splitlines()
                       if l.strip() and not l.startswith("#")]
            if exports:
                yield Finding(
                    title              = f"{len(exports)} NFS export(s) configured in /etc/exports",
                    severity           = Severity.INFO,
                    category           = "Network",
                    description        = f"NFS exports: {'; '.join(exports[:4])}",
                    affected_component = "/etc/exports",
                    remediation        = "Review /etc/exports. Restrict all exports to specific trusted IP ranges. Never use * as the host.",
                )
        except (PermissionError, FileNotFoundError):
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # NETWORK INTERFACE CHECKS
    # ─────────────────────────────────────────────────────────────────────────
    def _check_network_interfaces(self) -> Iterator[Finding]:
        self._emit_progress(88, "Checking network configuration...")
        if self.config.os_type == "linux":
            # Check for promiscuous mode interfaces
            stdout, _, _ = self.run_command(["ip", "link"], timeout=10)
            promisc = re.findall(r"(\S+):.+PROMISC", stdout)
            if promisc:
                yield Finding(
                    title              = f"Network interface(s) in promiscuous mode: {', '.join(promisc)}",
                    severity           = Severity.HIGH,
                    category           = "Network",
                    description        = f"Interface(s) {', '.join(promisc)} are in promiscuous mode, capturing all network traffic. This is typical of packet sniffers and may indicate an unauthorised monitoring tool.",
                    affected_component = f"Network interfaces: {', '.join(promisc)}",
                    remediation        = "Investigate: ip link set <interface> -promisc\nCheck for sniffers: ps aux | grep -E 'tcpdump|wireshark|tshark'",
                    cvss_score         = 7.0,
                )

            # Check IP forwarding
            stdout2, _, _ = self.run_command(
                ["sysctl", "-n", "net.ipv4.ip_forward"], timeout=5)
            if stdout2.strip() == "1":
                yield Finding(
                    title              = "IP forwarding is enabled",
                    severity           = Severity.MEDIUM,
                    category           = "Network",
                    description        = "IP packet forwarding is enabled. This allows the host to route traffic between interfaces. Disable unless this system is an intentional router or VPN gateway.",
                    affected_component = "kernel sysctl — net.ipv4.ip_forward",
                    remediation        = "Disable: sysctl -w net.ipv4.ip_forward=0\nPersist: echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.conf",
                )

    # ─────────────────────────────────────────────────────────────────────────
    # HELPER
    # ─────────────────────────────────────────────────────────────────────────
    def _port_open(self, host: str, port: int, timeout: float = 1.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((host, port)) == 0
            s.close()
            return result
        except Exception:
            return False
