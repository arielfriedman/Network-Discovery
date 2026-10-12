"""
SentinelScan — scanner/ports.py
Open Port & Service Scanner
Phase 4 — Scan Modules Tier 1

Wraps nmap via python-nmap. Falls back to a basic socket scan if nmap
is not installed. Generates findings for dangerous services, unexpected
open ports, and outdated/vulnerable service versions.
"""
from __future__ import annotations
import socket
import concurrent.futures
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module

# ─── DANGEROUS PORT DEFINITIONS ────────────────────────────────────────────────
# port: (service_name, severity, description, remediation)
DANGEROUS_PORTS: dict[int, tuple] = {
    21:   ("FTP",            Severity.HIGH,     "FTP transmits credentials in plaintext.",
           "Replace with SFTP (SSH file transfer) or FTPS. Disable vsftpd/proftpd: systemctl disable vsftpd"),
    23:   ("Telnet",         Severity.CRITICAL, "Telnet transmits all data including passwords in cleartext.",
           "Disable telnetd immediately and replace all Telnet access with SSH."),
    25:   ("SMTP",           Severity.MEDIUM,   "SMTP open — verify this host is an authorised mail relay.",
           "If not a mail server, block port 25 outbound. Ensure relay is restricted to authorised sources."),
    53:   ("DNS",            Severity.INFO,     "DNS service detected. Verify recursive resolution is restricted.",
           "Configure allow-recursion to trusted networks only in named.conf or Unbound."),
    69:   ("TFTP",           Severity.HIGH,     "TFTP has no authentication and transmits data in plaintext.",
           "Disable tftpd: systemctl disable tftpd. Use SFTP or SCP instead."),
    111:  ("rpcbind",        Severity.HIGH,     "rpcbind/portmapper exposes RPC service mapping and is frequently exploited.",
           "Disable rpcbind if NFS is not required: systemctl disable rpcbind. Block port 111 on firewall."),
    135:  ("MSRPC",          Severity.MEDIUM,   "Microsoft RPC endpoint mapper. Restrict access from external networks.",
           "Block TCP 135 at the perimeter firewall. Ensure Windows Firewall is enabled."),
    137:  ("NetBIOS-NS",     Severity.HIGH,     "NetBIOS Name Service leaks hostnames and enables reconnaissance.",
           "Disable NetBIOS over TCP/IP in adapter properties or via Group Policy."),
    139:  ("NetBIOS-SMB",    Severity.HIGH,     "NetBIOS Session Service — legacy SMB. Disable unless explicitly required.",
           "Disable NetBIOS over TCP/IP. Migrate to SMB2/3 via port 445 only."),
    161:  ("SNMP",           Severity.HIGH,     "SNMP v1/v2c uses community strings (often 'public') as weak authentication.",
           "Upgrade to SNMPv3 with authentication and encryption. Change community strings from defaults."),
    389:  ("LDAP",           Severity.MEDIUM,   "Unencrypted LDAP. Credentials may be transmitted in cleartext.",
           "Use LDAPS (port 636) or StartTLS. Restrict access to authorised management hosts."),
    443:  ("HTTPS",          Severity.INFO,     "HTTPS service detected.",
           "Verify TLS version and cipher suite configuration."),
    445:  ("SMB",            Severity.HIGH,     "SMB service. Unpatched SMB is vulnerable to EternalBlue/WannaCry.",
           "Apply all security patches immediately. Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false. Block 445 from untrusted networks."),
    512:  ("rexec",          Severity.CRITICAL, "rexec executes remote commands with no encryption.",
           "Disable rsh/rexec services immediately: remove rsh-server package."),
    513:  ("rlogin",         Severity.CRITICAL, "rlogin is a legacy remote login service with no encryption.",
           "Disable rlogind immediately. Use SSH instead."),
    514:  ("rsh/syslog",     Severity.HIGH,     "rsh allows remote command execution without encryption.",
           "Disable rsh services. Check if this is syslog (UDP 514) — restrict to log sources only."),
    548:  ("AFP",            Severity.MEDIUM,   "Apple Filing Protocol detected. Restrict to authorised Apple clients.",
           "Disable AFP if not required. Use SMB or SFTP instead."),
    631:  ("IPP/CUPS",       Severity.LOW,      "CUPS print server detected. Restrict access if not a print server.",
           "Configure CUPS to listen on localhost only: edit /etc/cups/cupsd.conf."),
    873:  ("rsync",          Severity.HIGH,     "rsync daemon detected. Anonymous rsync access may expose sensitive files.",
           "Configure rsync with authentication (secrets file). Restrict to trusted source IPs."),
    1433: ("MSSQL",          Severity.HIGH,     "Microsoft SQL Server port exposed. Should not be reachable externally.",
           "Block TCP 1433 from untrusted networks. Use Windows Authentication. Disable sa account."),
    1521: ("Oracle DB",      Severity.HIGH,     "Oracle Database listener exposed. Database ports should not be internet-accessible.",
           "Block TCP 1521 at perimeter. Restrict listener.ora to local connections."),
    2049: ("NFS",            Severity.HIGH,     "NFS service detected. Misconfigured NFS exports can allow unauthorised filesystem access.",
           "Review /etc/exports. Restrict all exports to specific trusted hosts. Set no_root_squash only if required."),
    2375: ("Docker API",     Severity.CRITICAL, "Docker daemon API exposed without TLS. Full host compromise is trivial.",
           "Never expose Docker socket on TCP without mTLS. Set DOCKER_HOST to unix socket only. Add -H fd:// in daemon.json."),
    2376: ("Docker TLS",     Severity.MEDIUM,   "Docker daemon API with TLS. Verify certificate is not self-signed.",
           "Ensure mTLS is properly configured. Restrict access to trusted management hosts."),
    3306: ("MySQL/MariaDB",  Severity.HIGH,     "MySQL/MariaDB port exposed. Database ports should not be internet-accessible.",
           "Block TCP 3306 from untrusted networks. Bind to 127.0.0.1 in my.cnf: bind-address = 127.0.0.1"),
    3389: ("RDP",            Severity.HIGH,     "Remote Desktop Protocol exposed. RDP is a top target for brute force and exploitation.",
           "Move RDP behind VPN. Enable Network Level Authentication (NLA). Use non-standard port. Apply all patches (BlueKeep/DejaBlue)."),
    4444: ("Metasploit",     Severity.CRITICAL, "Port 4444 is the default Metasploit listener port. May indicate active compromise.",
           "Investigate this process immediately: lsof -i :4444  or  netstat -anp | grep 4444. Treat as incident."),
    5432: ("PostgreSQL",     Severity.HIGH,     "PostgreSQL port exposed. Database ports should not be internet-accessible.",
           "Restrict pg_hba.conf to localhost/trusted hosts. Block TCP 5432 from untrusted networks."),
    5900: ("VNC",            Severity.HIGH,     "VNC remote desktop exposed. VNC has weak authentication by default.",
           "Place VNC behind VPN or SSH tunnel. Never expose VNC directly to untrusted networks."),
    5985: ("WinRM HTTP",     Severity.HIGH,     "Windows Remote Management over HTTP. Credentials sent unencrypted.",
           "Disable HTTP listener: winrm delete winrm/config/Listener?Address=*+Transport=HTTP. Use HTTPS (5986) only."),
    5986: ("WinRM HTTPS",    Severity.MEDIUM,   "Windows Remote Management over HTTPS.",
           "Restrict WinRM access to management network. Verify certificate configuration."),
    6379: ("Redis",          Severity.CRITICAL, "Redis is often deployed without authentication and is easily exploited.",
           "Set requirepass in redis.conf. Bind to 127.0.0.1: bind 127.0.0.1. Block TCP 6379 from untrusted networks."),
    8080: ("HTTP Alt",       Severity.INFO,     "Alternate HTTP port detected. Verify this is an authorised service.",
           "Ensure the application on port 8080 is patched and access-controlled."),
    8443: ("HTTPS Alt",      Severity.INFO,     "Alternate HTTPS port detected.",
           "Verify TLS configuration and that this service is intentionally exposed."),
    9200: ("Elasticsearch",  Severity.CRITICAL, "Elasticsearch is commonly exposed without authentication — data exposure risk.",
           "Enable X-Pack security (free tier). Bind to localhost: network.host: 127.0.0.1. Block 9200 from untrusted networks."),
    27017:("MongoDB",        Severity.CRITICAL, "MongoDB commonly deployed without authentication. Public exposure leads to data theft.",
           "Enable --auth on mongod. Bind to 127.0.0.1: net.bindIp: 127.0.0.1. Block TCP 27017 from untrusted networks."),
}

# Ports that are commonly expected on servers (generate INFO not HIGH)
EXPECTED_SERVER_PORTS = {80, 443, 8080, 8443, 22}


@register_module
class PortScanModule(ScanModule):
    name            = "open_ports"
    display_name    = "Open Port Scan"
    category        = "Ports"
    description     = "Scans for open TCP ports and detects running services"
    applies_to_os   = ["linux", "windows", "macos"]
    applies_to_mode = ["workstation", "server"]
    requires_tools  = []  # nmap preferred but falls back to socket scan

    # Quick scan: top 1000 ports. Full scan: 1–65535
    QUICK_PORTS = "1-1024,3306,3389,5432,5900,5985,5986,6379,8080,8443,9200,27017,2375,2376"
    FULL_PORTS  = "1-65535"

    def run(self) -> Iterator[Finding]:
        self._emit_progress(5, "Preparing port scan...")
        target      = getattr(self.config, "current_target", "127.0.0.1")
        port_range  = self.QUICK_PORTS if self.config.default_scan_type == "quick" else self.FULL_PORTS
        nmap_path   = self.config.tool("nmap")

        if nmap_path:
            yield from self._nmap_scan(target, port_range, nmap_path)
        else:
            self._emit_progress(10, "nmap not found — falling back to socket scan")
            yield from self._socket_scan(target)

    # ── nmap scan ─────────────────────────────────────────────────────────────
    def _nmap_scan(self, target: str, port_range: str, nmap_path: str) -> Iterator[Finding]:
        try:
            import nmap
        except ImportError:
            yield from self._socket_scan(target)
            return

        self._emit_progress(10, f"Running nmap scan on {target}...")
        nm = nmap.PortScanner(nmap_search_path=(nmap_path,))

        # Arguments: service version detection, default scripts, OS detection skipped (needs root+)
        args = f"-sV --version-intensity 5 -p {port_range} --open"
        if self.config.os_type != "windows":
            args += " -T4"  # Faster timing on Linux/macOS
        else:
            args += " -T3"

        self._emit_progress(20, "Scanning ports (this may take a moment)...")
        try:
            nm.scan(hosts=target, arguments=args)
        except Exception as e:
            self._emit_progress(90, f"nmap scan error: {e}")
            yield from self._socket_scan(target)
            return

        self._emit_progress(75, "Analysing scan results...")
        open_ports = []

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = sorted(nm[host][proto].keys())
                total_ports = len(ports)

                for i, port in enumerate(ports):
                    pct = 75 + int((i / max(total_ports, 1)) * 20)
                    self._emit_progress(pct, f"Checking port {port}...")

                    port_data = nm[host][proto][port]
                    if port_data.get("state") != "open":
                        continue

                    service  = port_data.get("name", "unknown")
                    product  = port_data.get("product", "")
                    version  = port_data.get("version", "")
                    svc_str  = f"{service} {product} {version}".strip()
                    open_ports.append(port)

                    # Check against dangerous ports registry
                    if port in DANGEROUS_PORTS:
                        svc_name, severity, desc, fix = DANGEROUS_PORTS[port]
                        # Downgrade to INFO if expected on servers and mode is server
                        if port in EXPECTED_SERVER_PORTS and self.config.default_scan_mode == "server":
                            severity = Severity.INFO
                        yield Finding(
                            title              = f"Port {port}/tcp open — {svc_name}",
                            severity           = severity,
                            category           = "Ports",
                            description        = f"{desc} Detected service: {svc_str or svc_name}.",
                            affected_component = f"Port {port}/tcp ({svc_str or service})",
                            remediation        = fix,
                            workaround         = f"Block port {port} on the host firewall as an immediate measure while planning full remediation.",
                        )
                    else:
                        # Unknown open port — report as INFO
                        yield Finding(
                            title              = f"Port {port}/tcp open — {service}",
                            severity           = Severity.INFO,
                            category           = "Ports",
                            description        = f"Open port detected: {port}/tcp running '{svc_str or service}'. Verify this service is required and authorised.",
                            affected_component = f"Port {port}/tcp ({svc_str})",
                            remediation        = f"If this service is not required, stop and disable it. Restrict access via firewall if it must remain running.",
                        )

        if not open_ports:
            yield Finding(
                title              = "No open ports detected",
                severity           = Severity.INFO,
                category           = "Ports",
                description        = f"Port scan of {target} found no open TCP ports in the scanned range.",
                affected_component = f"Host: {target}",
                remediation        = "No action required.",
            )

    # ── Socket fallback scan ───────────────────────────────────────────────────
    def _socket_scan(self, target: str) -> Iterator[Finding]:
        COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
                        1433,1521,2049,2375,3306,3389,5432,5900,5985,6379,8080,8443,9200,27017]
        self._emit_progress(15, f"Socket scanning {len(COMMON_PORTS)} common ports...")
        open_ports = []

        def check_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                result = s.connect_ex((target, port))
                s.close()
                return port if result == 0 else None
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_port, p): p for p in COMMON_PORTS}
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                pct = 15 + int((i / len(COMMON_PORTS)) * 75)
                self._emit_progress(pct, f"Scanning port {futures[future]}...")
                result = future.result()
                if result:
                    open_ports.append(result)

        self._emit_progress(90, f"Found {len(open_ports)} open port(s)")
        for port in sorted(open_ports):
            if port in DANGEROUS_PORTS:
                svc_name, severity, desc, fix = DANGEROUS_PORTS[port]
                yield Finding(
                    title              = f"Port {port}/tcp open — {svc_name}",
                    severity           = severity,
                    category           = "Ports",
                    description        = f"{desc} (Detected via socket scan — install nmap for full service version details.)",
                    affected_component = f"Port {port}/tcp",
                    remediation        = fix,
                    workaround         = f"Block port {port} on the host firewall immediately.",
                )
            else:
                yield Finding(
                    title              = f"Port {port}/tcp open",
                    severity           = Severity.INFO,
                    category           = "Ports",
                    description        = f"Port {port}/tcp is open. Install nmap for service version identification.",
                    affected_component = f"Port {port}/tcp",
                    remediation        = "Verify this service is required. Restrict access if not needed.",
                )
