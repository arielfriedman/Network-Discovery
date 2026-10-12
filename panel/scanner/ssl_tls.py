"""
SentinelScan — scanner/ssl_tls.py
SSL/TLS Certificate & Cipher Suite Audit
Phase 6 — Scan Modules Tier 3

Detects HTTPS services on the target host, checks certificate validity,
expiry, trust chain, TLS protocol versions, weak ciphers, and HTTP
security headers (HSTS, X-Frame-Options, etc.)
Uses Python's built-in ssl module + openssl CLI fallback.
"""
from __future__ import annotations
import ssl
import socket
import datetime
import re
import shutil
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module

# Ports to probe for TLS services
TLS_PORTS = [443, 8443, 8080, 8444, 9443, 4443, 6443, 10443]
# Ports to probe in full scan mode
TLS_PORTS_FULL = TLS_PORTS + [465, 587, 636, 993, 995, 3389, 5986, 8883]

WEAK_PROTOCOLS  = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHERS    = {
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
    "MD5", "RC2", "IDEA", "SEED",
}

# HTTP security headers that should be present on HTTPS responses
SECURITY_HEADERS = {
    "Strict-Transport-Security": (Severity.MEDIUM, "HSTS not set — browsers may allow HTTP downgrade"),
    "X-Content-Type-Options":    (Severity.LOW,    "X-Content-Type-Options missing — MIME sniffing possible"),
    "X-Frame-Options":           (Severity.LOW,    "X-Frame-Options missing — clickjacking possible"),
    "Content-Security-Policy":   (Severity.LOW,    "Content-Security-Policy missing — XSS risk"),
    "X-XSS-Protection":          (Severity.INFO,   "X-XSS-Protection header absent (deprecated but still useful)"),
    "Referrer-Policy":           (Severity.INFO,   "Referrer-Policy not configured"),
}


@register_module
class SSLTLSModule(ScanModule):
    name             = "ssl_tls"
    display_name     = "SSL/TLS Audit"
    category         = "SSL/TLS"
    description      = "Certificate expiry, TLS version, weak ciphers, and HTTP security headers"
    applies_to_os    = ["linux", "windows", "macos"]
    applies_to_mode  = ["workstation", "server"]

    def run(self) -> Iterator[Finding]:
        target = getattr(self.config, "current_target", "127.0.0.1")
        ports  = TLS_PORTS_FULL if self.config.default_scan_type == "full" else TLS_PORTS
        self._emit_progress(5, f"Probing TLS services on {target}...")

        tls_services = self._discover_tls_services(target, ports)

        if not tls_services:
            yield Finding(
                title              = f"No TLS services detected on {target}",
                severity           = Severity.INFO,
                category           = "SSL/TLS",
                description        = f"No HTTPS/TLS services found on the checked ports: {', '.join(str(p) for p in ports)}.",
                affected_component = f"Host: {target}",
                remediation        = "No action required if this host is not expected to serve TLS.",
            )
            return

        total = len(tls_services)
        for i, port in enumerate(tls_services):
            pct = 10 + int((i / total) * 85)
            self._emit_progress(pct, f"Auditing TLS on port {port}...")
            yield from self._audit_tls_service(target, port)

    # ── Service discovery ─────────────────────────────────────────────────────
    def _discover_tls_services(self, host: str, ports: list[int]) -> list[int]:
        found = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                if s.connect_ex((host, port)) == 0:
                    found.append(port)
                s.close()
            except Exception:
                continue
        return found

    # ── Per-service audit ─────────────────────────────────────────────────────
    def _audit_tls_service(self, host: str, port: int) -> Iterator[Finding]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_OPTIONAL

        try:
            conn = ctx.wrap_socket(
                socket.create_connection((host, port), timeout=5),
                server_hostname=host,
            )
        except ssl.SSLError as e:
            yield Finding(
                title              = f"TLS handshake failed on port {port}: {str(e)[:80]}",
                severity           = Severity.HIGH,
                category           = "SSL/TLS",
                description        = f"SSL/TLS negotiation failed on {host}:{port}. Error: {e}",
                affected_component = f"{host}:{port}",
                remediation        = "Check TLS configuration, supported versions, and certificate validity.",
            )
            return
        except Exception as e:
            return

        try:
            cert        = conn.getpeercert()
            tls_version = conn.version()
            cipher_info = conn.cipher()  # (name, protocol, bits)
            cipher_name = cipher_info[0] if cipher_info else "unknown"
            cipher_bits = cipher_info[2] if cipher_info else 0

            yield from self._check_cert(cert, host, port, tls_version)
            yield from self._check_tls_version(tls_version, host, port)
            yield from self._check_cipher(cipher_name, cipher_bits, host, port)
        finally:
            conn.close()

        # openssl additional checks (if available)
        if shutil.which("openssl"):
            yield from self._openssl_checks(host, port)

        # HTTP security headers check (port 443/8443/etc)
        if port in (443, 8443, 8444, 9443, 4443, 10443):
            yield from self._check_http_headers(host, port)

    # ── Certificate checks ────────────────────────────────────────────────────
    def _check_cert(self, cert: dict, host: str, port: int,
                    tls_version: str) -> Iterator[Finding]:
        if not cert:
            yield Finding(
                title              = f"No certificate presented on {host}:{port}",
                severity           = Severity.HIGH,
                category           = "SSL/TLS",
                description        = f"The service on {host}:{port} did not present an SSL/TLS certificate.",
                affected_component = f"{host}:{port}",
                remediation        = "Install a valid certificate. Use Let's Encrypt for free trusted certs.",
            )
            return

        # Expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                now       = datetime.datetime.utcnow()
                days_left = (not_after - now).days

                if days_left < 0:
                    yield Finding(
                        title              = f"Certificate EXPIRED {abs(days_left)} day(s) ago on {host}:{port}",
                        severity           = Severity.CRITICAL,
                        category           = "SSL/TLS",
                        description        = f"The TLS certificate for {host}:{port} expired on {not_after.strftime('%Y-%m-%d')}. Browsers and clients will reject connections.",
                        affected_component = f"TLS certificate: {host}:{port}",
                        remediation        = "Renew immediately. Use certbot for Let's Encrypt:\ncertbot renew\nOr use your CA's renewal process.",
                        cvss_score         = 7.5,
                    )
                elif days_left <= 7:
                    yield Finding(
                        title              = f"Certificate expires in {days_left} day(s): {host}:{port}",
                        severity           = Severity.CRITICAL,
                        category           = "SSL/TLS",
                        description        = f"TLS certificate expires in {days_left} days ({not_after.strftime('%Y-%m-%d')}). Immediate renewal required.",
                        affected_component = f"TLS certificate: {host}:{port}",
                        remediation        = "Renew now: certbot renew --force-renewal",
                        cvss_score         = 7.0,
                    )
                elif days_left <= 30:
                    yield Finding(
                        title              = f"Certificate expires in {days_left} day(s): {host}:{port}",
                        severity           = Severity.HIGH,
                        category           = "SSL/TLS",
                        description        = f"TLS certificate will expire in {days_left} days. Plan renewal now.",
                        affected_component = f"TLS certificate: {host}:{port}",
                        remediation        = "Schedule renewal. Automate with: certbot renew --pre-hook / --post-hook",
                    )
                elif days_left <= 90:
                    yield Finding(
                        title              = f"Certificate expires in {days_left} day(s): {host}:{port}",
                        severity           = Severity.MEDIUM,
                        category           = "SSL/TLS",
                        description        = f"Certificate expires {not_after.strftime('%Y-%m-%d')}. Set up automated renewal.",
                        affected_component = f"TLS certificate: {host}:{port}",
                        remediation        = "Enable auto-renewal: certbot renew (cron/systemd timer).",
                    )
                else:
                    yield Finding(
                        title              = f"Certificate valid for {days_left} day(s): {host}:{port}",
                        severity           = Severity.INFO,
                        category           = "SSL/TLS",
                        description        = f"Certificate valid until {not_after.strftime('%Y-%m-%d')}.",
                        affected_component = f"TLS certificate: {host}:{port}",
                        remediation        = "No action required. Ensure auto-renewal is configured.",
                    )
            except (ValueError, TypeError):
                pass

        # Self-signed check (issuer == subject)
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        if subject == issuer:
            yield Finding(
                title              = f"Self-signed certificate on {host}:{port}",
                severity           = Severity.HIGH,
                category           = "SSL/TLS",
                description        = f"The TLS certificate on {host}:{port} is self-signed. Clients will show security warnings and the connection cannot be trusted without manual certificate installation.",
                affected_component = f"TLS certificate: {host}:{port}",
                remediation        = "Replace with a certificate from a trusted CA. Let's Encrypt provides free certificates:\ncertbot certonly --standalone -d {host}",
                cvss_score         = 6.5,
            )

        # CN mismatch check
        cn = subject.get("commonName", "")
        if cn and host not in (cn, f"*.{'.'.join(host.split('.')[1:])}"):
            # Check SANs
            sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            if sans:
                if not any(host == s or (s.startswith("*.") and host.endswith(s[2:])) for s in sans):
                    yield Finding(
                        title              = f"Certificate hostname mismatch on {host}:{port}",
                        severity           = Severity.HIGH,
                        category           = "SSL/TLS",
                        description        = f"Certificate CN/SANs ({cn}, {', '.join(sans[:3])}) do not match host {host}.",
                        affected_component = f"TLS certificate CN/SAN: {host}:{port}",
                        remediation        = "Reissue certificate with the correct hostname in the Subject Alternative Names.",
                        cvss_score         = 6.5,
                    )

    # ── TLS version ───────────────────────────────────────────────────────────
    def _check_tls_version(self, version: str, host: str, port: int) -> Iterator[Finding]:
        if version in WEAK_PROTOCOLS:
            yield Finding(
                title              = f"Weak TLS version in use: {version} on {host}:{port}",
                severity           = Severity.HIGH,
                category           = "SSL/TLS",
                description        = f"The negotiated TLS version is {version}. {version} has known cryptographic weaknesses (POODLE, BEAST, ROBOT) and should be disabled.",
                affected_component = f"TLS version: {host}:{port}",
                remediation        = "Disable old TLS versions in your web server config:\nNginx: ssl_protocols TLSv1.2 TLSv1.3;\nApache: SSLProtocol -all +TLSv1.2 +TLSv1.3\nWindows: via IIS Crypto or Nartac Software",
                cvss_score         = 7.5,
                cve_ids            = ["CVE-2014-3566"] if "1.0" in version or "SSLv3" in version else [],
            )

        # Check if TLS 1.3 is available via openssl
        if shutil.which("openssl") and version and version < "TLSv1.3":
            tls13_out, _, rc = self.run_command(
                ["openssl", "s_client", "-connect", f"{host}:{port}",
                 "-tls1_3", "-brief"], timeout=5)
            if rc == 0 and "CONNECTED" in tls13_out:
                pass  # TLS 1.3 available, no finding
            elif version < "TLSv1.3":
                yield Finding(
                    title              = f"TLS 1.3 not supported on {host}:{port} (using {version})",
                    severity           = Severity.LOW,
                    category           = "SSL/TLS",
                    description        = f"TLS 1.3 provides significant security and performance improvements over {version}.",
                    affected_component = f"TLS version: {host}:{port}",
                    remediation        = "Enable TLS 1.3:\nNginx: ssl_protocols TLSv1.2 TLSv1.3;\nOpenSSL 1.1.1+ supports TLS 1.3 by default.",
                )

    # ── Cipher check ──────────────────────────────────────────────────────────
    def _check_cipher(self, cipher: str, bits: int,
                       host: str, port: int) -> Iterator[Finding]:
        upper = cipher.upper()
        for weak in WEAK_CIPHERS:
            if weak in upper:
                yield Finding(
                    title              = f"Weak cipher negotiated: {cipher} on {host}:{port}",
                    severity           = Severity.HIGH,
                    category           = "SSL/TLS",
                    description        = f"The TLS session negotiated weak cipher '{cipher}'. {weak}-based ciphers are cryptographically broken or export-grade.",
                    affected_component = f"TLS cipher: {host}:{port}",
                    remediation        = "Configure strong ciphers only:\nNginx: ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305';\nApache: SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES",
                    cvss_score         = 6.5,
                )
                return

        if bits and bits < 128:
            yield Finding(
                title              = f"Short cipher key length: {bits} bits on {host}:{port}",
                severity           = Severity.HIGH,
                category           = "SSL/TLS",
                description        = f"Cipher {cipher} uses only {bits}-bit keys, which is considered insecure.",
                affected_component = f"TLS cipher key length: {host}:{port}",
                remediation        = "Configure 256-bit AES-GCM ciphers. Disable all export and short-key ciphers.",
                cvss_score         = 6.5,
            )

    # ── openssl extended checks ───────────────────────────────────────────────
    def _openssl_checks(self, host: str, port: int) -> Iterator[Finding]:
        # Check for SSLv3 support (POODLE)
        out, _, rc = self.run_command(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-ssl3", "-brief"], timeout=4)
        if rc == 0 and "CONNECTED" in out:
            yield Finding(
                title              = f"SSLv3 accepted on {host}:{port} (POODLE vulnerability)",
                severity           = Severity.CRITICAL,
                category           = "SSL/TLS",
                description        = "The server accepts SSLv3 connections, which are vulnerable to the POODLE attack (CVE-2014-3566) allowing decryption of encrypted traffic.",
                affected_component = f"SSLv3: {host}:{port}",
                remediation        = "Disable SSLv3 entirely in your TLS configuration.",
                cvss_score         = 7.4,
                cve_ids            = ["CVE-2014-3566"],
            )

        # Check for TLS 1.0 (BEAST/POODLE)
        out10, _, rc10 = self.run_command(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-tls1", "-brief"], timeout=4)
        if rc10 == 0 and "CONNECTED" in out10:
            yield Finding(
                title              = f"TLS 1.0 accepted on {host}:{port}",
                severity           = Severity.HIGH,
                category           = "SSL/TLS",
                description        = "TLS 1.0 is accepted. It is deprecated (RFC 8996) and vulnerable to BEAST and POODLE attacks. PCI-DSS 3.2+ requires TLS 1.2 minimum.",
                affected_component = f"TLS 1.0: {host}:{port}",
                remediation        = "Disable TLS 1.0 and 1.1 in server config.",
                cvss_score         = 6.5,
                cve_ids            = ["CVE-2011-3389"],
            )

    # ── HTTP security headers ─────────────────────────────────────────────────
    def _check_http_headers(self, host: str, port: int) -> Iterator[Finding]:
        import urllib.request
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            url = f"https://{host}:{port}/"
            req = urllib.request.Request(url, headers={"User-Agent": "SentinelScan/1.0"})
            with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            return

        for header, (severity, desc) in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                yield Finding(
                    title              = f"Missing HTTP security header: {header} on {host}:{port}",
                    severity           = severity,
                    category           = "SSL/TLS",
                    description        = f"{desc}. The {header} header is absent from HTTPS responses.",
                    affected_component = f"HTTP headers: https://{host}:{port}",
                    remediation        = self._header_fix(header),
                )

        # Check HSTS max-age if present
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            match = re.search(r"max-age=(\d+)", hsts)
            if match:
                max_age = int(match.group(1))
                if max_age < 15552000:  # < 180 days
                    yield Finding(
                        title              = f"HSTS max-age too short: {max_age}s on {host}:{port}",
                        severity           = Severity.LOW,
                        category           = "SSL/TLS",
                        description        = f"HSTS max-age is {max_age} seconds ({max_age // 86400} days). OWASP recommends at least 15,552,000s (180 days). HSTS preload requires 31,536,000s (1 year).",
                        affected_component = f"HSTS max-age: {host}:{port}",
                        remediation        = "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    )

    def _header_fix(self, header: str) -> str:
        fixes = {
            "Strict-Transport-Security": "Add to web server config:\nNginx: add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';\nApache: Header always set Strict-Transport-Security 'max-age=31536000'",
            "X-Content-Type-Options":    "add_header X-Content-Type-Options nosniff;",
            "X-Frame-Options":           "add_header X-Frame-Options SAMEORIGIN;",
            "Content-Security-Policy":   "add_header Content-Security-Policy \"default-src 'self'\";",
            "X-XSS-Protection":          "add_header X-XSS-Protection '1; mode=block';",
            "Referrer-Policy":           "add_header Referrer-Policy 'strict-origin-when-cross-origin';",
        }
        return fixes.get(header, f"Add the {header} header to your web server configuration.")
