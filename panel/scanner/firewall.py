"""
SentinelScan — scanner/firewall.py
Host Firewall Status & Rules Audit
Phase 4 — Scan Modules Tier 1

Linux  : ufw, firewalld, iptables
Windows: netsh advfirewall
macOS  : socketfilterfw (Application Firewall), pf
"""
from __future__ import annotations
import re
import subprocess
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module


@register_module
class FirewallModule(ScanModule):
    name            = "firewall_status"
    display_name    = "Firewall Status"
    category        = "Firewall"
    description     = "Checks host firewall state, default policies, and rule gaps"
    applies_to_os   = ["linux", "windows", "macos"]
    applies_to_mode = ["workstation", "server"]

    def run(self) -> Iterator[Finding]:
        self._emit_progress(10, "Detecting firewall type...")
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
        import shutil

        self._emit_progress(15, "Checking Linux firewall tools...")
        has_ufw        = shutil.which("ufw") is not None
        has_firewalld  = shutil.which("firewall-cmd") is not None
        has_iptables   = shutil.which("iptables") is not None
        has_nftables   = shutil.which("nft") is not None

        fw_found = has_ufw or has_firewalld or has_iptables or has_nftables

        if not fw_found:
            yield Finding(
                title              = "No firewall tool detected",
                severity           = Severity.HIGH,
                category           = "Firewall",
                description        = "No firewall management tool (ufw, firewalld, iptables, nftables) was found on this system.",
                affected_component = "Host firewall",
                remediation        = "Install and enable a firewall:\nDebian/Ubuntu: sudo apt install ufw && sudo ufw enable\nRHEL/Fedora:   sudo dnf install firewalld && sudo systemctl enable --now firewalld",
                workaround         = "Apply network-level ACLs upstream as an interim measure.",
                cvss_score         = 7.5,
            )
            return

        # ── UFW ───────────────────────────────────────────────────────────────
        if has_ufw:
            yield from self._check_ufw()

        # ── firewalld ─────────────────────────────────────────────────────────
        elif has_firewalld:
            yield from self._check_firewalld()

        # ── iptables ──────────────────────────────────────────────────────────
        elif has_iptables:
            yield from self._check_iptables()

    def _check_ufw(self) -> Iterator[Finding]:
        self._emit_progress(25, "Checking ufw status...")
        stdout, _, rc = self.run_command(["ufw", "status", "verbose"])

        if "inactive" in stdout.lower() or rc != 0:
            yield Finding(
                title              = "ufw firewall is INACTIVE",
                severity           = Severity.HIGH,
                category           = "Firewall",
                description        = "ufw is installed but not active. The system has no host-based packet filtering.",
                affected_component = "ufw (Uncomplicated Firewall)",
                remediation        = "Enable ufw with a default-deny policy:\nsudo ufw default deny incoming\nsudo ufw default allow outgoing\nsudo ufw allow ssh\nsudo ufw enable",
                workaround         = "Apply upstream firewall rules immediately.",
                cvss_score         = 7.5,
            )
            return

        yield Finding(
            title              = "ufw firewall is active",
            severity           = Severity.INFO,
            category           = "Firewall",
            description        = "ufw is enabled and active.",
            affected_component = "ufw",
            remediation        = "No action required.",
        )
        self._emit_progress(40, "Analysing ufw rules...")

        # Check for any-to-any allow rules
        if re.search(r"ALLOW\s+Anywhere.*?ALLOW\s+Anywhere", stdout, re.DOTALL):
            yield Finding(
                title              = "ufw: Overly permissive ALLOW Anywhere rule detected",
                severity           = Severity.MEDIUM,
                category           = "Firewall",
                description        = "A firewall rule allows connections from ANY source to ANY destination. This negates the firewall's protective value.",
                affected_component = "ufw rules",
                remediation        = "Review ufw rules: sudo ufw status numbered\nDelete overly broad rules: sudo ufw delete <rule_number>",
                workaround         = "Document all intended exceptions before deletion.",
            )

        # Check default incoming policy
        if "default: deny (incoming)" not in stdout.lower() and \
           "default: disabled" not in stdout.lower():
            yield Finding(
                title              = "ufw: Default incoming policy is not DENY",
                severity           = Severity.MEDIUM,
                category           = "Firewall",
                description        = "The default policy for incoming connections should be DENY. Any non-DENY policy allows unexpected inbound access.",
                affected_component = "ufw default policy",
                remediation        = "Set default deny: sudo ufw default deny incoming",
            )

        self._emit_progress(90, "ufw analysis complete")

    def _check_firewalld(self) -> Iterator[Finding]:
        self._emit_progress(25, "Checking firewalld status...")
        stdout, _, rc = self.run_command(["systemctl", "is-active", "firewalld"])

        if "inactive" in stdout or rc != 0:
            yield Finding(
                title              = "firewalld is not running",
                severity           = Severity.HIGH,
                category           = "Firewall",
                description        = "firewalld is installed but not running. No host-based firewall is active.",
                affected_component = "firewalld",
                remediation        = "Enable and start firewalld:\nsudo systemctl enable --now firewalld\nsudo firewall-cmd --set-default-zone=drop",
                cvss_score         = 7.5,
            )
            return

        yield Finding(title="firewalld is active", severity=Severity.INFO,
                      category="Firewall", description="firewalld is running.",
                      affected_component="firewalld", remediation="No action required.")

        self._emit_progress(50, "Checking firewalld default zone...")
        z_out, _, _ = self.run_command(["firewall-cmd", "--get-default-zone"])
        zone = z_out.strip()
        permissive_zones = {"public", "trusted", "home", "work", "internal"}
        if zone in {"trusted"}:
            yield Finding(
                title              = f"firewalld default zone is '{zone}' — all connections trusted",
                severity           = Severity.HIGH,
                category           = "Firewall",
                description        = f"The '{zone}' zone allows all inbound connections. This provides no protection.",
                affected_component = "firewalld default zone",
                remediation        = "Change default zone to 'drop' or 'block':\nsudo firewall-cmd --set-default-zone=drop --permanent\nsudo firewall-cmd --reload",
            )

        self._emit_progress(75, "Checking for exposed services...")
        svc_out, _, _ = self.run_command(["firewall-cmd", "--list-all"])
        if "services:" in svc_out:
            services_line = [l for l in svc_out.splitlines() if "services:" in l]
            if services_line:
                svcs = services_line[0].replace("services:", "").strip()
                if "telnet" in svcs or "ftp" in svcs:
                    yield Finding(
                        title              = f"firewalld allows insecure services: {svcs}",
                        severity           = Severity.HIGH,
                        category           = "Firewall",
                        description        = "firewalld rules allow access to inherently insecure services (Telnet, FTP).",
                        affected_component = "firewalld service rules",
                        remediation        = "Remove insecure services:\nsudo firewall-cmd --remove-service=telnet --permanent\nsudo firewall-cmd --reload",
                    )

    def _check_iptables(self) -> Iterator[Finding]:
        self._emit_progress(25, "Checking iptables rules...")
        stdout, _, rc = self.run_command(["iptables", "-L", "-n", "--line-numbers"])

        if rc != 0:
            yield Finding(
                title="Could not read iptables rules",
                severity=Severity.MEDIUM, category="Firewall",
                description="iptables query failed — may require root privileges.",
                affected_component="iptables",
                remediation="Run SentinelScan as root/sudo to read firewall rules.",
            )
            return

        # Check if all chains are ACCEPT (no rules)
        if stdout.count("Chain INPUT (policy ACCEPT)") > 0:
            input_lines = []
            in_input = False
            for line in stdout.splitlines():
                if "Chain INPUT" in line:
                    in_input = True
                elif line.startswith("Chain ") and in_input:
                    break
                elif in_input:
                    input_lines.append(line)

            real_rules = [l for l in input_lines if l.strip() and not l.startswith("target")]
            if not real_rules:
                yield Finding(
                    title              = "iptables: INPUT chain ACCEPT with no rules — all traffic allowed",
                    severity           = Severity.HIGH,
                    category           = "Firewall",
                    description        = "The iptables INPUT chain has a default ACCEPT policy with no filtering rules. All inbound traffic is permitted.",
                    affected_component = "iptables INPUT chain",
                    remediation        = "Add a default-drop policy and explicit allow rules:\niptables -P INPUT DROP\niptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\niptables -A INPUT -p tcp --dport 22 -j ACCEPT\nPersist with: iptables-save > /etc/iptables/rules.v4",
                    cvss_score         = 7.5,
                )
            else:
                yield Finding(title="iptables INPUT rules active", severity=Severity.INFO,
                              category="Firewall",
                              description="iptables has INPUT filtering rules in place.",
                              affected_component="iptables", remediation="Review rules periodically.")

    # ─────────────────────────────────────────────────────────────────────────
    # WINDOWS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_windows(self) -> Iterator[Finding]:
        self._emit_progress(15, "Querying Windows Firewall profiles...")
        stdout, _, rc = self.run_command(
            ["netsh", "advfirewall", "show", "allprofiles"], timeout=20)

        if rc != 0 or not stdout:
            yield Finding(
                title="Could not query Windows Firewall",
                severity=Severity.MEDIUM, category="Firewall",
                description="netsh advfirewall query failed. Run as Administrator.",
                affected_component="Windows Firewall",
                remediation="Run SentinelScan as Administrator.",
            )
            return

        self._emit_progress(40, "Parsing firewall profile states...")
        profiles = {"Domain": {}, "Private": {}, "Public": {}}
        current = None
        for line in stdout.splitlines():
            line = line.strip()
            for p in profiles:
                if f"{p} Profile Settings:" in line:
                    current = p; break
            if current:
                if "State" in line and "ON" in line.upper():
                    profiles[current]["enabled"] = True
                elif "State" in line and "OFF" in line.upper():
                    profiles[current]["enabled"] = False
                if "Inbound Connections" in line:
                    profiles[current]["inbound"] = line.split()[-1].strip()
                if "Outbound Connections" in line:
                    profiles[current]["outbound"] = line.split()[-1].strip()

        self._emit_progress(65, "Analysing profile policies...")
        disabled_profiles = []
        allow_inbound_profiles = []

        for profile, state in profiles.items():
            if state.get("enabled") is False:
                disabled_profiles.append(profile)
            inbound = state.get("inbound", "").upper()
            if inbound and inbound not in ("BLOCK", "BLOCKINBOUND", "BLOCK (DEFAULT INBOUND ACTION)"):
                if inbound not in ("", "N/A"):
                    allow_inbound_profiles.append(f"{profile}({inbound})")

        if disabled_profiles:
            yield Finding(
                title              = f"Windows Firewall DISABLED on: {', '.join(disabled_profiles)}",
                severity           = Severity.HIGH,
                category           = "Firewall",
                description        = f"Windows Firewall is disabled on the following network profiles: {', '.join(disabled_profiles)}. This leaves the machine unprotected on those network types.",
                affected_component = f"Windows Defender Firewall — {', '.join(disabled_profiles)} profile(s)",
                remediation        = "Enable all firewall profiles:\nnetsh advfirewall set allprofiles state on\nOr: Windows Security → Firewall & network protection → Turn on for all profiles",
                cvss_score         = 7.5,
            )
        else:
            yield Finding(title="Windows Firewall active on all profiles", severity=Severity.INFO,
                          category="Firewall",
                          description="Windows Defender Firewall is enabled on Domain, Private, and Public profiles.",
                          affected_component="Windows Defender Firewall", remediation="No action required.")

        if allow_inbound_profiles:
            yield Finding(
                title              = "Windows Firewall: inbound connections not blocked on some profiles",
                severity           = Severity.MEDIUM,
                category           = "Firewall",
                description        = f"The following profiles do not have a default BLOCK inbound policy: {', '.join(allow_inbound_profiles)}",
                affected_component = "Windows Defender Firewall — inbound policy",
                remediation        = "Set default inbound to block:\nnetsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
            )

        self._emit_progress(85, "Checking for RDP exposure...")
        rdp_out, _, _ = self.run_command(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             "name=Remote Desktop - User Mode (TCP-In)", "profile=public"])
        if "Enabled:                              Yes" in rdp_out:
            yield Finding(
                title              = "RDP allowed through Windows Firewall on Public profile",
                severity           = Severity.HIGH,
                category           = "Firewall",
                description        = "The Windows Firewall Public profile has an allow-rule for Remote Desktop (TCP 3389). RDP should never be exposed on public networks.",
                affected_component = "Windows Firewall — Remote Desktop rule (Public profile)",
                remediation        = "Disable RDP on the public profile:\nnetsh advfirewall firewall set rule name='Remote Desktop - User Mode (TCP-In)' profile=public new enable=no",
                workaround         = "Restrict RDP access via VPN — only allow RDP from VPN network adapters.",
                cvss_score         = 8.5,
            )

    # ─────────────────────────────────────────────────────────────────────────
    # MACOS
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_macos(self) -> Iterator[Finding]:
        self._emit_progress(15, "Checking macOS Application Firewall...")
        fw_cmd = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        stdout, _, rc = self.run_command([fw_cmd, "--getglobalstate"])

        if rc != 0:
            yield Finding(
                title="Could not query macOS Application Firewall",
                severity=Severity.LOW, category="Firewall",
                description="socketfilterfw query failed. This may require admin privileges.",
                affected_component="macOS Application Firewall",
                remediation="Run with sudo or check System Settings → Privacy & Security → Firewall.",
            )
        elif "Firewall is disabled" in stdout or "disabled" in stdout.lower():
            yield Finding(
                title              = "macOS Application Firewall is DISABLED",
                severity           = Severity.HIGH,
                category           = "Firewall",
                description        = "The macOS built-in Application Firewall is not enabled. Inbound connections to applications are unrestricted.",
                affected_component = "macOS Application Firewall",
                remediation        = "Enable via Terminal:\nsudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on\nOr: System Settings → Privacy & Security → Firewall → Turn On",
                cvss_score         = 6.5,
            )
        else:
            yield Finding(title="macOS Application Firewall is enabled", severity=Severity.INFO,
                          category="Firewall", description="The built-in Application Firewall is active.",
                          affected_component="macOS Application Firewall", remediation="No action required.")

        self._emit_progress(45, "Checking stealth mode...")
        sm_out, _, _ = self.run_command([fw_cmd, "--getstealthmode"])
        if "disabled" in sm_out.lower():
            yield Finding(
                title              = "macOS Firewall stealth mode is disabled",
                severity           = Severity.LOW,
                category           = "Firewall",
                description        = "Stealth mode prevents the system from responding to ICMP ping probes and port scan probes, making it harder to discover.",
                affected_component = "macOS Firewall — stealth mode",
                remediation        = "Enable stealth mode:\nsudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
                workaround         = "Low priority for workstations on trusted networks.",
            )

        self._emit_progress(70, "Checking pf (packet filter) status...")
        pf_out, _, _ = self.run_command(["pfctl", "-s", "info"])
        if "Status: Disabled" in pf_out:
            yield Finding(
                title              = "macOS pf (packet filter) is disabled",
                severity           = Severity.INFO,
                category           = "Firewall",
                description        = "The BSD-level pf firewall is disabled. For servers, pf provides more granular control than the Application Firewall.",
                affected_component = "macOS pf (packet filter)",
                remediation        = "For servers, enable pf with a ruleset in /etc/pf.conf:\nsudo pfctl -e",
                workaround         = "Application Firewall is sufficient for workstations.",
            )
