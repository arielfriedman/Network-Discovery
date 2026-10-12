"""
Cisco simulators for the device lab: an SSH server that behaves like a
Catalyst 9300 (IOS-XE 17.12) and, optionally, a Catalyst 1300 (Cisco
Business CLI), closely enough for every wizard in devices/cisco.py.

    cd panel && python3 -m devices.lab cisco cisco-cbs

Test doubles, not emulators: the running configuration lives in memory,
commands outside what the wizards use answer "% Invalid input".
"""
from __future__ import annotations

import copy
import ipaddress
import os
import re
import socket
import threading
import time

import paramiko

from . import lab

USERS = {"admin": ("lab-cisco-pass", 15), "operator": ("lab-cisco-op", 1)}
ENABLE_SECRET = "lab-cisco-enable"
INVALID = "% Invalid input detected at '^' marker."


def host_key(name: str) -> paramiko.RSAKey:
    """One persistent SSH host key per simulator, so the pinned fingerprint survives restarts."""
    lab._CERT_DIR.mkdir(mode=0o700, exist_ok=True)
    path = lab._CERT_DIR / f"{name}-ssh-host.key"
    if not path.exists():
        k = paramiko.RSAKey.generate(2048)
        k.write_private_key_file(str(path))
        os.chmod(path, 0o600)
    return paramiko.RSAKey(filename=str(path))


IF_KEYS = ("description", "ip address", "switchport mode", "switchport access vlan", "switchport trunk allowed vlan",
           "switchport trunk native vlan", "name", "vrf forwarding", "negotiation", "transport input",
           "exec-timeout", "access-class", "login", "path", "maximum")


def ikey(line: str) -> str:
    for k in IF_KEYS:
        if line == k or line.startswith(k + " "):
            return k
    return line


def set_kid(kids: list, line: str) -> None:
    k = ikey(line)
    kids[:] = [x for x in kids if ikey(x) != k] + [line]


def del_kid(kids: list, key: str) -> None:
    kids[:] = [x for x in kids if ikey(x) != key]


def is_mask(m: str) -> bool:
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{m}")
        return True
    except ValueError:
        return False


def vlan_ok(s: str) -> bool:
    return s.isdigit() and 1 <= int(s) <= 4094


ABBR = [("GigabitEthernet", "Gi"), ("TenGigabitEthernet", "Te"), ("Vlan", "Vl"), ("Loopback", "Lo")]


class CiscoSim:
    def __init__(self, family: str = "iosxe"):
        self.family = family
        self.lock = threading.RLock()
        self.minute = 60.0          # seconds per "minute" of the revert timer (tests shrink it)
        self.hang = False           # True: log in, then never print anything (timeout tests)
        self.controller = False     # True: show version reports SD-WAN controller mode
        self.saves = 0
        self.revert_timer: threading.Timer | None = None
        self.snapshot = None
        self.reverts = 0
        self.log: list[str] = []
        ifs = {}
        if family == "cbs":
            self.model, self.hostname = "C1300-24P-4G", "switch5c1d2e"
            for i in range(1, 25):
                ifs[f"GigabitEthernet1/0/{i}"] = []
            for i in range(1, 5):
                ifs[f"TenGigabitEthernet1/0/{i}"] = []
            ifs["vlan 1"] = ["ip address 192.168.1.254 255.255.255.0"]
        else:
            self.model, self.hostname = "C9300-48P", "SW-LAB-9300"
            ifs["Vlan1"] = ["ip address 192.168.1.10 255.255.255.0"]
            ifs["GigabitEthernet0/0"] = ["vrf forwarding Mgmt-vrf", "no ip address", "negotiation auto"]
            for i in range(1, 25):
                ifs[f"GigabitEthernet1/0/{i}"] = []
            for i in range(1, 5):
                ifs[f"TenGigabitEthernet1/1/{i}"] = []
            ifs["GigabitEthernet1/0/1"] = ["description Uplink to core", "switchport mode trunk"]
            ifs["GigabitEthernet1/0/7"] = ["switchport access vlan 10", "switchport mode access", "shutdown"]
        self.state = {
            "hostname": self.hostname, "domain": None, "ns": ["192.168.1.1"], "ntp": [],
            "banner": None, "ssh_version": None, "http": True, "https": True, "routes": [
                "ip route 0.0.0.0 0.0.0.0 192.168.1.1"], "vlans": {1: "default", 10: "Servers"},
            "ifs": ifs, "vty": {"0 4": ["login local", "transport input ssh telnet"], "5 15": ["login local"]},
            "acls": {}, "archive": None,
        }
        self.startup = copy.deepcopy(self.state)

    # ── rendering ───────────────────────────────────────────────────────────
    def running(self) -> str:
        s = self.state
        if self.family == "cbs":
            return self._running_cbs()
        out = ["!", "! Last configuration change at 20:00:00 UTC Mon Oct 12 2026 by admin", "!", "version 17.12",
               "service timestamps debug datetime msec", "service timestamps log datetime msec",
               "service password-encryption", "!", f"hostname {s['hostname']}", "!",
               "vrf definition Mgmt-vrf", " !", " address-family ipv4", " exit-address-family", "!",
               "enable secret 9 $9$labHashOnlyNotASecret", "!"]
        if s["domain"]:
            out.append(f"ip domain name {s['domain']}")
        if s["ns"]:
            out.append(f"ip name-server {' '.join(s['ns'])}")
        out += ["login on-success log", "!", "username admin privilege 15 secret 9 $9$labHashOnly", "!"]
        if s["archive"] is not None:
            out += ["archive"] + [f" {k}" for k in s["archive"]] + ["!"]
        for name, kids in s["ifs"].items():
            out += [f"interface {name}"] + [f" {k}" for k in kids] + ["!"]
        out.append("ip http server" if s["http"] else "no ip http server")
        out += ["ip http authentication local"]
        out.append("ip http secure-server" if s["https"] else "no ip http secure-server")
        out += s["routes"]
        if s["ssh_version"]:
            out.append(f"ip ssh version {s['ssh_version']}")
        out.append("!")
        for name, ents in s["acls"].items():
            out += [f"ip access-list standard {name}"] + [f" {seq} {e}" for seq, e in ents] + ["!"]
        if s["banner"] is not None:
            out += ["banner motd ^C"] + s["banner"].split("\n") + ["^C"]
        out += ["!", "line con 0", " stopbits 1"]
        for rng, kids in s["vty"].items():
            out += [f"line vty {rng}"] + [f" {k}" for k in kids]
        out += ["!"] + [f"ntp server {x}" for x in s["ntp"]] + ["!", "end"]
        body = "\n".join(out)
        return f"Building configuration...\n\nCurrent configuration : {len(body)} bytes\n{body}"

    def _running_cbs(self) -> str:
        s = self.state
        out = ["config-file-header", s["hostname"], "v3.4.0.17 / RCBS3.4_950_377_134", "CLI v1.0",
               "file SSD indicator encrypted", "@", "ssd-control-start", "ssd config", "ssd file passphrase control "
               "unrestricted", "no ssd file integrity control", "ssd-control-end cb0a3fdb1f3a1af4e4430033719968c0",
               "!", "vlan database", "vlan " + ",".join(str(v) for v in sorted(s["vlans"]) if v != 1), "exit"]
        out += [f"hostname {s['hostname']}", "username admin password encrypted $15$labHashOnly privilege 15"]
        if s["domain"]:
            out.append(f"ip domain name {s['domain']}")
        if s["ns"]:
            out.append(f"ip name-server  {' '.join(s['ns'])}")
        for name, kids in s["ifs"].items():
            if kids:
                out += [f"interface {name}"] + [f" {k}" for k in kids] + ["!"]
        out += s["routes"] + ["exit"]
        return "\n".join(out)

    def show_version(self) -> str:
        if self.family == "cbs":
            return ("Active-image: flash://system/images/image_cbs_ros_3.4.0.17_release_cisco_signed.bin\n"
                    "  Version: 3.4.0.17\n  MD5 Digest: 3c1a0f2f0f6d9c1b6a2e7d1c3b5a4e9f\n"
                    "  Date: 01-Aug-2024\n  Time: 10:00:00\n")
        mode = "Router operating mode: Controller-Managed\n" if self.controller else ""
        return (f"Cisco IOS XE Software, Version 17.12.04\n"
                f"Cisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.12.4, "
                f"RELEASE SOFTWARE (fc3)\nTechnical Support: http://www.cisco.com/techsupport\n"
                f"Copyright (c) 1986-2024 by Cisco Systems, Inc.\n\nROM: IOS-XE ROMMON\n"
                f"BOOTLDR: System Bootstrap, Version 17.12.1r, RELEASE SOFTWARE (P)\n\n"
                f"{self.state['hostname']} uptime is 2 weeks, 3 days, 4 hours, 12 minutes\n"
                f"Uptime for this control processor is 2 weeks, 3 days, 4 hours, 14 minutes\n"
                f"System returned to ROM by Reload Command\n{mode}"
                f"System image file is \"flash:packages.conf\"\n\n"
                f"cisco {self.model} (X86) processor with 1331521K/6147K bytes of memory.\n"
                f"Processor board ID FOC2234X0AB\n36 Virtual Ethernet interfaces\n"
                f"52 Gigabit Ethernet interfaces\n\n"
                f"Base Ethernet MAC Address          : 70:1f:53:aa:bb:00\n"
                f"Model Number                       : {self.model}\n"
                f"System Serial Number               : FOC2234X0AB\n\n"
                f"Switch Ports Model              SW Version        SW Image              Mode\n"
                f"------ ----- -----              ----------        ----------            ----\n"
                f"*    1 65    {self.model:<18} 17.12.04          CAT9K_IOSXE           INSTALL\n\n"
                f"Configuration register is 0x102\n")

    def _ip(self, kids):
        a = next((k.split()[2:4] for k in kids if k.startswith("ip address ")), None)
        return a

    def _status(self, name, kids):
        if "shutdown" in kids:
            return "administratively down", "down"
        up = name in ("Vlan1", "GigabitEthernet1/0/1") or (name.startswith("Vlan") and name != "Vlan1")
        return ("up", "up") if up else ("down", "down")

    def show_ip_brief(self) -> str:
        out = ["Interface              IP-Address      OK? Method Status                Protocol"]
        for name, kids in self.state["ifs"].items():
            a = self._ip(kids)
            st, pr = self._status(name, kids)
            out.append(f"{name:<23}{(a[0] if a else 'unassigned'):<16}YES {'NVRAM' if a else 'unset':<7}{st:<22}{pr}")
        return "\n".join(out)

    def show_descr(self) -> str:
        out = ["Interface                      Status         Protocol Description"]
        for name, kids in self.state["ifs"].items():
            short = name
            for full, ab in ABBR:
                if name.startswith(full) and name[len(full):len(full) + 1].isdigit():
                    short = ab + name[len(full):]
            st, pr = self._status(name, kids)
            st = "admin down" if st.startswith("admin") else st
            d = next((k[12:] for k in kids if k.startswith("description ")), "")
            out.append(f"{short:<31}{st:<15}{pr:<9}{d}".rstrip())
        return "\n".join(out)

    def show_vlan(self) -> str:
        if self.family == "cbs":
            out = ["Created by: D-Default, S-Static, G-GVRP, R-Radius Assigned VLAN, V-Voice VLAN", "",
                   "Vlan       Name           Tagged Ports      UnTagged Ports      Created by",
                   "---- ----------------- ------------------ ------------------ ----------------"]
            for v, n in sorted(self.state["vlans"].items()):
                out.append(f" {v:<4} {n:<17}{'':<38}{'D' if v == 1 else 'S'}")
            return "\n".join(out)
        out = ["", "VLAN Name                             Status    Ports",
               "---- -------------------------------- --------- -------------------------------"]
        for v, n in sorted(self.state["vlans"].items()):
            ports = [k for k, kids in self.state["ifs"].items() if f"switchport access vlan {v}" in kids
                     or (v == 1 and k.startswith(("GigabitEthernet1/", "TenGig")) and not any(
                         x.startswith("switchport access vlan") or x == "switchport mode trunk" for x in kids))]
            out.append(f"{v:<5}{n:<33}active    {', '.join(p.replace('GigabitEthernet', 'Gi') for p in ports[:4])}")
        out += ["1002 fddi-default                     act/unsup", "1003 token-ring-default               act/unsup",
                "1004 fddinet-default                  act/unsup", "1005 trnet-default                    act/unsup"]
        return "\n".join(out)

    def find_if(self, name: str) -> str | None:
        n = name.replace(" ", "").lower()
        for k in self.state["ifs"]:
            kk = k.replace(" ", "").lower()
            if kk == n:
                return k
            for full, ab in ABBR + [("GigabitEthernet", "gi"), ("TenGigabitEthernet", "te")]:
                if kk.startswith(full.lower()) and ab.lower() + kk[len(full):] == n:
                    return k
        return None

    # ── revert timer ────────────────────────────────────────────────────────
    def start_revert(self, minutes: int) -> None:
        self.snapshot = copy.deepcopy(self.state)
        self.revert_timer = threading.Timer(minutes * self.minute, self.revert_now)
        self.revert_timer.daemon = True
        self.revert_timer.start()

    def revert_now(self) -> bool:
        with self.lock:
            if self.snapshot is None:
                return False
            if self.revert_timer:
                self.revert_timer.cancel()
            self.state, self.snapshot, self.revert_timer = self.snapshot, None, None
            self.reverts += 1
            return True

    def confirm(self) -> bool:
        with self.lock:
            if self.snapshot is None:
                return False
            if self.revert_timer:
                self.revert_timer.cancel()
            self.snapshot = self.revert_timer = None
            return True


class Session:
    """One SSH shell: line editing, modes, command dispatch."""

    def __init__(self, sim: CiscoSim, chan, user: str | None):
        self.sim, self.chan, self.user = sim, chan, user
        self.priv = USERS.get(user, ("", 1))[1] if user else 1
        self.mode = ""              # "" exec | config | if | vlan | line | acl | archive | vlandb
        self.target = None
        self.banner = None          # [delim, lines] while reading banner text
        self._next_mode = self._next_target = None

    def w(self, s: str) -> None:
        try:
            self.chan.sendall(s.replace("\n", "\r\n").encode())
        except (OSError, EOFError, paramiko.SSHException):
            pass

    def prompt(self) -> str:
        h = self.sim.state["hostname"]
        sub = {"config": "(config)", "if": "(config-if)", "vlan": "(config-vlan)", "line": "(config-line)",
               "acl": "(config-std-nacl)", "archive": "(config-archive)", "vlandb": "(config-vlan)"}.get(self.mode, "")
        return h + sub + ("#" if self.priv == 15 else ">")

    def readline(self, echo: bool = True) -> str | None:
        buf = b""
        while True:
            try:
                c = self.chan.recv(1)
            except (OSError, EOFError, paramiko.SSHException):
                return None
            if not c:
                return None
            if c in (b"\r", b"\n"):
                if c == b"\r":      # swallow a following \n
                    self.chan.settimeout(0.05)
                    try:
                        nxt = self.chan.recv(1)
                        if nxt and nxt != b"\n":
                            buf += nxt
                    except socket.timeout:
                        pass
                    finally:
                        self.chan.settimeout(None)
                if echo:
                    self.w("\n")
                return buf.decode(errors="replace")
            if c == b"\x03":
                buf = b""
                if echo:
                    self.w("^C\n")
                return ""
            buf += c
            if echo and c != b"?":
                self.w(c.decode(errors="replace"))

    def run(self) -> None:
        sim = self.sim
        if sim.hang:
            while self.chan.recv(1024):
                pass
            return
        if sim.family == "cbs" and self.user is None:      # in-band login, like CBS without password-auth
            self.w("\n\nUser Name:")
            u = self.readline()
            self.w("Password:")
            p = self.readline(echo=False)
            if u is None or p is None or USERS.get(u, ("\0",))[0] != p:
                self.w("\n% Login invalid\n\n")
                self.chan.close()
                return
            self.user, self.priv = u, USERS[u][1]
            self.w("\n")
        else:
            self.w("\n")
        self.w(self.prompt())
        while True:
            line = self.readline()
            if line is None:
                return
            with sim.lock:
                sim.log.append(line)
                try:
                    out = self.handle(line)
                except _Bye:
                    self.chan.close()
                    return
            if out is not None:
                self.w(out + ("\n" if out and not out.endswith("\n") else ""))
                if self.banner is None:
                    self.w(self.prompt())

    def ask(self, text: str, echo=True) -> str:
        self.w(text)
        return self.readline(echo) or ""

    # ── dispatch ────────────────────────────────────────────────────────────
    def handle(self, line: str):
        if self.banner is not None:
            d, acc = self.banner
            if d in line:
                if line.split(d)[0]:
                    acc.append(line.split(d)[0])
                self.sim.state["banner"] = "\n".join(acc)
                self.banner = None
                return ""
            acc.append(line)
            return None             # no prompt while reading banner text
        cmd = line.strip()
        if not cmd:
            return ""
        if self.mode == "":
            return self.exec_cmd(cmd)
        if cmd == "end" or cmd == "\x1a":
            self.mode, self.target = "", None
            return ""
        if cmd == "exit":
            self.mode, self.target = ("" if self.mode == "config" else "config"), None
            return ""
        if self.mode != "config":
            r = self.sub_cmd(cmd)
            if r is not _NOMATCH:
                return r
            # IOS falls back to global configuration for commands the submode does not know
            r = self.cfg_cmd(cmd, probe=True)
            if r is not _NOMATCH:
                self.mode, self.target = self._next_mode or "config", self._next_target
                return r
            return self.invalid(cmd)
        r = self.cfg_cmd(cmd)
        if r is _NOMATCH:
            return self.invalid(cmd)
        if self._next_mode:
            self.mode, self.target = self._next_mode, self._next_target
        return r

    def invalid(self, cmd: str) -> str:
        col = len(self.prompt()) + (len(cmd) - len(cmd.lstrip()))
        return " " * col + "^\n" + INVALID

    # ── exec mode ───────────────────────────────────────────────────────────
    def exec_cmd(self, cmd: str):
        sim, s = self.sim, self.sim.state
        cbs = sim.family == "cbs"
        if cmd in ("exit", "logout", "quit"):
            raise _Bye()
        if cmd in ("enable", "en"):
            if self.priv == 15:
                return ""
            for _ in range(3):
                if self.ask("Password: ", echo=False) == ENABLE_SECRET:
                    self.priv = 15
                    return ""
            return "% Bad secrets\n"
        if cmd == "disable":
            self.priv = 1
            return ""
        if re.match(r"^terminal (length|width) \d+$", cmd) and not cbs:
            return ""
        if cmd == "terminal datadump" and cbs:
            return ""
        if cmd == "show version":
            return sim.show_version()
        if self.priv < 15 and not cmd.startswith("show version"):
            if cmd.startswith(("show running", "conf", "write", "copy")):
                return self.invalid(cmd)
        if cmd == "show ip interface brief" and not cbs:
            return sim.show_ip_brief()
        if cmd == "show interfaces description":
            return sim.show_descr()
        if cmd == ("show vlan" if cbs else "show vlan brief"):
            return sim.show_vlan()
        if cbs and cmd == "show system":
            return (f"System Description:                       {sim.model} 24-Port Gigabit PoE Managed Switch\n"
                    f"System Up Time (days,hour:min:sec):       12,04:11:09\nSystem Contact:\n"
                    f"System Name:                              {s['hostname']}\nSystem Location:\n")
        if cbs and cmd == "show inventory":
            return f'NAME: "1"    DESCR: "{sim.model}"\nPID: {sim.model}    VID: V01    SN: PSZ27011ABC\n'
        if cbs and cmd == "show interfaces status":
            out = ["                                             Flow Link          Back   Mdix",
                   "Port     Type         Duplex  Speed Neg      ctrl State       Pressure Mode",
                   "-------- ------------ ------  ----- -------- ---- ----------- -------- -------"]
            for n in s["ifs"]:
                if n.startswith(("Gig", "Ten")):
                    short = ("gi" if n.startswith("Gig") else "te") + n.split("Ethernet")[1]
                    out.append(f"{short:<9}1G-Copper    Full    1000  Enabled  Off  {'Up' if n.endswith('/1') else 'Down':<12}"
                               "Disabled Off")
            return "\n".join(out)
        if cbs and cmd == "show ip interface":
            out = ["    IP Address         I/F      I/F Status  Type     Directed  Prec Redirect Status",
                   "------------------ --------- ------------ ------- --------- ---- -------- ------"]
            for n, kids in s["ifs"].items():
                a = sim._ip(kids)
                if a:
                    pl = ipaddress.IPv4Network(f"0.0.0.0/{a[1]}").prefixlen
                    out.append(f"{a[0] + '/' + str(pl):<19}{n:<10}UP/UP        Static  disable   No   enable   Valid")
            return "\n".join(out)
        if cmd == "show running-config":
            return sim.running()
        m = re.match(r"^show running-config interface (.+)$", cmd)
        if m and not cbs:
            name = sim.find_if(m.group(1))
            if not name:
                return self.invalid(cmd)
            body = "\n".join(["!", f"interface {name}"] + [f" {k}" for k in s["ifs"][name]] + ["end"])
            return f"Building configuration...\n\nCurrent configuration : {len(body)} bytes\n{body}"
        if cmd == "show archive" and not cbs:
            if s["archive"] is None:
                return "Archive feature not enabled"   # wording not verified against a real switch
            path = next((k[5:] for k in s["archive"] if k.startswith("path ")), "")
            return (f"The maximum archive configurations allowed is 14.\n"
                    f"The next archive file will be named {path}-Oct-12-20-00-00.000-0\n Archive #  Name\n   1\n")
        m = re.match(r"^conf(?:igure)?(?: t(?:erminal)?)?(?: revert timer (\d+))?$", cmd)
        if m:
            if m.group(1):
                if cbs:
                    return self.invalid(cmd)
                if s["archive"] is None or not any(k.startswith("path ") for k in s["archive"]):
                    return "%Error: Archive path is not configured"
                if sim.snapshot is not None:
                    return "%Error: A rollback confirmed change is already pending"
                sim.start_revert(int(m.group(1)))
                pre = (f"!Rollback Confirmed Change: Backing up current running config to "
                       f"{next(k[5:] for k in s['archive'] if k.startswith('path '))}-Oct-12-20-00-00.000-0\n")
            else:
                pre = ""
            self.mode = "config"
            return pre + "Enter configuration commands, one per line.  End with CNTL/Z."
        if cmd == "configure confirm" and not cbs:
            return "" if sim.confirm() else "%Error: No Rollback Confirmed Change pending"
        if cmd == "configure revert now" and not cbs:
            return "!Rollback Confirmed Change: rollback completed" if sim.revert_now() else \
                "%Error: No Rollback Confirmed Change pending"
        if cmd in ("write memory", "write", "wr") and not cbs:
            sim.startup = copy.deepcopy(s)
            sim.saves += 1
            return "Building configuration...\n[OK]"
        if cmd == "copy running-config startup-config":
            if cbs:
                self.w("Overwrite file [startup-config].... (Y/N)[N] ?")
                try:                                 # one key, no Enter needed (an Enter after it is harmless)
                    a = self.chan.recv(1).decode(errors="replace")
                except (OSError, EOFError, paramiko.SSHException):
                    return ""
                self.w(a + "\n")
                if a.strip().upper() != "Y":
                    return "Copy operation aborted."
                sim.startup = copy.deepcopy(s)
                sim.saves += 1
                return "\n12-Oct-2026 20:00:00 %COPY-N-TRAP: The copy operation was completed successfully\n"
            a = self.ask("Destination filename [startup-config]? ")
            sim.startup = copy.deepcopy(s)
            sim.saves += 1
            return "Building configuration...\n[OK]"
        return self.invalid(cmd)

    # ── global configuration ────────────────────────────────────────────────
    def cfg_cmd(self, cmd: str, probe: bool = False):
        sim, s = self.sim, self.sim.state
        cbs = sim.family == "cbs"
        self._next_mode, self._next_target = None, None
        w = cmd.split()
        if w[0] == "do":
            return self.exec_cmd(cmd[3:].strip())
        if w[0] == "hostname":
            if len(w) == 1:
                return "% Incomplete command."
            if len(w) > 2 or not re.match(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,62}$", w[1]):
                return "% Hostname contains one or more illegal characters."
            s["hostname"] = w[1]
            return ""
        m = re.match(r"^(no )?ip domain[ -]name(?: (\S+))?$", cmd)
        if m:
            if m.group(1):
                s["domain"] = None
                return ""
            if not m.group(2):
                return "% Incomplete command."
            s["domain"] = m.group(2)
            return ""
        m = re.match(r"^(no )?ip name-server((?: \S+)*)$", cmd)
        if m:
            ips = m.group(2).split()
            for ip in ips:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    return self.invalid(cmd)
            if m.group(1):
                s["ns"] = [x for x in s["ns"] if ips and x not in ips]
            else:
                if not ips:
                    return "% Incomplete command."
                s["ns"] += [x for x in ips if x not in s["ns"]]
                if len(s["ns"]) > 6:
                    s["ns"] = s["ns"][:6]
                    return "% Name server limit reached"
            return ""
        m = re.match(r"^(no )?ntp server (\S+)( prefer)?$", cmd)
        if m and not cbs:
            if m.group(1):
                s["ntp"] = [x for x in s["ntp"] if x.split()[0] != m.group(2)]
            elif not re.match(r"^[A-Za-z0-9][\w.\-:]*$", m.group(2)):
                return self.invalid(cmd)
            else:
                s["ntp"] = [x for x in s["ntp"] if x.split()[0] != m.group(2)] + [m.group(2) + (m.group(3) or "")]
            return ""
        m = re.match(r"^banner motd (\S)(.*)$", cmd)
        if m and not cbs:
            d, rest = m.group(1), m.group(2)
            if d in rest:
                s["banner"] = rest.split(d)[0]
                return ""
            self.banner = [d, [rest] if rest else []]
            return f"Enter TEXT message.  End with the character '{d}'."
        if cmd == "no banner motd" and not cbs:
            s["banner"] = None
            return ""
        if cbs and cmd == "vlan database":
            self._next_mode = "vlandb"
            return ""
        m = re.match(r"^(no )?vlan (\d+)$", cmd)
        if m and not cbs:
            v = int(m.group(2))
            if not 1 <= v <= 4094:
                return self.invalid(cmd)
            if 1002 <= v <= 1005:
                return "%Default VLAN 1002-1005 may not be deleted or modified."
            if m.group(1):
                if v == 1:
                    return "%Default VLAN 1 may not be deleted."
                s["vlans"].pop(v, None)
                return ""
            s["vlans"].setdefault(v, f"VLAN{v:04d}")
            self._next_mode, self._next_target = "vlan", v
            return ""
        m = re.match(r"^(no |default )?interface (.+)$", cmd)
        if m:
            raw = m.group(2).strip()
            name = sim.find_if(raw)
            if cbs:
                vm = re.match(r"^vlan ?(\d+)$", raw, re.I)
                if vm and not name and not m.group(1):
                    if int(vm.group(1)) not in s["vlans"]:
                        return "% VLAN does not exist"
                    name = f"vlan {vm.group(1)}"
                    s["ifs"][name] = []
            else:
                nm = re.match(r"^(Vlan|Loopback)(\d+)$", raw)
                if nm and not name and not m.group(1):
                    if nm.group(1) == "Vlan" and not vlan_ok(nm.group(2)):
                        return self.invalid(cmd)
                    name = raw
                    s["ifs"][name] = ["shutdown"] if nm.group(1) == "Vlan" else []
            if not name:
                return "% Invalid input detected at '^' marker." if m.group(1) else self.invalid(cmd)
            if m.group(1) == "no ":
                if not re.match(r"^(Vlan|Loopback)\d+$", name):
                    return "% Physical interfaces cannot be deleted"
                del s["ifs"][name]
                return ""
            if m.group(1) == "default ":
                s["ifs"][name] = ["shutdown"] if name.startswith("Vlan") else (
                    ["vrf forwarding Mgmt-vrf", "no ip address", "negotiation auto"] if name == "GigabitEthernet0/0"
                    else [])
                return f"Interface {name} set to default configuration"
            self._next_mode, self._next_target = "if", name
            return ""
        m = re.match(r"^(no )?ip route (\S+) (\S+) (\S+)(?: (\d+))?$", cmd)
        if m:
            try:
                net = ipaddress.IPv4Network(f"{m.group(2)}/{m.group(3)}")
                ipaddress.IPv4Address(m.group(4))
            except ValueError:
                return "%Inconsistent address and mask" if is_mask(m.group(3)) else self.invalid(cmd)
            base = f"ip route {net.network_address} {net.netmask} {m.group(4)}"
            if m.group(1):
                before = len(s["routes"])
                s["routes"] = [r for r in s["routes"] if not (r == base or r.startswith(base + " "))]
                return "" if len(s["routes"]) < before else "%No matching route to delete"
            if m.group(5) and not 1 <= int(m.group(5)) <= 255:
                return self.invalid(cmd)
            s["routes"] = [r for r in s["routes"] if not (r == base or r.startswith(base + " "))]
            s["routes"].append(base + (f" {m.group(5)}" if m.group(5) else ""))
            return ""
        if cbs:
            return _NOMATCH
        m = re.match(r"^(no )?ip ssh version(?: ([12]))?$", cmd)
        if m:
            if not m.group(1) and not m.group(2):
                return "% Incomplete command."
            s["ssh_version"] = None if m.group(1) else m.group(2)
            return ""
        m = re.match(r"^(no )?ip http (server|secure-server)$", cmd)
        if m:
            s["http" if m.group(2) == "server" else "https"] = not m.group(1)
            return ""
        m = re.match(r"^line vty (\d+)(?: (\d+))?$", cmd)
        if m:
            key = f"{m.group(1)} {m.group(2)}" if m.group(2) else m.group(1)
            if key not in s["vty"]:
                return "%Invalid line range"
            self._next_mode, self._next_target = "line", key
            return ""
        m = re.match(r"^(no )?ip access-list standard (\S+)$", cmd)
        if m:
            if m.group(1):
                s["acls"].pop(m.group(2), None)
                return ""
            s["acls"].setdefault(m.group(2), [])
            self._next_mode, self._next_target = "acl", m.group(2)
            return ""
        if cmd == "archive":
            if s["archive"] is None:
                s["archive"] = []
            self._next_mode = "archive"
            return ""
        if cmd == "no archive":
            s["archive"] = None
            return ""
        return _NOMATCH

    # ── submodes ────────────────────────────────────────────────────────────
    def sub_cmd(self, cmd: str):
        s, cbs = self.sim.state, self.sim.family == "cbs"
        t = self.target
        if self.mode == "vlandb":
            m = re.match(r"^(no )?vlan ([\d,\-]+)$", cmd)
            if not m:
                return _NOMATCH
            for part in m.group(2).split(","):
                a, _, b = part.partition("-")
                for v in range(int(a), int(b or a) + 1):
                    if not 1 <= v <= 4094:
                        return "% bad parameter value"
                    if m.group(1):
                        if v == 1:
                            return "% Default VLAN cannot be deleted"
                        s["vlans"].pop(v, None)
                    else:
                        s["vlans"].setdefault(v, str(v))
            return ""
        if self.mode == "vlan":
            m = re.match(r"^name (\S{1,32})$", cmd)
            if m:
                s["vlans"][t] = m.group(1)
                return ""
            if cmd == "no name":
                s["vlans"][t] = f"VLAN{t:04d}"
                return ""
            return _NOMATCH
        if self.mode == "archive":
            m = re.match(r"^path (\S+)$", cmd)
            if m:
                if not re.match(r"^(flash|bootflash|crashinfo):\S+$", m.group(1)):
                    return "%Error: invalid archive path"
                set_kid(s["archive"], cmd)
                return ""
            m = re.match(r"^maximum (\d+)$", cmd)
            if m:
                if not any(k.startswith("path ") for k in s["archive"]):
                    return "%Error: Archive path not specified."
                if not 1 <= int(m.group(1)) <= 14:
                    return self.invalid(cmd)
                set_kid(s["archive"], cmd)
                return ""
            if cmd in ("no path", "no maximum"):
                del_kid(s["archive"], cmd[3:])
                return ""
            return _NOMATCH
        if self.mode == "acl":
            ents = s["acls"][t]
            m = re.match(r"^(?:(\d+) )?(permit|deny) (?:host (\S+)|(\S+) (\S+)|any)$", cmd)
            if not m:
                return _NOMATCH
            seq = int(m.group(1)) if m.group(1) else (max([x[0] for x in ents] or [0]) + 10)
            body = cmd.split(None, 1)[1] if m.group(1) else cmd
            if m.group(3):
                body = f"{m.group(2)} {m.group(3)}"
            ents[:] = sorted([x for x in ents if x[0] != seq] + [(seq, body)])
            return ""
        if self.mode == "line":
            kids = s["vty"][t]
            m = re.match(r"^transport input ((?:ssh|telnet|none|all)(?: (?:ssh|telnet))?)$", cmd)
            if m:
                set_kid(kids, cmd)
                return ""
            if cmd == "default transport input":
                del_kid(kids, "transport input")
                return ""
            m = re.match(r"^exec-timeout (\d+)(?: (\d+))?$", cmd)
            if m:
                set_kid(kids, "exec-timeout " + m.group(1) + " " + (m.group(2) or "0"))
                return ""
            if cmd == "no exec-timeout":
                del_kid(kids, "exec-timeout")
                return ""
            m = re.match(r"^(no )?access-class (\S+) in( vrf-also)?$", cmd)
            if m:
                if m.group(1):
                    del_kid(kids, "access-class")
                else:
                    set_kid(kids, cmd)
                return ""
            if cmd in ("login local", "login"):
                set_kid(kids, cmd)
                return ""
            return _NOMATCH
        if self.mode == "if":
            kids = s["ifs"][t]
            l2 = (t.startswith(("GigabitEthernet1/", "TenGigabitEthernet", "GigabitEthernet1/0")) and
                  "no switchport" not in kids)
            if cbs:
                l2 = not t.startswith("vlan")
            m = re.match(r"^description (.+)$", cmd)
            if m:
                if len(m.group(1)) > 200:
                    return "% Description too long"
                set_kid(kids, cmd)
                return ""
            if cmd == "no description":
                del_kid(kids, "description")
                return ""
            if cbs and t.startswith("vlan"):
                m = re.match(r"^name (\S{1,32})$", cmd)
                if m:
                    s["vlans"][int(t.split()[1])] = m.group(1)
                    set_kid(kids, cmd)
                    return ""
                if cmd == "no name":
                    v = int(t.split()[1])
                    s["vlans"][v] = str(v)
                    del_kid(kids, "name")
                    return ""
            m = re.match(r"^ip address (\S+) (\S+)$", cmd)
            if m:
                if l2:
                    return "% IP addresses may not be configured on L2 links."
                try:
                    ipaddress.IPv4Interface(f"{m.group(1)}/{m.group(2)}")
                except ValueError:
                    return self.invalid(cmd)
                for other, okids in s["ifs"].items():
                    a = self.sim._ip(okids)
                    if other != t and a and "vrf forwarding" not in " ".join(okids) and \
                            ipaddress.IPv4Interface(f"{m.group(1)}/{m.group(2)}").network == \
                            ipaddress.IPv4Interface(f"{a[0]}/{a[1]}").network:
                        return f"% {ipaddress.IPv4Interface(m.group(1) + '/' + m.group(2)).network.network_address} " \
                               f"overlaps with {other}"
                set_kid(kids, cmd)
                return ""
            if cmd == "no ip address":
                del_kid(kids, "ip address")
                return ""
            if cmd == "shutdown":
                if "shutdown" not in kids:
                    kids.append("shutdown")
                return ""
            if cmd == "no shutdown":
                kids[:] = [k for k in kids if k != "shutdown"]
                return ""
            if cmd == "no switchport" and not cbs and t.startswith(("GigabitEthernet1/", "TenGig")):
                kids[:] = [k for k in kids if not k.startswith("switchport")] + ["no switchport"]
                return ""
            if cmd == "switchport" and not cbs:
                kids[:] = [k for k in kids if k != "no switchport" and not k.startswith("ip address")]
                return ""
            if cmd.startswith(("switchport", "no switchport")) and not l2:
                return "% Command rejected: this is not a switchport."
            m = re.match(r"^switchport mode (access|trunk)$", cmd)
            if m:
                set_kid(kids, cmd)
                return ""
            if cmd == "no switchport mode":
                del_kid(kids, "switchport mode")
                return ""
            m = re.match(r"^switchport access vlan (\d+)$", cmd)
            if m:
                if not vlan_ok(m.group(1)):
                    return self.invalid(cmd)
                if cbs and int(m.group(1)) not in s["vlans"]:
                    return "% VLAN does not exist"
                set_kid(kids, cmd)
                if not cbs and int(m.group(1)) not in s["vlans"]:
                    s["vlans"][int(m.group(1))] = f"VLAN{int(m.group(1)):04d}"
                    return "% Access VLAN does not exist. Creating vlan " + m.group(1)
                return ""
            if cmd == "no switchport access vlan":
                del_kid(kids, "switchport access vlan")
                return ""
            if cbs:
                return _NOMATCH
            m = re.match(r"^switchport trunk allowed vlan ([\d,\-]+)$", cmd)
            if m:
                for part in m.group(1).split(","):
                    if not all(vlan_ok(x) for x in part.split("-")):
                        return self.invalid(cmd)
                set_kid(kids, cmd)
                return ""
            m = re.match(r"^switchport trunk native vlan (\d+)$", cmd)
            if m:
                if not vlan_ok(m.group(1)):
                    return self.invalid(cmd)
                set_kid(kids, cmd)
                return ""
            m = re.match(r"^no switchport trunk (allowed|native) vlan$", cmd)
            if m:
                del_kid(kids, f"switchport trunk {m.group(1)} vlan")
                return ""
            return _NOMATCH
        return _NOMATCH


class _Bye(Exception):
    pass


_NOMATCH = object()


class _Server(paramiko.ServerInterface):
    def __init__(self, sim: CiscoSim):
        self.sim, self.user = sim, None
        self.shell = threading.Event()

    def get_allowed_auths(self, username):
        return "none,password" if self.sim.family == "cbs" else "password"

    def check_auth_none(self, username):
        return paramiko.AUTH_SUCCESSFUL if self.sim.family == "cbs" else paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        if self.sim.family == "cbs":
            return paramiko.AUTH_SUCCESSFUL      # like CBS without 'ip ssh password-auth': real login is in-band
        if USERS.get(username, ("\0",))[0] == password:
            self.user = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        self.shell.set()
        return True


class SSHLabServer:
    """Accept loop; one thread per connection. shutdown() stops accepting."""

    def __init__(self, sim: CiscoSim, port: int, key: paramiko.RSAKey):
        self.sim, self.key = sim, key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((lab.HOST, port))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _allowed(self, ip: str) -> bool:
        """vty access-class: a new session from a source the ACL does not permit is refused."""
        with self.sim.lock:
            st = self.sim.state
            acl = next((k.split()[1] for k in st["vty"].get("0 4", []) if k.startswith("access-class ")), None)
            if not acl:
                return True
            for _, e in st["acls"].get(acl, []):
                w = e.split()
                try:
                    if w[0] == "permit" and len(w) == 2 and w[1] == ip:
                        return True
                    if w[0] == "permit" and len(w) == 3:
                        mask = int(ipaddress.IPv4Address(w[2]))
                        if int(ipaddress.IPv4Address(ip)) & ~mask & 0xFFFFFFFF == int(ipaddress.IPv4Address(w[1])):
                            return True
                except ValueError:
                    pass
            return False

    def _handle(self, conn):
        if not self._allowed(conn.getpeername()[0]):
            conn.close()
            return
        t = paramiko.Transport(conn)
        try:
            t.add_server_key(self.key)
            srv = _Server(self.sim)
            t.start_server(server=srv)
            chan = t.accept(20)
            if chan is None or not srv.shell.wait(10):
                return
            Session(self.sim, chan, srv.user).run()
        except Exception:  # noqa: BLE001 - a broken client must not kill the lab
            pass
        finally:
            time.sleep(0.05)
            t.close()

    def shutdown(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass

    server_close = shutdown


def start_cisco(port: int = 2222):
    sim = CiscoSim("iosxe")
    srv = SSHLabServer(sim, port, host_key("cisco"))
    return sim, srv, {"vendor": "cisco", "family": "iosxe", "model": "Catalyst 9300 / 9300L",
                      "address": lab.HOST, "port": srv.port,
                      "creds": {"username": "admin", "password": USERS["admin"][0]}}


def start_cisco_cbs(port: int = 2223):
    sim = CiscoSim("cbs")
    srv = SSHLabServer(sim, port, host_key("cisco-cbs"))
    return sim, srv, {"vendor": "cisco", "family": "cbs", "model": "Catalyst 1300",
                      "address": lab.HOST, "port": srv.port,
                      "creds": {"username": "admin", "password": USERS["admin"][0]}}


lab.register("cisco", start_cisco)
lab.register("cisco-cbs", start_cisco_cbs)
