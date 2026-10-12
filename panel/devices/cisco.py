"""
Cisco driver - SSH CLI for IOS-XE (Catalyst 9200/9300, Catalyst 8200/8300,
ISR 1100) and Cisco Business CLI (Catalyst 1200/1300, CBS350).

What the device needs:

- SSH enabled and a local (or AAA) user. A privilege-15 user is easiest;
  otherwise fill in the enable secret and SentinelScan runs 'enable'.
- IOS-XE: for safe changes, the config archive. With it, every change is
  applied inside 'configure terminal revert timer <minutes>' and confirmed
  ('configure confirm') only after a *fresh* SSH login works. If the change
  cuts you off, the device rolls itself back. The 'Enable config archive'
  wizard sets it up:

      archive
       path flash:sentinel-archive
       maximum 5

- Catalyst 1200/1300 and CBS have no auto-revert: a backup is taken before
  every change and each wizard has an Undo.
- C8000 / ISR 1100 must be in autonomous mode; in SD-WAN controller mode the
  configuration belongs to SD-WAN Manager and the wizards refuse to run.

The first connection shows the switch's SSH host key fingerprint (as in
'ssh -o FingerprintHash=sha256'). Compare it with 'show ip ssh' / 'show crypto
key mypubkey rsa' on the console before trusting it. No wizard reads, sets or
shows passwords or secrets.
"""
from __future__ import annotations

import base64
import codecs
import hashlib
import ipaddress
import logging
import re
import socket
import threading
import time

import paramiko

from .base import (DeviceError, Driver, Field, PinMismatch, PinRequired, Plan, Step, ValidationError, Wizard, fill,
                   v_address, v_cidr, v_choice, v_hostname, v_iface, v_iface_addr, v_int, v_ip, v_ipv4, v_list,
                   v_multiline, v_name, v_text, v_vlan)

KIND = "SSH host key"
logging.getLogger("paramiko").addHandler(logging.NullHandler())   # failures surface as DeviceError instead

# ── terminal parsing ─────────────────────────────────────────────────────────
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\x1b[=>78]")
# SW1>  SW1#  SW1(config)#  SW1(config-if)#  switch5c1d2e(config-vlan)#
PROMPT_RE = re.compile(r"(?:^|\n)([A-Za-z0-9][\w.\-/:]*?)(\([\w.\-/: ]+\))?([>#])[ \t]*$")
MORE_RE = re.compile(r"(?:-+ ?More ?-+|More: <space>,[^\n]*)[ \t]*$")
LOGIN_RE = re.compile(r"(?:User ?Name|Username|login)\s*:\s*$", re.I)
PASS_RE = re.compile(r"Password\s*:\s*$", re.I)
SYSLOG_RE = re.compile(r"%[A-Z0-9_]+-\d-[A-Z0-9_]+:")
ERR_RE = re.compile(r"^\s*%\s*\S|^\s*%?Error\b|^\s*ERROR:", re.I)
BENIGN_RE = re.compile(r"^\s*%\s*(Warning|Note|Info|Applying VLAN|Access VLAN does not exist|Generating|The key modulus|Please wait)", re.I)
SAVE_ANSWERS = [  # exec prompts we may answer while saving the configuration
    (re.compile(r"\(Y/N\)\s*\[[YN]\]\s*\?\s*$", re.I), "Y\n"),
    (re.compile(r"\[yes/no\]:?\s*$", re.I), "yes\n"),
    (re.compile(r"\[confirm\]\s*$", re.I), "\n"),
    (re.compile(r"Destination filename \[[^\]\n]*\]\?\s*$", re.I), "\n"),
]
BANNER_RE = re.compile(r"^banner (motd|login|exec) (\S)$")

# interface abbreviations seen in 'show interfaces description' / CBS output
FULL_IFACES = ["GigabitEthernet", "TenGigabitEthernet", "TwoGigabitEthernet", "FiveGigabitEthernet",
               "TwentyFiveGigE", "FortyGigabitEthernet", "HundredGigE", "FastEthernet", "AppGigabitEthernet",
               "Vlan", "Loopback", "Port-channel", "Tunnel", "Bluetooth", "Dialer", "Virtual-Access", "Null"]
ABBR = {"gi": "GigabitEthernet", "te": "TenGigabitEthernet", "tw": "TwoGigabitEthernet",
        "twe": "TwentyFiveGigE", "fi": "FiveGigabitEthernet", "fo": "FortyGigabitEthernet", "hu": "HundredGigE",
        "fa": "FastEthernet", "ap": "AppGigabitEthernet", "vl": "Vlan", "lo": "Loopback", "po": "Port-channel",
        "tu": "Tunnel", "bl": "Bluetooth", "nu": "Null"}

ARCHIVE_PREFIX = "sentinel-archive"
MGMT_ACL = "SENTINEL-MGMT"
NO_TEXT = "?"            # typing '?' on a Cisco CLI asks for help instead of entering the character


def canon_iface(name: str) -> str:
    """'Gi1/0/5', 'gi1/0/5', 'GigabitEthernet1/0/5' → 'gigabitethernet1/0/5' (for comparing only)."""
    m = re.match(r"^([A-Za-z\-]+)\s*(.*)$", str(name).strip())
    if not m:
        return str(name).strip().lower()
    alpha, rest = m.group(1).lower(), m.group(2)
    full = next((f for f in FULL_IFACES if f.lower() == alpha), None) or ABBR.get(alpha)
    if not full:
        cands = [f for f in FULL_IFACES if f.lower().startswith(alpha)]
        full = cands[0] if len(cands) == 1 else alpha
    return (full + rest).lower()


def _flag(p: dict, name: str, default: bool = False) -> bool:
    if name not in p or p[name] is None or p[name] == "":
        return default
    return p[name] in (True, "true", "on", "1", 1, "yes")


def ssh_fingerprint(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


# ── running-config helpers ──────────────────────────────────────────────────
def rc_lines(cfg: str) -> list[str]:
    return cfg.replace("\r", "").split("\n")


def rc_top(cfg: str, prefix: str) -> list[str]:
    """Top-level lines starting with prefix."""
    return [l.rstrip() for l in rc_lines(cfg) if l.startswith(prefix)]


def rc_sections(cfg: str, header_re: str) -> dict[str, list[str]]:
    """{header line: [child lines, stripped]} for top-level blocks whose header matches."""
    out, cur = {}, None
    rx = re.compile(header_re)
    for l in rc_lines(cfg):
        if l and not l[0].isspace():
            cur = l.rstrip() if rx.match(l) else None
            if cur is not None:
                out[cur] = []
        elif cur is not None and l.strip() and l.strip() != "!":
            out[cur].append(l.strip())
    return out


def rc_iface(cfg: str, name: str) -> list[str] | None:
    want = canon_iface(name)
    for head, kids in rc_sections(cfg, r"^interface \S").items():
        if canon_iface(head.split(None, 1)[1]) == want:
            return kids
    return None


def rc_banner(cfg: str, kind: str = "motd") -> str | None:
    lines = rc_lines(cfg)
    for i, l in enumerate(lines):
        if l.startswith(f"banner {kind} "):
            rest = l[len(f"banner {kind} "):]
            if rest.startswith("^C"):
                d, rest = "^C", rest[2:]
            else:
                d, rest = rest[:1], rest[1:]
            if d and d in rest:
                return rest.split(d)[0]
            body = [rest] if rest else []
            for l2 in lines[i + 1:]:
                if d in l2:
                    if l2.split(d)[0]:
                        body.append(l2.split(d)[0])
                    break
                body.append(l2)
            return "\n".join(body)
    return None


def has_archive(cfg: str) -> bool:
    for head, kids in rc_sections(cfg, r"^archive\s*$").items():
        if any(k.startswith("path ") for k in kids):
            return True
    return False


def vlan_list(v) -> str:
    """'10, 20,30-40' → '10,20,30-40' with every VLAN checked."""
    parts = v_list(v, lambda s: s, "allowed VLANs", 200)
    if not parts:
        raise ValidationError("allowed VLANs: enter at least one VLAN, e.g. 10,20,30-40")
    out = []
    for s in parts:
        m = re.match(r"^(\d+)-(\d+)$", s)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a >= b:
                raise ValidationError(f"allowed VLANs: range '{s}' must go from low to high")
            v_int(a, 1, 4094, "VLAN ID"), v_int(b, 1, 4094, "VLAN ID")
            out.append(f"{a}-{b}")
        else:
            out.append(str(v_int(s, 1, 4094, "VLAN ID")))
    return ",".join(out)


def v_domain(v) -> str:
    s = v_text(v, 64, "domain name")
    try:
        ipaddress.ip_address(s)
        raise ValidationError("domain name: enter a name like lab.local, not an IP address")
    except ValueError:
        pass
    return v_address(s)


def v_line(v, max_len: int, what: str) -> str:
    """Free text that goes onto a CLI line: one line, no '?'."""
    return v_text(v, max_len, what, forbid=NO_TEXT)


class _Closed(DeviceError):
    pass


# ── the driver ──────────────────────────────────────────────────────────────
class CiscoCLI(Driver):
    vendor = "cisco"
    label = "Cisco"
    default_port = 22
    pin_kind = KIND
    auth_fields = [
        Field("username", "Username", placeholder="admin"),
        Field("password", "Password", "password"),
        Field("secret", "Enable secret", "password", required=False,
              help="Only if the user does not log in at privilege 15 (prompt ends in '>')."),
    ]

    CMD_TIMEOUT = 30
    LONG_TIMEOUT = 120

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._t: paramiko.Transport | None = None
        self._chan = None
        self._dec = None
        self._prompt = ""
        self._local_ip = ""
        self._lock = threading.RLock()
        self.cbs = self.family == "cbs"

    # ── transport ───────────────────────────────────────────────────────────
    def _transport(self) -> paramiko.Transport:
        try:
            sock = socket.create_connection((self.address, self.port), timeout=10)
        except OSError as e:
            raise DeviceError(f"cannot reach {self.address}:{self.port} - {e}") from None
        sock.settimeout(None)
        t = paramiko.Transport(sock)
        t.banner_timeout, t.handshake_timeout, t.auth_timeout = 15, 20, 20
        try:            # modern algorithms first (paramiko's order); legacy ones last for old IOS
            opts = t.get_security_options()
            for attr, extra in (("kex", ["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"]),
                                ("ciphers", ["aes128-cbc", "aes256-cbc", "3des-cbc"])):
                cur = list(getattr(opts, attr))
                add = [x for x in extra if x not in cur and x in getattr(t, f"_{'cipher' if attr == 'ciphers' else 'kex'}_info", {})]
                if add:
                    setattr(opts, attr, tuple(cur + add))
        except Exception:  # noqa: BLE001 - algorithm tuning is best effort
            pass
        try:
            t.start_client(timeout=20)
            key = t.get_remote_server_key()     # raises if the handshake did not finish in time
        except (paramiko.SSHException, OSError, EOFError) as e:
            t.close()
            raise DeviceError(f"SSH handshake with {self.address}:{self.port} failed - {e or 'timed out'}") from None
        if key is None:
            t.close()
            raise DeviceError(f"SSH handshake with {self.address}:{self.port} timed out")
        t._sentinel_fp = ssh_fingerprint(key)
        return t

    def probe_fingerprint(self) -> str:
        t = self._transport()
        try:
            return t._sentinel_fp
        finally:
            t.close()

    def _login(self):
        """New SSH session → (transport, channel, decoder, prompt). Pin is checked before the password is sent."""
        t = self._transport()
        try:
            got = t._sentinel_fp
            if not self.pin:
                raise PinRequired(got, KIND)
            if got != self.pin:
                raise PinMismatch(self.pin, got, KIND)
            user = str(self.creds.get("username") or "").strip()
            pw = str(self.creds.get("password") or "")
            if not user:
                raise DeviceError("enter the username")
            try:
                t.auth_password(user, pw)           # falls back to keyboard-interactive by itself
            except paramiko.BadAuthenticationType as e:
                if "none" in (e.allowed_types or []) or not e.allowed_types:
                    t.auth_none(user)               # CBS without 'ip ssh password-auth': login in-band below
                else:
                    raise DeviceError(f"the device does not accept password login (it offers: "
                                      f"{', '.join(e.allowed_types)})") from None
            except paramiko.AuthenticationException:
                raise DeviceError("login failed: wrong username or password") from None
            if not t.is_authenticated():
                raise DeviceError("login failed: wrong username or password")
            chan = t.open_session(timeout=15)
            chan.get_pty(term="vt100", width=511, height=200)
            chan.invoke_shell()
            dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
            st = {"chan": chan, "dec": dec}
            buf = self._read(st, lambda b: PROMPT_RE.search(b) or LOGIN_RE.search(b) or PASS_RE.search(b),
                             20, nudge=3, quiet=0.3, what="the login prompt")
            if LOGIN_RE.search(buf):                # Cisco Business in-band login
                self._send(st, user + "\n")
                buf = self._read(st, lambda b: PASS_RE.search(b) or PROMPT_RE.search(b), 15, what="Password:")
            if PASS_RE.search(buf) and not PROMPT_RE.search(buf):
                self._send(st, pw + "\n")
                buf = self._read(st, lambda b: PROMPT_RE.search(b) or LOGIN_RE.search(b), 20, what="the prompt")
                if not PROMPT_RE.search(buf):
                    raise DeviceError("login failed: wrong username or password")
            m = PROMPT_RE.search(buf)
            if m.group(3) == ">":
                self._send(st, "enable\n")
                buf = self._read(st, lambda b: PROMPT_RE.search(b.split("\n", 1)[-1]) or PASS_RE.search(b), 15,
                                 what="enable")
                if PASS_RE.search(buf):
                    self._send(st, str(self.creds.get("secret") or pw) + "\n")
                    buf = self._read(st, lambda b: PROMPT_RE.search(b) or PASS_RE.search(b), 15, what="enable")
                    if PASS_RE.search(buf) and not PROMPT_RE.search(buf):
                        self._send(st, "\x03\n")
                        buf = self._read(st, lambda b: PROMPT_RE.search(b), 10, what="enable")
                m = PROMPT_RE.search(buf)
                if not m or m.group(3) != "#":
                    raise DeviceError("'enable' failed: check the enable secret, or give the user privilege 15")
            prompt = m.group(0).strip()
            pagers = ["terminal datadump"] if self.cbs else ["terminal length 0", "terminal width 0"]
            for c in pagers:
                self._send(st, c + "\n")
                self._read(st, self._after_echo_prompt, 15, what=c)
            local_ip = t.sock.getsockname()[0] if t.sock else ""
            return t, chan, dec, prompt, local_ip
        except DeviceError:
            t.close()
            raise
        except (paramiko.SSHException, OSError, EOFError) as e:
            t.close()
            raise DeviceError(f"SSH session to {self.address} failed - {e}") from None

    def connect(self) -> None:
        with self._lock:
            self.close()
            self._t, self._chan, self._dec, self._prompt, self._local_ip = self._login()
            self.facts_cache = self.facts()

    def close(self) -> None:
        with self._lock:
            for x in (self._chan, self._t):
                try:
                    if x is not None:
                        x.close()
                except Exception:  # noqa: BLE001
                    pass
            self._t = self._chan = None

    def _alive(self) -> bool:
        return bool(self._t and self._t.is_active() and self._chan and not self._chan.closed
                    and not self._chan.exit_status_ready())

    def _ensure(self) -> None:
        """Reconnect if the device closed an idle session (vty exec-timeout)."""
        if not self._alive():
            self.close()
            self._t, self._chan, self._dec, self._prompt, self._local_ip = self._login()

    # ── reading / writing the shell ─────────────────────────────────────────
    @staticmethod
    def _send(st, text: str) -> None:
        try:
            st["chan"].sendall(text.encode())
        except (OSError, paramiko.SSHException, EOFError) as e:
            raise _Closed(f"connection to the device was lost - {e}") from None

    @staticmethod
    def _after_echo_prompt(buf: str):
        return "\n" in buf and PROMPT_RE.search(buf.split("\n", 1)[1])

    def _read(self, st, done, timeout: float, answers=(), nudge: float = 0, quiet: float = 0.08,
              what: str = "the command") -> str:
        """Read until done(buffer) holds and the device has gone quiet; page through --More--.
        Raises DeviceError on timeout or when the device closes the session."""
        chan, dec = st["chan"], st["dec"]
        buf, answered = "", 0
        start = time.monotonic()
        deadline = start + timeout
        last_data = start
        nudged = False
        while True:
            now = time.monotonic()
            if done(buf):
                if now - last_data >= quiet:
                    return buf
            elif now >= deadline:
                tail = buf.strip().splitlines()[-1:] or ["nothing"]
                raise DeviceError(f"no prompt from the device after {timeout:.0f}s waiting for {what} "
                                  f"(last output: {tail[0][:120]!r})")
            if nudge and not nudged and not buf.strip() and now - start > nudge:
                self._send(st, "\n")
                nudged = True
            chan.settimeout(max(0.02, min(quiet if done(buf) else 0.3, deadline - now)))
            try:
                data = chan.recv(65536)
            except socket.timeout:
                continue
            except (OSError, paramiko.SSHException, EOFError) as e:
                raise _Closed(f"connection to the device was lost - {e}") from None
            if not data:
                raise _Closed("the device closed the session")
            last_data = time.monotonic()
            text = dec.decode(data)
            text = ANSI_RE.sub("", text).replace("\r\n", "\n").replace("\r", "").replace("\x08", "")
            buf += text
            if MORE_RE.search(buf[-80:]):
                buf = MORE_RE.sub("", buf)
                self._send(st, " ")
                continue
            for rx, reply in answers:
                if rx.search(buf[answered:]):
                    answered = len(buf)
                    self._send(st, reply)
                    break

    def _drain(self) -> None:
        """Throw away output nobody waited for (an extra prompt after a one-key answer, late syslog)."""
        chan = self._chan
        try:
            chan.settimeout(0.0)
            while chan.recv_ready():
                if not chan.recv(65536):
                    break
        except (socket.timeout, OSError, paramiko.SSHException, EOFError):
            pass

    def _st(self):
        return {"chan": self._chan, "dec": self._dec}

    def _raw(self, line: str, timeout: float | None = None, answers=()) -> str:
        """Send one line, return everything after the echo up to (not including) the prompt."""
        st = self._st()
        self._drain()
        self._send(st, line + "\n")
        try:
            buf = self._read(st, self._after_echo_prompt, timeout or self.CMD_TIMEOUT, answers, what=repr(line))
        except DeviceError:
            self.close()            # unknown state: next use logs in again
            raise
        body = buf.split("\n", 1)[1]
        m = PROMPT_RE.search(body)
        self._prompt = m.group(0).strip()
        return body[:m.start()].strip("\n")

    def show(self, cmd: str, timeout: float | None = None) -> str:
        with self._lock:
            self._ensure()
            out = self._raw(cmd, timeout)
        err = self._errors(out)
        if err:
            raise DeviceError(f"'{cmd}': {err}")
        return out

    @staticmethod
    def _errors(out: str) -> str:
        bad = []
        for l in out.split("\n"):
            if SYSLOG_RE.search(l) or BENIGN_RE.match(l):
                continue
            if ERR_RE.match(l):
                bad.append(l.strip())
        return " ".join(bad)

    def _mode(self) -> str:
        m = PROMPT_RE.search("\n" + self._prompt)
        return (m.group(2) or "") if m else ""

    # ── read-only views ─────────────────────────────────────────────────────
    def facts(self) -> dict:
        ver = self.show("show version")
        f = {"hostname": "", "model": "", "version": "", "serial": "", "uptime": ""}
        m = PROMPT_RE.search("\n" + self._prompt)
        if m:
            f["hostname"] = m.group(1)
        if self.cbs:
            m = re.search(r"^\s*(?:SW )?[Vv]ersion:?\s+(\S+)", ver, re.M)
            f["version"] = m.group(1) if m else ""
            try:
                sysinfo = self.show("show system")
                for key, rx in (("model", r"System Description:\s*(.+)"), ("uptime", r"System Up Time[^:]*:\s*(.+)"),
                                ("hostname", r"System Name:\s*(\S+)")):
                    m = re.search(rx, sysinfo)
                    if m:
                        f[key] = m.group(1).strip()
                f["model"] = f["model"].split()[0] if f["model"] else ""
                inv = self.show("show inventory")
                m = re.search(r"SN:\s*(\S+)", inv)
                f["serial"] = m.group(1) if m else ""
            except DeviceError:
                pass
        else:
            for key, rx in (("version", r"Cisco IOS XE Software, Version (\S+)"),
                            ("model", r"^Model Number\s*:\s*(\S+)"),
                            ("serial", r"^System Serial Number\s*:\s*(\S+)"),
                            ("uptime", r"^\S+ uptime is (.+)$")):
                m = re.search(rx, ver, re.M)
                if m:
                    f[key] = m.group(1).strip()
            if not f["version"]:
                m = re.search(r"Version ([\w.()]+)", ver)
                f["version"] = m.group(1) if m else ""
            if not f["model"]:
                m = re.search(r"^cisco (\S+) .*processor", ver, re.M | re.I)
                f["model"] = m.group(1) if m else ""
            if not f["serial"]:
                m = re.search(r"Processor board ID (\S+)", ver)
                f["serial"] = m.group(1) if m else ""
            m = re.search(r"^Router operating mode:\s*(.+)$", ver, re.M)
            if m:
                f["mode"] = m.group(1).strip()
                if "controller" in f["mode"].lower():
                    f["warning"] = ("This router is in SD-WAN controller mode: its configuration is managed by "
                                    "SD-WAN Manager. The wizards only work in autonomous mode.")
        self.facts_cache = f
        return f

    def _controller_guard(self):
        if "controller" in str(self.facts_cache.get("mode", "")).lower():
            raise ValidationError("This device is in SD-WAN controller mode. Change its configuration from "
                                  "SD-WAN Manager (or convert it to autonomous mode first).")

    def interfaces(self) -> list[dict]:
        out = self._interfaces_cbs() if self.cbs else self._interfaces_ios()
        self.iface_cache = out
        return out

    def _interfaces_ios(self) -> list[dict]:
        brief = self.show("show ip interface brief")
        out, by = [], {}
        for l in brief.split("\n"):
            parts = l.split()
            if len(parts) < 6 or parts[0] == "Interface" or not IFACE_NAME_OK(parts[0]):
                continue
            st = " ".join(parts[4:-1])
            row = {"name": parts[0], "ip": "" if parts[1] == "unassigned" else parts[1],
                   "status": f"{st}/{parts[-1]}" if st != parts[-1] else st, "description": ""}
            out.append(row)
            by[canon_iface(parts[0])] = row
        try:
            self._descriptions(self.show("show interfaces description"), by)
        except DeviceError:
            pass
        return out

    @staticmethod
    def _descriptions(text: str, by: dict) -> None:
        lines = text.split("\n")
        hdr = next((l for l in lines if "Description" in l and ("Interface" in l or "Port" in l)), None)
        if not hdr:
            return
        col = hdr.index("Description")
        for l in lines[lines.index(hdr) + 1:]:
            if not l.strip() or set(l.strip()) <= {"-", " "}:
                continue
            row = by.get(canon_iface(l.split()[0]))
            if row is not None and len(l) > col:
                row["description"] = l[col:].strip()

    def _interfaces_cbs(self) -> list[dict]:
        out, by = [], {}
        try:
            for l in self.show("show interfaces status").split("\n"):
                parts = l.split()
                if parts and re.match(r"^(gi|te|fa|xg|po)\d", parts[0], re.I):
                    st = next((x for x in parts[1:] if x in ("Up", "Down", "Not")), "")
                    row = {"name": parts[0], "ip": "", "status": st.lower(), "description": ""}
                    out.append(row)
                    by[canon_iface(parts[0])] = row
        except DeviceError:
            pass
        try:
            for l in self.show("show ip interface").split("\n"):
                m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)/(\d+)\s+vlan\s*(\d+)\s+(\S+)", l, re.I)
                if m:
                    out.append({"name": f"vlan {m.group(3)}", "ip": f"{m.group(1)}/{m.group(2)}",
                                "status": m.group(4).lower(), "description": ""})
        except DeviceError:
            pass
        try:
            self._descriptions(self.show("show interfaces description"), by)
        except DeviceError:
            pass
        return out

    def backup(self) -> str:
        text = self.show("show running-config", self.LONG_TIMEOUT)
        lines = text.split("\n")
        while lines and (not lines[0].strip() or lines[0].startswith("Building configuration")):
            lines.pop(0)
        text = "\n".join(lines).strip("\n") + "\n"
        if "hostname" not in text and "interface" not in text:
            raise DeviceError("the device returned something that is not a configuration")
        return text

    def _running(self) -> str:
        return self.show("show running-config", self.LONG_TIMEOUT)

    def _vlans(self, cfg: str) -> dict[int, str]:
        out: dict[int, str] = {}
        try:
            text = self.show("show vlan" if self.cbs else "show vlan brief")
        except DeviceError:
            text = ""
        for l in text.split("\n"):
            m = re.match(r"^\s*(\d{1,4})\s+(\S+)", l)
            if m and 1 <= int(m.group(1)) <= 4094:
                out[int(m.group(1))] = m.group(2)
        for head, kids in rc_sections(cfg, r"^vlan \d+$").items():     # VTP transparent: names in the config
            vid = int(head.split()[1])
            names = [k[5:] for k in kids if k.startswith("name ")]
            out[vid] = names[0] if names else out.get(vid, "")
        return out

    # ── run a plan ──────────────────────────────────────────────────────────
    def execute(self, steps, values=None):
        """Config steps (extra.mode == 'config', the default) run in one configuration session per run of
        consecutive steps. With extra.revert > 0 (IOS-XE + archive) the session is opened with
        'configure terminal revert timer N' and confirmed only after a fresh SSH login succeeds; on any
        error it is rolled back at once with 'configure revert now'. Exec steps (extra.mode == 'exec')
        run in privileged EXEC, answering the save prompts."""
        values = dict(values or {})
        results: list[dict] = []
        steps = list(steps)
        if not steps:
            return results, values
        with self._lock:
            try:
                self._ensure()
            except DeviceError as e:
                return [{"step": steps[0].title, "ok": False, "detail": str(e)}], values
            i = 0
            while i < len(steps):
                st = steps[i]
                if (st.extra or {}).get("mode") == "exec":
                    ok, detail = self._exec_step(st, values)
                    results.append({"step": st.title, "ok": ok, "detail": detail})
                    if not ok:
                        break
                    i += 1
                    continue
                j = i
                while j < len(steps) and (steps[j].extra or {}).get("mode", "config") == "config":
                    j += 1
                res, ok = self._config_session(steps[i:j], values)
                results += res
                if not ok:
                    break
                i = j
        return results, values

    def _lines(self, st: Step, values: dict) -> list[str]:
        lines = [fill(l, values) if (st.extra or {}).get("fill") else l for l in st.cli]
        for l in lines:
            if re.search(r"[\x00-\x1f\x7f]", l) or NO_TEXT in l:
                raise DeviceError(f"refusing to send a line with control characters or '?': {l!r}")
        return lines

    def _exec_step(self, st: Step, values: dict) -> tuple[bool, str]:
        out_all = []
        try:
            self._ensure()
            if self._mode():
                self._raw("end")
            for line in self._lines(st, values):
                out = self._raw(line, self.LONG_TIMEOUT, SAVE_ANSWERS)
                err = self._errors(out)
                if err:
                    return False, f"'{line}' failed: {err}"
                out_all.append(out.strip().split("\n")[-1] if out.strip() else "")
        except DeviceError as e:
            return False, str(e)
        return True, " ".join(x for x in out_all if x) or "done"

    def _config_session(self, group: list[Step], values: dict) -> tuple[list[dict], bool]:
        revert = 0 if self.cbs else max(int((s.extra or {}).get("revert") or 0) for s in group)
        results: list[dict] = []
        entered = False
        cur = group[0]
        try:
            self._ensure()
            if self._mode():
                self._raw("end")
            enter = f"configure terminal revert timer {revert}" if revert else "configure terminal"
            out = self._raw(enter, 60)
            err = self._errors(out)
            if err or not self._mode():
                if self._mode():
                    self._raw("end")
                return [{"step": cur.title, "ok": False,
                         "detail": f"could not enter configuration mode ('{enter}'): {err or out.strip()}"}], False
            entered = True
            for cur in group:
                lines = self._lines(cur, values)
                for _ in range(6):
                    if self._mode() in ("(config)", ""):
                        break
                    self._raw("exit")
                k = 0
                while k < len(lines):
                    line = lines[k]
                    bm = BANNER_RE.match(line)
                    if bm:              # multi-line text: no prompt until the closing delimiter
                        end = next((x for x in range(k + 1, len(lines)) if bm.group(2) in lines[x]), None)
                        if end is None:
                            raise DeviceError(f"banner text in '{cur.title}' has no closing delimiter")
                        block = lines[k:end + 1]
                        out = self._banner(block, bm.group(2))
                        k = end + 1
                    else:
                        out = self._raw(line)
                        k += 1
                    err = self._errors(out)
                    if err:
                        detail = f"the device rejected '{line}': {err}"
                        detail += self._abort(revert)
                        results.append({"step": cur.title, "ok": False, "detail": detail})
                        return results, False
                results.append({"step": cur.title, "ok": True, "detail": f"{len(lines)} lines sent"})
            self._raw("end")
            entered = False
            if revert:
                ok, why = self._fresh_login()
                if not ok:
                    detail = (f"a new SSH login failed after the change ({why}), so it was not confirmed"
                              + self._abort(revert, in_config=False))
                    results[-1].update(ok=False, detail=results[-1]["detail"] + "; " + detail)
                    return results, False
                out = self._raw("configure confirm", 60)
                err = self._errors(out)
                if err:
                    results[-1].update(ok=False, detail=f"'configure confirm' failed: {err}. The device will roll "
                                                        f"back by itself within {revert} minutes.")
                    return results, False
                results[-1]["detail"] += "; a fresh SSH login worked, change confirmed (auto-revert cancelled)"
            return results, True
        except DeviceError as e:
            detail = str(e)
            if revert:
                detail += self._abort(revert, in_config=entered) if self._alive() else (
                    f". The session was lost before the change was confirmed: the device rolls back by itself "
                    f"within {revert} minutes.")
            elif entered and self._alive():
                try:
                    self._raw("end")
                except DeviceError:
                    pass
            results.append({"step": cur.title, "ok": False, "detail": detail})
            return results, False

    def _banner(self, block: list[str], delim: str) -> str:
        st = self._st()
        for line in block:
            self._send(st, line + "\n")
        try:
            buf = self._read(st, lambda b: delim in b[b.find("\n"):] and
                             PROMPT_RE.search(b[b.rfind(delim):].split("\n", 1)[-1]),
                             self.CMD_TIMEOUT, what="the end of the banner")
        except DeviceError:
            self.close()
            raise
        m = PROMPT_RE.search(buf, buf.rfind(delim))
        self._prompt = m.group(0).strip()
        # only what follows the closing delimiter is device output; the rest is the echoed banner text
        after = buf[buf.rfind(delim):m.start()]
        return after.split("\n", 1)[1] if "\n" in after else ""

    def _abort(self, revert: int, in_config: bool = True) -> str:
        """After a failure: leave config mode; with a revert timer roll back right away."""
        try:
            if in_config and self._mode():
                self._raw("end")
            if revert:
                out = self._raw("configure revert now", 120, SAVE_ANSWERS)
                err = self._errors(out)
                if err:
                    return (f". Rolling back failed ({err}); the device rolls back by itself within "
                            f"{revert} minutes.")
                return ". Nothing was kept: the device was rolled back to the configuration before this change."
            return (". Earlier lines of this change were applied and stay in place; use Undo or restore the "
                    "backup taken before the change.")
        except DeviceError as e:
            return (f". Could not roll back now ({e}); " +
                    (f"the device rolls back by itself within {revert} minutes." if revert else
                     "use Undo or restore the backup."))

    def _fresh_login(self) -> tuple[bool, str]:
        try:
            t, chan, *_ = self._login()
        except DeviceError as e:
            return False, str(e)
        try:
            chan.close()
            t.close()
        except Exception:  # noqa: BLE001
            pass
        return True, ""

    # ── wizards ─────────────────────────────────────────────────────────────
    def wizards(self):
        iface = lambda name, label, **kw: Field(name, label, "select", source="interfaces", **kw)
        common = [Field("save", "Save to startup-config (keeps the change after a reload)", "checkbox",
                        required=False, default=True)]
        if not self.cbs:
            common.insert(0, Field("revert", "Auto-revert timer (minutes)", "number", required=False, default=5,
                                   help="Used when the config archive is set up: if SentinelScan cannot log in "
                                        "again after the change, the device rolls it back after this time."))
        both, ios = ("iosxe", "cbs"), ("iosxe",)
        basics = [Field("hostname", "Hostname", placeholder="SW-CORE-1"),
                  Field("domain", "Domain name", required=False, placeholder="lab.local",
                        help="Leave empty to keep the current one."),
                  Field("dns", "DNS servers", required=False, placeholder="1.1.1.1, 9.9.9.9",
                        help="Replaces the current name servers (VRF-specific ones are kept). Empty = keep.")]
        if not self.cbs:
            basics.append(Field("ntp", "NTP servers", required=False, placeholder="pool.ntp.org or 192.168.1.1",
                                help="Replaces the current NTP servers (VRF-specific ones are kept). Empty = keep. "
                                     "Names need DNS working on the device."))
        return [
            Wizard("archive", "Enable config archive (needed for auto-revert)",
                   "Sets up 'archive' so every later change can be applied with an automatic rollback timer.", [
                       Field("location", "Archive location", "select", default="flash:",
                             options=[["flash:", "flash: (Catalyst 9000)"], ["bootflash:", "bootflash: (C8000 / ISR)"]]),
                       Field("maximum", "Archive copies to keep", "number", default=5, required=False),
                       common[-1],
                   ], self._w_archive, "Safety", ios),
            Wizard("basics", "Hostname, DNS and NTP" if not self.cbs else "Hostname and DNS",
                   "Name the device and point it at your DNS" + ("" if self.cbs else " and time servers") + ".",
                   basics + common, self._w_basics, "System", both),
            Wizard("banner", "Login banner", "The message shown before login (banner motd).", [
                Field("text", "Banner text", "textarea", placeholder="Authorized access only. Activity is logged.",
                      help="Up to 1000 characters. '^' and '?' are not allowed."),
            ] + common, self._w_banner, "System", ios),
            Wizard("vlan", "VLAN and access ports", "Create a VLAN and optionally put access ports in it.", [
                Field("vlan", "VLAN ID", "number", placeholder="20"),
                Field("name", "VLAN name", placeholder="Users", help="Letters, digits, '.', '_' or '-', max 32."),
                Field("ports", "Access ports", "multiselect", required=False, options=self._port_options(),
                      help="Optional. These ports become access ports in this VLAN."),
            ] + common, self._w_vlan, "Switching", both),
            Wizard("trunk", "Trunk port", "Make a port an 802.1Q trunk with an allowed VLAN list.", [
                iface("interface", "Port"),
                Field("allowed", "Allowed VLANs", placeholder="10,20,30-40"),
                Field("native", "Native VLAN", "number", required=False, placeholder="1",
                      help="Untagged VLAN on this trunk. Empty = keep."),
            ] + common, self._w_trunk, "Switching", ios),
            Wizard("l3iface", "Interface / SVI IP address", "Give an interface or VLAN interface an IPv4 address.", [
                iface("interface", "Interface", required=False, help="An existing interface, or leave empty and "
                      "enter a VLAN ID below to create a VLAN interface (SVI)."),
                Field("svi", "New VLAN interface (VLAN ID)", "number", required=False, placeholder="20",
                      help="Creates interface VlanN if it does not exist yet."),
                Field("address", "Address", placeholder="192.168.20.1/24"),
                Field("description", "Description", required=False),
                Field("routed", "Physical switch port: make it a routed port (no switchport)", "checkbox",
                      required=False, default=False),
                Field("noshut", "Enable the interface (no shutdown)", "checkbox", required=False, default=True),
                Field("confirm_lockout", "I am not managing the device through this address, or I have another way in",
                      "checkbox", required=False, default=False),
            ] + common, self._w_l3iface, "Routing", ios),
            Wizard("route", "Static route", "Send traffic for a network to a next-hop router.", [
                Field("prefix", "Destination network", placeholder="10.20.0.0/16 or 0.0.0.0/0"),
                Field("next_hop", "Next-hop IP", placeholder="192.168.1.254"),
                Field("distance", "Administrative distance", "number", required=False,
                      help="Optional (1-255). Higher = backup route."),
            ] + common, self._w_route, "Routing", ios),
            Wizard("hardening", "Management hardening",
                   "SSH version 2 only on the VTY lines, an idle timeout, no plain-HTTP web UI, and optionally "
                   "management only from trusted networks.", [
                       Field("exec_timeout", "Idle timeout (minutes)", "number", default=10),
                       Field("keep_https", "Keep the HTTPS web UI (ip http secure-server)", "checkbox",
                             required=False, default=False),
                       Field("mgmt_nets", "Allow management only from", required=False,
                             placeholder="192.168.1.0/24, 10.0.0.5",
                             help=f"Optional. Creates ACL {MGMT_ACL} on the VTY lines. Empty = from anywhere."),
                       Field("confirm_lockout", "I know SentinelScan's own address is not in that list "
                                                "and I have another way in", "checkbox", required=False, default=False),
                   ] + common, self._w_hardening, "Hardening", ios),
        ]

    # shared preparation
    def _ctx(self, p: dict, use_revert: bool = True):
        self._controller_guard()
        cfg = self._running()
        notes, revert = [], 0
        if self.cbs:
            notes.append("Catalyst 1200/1300 and CBS have no auto-revert. A backup is taken first; "
                         "use Undo or restore the backup if something goes wrong.")
        elif use_revert and has_archive(cfg):
            revert = v_int(p.get("revert") or 5, 1, 120, "auto-revert timer")
            notes.append(f"Applied inside 'configure terminal revert timer {revert}'. SentinelScan sends "
                         "'configure confirm' only after a new SSH login works; if it does not, the change is "
                         f"rolled back at once, or by the device itself within {revert} minutes.")
        elif use_revert:
            notes.append("The config archive is not set up, so this change uses plain 'configure terminal' "
                         "with no auto-revert. Run 'Enable config archive' first to get a safety net.")
        return cfg, revert, _flag(p, "save", True), notes

    def _cfg(self, title: str, lines: list[str], revert: int) -> Step:
        return Step(title, cli=lines, extra={"mode": "config", "revert": revert})

    def _save_step(self) -> Step:
        return Step("Save to startup-config",
                    cli=["copy running-config startup-config" if self.cbs else "write memory"],
                    extra={"mode": "exec"})

    def _plan(self, summary, steps, undo, notes, save) -> Plan:
        if save:
            steps.append(self._save_step())
            undo.append(self._save_step())
        else:
            notes.append("Not saved to startup-config: the change is lost at the next reload unless you save it.")
        return Plan(summary, steps, undo, notes)

    def _port_options(self) -> list[list[str]]:
        return [o for o in self.iface_options()
                if not re.match(r"^(vlan|loopback|tunnel|null|bdi|dialer)", canon_iface(o[0]))]

    def _ifaces(self) -> list[dict]:
        return self.iface_cache or self.interfaces()

    def _find_iface(self, name: str) -> dict | None:
        want = canon_iface(name)
        return next((i for i in self._ifaces() if canon_iface(i["name"]) == want), None)

    # wizard: archive
    def _w_archive(self, p, drv):
        loc = v_choice(p.get("location") or "flash:", ["flash:", "bootflash:"], "archive location")
        mx = v_int(p.get("maximum") or 5, 1, 14, "archive copies")
        cfg, _, save, notes = self._ctx(p, use_revert=False)
        if has_archive(cfg):
            raise ValidationError("The config archive is already set up on this device; auto-revert is available.")
        steps = [self._cfg("Configure the archive", ["archive", f" path {loc}{ARCHIVE_PREFIX}", f" maximum {mx}",
                                                      "exit"], 0)]
        if rc_sections(cfg, r"^archive\s*$"):       # an archive block exists (e.g. 'log config'): keep it
            undo = [self._cfg("Remove the archive path", ["archive", " no maximum", " no path", "exit"], 0)]
        else:
            undo = [self._cfg("Remove the archive", ["no archive"], 0)]
        notes.append(f"Archive copies go to {loc}{ARCHIVE_PREFIX}-<n>; at most {mx} are kept.")
        return self._plan(f"Config archive at {loc}{ARCHIVE_PREFIX}, keep {mx}", steps, undo, notes, save)

    # wizard: hostname / domain / DNS / NTP
    def _w_basics(self, p, drv):
        host = v_hostname(p["hostname"])
        domain = v_domain(p["domain"]) if str(p.get("domain") or "").strip() else ""
        dns = v_list(p.get("dns", ""), lambda s: v_ip(s, "DNS server"), "DNS servers", 6)
        ntp = [] if self.cbs else v_list(p.get("ntp", ""), lambda s: v_address(v_line(s, 80, "NTP server")),
                                          "NTP servers", 4)
        cfg, revert, save, notes = self._ctx(p)
        cur_host = (rc_top(cfg, "hostname ") or [""])[0][9:].strip()
        cur_dom = [l for l in rc_top(cfg, "ip domain") if re.match(r"^ip domain[ -]name (?!vrf )\S", l)]
        cur_ns = [s for l in rc_top(cfg, "ip name-server ") if " vrf " not in l for s in l.split()[2:]]
        cur_ntp = [l for l in rc_top(cfg, "ntp server ") if " vrf " not in l]
        lines, back = [f"hostname {host}"], [f"hostname {cur_host}"] if cur_host else []
        if domain:
            lines.append(f"ip domain name {domain}")
            back += cur_dom[:1] or ["no ip domain name"]
        if dns:
            lines += [f"no ip name-server {s}" for s in cur_ns] + [f"ip name-server {' '.join(dns)}"]
            back += [f"no ip name-server {s}" for s in dns] + ([f"ip name-server {' '.join(cur_ns)}"] if cur_ns else [])
        if ntp:
            lines += [f"no ntp server {l.split()[2]}" for l in cur_ntp] + [f"ntp server {s}" for s in ntp]
            back += [f"no ntp server {s}" for s in ntp] + cur_ntp
        if not cur_host:
            notes.append("The current hostname could not be read; Undo leaves the new one in place.")
        if ntp and any(not re.match(r"^[\d.:]+$", s) for s in ntp):
            notes.append("NTP server names are resolved by the device: it needs 'ip domain lookup' and a name server.")
        summary = f"Hostname {host}" + (f", domain {domain}" if domain else "") + \
                  (f", DNS {' '.join(dns)}" if dns else "") + (f", NTP {' '.join(ntp)}" if ntp else "")
        return self._plan(summary, [self._cfg("Hostname, domain, DNS and NTP", lines, revert)],
                          [self._cfg("Restore hostname, domain, DNS and NTP", back, revert)] if back else [],
                          notes, save)

    # wizard: banner
    def _w_banner(self, p, drv):
        text = v_multiline(p.get("text"), 1000, "banner text", forbid="^" + NO_TEXT)
        if not text.strip():
            raise ValidationError("banner text is empty")
        body = [l.rstrip() for l in text.split("\n")]
        cfg, revert, save, notes = self._ctx(p)
        old = rc_banner(cfg)
        steps = [self._cfg("Set the login banner", ["banner motd ^", *body, "^"], revert)]
        if old is None:
            back = ["no banner motd"]
        else:
            old_lines = [l.replace(NO_TEXT, "") for l in old.split("\n")]
            if NO_TEXT in old:
                notes.append("The current banner contains '?', which cannot be typed on the CLI; Undo restores it "
                             "without those characters.")
            d = next((c for c in "^#~@|&" if c not in old), None)
            back = ["banner motd " + d, *old_lines, d] if d else ["no banner motd"]
        return self._plan(f"Login banner ({len(body)} lines)", steps,
                          [self._cfg("Restore the previous banner", back, revert)], notes, save)

    # wizard: VLAN + access ports
    def _port(self, name: str, cfg: str) -> str:
        name = v_iface(name)
        i = self._find_iface(name)
        if not i:
            raise ValidationError(f"port {name} not found on the device")
        if re.match(r"^(vlan|loopback|tunnel|null|bdi|dialer)", canon_iface(name)):
            raise ValidationError(f"{name} is not a switch port")
        kids = rc_iface(cfg, name) or []
        if any(k.startswith("vrf forwarding") or k == "no switchport" for k in kids):
            raise ValidationError(f"{name} is a routed / management port, not a switch port")
        return i["name"]

    @staticmethod
    def _restore(kids: list[str], prefixes: list[tuple[str, str]]) -> list[str]:
        """For each (prefix, 'no …' line): re-apply the old lines with that prefix, or the 'no' line."""
        out = []
        for pre, neg in prefixes:
            old = [k for k in kids if k.startswith(pre)]
            out += [f" {k}" for k in old] if old else [f" {neg}"]
        return out

    def _w_vlan(self, p, drv):
        vid = v_vlan(p["vlan"])
        name = v_name(p["name"], "VLAN name")
        if len(name) > 32:
            raise ValidationError("VLAN name: at most 32 characters")
        cfg, revert, save, notes = self._ctx(p)
        ports = v_list(p.get("ports") or [], lambda s: self._port(s, cfg), "access ports", 48)
        existing = self._vlans(cfg)
        if self.cbs:
            lines = ["vlan database", f"vlan {vid}", "exit", f"interface vlan {vid}", f"name {name}", "exit"]
        else:
            lines = [f"vlan {vid}", f" name {name}", "exit"]
        back = []
        for port in ports:
            lines += [f"interface {port}", " switchport mode access", f" switchport access vlan {vid}", "exit"]
            kids = rc_iface(cfg, port) or []
            back += [f"interface {port}"] + self._restore(kids, [("switchport access vlan", "no switchport access vlan"),
                                                                 ("switchport mode", "no switchport mode")]) + ["exit"]
        if vid in existing:
            old = existing[vid]
            ok_old = bool(old) and not re.search(r"[\s?]", old)
            notes.append(f"VLAN {vid} already exists (name {old or '-'}); it is renamed, Undo restores the name.")
            if self.cbs:
                back += [f"interface vlan {vid}", f"name {old}" if ok_old else "no name", "exit"]
            else:
                back += [f"vlan {vid}", f" name {old}" if ok_old else " no name", "exit"]
        else:
            back += ["vlan database", f"no vlan {vid}", "exit"] if self.cbs else [f"no vlan {vid}"]
        if ports:
            notes.append("If you manage the switch through one of these ports, moving it to another VLAN cuts "
                         "the connection" + (" (the auto-revert would then undo it)." if revert else "."))
        return self._plan(f"VLAN {vid} '{name}'" + (f", access ports {', '.join(ports)}" if ports else ""),
                          [self._cfg(f"VLAN {vid}", lines, revert)],
                          [self._cfg(f"Undo VLAN {vid}", back, revert)], notes, save)

    # wizard: trunk
    def _w_trunk(self, p, drv):
        allowed = vlan_list(p["allowed"])
        native = v_vlan(p["native"]) if str(p.get("native") or "").strip() else None
        cfg, revert, save, notes = self._ctx(p)
        port = self._port(p["interface"], cfg)
        kids = rc_iface(cfg, port) or []
        lines = [f"interface {port}", " switchport mode trunk", f" switchport trunk allowed vlan {allowed}"]
        if native:
            lines.append(f" switchport trunk native vlan {native}")
        lines.append("exit")
        back = [f"interface {port}"] + self._restore(kids, [("switchport trunk allowed vlan", "no switchport trunk allowed vlan"),
                                                            ("switchport trunk native vlan", "no switchport trunk native vlan"),
                                                            ("switchport mode", "no switchport mode")]) + ["exit"]
        notes.append("If this port is your uplink to the switch, make sure the management VLAN is in the allowed "
                     "list and the native VLAN matches the other side.")
        return self._plan(f"{port}: trunk, VLANs {allowed}" + (f", native {native}" if native else ""),
                          [self._cfg(f"Trunk on {port}", lines, revert)],
                          [self._cfg(f"Restore {port}", back, revert)], notes, save)

    # wizard: interface / SVI address
    def _w_l3iface(self, p, drv):
        if str(p.get("svi") or "").strip():
            name = f"Vlan{v_vlan(p['svi'])}"
        elif str(p.get("interface") or "").strip():
            name = v_iface(p["interface"])
        else:
            raise ValidationError("choose an interface, or enter a VLAN ID for a new VLAN interface")
        addr = v_iface_addr(p["address"])
        if addr.network.prefixlen < 31 and addr.ip in (addr.network.network_address, addr.network.broadcast_address):
            raise ValidationError(f"address: {addr.ip} is the network or broadcast address of {addr.network}")
        desc = v_line(p.get("description"), 200, "description")
        routed, noshut = _flag(p, "routed"), _flag(p, "noshut", True)
        cfg, revert, save, notes = self._ctx(p)
        cur = self._find_iface(name)
        if cur:
            name = cur["name"]
        elif not re.match(r"^(Vlan([1-9]\d{0,3})|Loopback\d{1,10})$", name):
            raise ValidationError(f"interface {name} not found on the device (new ones: VlanN or LoopbackN)")
        elif name.startswith("Vlan"):
            v_vlan(name[4:])
        if cur and cur.get("ip") and cur["ip"].split("/")[0] == self.address and str(addr.ip) != self.address \
                and not _flag(p, "confirm_lockout"):
            raise ValidationError(f"You are connected to the device through {name} ({self.address}). Changing its "
                                  "address would cut this connection. Tick the confirmation if you have another way in.")
        kids = rc_iface(cfg, name)
        lines = [f"interface {name}"] + ([" no switchport"] if routed else []) + \
                ([f" description {desc}"] if desc else []) + [f" ip address {addr.ip} {addr.netmask}"] + \
                ([" no shutdown"] if noshut else []) + ["exit"]
        if kids is None:
            back = [f"no interface {name}"]
        else:
            back = [f"default interface {name}", f"interface {name}"] + [f" {k}" for k in kids if NO_TEXT not in k]
            if "shutdown" not in kids:
                back.append(" no shutdown")
            back.append("exit")
            if any(NO_TEXT in k for k in kids):
                notes.append("A current line on this interface contains '?' and cannot be restored by Undo.")
        return self._plan(f"{name}: {addr}" + (f" '{desc}'" if desc else ""),
                          [self._cfg(f"Address on {name}", lines, revert)],
                          [self._cfg(f"Restore {name}", back, revert)], notes, save)

    # wizard: static route
    def _w_route(self, p, drv):
        net = v_cidr(p["prefix"], "destination network")
        nh = v_ipv4(p["next_hop"], "next-hop")
        dist = v_int(p["distance"], 1, 255, "distance") if str(p.get("distance") or "").strip() else None
        cfg, revert, save, notes = self._ctx(p)
        base = f"ip route {net.network_address} {net.netmask} {nh}"
        line = base + (f" {dist}" if dist else "")
        same = [l for l in rc_top(cfg, f"ip route {net.network_address} {net.netmask} ")]
        if any(l == base or l.startswith(base + " ") for l in same):
            raise ValidationError(f"a route to {net} via {nh} already exists")
        if same:
            notes.append(f"Other routes to {net} stay in place: {'; '.join(same)}")
        if net.prefixlen == 0:
            notes.append("This is a default route. If your management traffic depends on it, a wrong next hop "
                         "cuts you off" + (" (the auto-revert would undo it)." if revert else "."))
        return self._plan(f"Route {net} via {nh}" + (f" (distance {dist})" if dist else ""),
                          [self._cfg(f"Add route {net}", [line], revert)],
                          [self._cfg(f"Remove route {net}", [f"no {base}"], revert)], notes, save)

    # wizard: management hardening
    def _w_hardening(self, p, drv):
        tmo = v_int(p.get("exec_timeout") or 10, 1, 120, "idle timeout")
        keep_https = _flag(p, "keep_https")
        nets = v_list(p.get("mgmt_nets", ""), lambda s: v_cidr(s, "management network"), "management networks", 20)
        cfg, revert, save, notes = self._ctx(p)
        vty = rc_sections(cfg, r"^line vty \d+( \d+)?$")
        if not vty:
            raise ValidationError("no 'line vty' found in the running configuration")
        me = self._local_ip
        if nets and me:
            try:
                inside = any(ipaddress.ip_address(me) in n for n in nets)
            except ValueError:
                inside = False
            if not inside and not _flag(p, "confirm_lockout"):
                raise ValidationError(f"SentinelScan connects from {me}, which is not in the allowed networks. "
                                      "That would lock this connection out. Add it, or tick the confirmation.")
        top = {l.rstrip() for l in rc_lines(cfg)}
        lines = ["ip ssh version 2", "no ip http server",
                 "ip http secure-server" if keep_https else "no ip http secure-server"]
        back = [*(rc_top(cfg, "ip ssh version ") or ["no ip ssh version"]),
                "ip http server" if "ip http server" in top else "no ip http server",
                "ip http secure-server" if "ip http secure-server" in top else "no ip http secure-server"]
        acl_old = rc_sections(cfg, rf"^ip access-list standard {MGMT_ACL}$").get(f"ip access-list standard {MGMT_ACL}")
        if nets:
            if acl_old is not None:
                lines.append(f"no ip access-list standard {MGMT_ACL}")
            lines += [f"ip access-list standard {MGMT_ACL}"] + \
                     [f" permit host {n.network_address}" if n.prefixlen == 32 else
                      f" permit {n.network_address} {n.hostmask}" for n in nets] + ["exit"]
        for head, kids in vty.items():
            lines += [head, " transport input ssh", f" exec-timeout {tmo} 0"] + \
                     ([f" access-class {MGMT_ACL} in vrf-also"] if nets else []) + ["exit"]
            back += [head] + self._restore(kids, [("transport input", "default transport input"),
                                                  ("exec-timeout", "no exec-timeout")])
            if nets:
                old_ac = [k for k in kids if k.startswith("access-class ")]
                back += [f" {k}" for k in old_ac] if old_ac else [f" no access-class {MGMT_ACL} in"]
            back.append("exit")
        if nets:
            back.append(f"no ip access-list standard {MGMT_ACL}")
            if acl_old is not None:
                back += [f"ip access-list standard {MGMT_ACL}"] + [f" {k}" for k in acl_old] + ["exit"]
        notes.append("SentinelScan is connected over SSH, so 'transport input ssh' keeps this session working. "
                     "Telnet stops working on the VTY lines.")
        if not keep_https:
            notes.append("The web UI (HTTP and HTTPS) is switched off. Tick 'Keep the HTTPS web UI' if you use it.")
        if not rc_top(cfg, "ip ssh version 2") and not revert:
            notes.append("SSH version 2 needs an RSA key of at least 768 bits ('crypto key generate rsa modulus "
                         "2048'); SentinelScan already uses SSHv2, so the key exists.")
        return self._plan(f"SSHv2 only, idle timeout {tmo} min, HTTP off" + (", HTTPS kept" if keep_https else
                          ", HTTPS off") + (f", management from {', '.join(map(str, nets))}" if nets else ""),
                          [self._cfg("Harden management access", lines, revert)],
                          [self._cfg("Restore management access", back, revert)], notes, save)


def IFACE_NAME_OK(s: str) -> bool:
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9_./:\-]{0,47}$", s))
