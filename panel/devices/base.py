"""
Device wizard framework: what every vendor driver provides.

A *driver* talks to one device (REST/XML API over HTTPS, or SSH CLI).
A *wizard* turns form input into a *Plan*: the exact API calls or CLI lines
that will be sent, plus an undo plan where one exists. Nothing is sent until
the user has seen the plan and pressed Apply; the manager takes a config
backup first.

Every value that reaches a device passes a validator here. For CLI vendors
this is what stops a newline in a form field from becoming an extra command.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, Callable


# ── errors ───────────────────────────────────────────────────────────────────
class DeviceError(Exception):
    """Something the user should read: bad credentials, unreachable, API refused."""


class PinRequired(DeviceError):
    """First connection: the user must confirm the device's certificate / host key."""
    def __init__(self, fingerprint: str, kind: str = "TLS certificate"):
        super().__init__(f"Confirm the device's {kind} fingerprint before sending credentials")
        self.fingerprint = fingerprint
        self.kind = kind


class PinMismatch(DeviceError):
    def __init__(self, expected: str, got: str, kind: str = "TLS certificate"):
        super().__init__(
            f"The device's {kind} changed (expected {expected[:23]}…, got {got[:23]}…). "
            "This happens after a certificate renewal or factory reset - or if something is "
            "impersonating the device. Credentials were not sent.")
        self.fingerprint = got
        self.kind = kind


class ValidationError(DeviceError):
    pass


# ── validators ───────────────────────────────────────────────────────────────
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,62}$")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$")
IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_./:\-]{0,47}$")
CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def v_name(v: str, what: str = "name") -> str:
    v = str(v).strip()
    if not NAME_RE.match(v):
        raise ValidationError(f"{what}: use letters, digits, '.', '_' or '-' (max 63, start with a letter or digit)")
    return v


def v_hostname(v: str) -> str:
    v = str(v).strip()
    if not HOSTNAME_RE.match(v):
        raise ValidationError("hostname: letters, digits and '-', 1-63 characters, no dots or spaces")
    return v


def v_address(v: str) -> str:
    """A device address: an IP, or a DNS name like fw1.lab.local."""
    s = str(v).strip()
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        pass
    labels = s.rstrip(".").split(".")
    if s and len(s) <= 253 and all(HOSTNAME_RE.match(x) for x in labels):
        return s
    raise ValidationError(f"address: '{v}' is neither an IP address nor a host name")


def v_iface(v: str) -> str:
    v = str(v).strip()
    if not IFACE_RE.match(v):
        raise ValidationError(f"interface '{v}' does not look like an interface name")
    return v


def v_ip(v: str, what: str = "IP address") -> str:
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        raise ValidationError(f"{what}: '{v}' is not a valid IP address") from None


def v_ipv4(v: str, what: str = "IPv4 address") -> str:
    ip = v_ip(v, what)
    if ":" in ip:
        raise ValidationError(f"{what}: IPv4 only")
    return ip


def v_cidr(v: str, what: str = "network", host_ok: bool = False) -> ipaddress.IPv4Network:
    """'10.0.0.0/24' (or a bare IP = /32). host_ok allows '10.0.0.1/24' (interface address)."""
    s = str(v).strip()
    if "/" not in s:
        s += "/32"
    try:
        return ipaddress.IPv4Network(s, strict=not host_ok)
    except ValueError:
        raise ValidationError(f"{what}: '{v}' is not a valid IPv4 network like 192.168.10.0/24") from None


def v_iface_addr(v: str, what: str = "interface address") -> ipaddress.IPv4Interface:
    s = str(v).strip()
    if "/" not in s:
        raise ValidationError(f"{what}: include the prefix, e.g. 192.168.10.1/24")
    try:
        return ipaddress.IPv4Interface(s)
    except ValueError:
        raise ValidationError(f"{what}: '{v}' is not valid, use e.g. 192.168.10.1/24") from None


def v_int(v, lo: int, hi: int, what: str = "value") -> int:
    try:
        n = int(str(v).strip())
    except ValueError:
        raise ValidationError(f"{what}: must be a whole number") from None
    if not lo <= n <= hi:
        raise ValidationError(f"{what}: must be between {lo} and {hi}")
    return n


def v_port(v, what: str = "port") -> int:
    return v_int(v, 1, 65535, what)


def v_choice(v, options, what: str = "value") -> str:
    v = str(v).strip()
    if v not in options:
        raise ValidationError(f"{what}: choose one of {', '.join(options)}")
    return v


def v_text(v, max_len: int = 200, what: str = "text", forbid: str = "") -> str:
    """One line of free text (comments, descriptions)."""
    s = str(v or "").strip()
    if CTRL_RE.search(s):
        raise ValidationError(f"{what}: must be a single line")
    if len(s) > max_len:
        raise ValidationError(f"{what}: at most {max_len} characters")
    bad = [c for c in forbid if c in s]
    if bad:
        raise ValidationError(f"{what}: may not contain {' '.join(repr(c) for c in bad)}")
    return s


def v_multiline(v, max_len: int = 1000, what: str = "text", forbid: str = "") -> str:
    """Banner-style text: newlines allowed, other control characters not."""
    s = str(v or "").replace("\r\n", "\n").strip("\n")
    if re.search(r"[\x00-\x09\x0b-\x1f\x7f]", s):
        raise ValidationError(f"{what}: contains control characters")
    if len(s) > max_len:
        raise ValidationError(f"{what}: at most {max_len} characters")
    bad = [c for c in forbid if c in s]
    if bad:
        raise ValidationError(f"{what}: may not contain {' '.join(repr(c) for c in bad)}")
    return s


def v_list(v, item: Callable[[str], Any], what: str = "list", max_items: int = 64) -> list:
    """Comma / space / newline separated input → validated items."""
    if isinstance(v, (list, tuple)):
        parts = [str(x) for x in v]
    else:
        parts = re.split(r"[,\s]+", str(v or ""))
    parts = [p for p in (x.strip() for x in parts) if p]
    if len(parts) > max_items:
        raise ValidationError(f"{what}: at most {max_items} entries")
    return [item(p) for p in parts]


def v_vlan(v) -> int:
    n = v_int(v, 1, 4094, "VLAN ID")
    if 1002 <= n <= 1005:
        raise ValidationError("VLAN 1002-1005 are reserved on Cisco switches")
    return n


# ── wizard description (sent to the browser to draw the form) ──────────────
@dataclass
class Field:
    name: str
    label: str
    type: str = "text"          # text | textarea | number | select | multiselect | checkbox | password
    required: bool = True
    default: Any = ""
    help: str = ""
    placeholder: str = ""
    options: list = field(default_factory=list)   # [[value, label], ...]
    source: str = ""            # "interfaces" → options filled from the live device

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class Wizard:
    id: str
    title: str
    summary: str
    fields: list[Field]
    build: Callable[[dict, "Driver"], "Plan"]
    group: str = "Setup"
    applies_to: tuple = ()      # family keys this wizard supports; empty = all

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "summary": self.summary, "group": self.group,
                "fields": [f.to_dict() for f in self.fields]}


# ── plans ────────────────────────────────────────────────────────────────────
@dataclass
class Step:
    """One unit of work. Either an API request or a block of CLI lines."""
    title: str
    method: str = ""            # API: GET POST PUT DELETE   (empty for CLI)
    path: str = ""              # API path; may contain {name} placeholders filled from earlier results
    body: Any = None            # API body (dict → JSON)
    cli: list[str] = field(default_factory=list)
    capture: dict = field(default_factory=dict)   # {"policy_id": "mkey"}: remember a value from the response
    extra: dict = field(default_factory=dict)     # vendor specific (PAN-OS xpath/element, …)

    def render(self) -> str:
        if self.cli:
            return "\n".join(self.cli)
        out = f"{self.method} {self.path}"
        if self.extra:
            out += "".join(f"\n  {k}: {v}" for k, v in self.extra.items())
        if self.body is not None:
            out += "\n" + (json.dumps(self.body, indent=2) if not isinstance(self.body, str) else self.body)
        return out

    def to_dict(self) -> dict:
        return {"title": self.title, "text": self.render()}


@dataclass
class Plan:
    summary: str
    steps: list[Step]
    undo: list[Step] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)     # warnings shown with the preview
    commit: bool = False        # vendor needs a commit / publish after the steps

    def render(self) -> str:
        return "\n\n".join(f"# {s.title}\n{s.render()}" for s in self.steps)

    def to_dict(self) -> dict:
        return {"summary": self.summary, "steps": [s.to_dict() for s in self.steps],
                "undo": [s.to_dict() for s in self.undo], "notes": self.notes, "commit": self.commit,
                "text": self.render()}


def fill(template: str, values: dict) -> str:
    """Put captured values into a path: '/policy/{policy_id}'."""
    def sub(m):
        k = m.group(1)
        if k not in values:
            raise DeviceError(f"value '{k}' from an earlier step is missing")
        return str(values[k])
    return re.sub(r"\{(\w+)\}", sub, template)


# ── HTTPS with certificate pinning ───────────────────────────────────────────
def cert_fingerprint(der: bytes) -> str:
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


class PinnedHTTPS:
    """
    Network devices ship self-signed certificates, so normal CA checks fail.
    Instead we pin: the first connection shows the certificate's SHA-256
    fingerprint, the user confirms it, and every later connection must present
    the same certificate *before* any credential is sent.
    """
    def __init__(self, host: str, port: int, pin: str | None, timeout: float = 15):
        self.host, self.port, self.pin, self.timeout = host, port, pin, timeout
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE      # replaced by the pin check below
        try:
            self.ctx.set_ciphers("DEFAULT:@SECLEVEL=1")   # older FortiOS / Spark firmware
        except ssl.SSLError:
            pass
        self.cookies: dict[str, str] = {}

    def fingerprint(self) -> str:
        conn = self._open()
        try:
            return cert_fingerprint(conn.sock.getpeercert(binary_form=True))
        finally:
            conn.close()

    def _open(self) -> http.client.HTTPSConnection:
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.ctx)
        try:
            conn.connect()
        except (OSError, ssl.SSLError) as e:
            raise DeviceError(f"cannot reach {self.host}:{self.port} - {e}") from None
        return conn

    def request(self, method: str, path: str, body: bytes | None = None,
                headers: dict | None = None) -> tuple[int, dict, bytes]:
        conn = self._open()
        try:
            got = cert_fingerprint(conn.sock.getpeercert(binary_form=True))
            if not self.pin:
                raise PinRequired(got)
            if got != self.pin:
                raise PinMismatch(self.pin, got)
            h = dict(headers or {})
            if self.cookies:
                h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            conn.request(method, path, body=body, headers=h)
            resp = conn.getresponse()
            data = resp.read()
            for k, v in resp.getheaders():
                if k.lower() == "set-cookie":
                    name, _, rest = v.partition("=")
                    self.cookies[name.strip()] = rest.split(";", 1)[0]
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
        except (OSError, http.client.HTTPException) as e:
            raise DeviceError(f"connection to {self.host}:{self.port} failed - {e}") from None
        finally:
            conn.close()


# ── the driver contract ──────────────────────────────────────────────────────
class Driver:
    vendor = ""                 # fortinet | cisco | paloalto | checkpoint
    label = ""
    default_port = 443
    pin_kind = "TLS certificate"
    # credential fields the Add-device form shows for this vendor
    auth_fields: list[Field] = []

    def __init__(self, address: str, port: int | None, creds: dict, pin: str | None, family: str = ""):
        self.address = address
        self.port = port or self.default_port
        self.creds = creds          # held in memory only, never written anywhere
        self.pin = pin
        self.family = family        # model family key from the catalog
        self.facts_cache: dict = {}
        self.iface_cache: list[dict] = []

    # connection
    def probe_fingerprint(self) -> str:
        raise NotImplementedError

    def connect(self) -> None:
        """Log in (raises PinRequired / PinMismatch / DeviceError)."""
        raise NotImplementedError

    def close(self) -> None:
        pass

    # read-only views
    def facts(self) -> dict:
        """{"hostname", "model", "version", "serial", "uptime"?}"""
        raise NotImplementedError

    def interfaces(self) -> list[dict]:
        """[{"name", "ip", "status", "description"}]"""
        raise NotImplementedError

    def backup(self) -> str:
        """Full configuration as text."""
        raise NotImplementedError

    # changes
    def wizards(self) -> list[Wizard]:
        raise NotImplementedError

    def execute(self, steps: list[Step], values: dict | None = None) -> tuple[list[dict], dict]:
        """Run steps in order, stop at the first failure.
        Returns ([{"step", "ok", "detail"}, ...], captured values for the undo plan)."""
        raise NotImplementedError

    def commit(self) -> str:
        """Vendors with a candidate config (PAN-OS, Check Point) override this."""
        return ""

    def discard(self) -> str:
        return ""

    def wizard(self, wid: str) -> Wizard:
        for w in self.wizards():
            if w.id == wid:
                return w
        raise DeviceError(f"unknown wizard {wid}")

    def iface_options(self) -> list[list[str]]:
        if not self.iface_cache:
            try:
                self.iface_cache = self.interfaces()
            except DeviceError:
                self.iface_cache = []
        return [[i["name"], f"{i['name']}  {i.get('ip') or ''}  {i.get('description') or ''}".strip()]
                for i in self.iface_cache]


def tcp_reachable(host: str, port: int, timeout: float = 4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
