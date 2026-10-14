"""Machines the Actions page can run on, reached over SSH.

The user opens a connection (host, port, user; password, pasted key or key
file), confirms the machine's SSH host key on first contact (pinned after
that, like the device wizard), and the Actions page then runs its steps
there. The machine's distro is read from its /etc/os-release, so each action
picks the right package manager for *that* machine.

Secrets (password, key, key passphrase, sudo password) are kept in this
process's memory for the open connection only, and dropped on disconnect.
The database keeps host, port, user, the confirmed fingerprint, distro and
when it was last used (table action_targets).

sudo on the remote machine: the step's `sudo` becomes
`sudo -S -p <random marker>`. When that marker appears in the output the
panel sends the sudo password on the session's input; the password is never
part of a command line, so it doesn't show in the remote `ps`. Without a
sudo password, `sudo -n` is used (fails at once instead of waiting).
"""
from __future__ import annotations

import base64
import hashlib
import io
import secrets
import shlex
import socket
import threading
import time
import uuid

import paramiko

import db

KIND = "SSH host key"
TARGETS: dict[str, dict] = {}
_LOCK = threading.Lock()


class TargetError(ValueError):
    pass


class NeedsTrust(TargetError):
    def __init__(self, fingerprint: str, changed_from: str | None = None):
        msg = ("The machine's SSH host key CHANGED since you last connected - this happens after a reinstall, "
               "or if something is impersonating it. Nothing was sent." if changed_from else
               "First connection: confirm the machine's SSH host key fingerprint.")
        super().__init__(msg)
        self.fingerprint, self.changed_from = fingerprint, changed_from


def fingerprint(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def _q(sql, args=(), one=False):
    import actions
    return actions._q(sql, args, one)


def _transport(host: str, port: int) -> paramiko.Transport:
    try:
        sock = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        raise TargetError(f"cannot reach {host}:{port} - {e}") from None
    t = paramiko.Transport(sock)
    t.banner_timeout, t.handshake_timeout, t.auth_timeout = 15, 20, 20
    try:
        t.start_client(timeout=20)
    except (paramiko.SSHException, OSError, EOFError) as e:
        t.close()
        raise TargetError(f"SSH handshake with {host}:{port} failed - {e or 'timed out'}") from None
    return t


def _pinned(host: str, port: int) -> str | None:
    r = _q("SELECT fingerprint FROM action_targets WHERE host = %s AND port = %s AND fingerprint IS NOT NULL "
           "ORDER BY last_used DESC NULLS LAST LIMIT 1", (host, port), one=True)
    return r["fingerprint"] if r else None


def _load_key(text: str, passphrase: str | None):
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase or None)
        except paramiko.PasswordRequiredException:
            raise TargetError("this key is protected by a passphrase - enter it") from None
        except (paramiko.SSHException, ValueError, IndexError):
            continue
    raise TargetError("the private key could not be read (OpenSSH Ed25519, ECDSA or RSA keys are supported)")


def connect(body: dict) -> dict:
    """Open (or re-check) a connection. Raises NeedsTrust until the user confirms the fingerprint."""
    host = str(body.get("host") or "").strip()
    user = str(body.get("user") or "").strip()
    try:
        port = int(body.get("port") or 22)
    except (TypeError, ValueError):
        raise TargetError("port must be a number") from None
    if not host or not 1 <= port <= 65535:
        raise TargetError("enter the machine's address")
    if not user or not all(c.isalnum() or c in "._-" for c in user):
        raise TargetError("enter a valid user name")
    auth = body.get("auth") or "password"
    password = str(body.get("password") or "")
    key_text = str(body.get("key") or "")
    if auth == "key_path":
        path = str(body.get("key_path") or "").strip()
        try:
            import os
            key_text = open(os.path.expanduser(path)).read()
        except OSError as e:
            raise TargetError(f"cannot read the key file: {e.strerror}") from None
    if auth == "password" and not password:
        raise TargetError("enter the password")
    if auth in ("key", "key_path") and "PRIVATE KEY" not in key_text:
        raise TargetError("that doesn't look like a private key")

    t = _transport(host, port)
    try:
        got = fingerprint(t.get_remote_server_key())
        pinned = _pinned(host, port)
        trust = str(body.get("trust") or "")
        if pinned and got != pinned:
            if trust != got:
                raise NeedsTrust(got, pinned)            # changed key: only a fresh explicit confirmation
        elif not pinned and trust != got:
            raise NeedsTrust(got)
        try:
            if auth == "password":
                t.auth_password(user, password)
            else:
                t.auth_publickey(user, _load_key(key_text, str(body.get("key_passphrase") or "")))
        except paramiko.AuthenticationException:
            raise TargetError("login failed: wrong user name, password or key") from None
        except paramiko.SSHException as e:
            raise TargetError(f"login failed: {e}") from None
        t.set_keepalive(30)
        tid = uuid.uuid4().hex[:10]
        sudo_pw = password if (auth == "password" and body.get("sudo_with_login", True) is not False) \
            else str(body.get("sudo_password") or "")
        tgt = {"id": tid, "host": host, "port": port, "user": user, "transport": t, "fingerprint": got,
               "sudo_pw": sudo_pw, "auth": auth, "connected_at": time.time()}
        info = _probe_system(tgt)
        tgt.update(info)
    except Exception:
        t.close()
        raise
    with _LOCK:
        TARGETS[tid] = tgt
    _q("""INSERT INTO action_targets (host, port, username, fingerprint, distro, last_used)
          VALUES (%s, %s, %s, %s, %s, now())
          ON CONFLICT (host, port, username) DO UPDATE
          SET fingerprint = EXCLUDED.fingerprint, distro = EXCLUDED.distro, last_used = now()""",
       (host, port, user, got, tgt["distro"]["pretty"]))
    db.log("action.target.connect", f"{user}@{host}:{port}", {"fingerprint": got, "distro": tgt["distro"]["pretty"],
                                                            "auth": auth, "sudo_password": bool(sudo_pw)})
    return public(tgt)


def _exec_simple(tgt: dict, cmd: str, timeout: float = 20) -> tuple[int, str]:
    ch = tgt["transport"].open_session(timeout=15)
    ch.settimeout(timeout)
    ch.exec_command(cmd)
    out = b""
    try:
        while True:
            d = ch.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    rc = ch.recv_exit_status() if ch.exit_status_ready() else -1
    ch.close()
    return rc, out.decode("utf-8", "replace")


def _probe_system(tgt: dict) -> dict:
    import actions
    rc, out = _exec_simple(tgt, "cat /etc/os-release 2>/dev/null; echo '---'; command -v bash || echo nobash; "
                                "echo '---'; hostname")
    parts = out.split("---")
    info = {}
    for line in parts[0].splitlines():
        k, _, v = line.partition("=")
        info[k.strip()] = v.strip().strip('"')
    d = actions.distro_from(info)
    shell = "bash" if len(parts) > 1 and "nobash" not in parts[1] else "sh"
    name = parts[2].strip() if len(parts) > 2 else tgt["host"]
    return {"distro": d, "shell": shell, "hostname": name[:80]}


def public(t: dict) -> dict:
    return {"id": t["id"], "host": t["host"], "port": t["port"], "user": t["user"], "hostname": t.get("hostname"),
            "distro": t["distro"], "fingerprint": t["fingerprint"], "sudo": bool(t.get("sudo_pw")),
            "connected": t["transport"].is_active()}


def get(tid: str) -> dict:
    with _LOCK:
        t = TARGETS.get(tid)
    if not t:
        raise TargetError("that connection is closed - connect again")
    if not t["transport"].is_active():
        disconnect(tid)
        raise TargetError(f"the connection to {t['host']} was lost - connect again")
    return t


def list_open() -> list[dict]:
    with _LOCK:
        items = list(TARGETS.values())
    return [public(t) for t in items]


def disconnect(tid: str) -> dict:
    with _LOCK:
        t = TARGETS.pop(tid, None)
    if t:
        try:
            t["transport"].close()
        finally:
            t["sudo_pw"] = ""
        db.log("action.target.disconnect", f"{t['user']}@{t['host']}:{t['port']}")
    return {"closed": bool(t)}


def known() -> dict:
    """Machines connected to before (no secrets) and SSH hosts from the latest scans."""
    prev = _q("SELECT host, port, username, fingerprint, distro, last_used FROM action_targets "
              "ORDER BY last_used DESC NULLS LAST LIMIT 30")
    try:
        scanned = _q("""SELECT DISTINCT ON (host(h.ip)) host(h.ip) AS host, h.hostname, h.device_type, h.os_guess,
                               s2.started_at
                        FROM hosts h JOIN services sv ON sv.host_id = h.id AND sv.port = 22
                        JOIN scans s2 ON s2.id = h.scan_id
                        ORDER BY host(h.ip), s2.started_at DESC""")
    except Exception:  # noqa: BLE001
        scanned = []
    return {"previous": prev, "scanned": scanned[:100]}


def forget(host: str, port: int) -> dict:
    """Drop a confirmed host key (e.g. after reinstalling that machine)."""
    _q("DELETE FROM action_targets WHERE host = %s AND port = %s", (host, int(port)))
    db.log("action.target.forget", f"{host}:{port}")
    return {"forgotten": True}


def _redact(t: dict, text: str) -> str:
    """Second line of defence if a remote tty echoes the sudo password anyway."""
    pw = t.get("sudo_pw") or ""
    return text.replace(pw, "[sudo password hidden]") if len(pw) >= 4 else text


def run_step(t: dict, cmd: str, emit, should_stop, timeout: float = 30 * 60) -> int:
    """Run one step on the remote machine; stream output through emit(text). Returns the exit code."""
    marker = "SENTINEL_SUDO_" + secrets.token_hex(6) + ":"
    if t.get("sudo_pw"):
        wrap = f"sudo() {{ command sudo -S -p '{marker}' \"$@\"; }}\n"
    else:
        wrap = 'sudo() { command sudo -n "$@"; }\n'
    # the pty echoes what we send; with echo off the sudo password never shows in the output
    script = "stty -echo 2>/dev/null\n" + wrap + cmd
    line = (f"{t['shell']} -o pipefail -c {shlex.quote(script)}" if t["shell"] == "bash"
            else f"sh -c {shlex.quote(script)}")
    ch = t["transport"].open_session(timeout=15)
    ch.get_pty(term="dumb", width=200, height=50)       # a pty: closing it stops the remote command
    ch.settimeout(0.5)
    ch.exec_command(line)
    pending, prompts, t0 = "", 0, time.time()
    while True:
        if should_stop():
            ch.close()
            return -15
        if time.time() - t0 > timeout:
            emit(f"\n[step timed out after {int(timeout)} s]\n")
            ch.close()
            return 124
        try:
            data = ch.recv(32768)
        except socket.timeout:
            if ch.exit_status_ready():
                break
            continue
        if not data:
            break
        text = pending + data.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "")
        pending = ""
        if marker in text:
            prompts += 1
            text = text.replace(marker, "")
            if prompts > 1:
                emit(text + "\n[the sudo password was not accepted]\n")
                ch.close()
                return 1
            ch.send((t["sudo_pw"] + "\n").encode())
        elif len(text) < len(marker) and marker.startswith(text[-len(text):]) and text:
            pending = text                               # maybe the start of the marker: wait for more
            continue
        else:
            # keep a possible partial marker at the end for the next read
            for k in range(min(len(marker) - 1, len(text)), 0, -1):
                if marker.startswith(text[-k:]):
                    pending, text = text[-k:], text[:-k]
                    break
        if text:
            emit(_redact(t, text))
    if pending:
        emit(_redact(t, pending))
    rc = ch.recv_exit_status()
    ch.close()
    return rc
