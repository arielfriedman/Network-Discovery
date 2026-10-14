"""Interactive terminal for the Actions page (stage 4, docs/ACTIONS_PLAN.md).

A session is a real shell: on this machine through a pseudo-terminal
(`bash -l` in the home folder), or on a machine connected over SSH
(panel/action_targets.py) through an SSH channel with a pty. The browser
draws it with xterm.js and talks to it by long-polling the panel's normal
HTTP API, so nothing extra has to be installed.

Everything goes through POST with the panel token (reads too), because the
output can contain anything typed on the machine. Typed text and output are
never written to the database or the activity log; only open/close is logged.
sudo passwords are typed into the terminal like in any other terminal.

Limits: 4 sessions at once; a session nobody has read for 2 minutes (tab
closed) is closed; the last 1 MB of output is kept for reloads.
"""
from __future__ import annotations

import base64
import fcntl
import os
import pty
import signal
import socket
import struct
import termios
import threading
import time
import uuid
from pathlib import Path

import db

MAX_SESSIONS = 4
KEEP = 1024 * 1024
IDLE = 120
POLL_WAIT = 20

SESSIONS: dict[str, "Session"] = {}
_LOCK = threading.Lock()


class TermError(ValueError):
    pass


class Session:
    def __init__(self, where: str):
        self.id = uuid.uuid4().hex[:12]
        self.where = where
        self.buf = bytearray()
        self.base = 0                       # absolute offset of buf[0]
        self.alive = True
        self.cond = threading.Condition()
        self.seen = time.time()
        self.opened = time.time()

    # output side
    def _add(self, data: bytes) -> None:
        with self.cond:
            self.buf += data
            if len(self.buf) > KEEP:
                cut = len(self.buf) - KEEP
                del self.buf[:cut]
                self.base += cut
            self.cond.notify_all()

    def _ended(self) -> None:
        with self.cond:
            self.alive = False
            self.cond.notify_all()

    def read(self, offset: int, wait: float = POLL_WAIT) -> dict:
        self.seen = time.time()
        end = time.time() + wait
        with self.cond:
            while self.alive and self.base + len(self.buf) <= offset:
                left = end - time.time()
                if left <= 0:
                    break
                self.cond.wait(left)
            total = self.base + len(self.buf)
            start = max(offset, self.base) if 0 <= offset <= total else self.base
            data = bytes(self.buf[start - self.base:])
            return {"data": base64.b64encode(data).decode(), "offset": total, "alive": self.alive,
                    "reset": not (self.base <= offset <= total)}


class LocalSession(Session):
    def __init__(self, cols: int, rows: int):
        super().__init__("this machine")
        import actions
        env = actions._clean_env()
        env.update(TERM="xterm-256color", COLORTERM="truecolor")
        for k in ("NO_COLOR", "PAGER", "SYSTEMD_PAGER", "DEBIAN_FRONTEND"):
            env.pop(k, None)
        pid, fd = pty.fork()
        if pid == 0:                                        # child: becomes the shell
            try:
                os.chdir(str(Path.home()))
                os.execvpe("bash", ["bash", "-l"], env)
            finally:
                os._exit(127)
        self.pid, self.fd = pid, fd
        self.resize(cols, rows)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        while True:
            try:
                data = os.read(self.fd, 65536)
            except OSError:
                break
            if not data:
                break
            self._add(data)
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        self._ended()

    def write(self, data: bytes) -> None:
        os.write(self.fd, data)

    def resize(self, cols: int, rows: int) -> None:
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def close(self) -> None:
        for sig in (signal.SIGHUP, signal.SIGKILL):
            try:
                os.killpg(self.pid, sig)                    # the shell leads its own session/group
            except (ProcessLookupError, PermissionError):
                return
            for _ in range(20):
                if not self.alive:
                    return
                time.sleep(0.05)


class RemoteSession(Session):
    def __init__(self, target: dict, cols: int, rows: int):
        super().__init__(f"{target['user']}@{target['host']}")
        self.ch = target["transport"].open_session(timeout=15)
        self.ch.get_pty(term="xterm-256color", width=cols, height=rows)
        self.ch.invoke_shell()
        self.ch.settimeout(1.0)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        while True:
            try:
                data = self.ch.recv(65536)
            except socket.timeout:
                if self.ch.closed or self.ch.exit_status_ready():
                    break
                continue
            except Exception:  # noqa: BLE001 - connection dropped
                break
            if not data:
                break
            self._add(data)
        self.ch.close()
        self._ended()

    def write(self, data: bytes) -> None:
        self.ch.sendall(data)

    def resize(self, cols: int, rows: int) -> None:
        self.ch.resize_pty(width=cols, height=rows)

    def close(self) -> None:
        self.ch.close()


def _size(body: dict) -> tuple[int, int]:
    try:
        cols, rows = int(body.get("cols") or 100), int(body.get("rows") or 30)
    except (TypeError, ValueError):
        cols, rows = 100, 30
    return max(20, min(cols, 500)), max(5, min(rows, 200))


def _reap() -> None:
    now = time.time()
    with _LOCK:
        stale = [s for s in SESSIONS.values() if not s.alive or now - s.seen > IDLE]
    for s in stale:
        close(s.id, reason="idle" if s.alive else "ended")


_reaper = None


def _reaper_loop() -> None:
    while True:
        time.sleep(30)
        _reap()


def open_session(body: dict, source_ip: str | None = None) -> dict:
    global _reaper
    if _reaper is None:
        _reaper = threading.Thread(target=_reaper_loop, daemon=True)
        _reaper.start()
    _reap()
    with _LOCK:
        if len(SESSIONS) >= MAX_SESSIONS:
            raise TermError(f"at most {MAX_SESSIONS} terminals at once - close one first")
    cols, rows = _size(body)
    tid = str(body.get("target") or "")
    if tid:
        import action_targets
        try:
            s = RemoteSession(action_targets.get(tid), cols, rows)
        except action_targets.TargetError as e:
            raise TermError(str(e)) from None
        except Exception as e:  # noqa: BLE001
            raise TermError(f"could not open a shell there: {e}") from None
    else:
        s = LocalSession(cols, rows)
    with _LOCK:
        SESSIONS[s.id] = s
    db.log("terminal.open", s.where, {"session": s.id}, source_ip)
    return {"id": s.id, "where": s.where}


def get(sid: str) -> Session:
    with _LOCK:
        s = SESSIONS.get(sid)
    if not s:
        raise TermError("that terminal is closed")
    return s


def write(sid: str, data: str) -> dict:
    s = get(sid)
    if not s.alive:
        raise TermError("the shell has ended")
    raw = data.encode("utf-8")
    if len(raw) > 64 * 1024:
        raise TermError("too much input at once")
    s.write(raw)
    s.seen = time.time()
    return {"ok": True}


def resize(sid: str, body: dict) -> dict:
    s = get(sid)
    if s.alive:
        s.resize(*_size(body))
    return {"ok": True}


def close(sid: str, reason: str = "closed") -> dict:
    with _LOCK:
        s = SESSIONS.pop(sid, None)
    if not s:
        return {"closed": False}
    try:
        s.close()
    except Exception:  # noqa: BLE001
        pass
    db.log("terminal.close", s.where, {"session": s.id, "reason": reason,
                                       "minutes": round((time.time() - s.opened) / 60, 1)})
    return {"closed": True}


def list_open() -> list[dict]:
    _reap()
    with _LOCK:
        return [{"id": s.id, "where": s.where, "alive": s.alive} for s in SESSIONS.values()]


def close_all() -> None:
    with _LOCK:
        ids = list(SESSIONS)
    for i in ids:
        close(i, reason="panel stopped")
