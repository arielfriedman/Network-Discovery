#!/usr/bin/env python3
"""Database backups for SentinelScan (pg_dump, custom format).

    python3 panel/db_backup.py run             # take a backup now, then prune
    python3 panel/db_backup.py list
    python3 panel/db_backup.py schedule on|off|status   # nightly, via your crontab

Backups go to panel/backups/db/sentinel-YYYYmmdd-HHMMSS.dump (mode 600; they
hold your scan history, not passwords). The newest KEEP are kept (14 by
default; "backup_keep" in panel/settings.local.json changes it).

Restore (replaces the current contents of the database):
    pg_restore --clean --if-exists --no-owner -d "<database_url>" panel/backups/db/<file>.dump

The database password reaches pg_dump through a temporary pgpass file
(0600, in /dev/shm when available), never through its arguments.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

APP = Path(__file__).resolve().parent
BACKUP_DIR = APP / "backups" / "db"
SETTINGS = APP / "settings.local.json"
NAME_RE = re.compile(r"^sentinel-\d{8}-\d{6}\.dump$")
CRON_TAG = "# sentinelscan-db-backup"
CRON_TIME = "17 3 * * *"                 # 03:17 every night

sys.path.insert(0, str(APP))
import db  # noqa: E402  (database_url, log)


def keep_count() -> int:
    try:
        return max(1, int(json.loads(SETTINGS.read_text()).get("backup_keep", 14)))
    except (OSError, ValueError, TypeError):
        return 14


def _pg_env(url: str) -> tuple[dict, str | None]:
    """libpq environment for the URL, with the password in a temp pgpass file."""
    u = urllib.parse.urlsplit(url)
    q = dict(urllib.parse.parse_qsl(u.query))
    env = dict(os.environ)
    for k in ("PGPASSWORD", "PGPASSFILE", "PGSERVICE"):
        env.pop(k, None)
    env.update({"PGHOST": q.get("host") or u.hostname or "localhost",
                "PGPORT": str(q.get("port") or u.port or 5432),
                "PGUSER": urllib.parse.unquote(u.username or ""),
                "PGDATABASE": u.path.lstrip("/") or "sentinel",
                "PGCONNECT_TIMEOUT": "10"})
    pw = urllib.parse.unquote(u.password or "")
    if not pw:
        return env, None
    tmpdir = "/dev/shm" if os.access("/dev/shm", os.W_OK) else None
    fd, path = tempfile.mkstemp(prefix="sentinel-pgpass.", dir=tmpdir)
    esc = lambda s: s.replace("\\", "\\\\").replace(":", "\\:")
    with os.fdopen(fd, "w") as fh:          # mkstemp creates it 0600
        fh.write(f"*:*:*:{esc(env['PGUSER'])}:{esc(pw)}\n")
    env["PGPASSFILE"] = path
    return env, path


def list_backups() -> list[dict]:
    if not BACKUP_DIR.is_dir():
        return []
    out = []
    for f in sorted(BACKUP_DIR.iterdir(), reverse=True):
        if NAME_RE.match(f.name) and f.is_file():
            st = f.stat()
            out.append({"name": f.name, "size": st.st_size,
                        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(st.st_mtime))})
    return out


def prune(keep: int | None = None) -> list[str]:
    keep = keep or keep_count()
    removed = []
    for b in list_backups()[keep:]:
        (BACKUP_DIR / b["name"]).unlink(missing_ok=True)
        removed.append(b["name"])
    return removed


def run_backup() -> dict:
    """Take one backup. Returns {"ok", "name", "size", "error", "pruned"}."""
    url = db.database_url()
    if not url:
        return {"ok": False, "error": "no database configured (run install.sh)"}
    pg_dump = shutil.which("pg_dump")
    if not pg_dump:
        return {"ok": False, "error": "pg_dump not found (sudo apt install postgresql-client)"}
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_DIR, 0o700)
    name = time.strftime("sentinel-%Y%m%d-%H%M%S.dump")
    final, part = BACKUP_DIR / name, BACKUP_DIR / (name + ".part")
    env, passfile = _pg_env(url)
    try:
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            p = subprocess.run([pg_dump, "--format=custom", "--no-owner", "--no-privileges"],
                               stdout=fh, stderr=subprocess.PIPE, env=env, timeout=600)
        if p.returncode != 0:
            part.unlink(missing_ok=True)
            err = p.stderr.decode("utf-8", "replace").strip().splitlines()
            # libpq adds context lines (e.g. "password retrieved from file ...") after the cause
            cause = next((l for l in err if "FATAL" in l or "error:" in l), err[-1] if err else "")
            cause = re.sub(r"/dev/shm/sentinel-pgpass\.\S+|/tmp/sentinel-pgpass\.\S+", "<temp pgpass>", cause)
            return {"ok": False, "error": cause or f"pg_dump exited {p.returncode}"}
        part.rename(final)
    except subprocess.TimeoutExpired:
        part.unlink(missing_ok=True)
        return {"ok": False, "error": "pg_dump took longer than 10 minutes"}
    finally:
        if passfile:
            Path(passfile).unlink(missing_ok=True)
    pruned = prune()
    size = final.stat().st_size
    db.log("db.backup", name, {"size": size, "pruned": pruned})
    return {"ok": True, "name": name, "size": size, "pruned": pruned}


# ── nightly schedule (the user's crontab) ────────────────────────────────────
def _crontab() -> list[str]:
    p = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    return p.stdout.splitlines() if p.returncode == 0 else []


def _cron_line() -> str:
    q = lambda s: "'" + str(s).replace("'", "'\\''") + "'"
    log = BACKUP_DIR / "backup.log"
    return (f"{CRON_TIME} cd {q(APP)} && /usr/bin/env python3 db_backup.py run "
            f">> {q(log)} 2>&1 {CRON_TAG}")


def schedule_status() -> dict:
    if not shutil.which("crontab"):
        return {"available": False, "enabled": False, "when": "03:17 every night"}
    lines = [l for l in _crontab() if CRON_TAG in l]
    return {"available": True, "enabled": bool(lines), "when": "03:17 every night",
            "current": lines[0] if lines else None, "up_to_date": bool(lines) and lines[0] == _cron_line()}


def schedule(on: bool) -> dict:
    if not shutil.which("crontab"):
        return {"ok": False, "error": "cron is not installed (sudo apt install cron)"}
    lines = [l for l in _crontab() if CRON_TAG not in l]
    if on:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(BACKUP_DIR, 0o700)
        lines.append(_cron_line())
    if lines:
        p = subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, capture_output=True)
    else:                                   # nothing else in it: remove instead of leaving it empty
        p = subprocess.run(["crontab", "-r"], text=True, capture_output=True)
        if p.returncode != 0 and "no crontab" in (p.stderr or ""):
            p = subprocess.CompletedProcess(p.args, 0, "", "")
    if p.returncode != 0:
        return {"ok": False, "error": p.stderr.strip() or "crontab failed"}
    db.log("db.backup.schedule", "on" if on else "off")
    return {"ok": True, **schedule_status()}


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "run":
        r = run_backup()
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        if r["ok"]:
            msg = f"{stamp} backup {r['name']} ({r['size']} bytes)" + (f", removed {len(r['pruned'])} old" if r["pruned"] else "")
        else:
            msg = f"{stamp} backup FAILED: {r['error']}"
        print(msg)                       # one line, also what the nightly log collects
        return 0 if r["ok"] else 1
    if cmd == "list":
        for b in list_backups():
            print(f"{b['created']}  {b['size']:>10}  {b['name']}")
        return 0
    if cmd == "schedule" and len(argv) > 2 and argv[2] in ("on", "off", "status"):
        r = schedule_status() if argv[2] == "status" else schedule(argv[2] == "on")
        print(json.dumps(r, indent=1))
        return 0 if r.get("ok", True) else 1
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
