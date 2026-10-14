"""Actions page: saved command buttons, run on this machine with live output.

Design: docs/ACTIONS_PLAN.md. An action is a name and an ordered list of
steps (shell commands). Built-in starter actions carry a variant per Linux
distro family; the one for the machine it runs on is picked from
/etc/os-release. Actions can be created by pasting commands, edited,
combined (drag one onto another) and exported / imported as JSON.

Running: one run at a time, each step through `bash -c`, output streamed to
the page by polling. The panel's database settings are removed from the
environment. `sudo` inside a step becomes `sudo -n`, so a step that needs a
password fails at once with a clear message instead of waiting for a prompt
nobody can answer (unlock with `sudo -v` in the panel's terminal; the
interactive terminal, stage 4, will take passwords directly).
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path

import db

MAX_STEPS = 50
MAX_STEP_LEN = 4000
MAX_OUTPUT = 2 * 1024 * 1024        # per run, in memory
STORE_OUTPUT = 256 * 1024           # per step, in the database
STEP_TIMEOUT = 30 * 60

DANGER = re.compile(
    r"\brm\s+-[a-zA-Z]*[rf]|\b(reboot|shutdown|poweroff|halt|mkfs\S*|wipefs|fdisk|parted|userdel|deluser)\b|"
    r"\bdd\s+if=|\biptables\s+-[FX]|\bnft\s+flush|\bufw\s+(disable|reset)|"
    r"\bsystemctl\s+(stop|disable|mask|reboot|poweroff|halt)|\b(docker|podman)\s+(system|volume|image|container)\s+prune|"
    r"\bkubectl\s+delete|\bchmod\s+-R|\bchown\s+-R|\btruncate\b|>\s*/dev/sd|\bkill\s+-9\s+1\b")

# ── starter library ──────────────────────────────────────────────────────────
# (key, folder, name, steps, dangerous). A step is a string, or a dict of
# per-family variants with "*" as the fallback ("" = not available there).
LIBRARY = [
    ("pkg.update", "Packages", "Update package lists", [{
        "debian": "sudo apt-get update", "rhel": "sudo dnf makecache", "suse": "sudo zypper --non-interactive refresh",
        "arch": "command -v checkupdates >/dev/null && checkupdates || echo 'install pacman-contrib for checkupdates'",
        "alpine": "sudo apk update"}], False),
    ("pkg.upgradable", "Packages", "List available upgrades", [{
        "debian": "apt list --upgradable 2>/dev/null", "rhel": "dnf check-update; test $? -ne 1",
        "suse": "zypper --non-interactive list-updates", "arch": "pacman -Qu || true", "alpine": "apk list --upgradable"}], False),
    ("pkg.upgrade", "Packages", "Upgrade packages", [{
        "debian": "sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade", "rhel": "sudo dnf -y upgrade",
        "suse": "sudo zypper --non-interactive update", "opensuse-tumbleweed": "sudo zypper --non-interactive dup",
        "arch": "sudo pacman -Syu --noconfirm", "alpine": "sudo apk upgrade"}], False),
    ("pkg.autoremove", "Packages", "Remove unused packages", [{
        "debian": "sudo apt-get -y autoremove", "rhel": "sudo dnf -y autoremove",
        "suse": "zypper packages --unneeded", "arch": "pacman -Qdtq || echo 'no orphans'", "alpine": ""}], False),
    ("pkg.reboot_needed", "Packages", "Reboot needed?", [{
        "debian": "test -f /var/run/reboot-required && cat /var/run/reboot-required* || echo 'no reboot needed'",
        "rhel": "command -v needs-restarting >/dev/null && needs-restarting -r || echo 'install dnf-utils for needs-restarting'",
        "*": "echo 'compare: running kernel'; uname -r; ls -t /lib/modules | head -n 1"}], False),
    ("sys.info", "System", "OS and hardware", ["cat /etc/os-release", "uname -a", "hostnamectl 2>/dev/null || hostname",
                                              "lscpu | head -n 15"], False),
    ("sys.uptime", "System", "Uptime and load", ["uptime"], False),
    ("sys.memory", "System", "Memory", ["free -h"], False),
    ("sys.top_cpu", "System", "Top processes (CPU)", ["ps aux --sort=-%cpu | head -n 15"], False),
    ("sys.top_mem", "System", "Top processes (memory)", ["ps aux --sort=-%mem | head -n 15"], False),
    ("svc.failed", "Services", "Failed services", ["systemctl --failed --no-pager"], False),
    ("svc.running", "Services", "Running services", ["systemctl list-units --type=service --state=running --no-pager"], False),
    ("svc.timers", "Services", "Scheduled timers", ["systemctl list-timers --no-pager"], False),
    ("log.errors", "Logs", "Errors since boot", ["journalctl -p err -b --no-pager | tail -n 60"], False),
    ("log.recent", "Logs", "Last 50 log lines", ["journalctl -n 50 --no-pager"], False),
    ("log.auth", "Logs", "Recent logins", ["last -n 20", "who"], False),
    ("disk.usage", "Disks", "Disk usage", ["df -h -x tmpfs -x devtmpfs -x squashfs"], False),
    ("disk.devices", "Disks", "Block devices", ["lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS"], False),
    ("disk.biggest", "Disks", "Largest folders in home", ["du -xh ~ --max-depth=1 2>/dev/null | sort -h | tail -n 15"], False),
    ("net.addr", "Network", "Addresses", ["ip -br addr"], False),
    ("net.routes", "Network", "Routes", ["ip route"], False),
    ("net.listen", "Network", "Listening ports", ["ss -tulpn"], False),
    ("net.dns", "Network", "DNS settings", ["resolvectl status 2>/dev/null | head -n 30 || cat /etc/resolv.conf"], False),
    ("net.ping", "Network", "Internet reachable?", ["ping -c 3 -W 2 1.1.1.1", "getent hosts gitlab.com"], False),
    ("fw.status", "Firewall", "Firewall status", [{
        "debian": "sudo ufw status verbose", "rhel": "sudo firewall-cmd --list-all", "suse": "sudo firewall-cmd --list-all",
        "*": "sudo nft list ruleset | head -n 80"}], False),
    ("docker.ps", "Docker", "Containers", ["docker ps -a"], False),
    ("docker.df", "Docker", "Docker disk usage", ["docker system df"], False),
    ("docker.prune", "Docker", "Clean up unused Docker data", ["docker system prune -f"], True),
    ("k8s.nodes", "Kubernetes", "Nodes", ["kubectl get nodes -o wide"], False),
    ("k8s.pods", "Kubernetes", "All pods", ["kubectl get pods -A -o wide"], False),
    ("power.reboot", "Power", "Reboot this machine", ["sudo systemctl reboot"], True),
]


# ── distro ───────────────────────────────────────────────────────────────────
def distro() -> dict:
    """{id, like, family, pretty} from /etc/os-release."""
    info = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            k, _, v = line.partition("=")
            info[k] = v.strip().strip('"')
    except OSError:
        pass
    ids = [info.get("ID", "")] + info.get("ID_LIKE", "").split()
    fam = ""
    for i in ids:
        if i in ("debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali"):
            fam = "debian"; break
        if i in ("rhel", "fedora", "centos", "rocky", "almalinux", "ol"):
            fam = "rhel"; break
        if i.startswith("opensuse") or i in ("suse", "sles"):
            fam = "suse"; break
        if i in ("arch", "manjaro", "endeavouros"):
            fam = "arch"; break
        if i == "alpine":
            fam = "alpine"; break
    return {"id": info.get("ID", ""), "like": info.get("ID_LIKE", ""), "family": fam,
            "pretty": info.get("PRETTY_NAME", "") or info.get("ID", "unknown")}


def resolve(command: str, variants: dict | None, d: dict) -> str:
    """The command for this machine; '' when the step doesn't apply here."""
    if not variants:
        return command
    for k in (d["id"], d["family"], "*"):
        if k and k in variants:
            return variants[k]
    return ""


# ── storage ──────────────────────────────────────────────────────────────────
class ActionError(ValueError):
    pass


def _q(sql, args=(), one=False):
    if not db.ready():
        raise ActionError("The Actions page needs the database. Run ./install.sh, then restart the panel.")
    import psycopg2.extras
    conn = db.connect()
    try:
        with conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, args)
            if cur.description is None:
                return None
            rows = cur.fetchall()
            return db._jsonable(rows[0] if rows else None) if one else db._jsonable(rows)
    finally:
        conn.close()


def _folder_id(name: str | None) -> int | None:
    name = (name or "").strip()[:60]
    if not name:
        return None
    _q("INSERT INTO action_folders (name, position) VALUES (%s, (SELECT coalesce(max(position),0)+1 FROM action_folders)) "
       "ON CONFLICT (name) DO NOTHING", (name,))
    return _q("SELECT id FROM action_folders WHERE name = %s", (name,), one=True)["id"]


def ensure_library() -> None:
    """Add starter actions that aren't there yet (never overwrites edits, never re-adds deleted ones)."""
    have = {r["builtin_key"] for r in _q("SELECT builtin_key FROM actions WHERE builtin_key IS NOT NULL")}
    for pos, (key, folder, name, steps, dangerous) in enumerate(LIBRARY):
        if key in have:
            continue
        aid = _q("""INSERT INTO actions (folder_id, name, dangerous, builtin_key, position)
                    VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                 (_folder_id(folder), name, dangerous, key, pos), one=True)["id"]
        _write_steps(aid, [{"command": next((v for v in s.values() if v), ""), "variants": s}
                           if isinstance(s, dict) else {"command": s} for s in steps])


def _write_steps(aid: int, steps: list[dict]) -> None:
    _q("DELETE FROM action_steps WHERE action_id = %s", (aid,))
    for i, s in enumerate(steps):
        _q("INSERT INTO action_steps (action_id, position, command, variants) VALUES (%s, %s, %s, %s)",
           (aid, i, s["command"], json.dumps(s["variants"]) if s.get("variants") else None))


def list_actions() -> dict:
    ensure_library()
    d = distro()
    folders = _q("SELECT id, name, position FROM action_folders ORDER BY position, name")
    acts = _q("""SELECT a.id, a.folder_id, a.name, a.description, a.dangerous, a.stop_on_error, a.builtin_key, a.position,
                        coalesce(json_agg(json_build_object('command', s.command, 'variants', s.variants)
                                          ORDER BY s.position) FILTER (WHERE s.action_id IS NOT NULL), '[]') AS steps
                 FROM actions a LEFT JOIN action_steps s ON s.action_id = a.id
                 WHERE NOT a.hidden GROUP BY a.id ORDER BY a.position, a.id""")
    for a in acts:
        for s in a["steps"]:
            s["here"] = resolve(s["command"], s.get("variants"), d)
        a["available"] = any(s["here"] for s in a["steps"])
    hidden = _q("SELECT count(*) AS n FROM actions WHERE hidden", one=True)["n"]
    return {"folders": folders, "actions": acts, "distro": d, "hidden_builtins": hidden}


def parse_text(text: str) -> list[str]:
    """Pasted commands -> steps: one per line, a trailing backslash continues, # lines are comments."""
    steps, cur = [], ""
    for raw in (text or "").replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if not cur and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if line.endswith("\\"):
            cur += (line[:-1].strip() if cur else line[:-1].rstrip()) + " "
            continue
        steps.append((cur + (line.strip() if cur else line)).strip())
        cur = ""
    if cur.strip():
        steps.append(cur.strip())
    if len(steps) > MAX_STEPS:
        raise ActionError(f"at most {MAX_STEPS} steps per action")
    for s in steps:
        if len(s) > MAX_STEP_LEN:
            raise ActionError(f"a step is longer than {MAX_STEP_LEN} characters")
        if "\0" in s:
            raise ActionError("a step contains a NUL byte")
    return steps


def is_dangerous(steps: list[str]) -> bool:
    return any(DANGER.search(s) for s in steps)


def save(body: dict) -> dict:
    """Create or update an action. Steps come as text (pasted) or a list."""
    name = re.sub(r"[\x00-\x1f]", "", str(body.get("name") or "")).strip()[:80]
    if not name:
        raise ActionError("give the action a name")
    raw = body.get("steps")
    if isinstance(raw, list):
        steps = [{"command": str(s.get("command", "")).strip(), "variants": s.get("variants") or None}
                 if isinstance(s, dict) else {"command": str(s).strip()} for s in raw]
        steps = [s for s in steps if s["command"]]
        if len(steps) > MAX_STEPS or any(len(s["command"]) > MAX_STEP_LEN for s in steps):
            raise ActionError(f"at most {MAX_STEPS} steps of {MAX_STEP_LEN} characters")
    else:
        steps = [{"command": s} for s in parse_text(str(raw or ""))]
    if not steps:
        raise ActionError("an action needs at least one command")
    for s in steps:
        if s.get("variants") is not None and (not isinstance(s["variants"], dict) or
                                              not all(isinstance(k, str) and isinstance(v, str) for k, v in s["variants"].items())):
            raise ActionError("step variants must map distro names to commands")
    flagged = is_dangerous([s["command"] for s in steps] + [v for s in steps for v in (s.get("variants") or {}).values()])
    dangerous = bool(body.get("dangerous")) or flagged
    folder = _folder_id(body.get("folder"))
    aid = body.get("id")
    if aid:
        if not _q("SELECT id FROM actions WHERE id = %s", (int(aid),), one=True):
            raise ActionError("action not found")
        _q("""UPDATE actions SET name = %s, folder_id = %s, dangerous = %s, stop_on_error = %s,
                                 description = %s, updated_at = now() WHERE id = %s""",
           (name, folder, dangerous, body.get("stop_on_error", True) is not False,
            (str(body.get("description") or "")[:300] or None), int(aid)))
        action = "action.edit"
    else:
        aid = _q("""INSERT INTO actions (folder_id, name, dangerous, stop_on_error, description, position, created_by)
                    VALUES (%s, %s, %s, %s, %s, (SELECT coalesce(max(position),0)+1 FROM actions),
                            (SELECT id FROM users WHERE email = 'local@localhost'))
                    RETURNING id""",
                 (folder, name, dangerous, body.get("stop_on_error", True) is not False,
                  (str(body.get("description") or "")[:300] or None)), one=True)["id"]
        action = "action.create"
    _write_steps(int(aid), steps)
    db.log(action, name, {"steps": [s["command"] for s in steps], "dangerous": dangerous})
    return {"id": int(aid), "dangerous": dangerous, "auto_flagged": flagged and not body.get("dangerous")}


def delete(aid: int) -> dict:
    a = _q("SELECT id, name, builtin_key FROM actions WHERE id = %s", (aid,), one=True)
    if not a:
        raise ActionError("action not found")
    if a["builtin_key"]:
        _q("UPDATE actions SET hidden = true WHERE id = %s", (aid,))      # stays deleted
    else:
        _q("DELETE FROM actions WHERE id = %s", (aid,))
    db.log("action.delete", a["name"])
    return {"deleted": aid}


def restore_builtins() -> dict:
    n = _q("UPDATE actions SET hidden = false WHERE hidden RETURNING id")
    return {"restored": len(n or [])}


def combine(first: int, second: int, name: str) -> dict:
    """Drag one action onto another: a new action with both step lists, in order."""
    a, b = (_q("SELECT a.id, a.name, a.dangerous, a.stop_on_error, f.name AS folder FROM actions a "
               "LEFT JOIN action_folders f ON f.id = a.folder_id WHERE a.id = %s", (i,), one=True) for i in (first, second))
    if not a or not b:
        raise ActionError("action not found")
    steps = []
    for x in (a, b):
        steps += [{"command": s["command"], "variants": s["variants"]} for s in
                  _q("SELECT command, variants FROM action_steps WHERE action_id = %s ORDER BY position", (x["id"],))]
    return save({"name": name or f"{a['name']} + {b['name']}", "folder": a["folder"], "steps": steps,
                 "dangerous": a["dangerous"] or b["dangerous"],
                 "stop_on_error": a["stop_on_error"] and b["stop_on_error"]})


def reorder(ids: list[int]) -> dict:
    for pos, i in enumerate(ids[:1000]):
        _q("UPDATE actions SET position = %s WHERE id = %s", (pos, int(i)))
    return {"ok": True}


def export_all() -> dict:
    data = list_actions()
    folders = {f["id"]: f["name"] for f in data["folders"]}
    return {"format": "sentinelscan-actions/1", "actions": [
        {"name": a["name"], "folder": folders.get(a["folder_id"]), "dangerous": a["dangerous"],
         "stop_on_error": a["stop_on_error"], "description": a["description"],
         "steps": [{"command": s["command"], "variants": s["variants"]} for s in a["steps"]]}
        for a in data["actions"] if not a["builtin_key"]]}


def import_all(doc: dict) -> dict:
    if not isinstance(doc, dict) or doc.get("format") != "sentinelscan-actions/1":
        raise ActionError("not a SentinelScan actions export")
    items = doc.get("actions") if isinstance(doc.get("actions"), list) else []
    existing = {r["name"] for r in _q("SELECT name FROM actions WHERE NOT hidden")}
    made = 0
    for it in items[:500]:
        if not isinstance(it, dict):
            continue
        name = str(it.get("name") or "imported")[:70]
        while name in existing:
            name += " (imported)"
        save({**it, "name": name, "id": None})
        existing.add(name); made += 1
    return {"imported": made}


# ── running ──────────────────────────────────────────────────────────────────
RUNS: dict[int, dict] = {}
_RUN_LOCK = threading.Lock()
SUDO_N = 'sudo() { command sudo -n "$@"; }\n'      # never wait for a password prompt


def _clean_env() -> dict:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("SENTINEL_", "PG")) and k not in ("ND_CREDS_FD", "ND_VAULT_PASS_FD")}
    env.update(TERM="dumb", NO_COLOR="1", DEBIAN_FRONTEND="noninteractive", PAGER="cat", SYSTEMD_PAGER="")
    return env


def active_run() -> int | None:
    with _RUN_LOCK:
        return next((i for i, r in RUNS.items() if r["status"] == "running"), None)


def start(aid: int, confirm_dangerous: bool = False, source_ip: str | None = None) -> dict:
    data = {a["id"]: a for a in list_actions()["actions"]}
    a = data.get(aid)
    if not a:
        raise ActionError("action not found")
    if a["dangerous"] and not confirm_dangerous:
        raise ActionError("this action is marked dangerous - confirm it to run")
    steps = [s["here"] for s in a["steps"] if s["here"]]
    if not steps:
        raise ActionError(f"none of this action's steps apply to {distro()['pretty']}")
    if active_run():
        raise ActionError("another action is still running - wait for it or stop it")
    d = distro()
    rid = _q("""INSERT INTO action_runs (action_id, action_name, distro, status, started_by)
                VALUES (%s, %s, %s, 'running', (SELECT id FROM users WHERE email = 'local@localhost')) RETURNING id""",
             (aid, a["name"], d["pretty"]), one=True)["id"]
    run = {"id": rid, "action": a["name"], "status": "running", "out": "", "steps": [], "proc": None,
           "stop": False, "started": time.time()}
    with _RUN_LOCK:
        RUNS[rid] = run
        for old in sorted(RUNS)[:-20]:                  # keep the last 20 in memory
            if RUNS[old]["status"] != "running":
                del RUNS[old]
    db.log("action.run", a["name"], {"run": rid, "steps": steps, "distro": d["pretty"]}, source_ip)
    threading.Thread(target=_run, args=(run, steps, a["stop_on_error"]), daemon=True).start()
    return {"run_id": rid, "steps": steps}


def _emit(run: dict, text: str) -> None:
    with _RUN_LOCK:
        run["out"] += text
        if len(run["out"]) > MAX_OUTPUT:
            run["out"] = "[... earlier output trimmed ...]\n" + run["out"][-MAX_OUTPUT // 2:]
            run["trimmed"] = run.get("trimmed", 0) + 1


def _run(run: dict, steps: list[str], stop_on_error: bool) -> None:
    status = "ok"
    for pos, cmd in enumerate(steps):
        if run["stop"]:
            status = "stopped"; break
        _emit(run, ("\n" if run["out"] else "") + f"$ {cmd}\n")
        t0, buf = time.time(), []
        try:
            p = subprocess.Popen(["bash", "-o", "pipefail", "-c", SUDO_N + cmd], cwd=str(Path.home()),
                                 env=_clean_env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, process_group=0)
        except OSError as e:
            _emit(run, f"could not start: {e}\n"); status = "failed"; break
        run["proc"] = p
        killer = threading.Timer(STEP_TIMEOUT, lambda: _kill(p))
        killer.start()
        for chunk in iter(lambda: p.stdout.read1(4096), b""):
            text = chunk.decode("utf-8", "replace")
            buf.append(text); _emit(run, text)
        rc = p.wait(); killer.cancel(); run["proc"] = None
        out = "".join(buf)
        if rc != 0 and "sudo: a password is required" in out:
            _emit(run, "\n[sudo needs your password: run `sudo -v` in the terminal where the panel runs, "
                       "then run this action again]\n")
        dur = round(time.time() - t0, 1)
        _emit(run, f"[exit {rc} · {dur} s]\n")
        run["steps"].append({"command": cmd, "exit": rc, "duration": dur})
        try:
            _q("""INSERT INTO action_run_steps (run_id, position, command, exit_code, duration_s, output)
                  VALUES (%s, %s, %s, %s, %s, %s)""", (run["id"], pos, cmd, rc, dur, out[-STORE_OUTPUT:]))
        except Exception:  # noqa: BLE001 - keep running even if the database hiccups
            pass
        if run["stop"]:
            status = "stopped"; break
        if rc != 0:
            status = "failed"
            if stop_on_error:
                _emit(run, "[stopped at the first failing step]\n"); break
    run["status"] = status
    try:
        _q("UPDATE action_runs SET status = %s, finished_at = now() WHERE id = %s", (status, run["id"]))
    except Exception:  # noqa: BLE001
        pass
    db.log("action.done", run["action"], {"run": run["id"], "status": status,
                                          "exit_codes": [s["exit"] for s in run["steps"]]})


def _kill(p) -> None:
    try:
        os.killpg(p.pid, signal.SIGTERM)
        time.sleep(2)
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def stop(rid: int) -> dict:
    with _RUN_LOCK:
        run = RUNS.get(rid)
    if not run or run["status"] != "running":
        return {"stopped": False}
    run["stop"] = True
    if run.get("proc"):
        _kill(run["proc"])
    db.log("action.stop", run["action"], {"run": rid})
    return {"stopped": True}


def run_status(rid: int, offset: int = 0) -> dict | None:
    with _RUN_LOCK:
        run = RUNS.get(rid)
        if not run:
            return None
        out = run["out"]
        return {"id": rid, "action": run["action"], "status": run["status"], "steps": run["steps"],
                "offset": len(out), "text": out[offset:] if 0 <= offset <= len(out) else out,
                "reset": offset > len(out)}


def recent_runs(limit: int = 30) -> list[dict]:
    return _q("""SELECT r.id, r.action_name, r.status, r.distro, r.started_at, r.finished_at,
                        (SELECT json_agg(json_build_object('command', s.command, 'exit', s.exit_code) ORDER BY s.position)
                         FROM action_run_steps s WHERE s.run_id = r.id) AS steps
                 FROM action_runs r ORDER BY r.started_at DESC LIMIT %s""", (limit,))


def mark_interrupted() -> None:
    """At panel start: runs an earlier panel left 'running'."""
    try:
        _q("UPDATE action_runs SET status = 'interrupted', finished_at = coalesce(finished_at, now()) "
           "WHERE status = 'running'")
    except Exception:  # noqa: BLE001
        pass
