#!/usr/bin/env python3
"""
SentinelScan — PostgreSQL storage

The panel writes every scan, its findings, discovered hosts/services and an
activity log here, and reads them back for the History page. If the database
is not configured or unreachable the panel keeps working without it; every
public function here fails soft and reports why through status().

    python3 db.py status            # can we connect? which migrations ran?
    python3 db.py migrate           # create / upgrade the tables
    python3 db.py import            # load old JSON reports into the database

Connection string, first match wins:
    $SENTINEL_DATABASE_URL
    panel/settings.local.json  {"database_url": "postgresql://..."}   (written by install.sh)
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    import psycopg2
    import psycopg2.extras
except ImportError:  # the panel still runs, just without history
    psycopg2 = None

APP_DIR = Path(__file__).resolve().parent
REPO = APP_DIR.parent
MIGRATIONS = REPO / "db" / "migrations"
SETTINGS = APP_DIR / "settings.local.json"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

_state = {"ok": False, "error": "not checked yet", "checked": False, "at": 0.0}
RECHECK_S = 30  # after a failure, try again this often (e.g. Postgres started later)
_lock = threading.Lock()


# ── connection ───────────────────────────────────────────────────────────────
def database_url() -> str:
    url = os.environ.get("SENTINEL_DATABASE_URL", "")
    if url:
        return url
    try:
        return json.loads(SETTINGS.read_text()).get("database_url", "")
    except (OSError, ValueError):
        return ""


def connect():
    if psycopg2 is None:
        raise RuntimeError("the Python PostgreSQL driver is missing (sudo apt install python3-psycopg2)")
    url = database_url()
    if not url:
        raise RuntimeError("no database configured (run install.sh, or set SENTINEL_DATABASE_URL)")
    return psycopg2.connect(url, connect_timeout=3, application_name="sentinelscan")


def _fail(e: Exception) -> None:
    msg = str(e).strip().splitlines()[0] if str(e).strip() else type(e).__name__
    with _lock:
        _state.update(ok=False, error=msg, checked=True, at=time.time())
    print(f"  [db] {msg}", file=sys.stderr)


def status() -> dict:
    """{"ok": bool, "error": str, "migrations": [...]} — shown in the panel."""
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT to_regclass('schema_migrations') IS NOT NULL")
            done = []
            if cur.fetchone()[0]:
                cur.execute("SELECT version FROM schema_migrations ORDER BY version")
                done = [r[0] for r in cur.fetchall()]
            pending = [p.name for p in sorted(MIGRATIONS.glob("*.sql")) if p.name not in done]
        conn.close()
        with _lock:
            _state.update(ok=not pending, checked=True, at=time.time(),
                          error="" if not pending else f"tables not created yet - run: python3 panel/db.py migrate")
        return {"ok": not pending, "error": _state["error"], "migrations": done, "pending": pending}
    except Exception as e:  # noqa: BLE001
        _fail(e)
        return {"ok": False, "error": _state["error"], "migrations": [], "pending": []}


def ready() -> bool:
    if not _state["checked"] or (not _state["ok"] and time.time() - _state["at"] > RECHECK_S):
        status()
    return _state["ok"]


def migrate() -> list[str]:
    """Apply db/migrations/NNN_*.sql that have not run yet, each in its own transaction."""
    applied = []
    conn = connect()
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                               version    text PRIMARY KEY,
                               applied_at timestamptz NOT NULL DEFAULT now())""")
        for path in sorted(MIGRATIONS.glob("*.sql")):
            with conn, conn.cursor() as cur:
                cur.execute("SELECT 1 FROM schema_migrations WHERE version = %s", (path.name,))
                if cur.fetchone():
                    continue
                cur.execute(path.read_text())
                cur.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (path.name,))
                applied.append(path.name)
    finally:
        conn.close()
    with _lock:
        _state.update(ok=True, error="", checked=True)
    return applied


def _run(fn, default=None):
    """Run fn(cursor) in one transaction; on any error log it and return default."""
    if not ready():
        return default
    try:
        conn = connect()
        try:
            with conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                return fn(cur)
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001
        _fail(e)
        return default


def _norm_target(t):
    """The panel says 'localhost', main.py says '127.0.0.1': same machine, same history."""
    return "localhost" if t in ("127.0.0.1", "::1", "localhost") else t


def _local_user(cur) -> int:
    cur.execute("SELECT id FROM users WHERE email = 'local@localhost'")
    return cur.fetchone()["id"]


# ── activity log ─────────────────────────────────────────────────────────────
def log(action: str, target: str | None = None, details: dict | None = None,
        source_ip: str | None = None) -> None:
    def fn(cur):
        cur.execute("""INSERT INTO user_activity (user_id, action, target, source_ip, details)
                       VALUES (%s, %s, %s, %s, %s)""",
                    (_local_user(cur), action[:50], target, source_ip,
                     psycopg2.extras.Json(details) if details else None))
    _run(fn)


def save_credential(vault_key: str, name: str, ctype: str, hosts: list[str]) -> None:
    """Metadata for a card saved in the vault (never the secret)."""
    def fn(cur):
        cur.execute("""INSERT INTO credentials (vault_key, name, type, hosts, created_by)
                       VALUES (%s, %s, %s, %s, %s)
                       ON CONFLICT (vault_key) DO UPDATE
                       SET name = EXCLUDED.name, type = EXCLUDED.type, hosts = EXCLUDED.hosts""",
                    (vault_key, name, ctype, hosts, _local_user(cur)))
    _run(fn)


def list_credentials() -> list[dict]:
    def fn(cur):
        cur.execute("""SELECT vault_key, name, type, hosts, created_at, last_used, last_result
                       FROM credentials ORDER BY type, name""")
        return [_jsonable(r) for r in cur.fetchall()]
    return _run(fn, [])


def delete_credential(vault_key: str) -> bool:
    def fn(cur):
        cur.execute("DELETE FROM credentials WHERE vault_key = %s", (vault_key,))
        return cur.rowcount > 0
    return bool(_run(fn, False))


def mark_interrupted() -> int:
    """At panel start nothing can be running yet: scans still marked
    'running' belong to a panel that stopped mid-scan."""
    def fn(cur):
        cur.execute("""UPDATE scans SET status = 'interrupted', finished_at = coalesce(finished_at, now())
                       WHERE status = 'running'""")
        return cur.rowcount
    return _run(fn, 0)


def delete_scans(refs: list[str] | None = None, older_than_days: int | None = None) -> list[dict]:
    """Delete saved scans (their findings, hosts, targets go with them via
    ON DELETE CASCADE). refs=None and older_than_days=None means all.
    Running scans are never deleted. Returns [{scan_ref, report_path}] so the
    caller can remove report files. The activity log is not touched."""
    def fn(cur):
        where, args = ["status <> 'running'"], []
        if refs is not None:
            where.append("scan_ref = ANY(%s)"); args.append(list(refs))
        if older_than_days is not None:
            where.append("started_at < now() - make_interval(days => %s)"); args.append(int(older_than_days))
        cur.execute(f"DELETE FROM scans WHERE {' AND '.join(where)} RETURNING scan_ref, report_path", args)
        return [dict(r) for r in cur.fetchall()]
    return _run(fn, [])


def recent_activity(limit: int = 50) -> list[dict]:
    def fn(cur):
        cur.execute("""SELECT a.created_at, u.name AS user_name, a.action, a.target, host(a.source_ip) AS source_ip, a.details
                       FROM user_activity a JOIN users u ON u.id = a.user_id
                       ORDER BY a.created_at DESC, a.id DESC LIMIT %s""", (limit,))
        return [_jsonable(r) for r in cur.fetchall()]
    return _run(fn, [])


# ── writing scans ────────────────────────────────────────────────────────────
def scan_started(ref: str, kind: str, target: str | None = None,
                 mode: str | None = None, scan_type: str | None = None,
                 options: dict | None = None, target_spec: dict | None = None) -> None:
    def fn(cur):
        cur.execute("""INSERT INTO scans (scan_ref, kind, target, mode, scan_type, started_by,
                                          options, target_spec)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (scan_ref) DO NOTHING""",
                    (ref, kind, _norm_target(target), mode, scan_type, _local_user(cur),
                     psycopg2.extras.Json(options) if options else None,
                     psycopg2.extras.Json(target_spec) if target_spec else None))
    _run(fn)


def scan_ended(ref: str, status: str) -> None:
    """For scans that ended without results (error, or stopped early)."""
    def fn(cur):
        cur.execute("""UPDATE scans SET status = %s, finished_at = now(),
                              elapsed_s = round(extract(epoch FROM now() - started_at)::numeric, 1)
                       WHERE scan_ref = %s AND status = 'running'""", (status, ref))
    _run(fn)


def _upsert_scan(cur, ref, kind, **cols) -> int:
    cur.execute("""INSERT INTO scans (scan_ref, kind, started_by) VALUES (%s, %s, %s)
                   ON CONFLICT (scan_ref) DO UPDATE SET kind = EXCLUDED.kind RETURNING id""",
                (ref, kind, _local_user(cur)))
    scan_id = cur.fetchone()["id"]
    if cols:
        sets = ", ".join(f"{k} = %s" for k in cols)
        cur.execute(f"UPDATE scans SET {sets} WHERE id = %s", (*cols.values(), scan_id))
    # a re-import replaces the old rows instead of doubling them
    for table in ("scan_modules", "findings", "hosts", "scan_targets", "scan_credential_use"):
        cur.execute(f"DELETE FROM {table} WHERE scan_id = %s", (scan_id,))
    return scan_id


def _insert_findings(cur, scan_id: int, findings: list[dict]) -> None:
    rows = []
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        sev = sev if sev in SEVERITIES else "INFO"
        title = f.get("title") or "(untitled)"
        rows.append((scan_id, sev, f.get("category"), title, f.get("description"),
                     f.get("affected_component"), f.get("remediation"), f.get("cvss_score"),
                     list(f.get("cve_ids") or []), f"{f.get('category') or ''}|{_stable_title(title)}",
                     psycopg2.extras.Json(f)))
    if rows:
        psycopg2.extras.execute_values(cur, """INSERT INTO findings
            (scan_id, severity, category, title, description, affected_component, remediation,
             cvss_score, cve_ids, fingerprint, raw) VALUES %s""", rows)


def _stable_title(title: str) -> str:
    """Numbers change between scans ("15 SUID binaries" → "16 …"); compare without them."""
    return re.sub(r"\d+", "#", title.strip().lower())


def save_host_scan(d: dict, report_path: str | None = None) -> bool:
    """Store a ScanSession.to_dict() result."""
    def fn(cur):
        started = _parse_time(d.get("started"))
        sid = _upsert_scan(
            cur, d["scan_id"], d.get("kind", "host"),
            target=_norm_target(d.get("target")), mode=d.get("mode"), scan_type=d.get("scan_type"),
            status=d.get("status", "complete"), risk_score=d.get("risk_score"),
            severity_counts=psycopg2.extras.Json(d.get("severity_counts") or {}),
            elapsed_s=d.get("elapsed_s"), report_path=report_path,
            **({"started_at": started} if started else {}),
        )
        cur.execute("""UPDATE scans SET finished_at = started_at + make_interval(secs => coalesce(elapsed_s, 0))
                       WHERE id = %s""", (sid,))
        mods = [(sid, m.get("name"), m.get("display_name"), m.get("status", "done"),
                 m.get("finding_count", 0), m.get("elapsed_s"), m.get("detail"))
                for m in d.get("modules", []) if m.get("name")]
        if mods:
            psycopg2.extras.execute_values(cur, """INSERT INTO scan_modules
                (scan_id, name, display_name, status, finding_count, elapsed_s, detail) VALUES %s""", mods)
        _insert_findings(cur, sid, d.get("findings", []))
        return True
    return bool(_run(fn, False))


NOTABLE_SEVERITY = {"crit": "HIGH", "warn": "MEDIUM", "info": "INFO"}


TARGET_STATUSES = ("up", "assumed_up", "no_response", "unresolved", "not_seen")


def save_network_scan(data: dict, kind: str = "network", status: str = "complete",
                      ref: str | None = None, report_path: str | None = None) -> bool:
    """Store a discovery findings.json (discovery/lib/build_json.py)."""
    meta = data.get("meta", {})
    ref = ref or meta.get("run_id") or datetime.now().strftime("%Y%m%d-%H%M%S")

    def fn(cur):
        started = _parse_time(meta.get("started"))
        notable = data.get("notable", [])
        findings = [{"severity": NOTABLE_SEVERITY.get(n.get("level"), "INFO"),
                     "category": "Cloud" if kind == "cloud" else "Network",
                     "title": n.get("text", ""), "affected_component": meta.get("target")}
                    for n in notable]
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
        sid = _upsert_scan(
            # a cloud-only run still records the local range in meta.target; it isn't the target
            cur, ref, kind, target=(meta.get("target") or None) if kind != "cloud" else "cloud accounts", status=status,
            severity_counts=psycopg2.extras.Json(counts),
            summary=psycopg2.extras.Json({"stats": data.get("stats", {}), "meta": meta,
                                          "cloud": data.get("cloud", {})}),
            report_path=report_path, finished_at=datetime.now().astimezone(),
            **({"started_at": started} if started else {}),
        )
        cur.execute("""UPDATE scans SET elapsed_s = round(extract(epoch FROM finished_at - started_at)::numeric, 1)
                       WHERE id = %s""", (sid,))
        _insert_findings(cur, sid, findings)
        trows = []
        for t in data.get("targets", []):
            if t.get("kind") in ("ip", "cidr", "mac", "host") and t.get("status") in TARGET_STATUSES:
                ips = [x for x in str(t.get("ip") or "").split(",") if re.match(r"^\d+\.\d+\.\d+\.\d+$", x)]
                trows.append((sid, t["kind"], str(t.get("value", ""))[:300], str(t.get("source") or "typed")[:60],
                              ips, t["status"], t.get("detail") or None))
        if trows:
            psycopg2.extras.execute_values(cur, """INSERT INTO scan_targets
                (scan_id, kind, value, source, resolved_ip, status, detail) VALUES %s""", trows,
                template="(%s, %s, %s, %s, %s::inet[], %s, %s)")
        crows = []
        for c in data.get("credential_use", []):
            if c.get("result") in ("ok", "auth_failed", "unreachable", "error"):
                crows.append((sid, str(c.get("type", ""))[:20], str(c.get("name", ""))[:60],
                              str(c.get("host", ""))[:100], c["result"], (c.get("detail") or None)))
        if crows:
            psycopg2.extras.execute_values(cur, """INSERT INTO scan_credential_use
                (scan_id, cred_type, cred_name, host, result, detail) VALUES %s""", crows)
            # saved cards: remember when they were last used and how it went
            cur.execute("""UPDATE credentials c SET last_used = now(),
                               last_result = CASE WHEN bool_or THEN 'ok' ELSE 'failed' END
                           FROM (SELECT cred_name, cred_type, bool_or(result = 'ok')
                                 FROM scan_credential_use WHERE scan_id = %s
                                 GROUP BY cred_name, cred_type) u
                           WHERE c.name = u.cred_name AND c.type = u.cred_type""", (sid,))
        for h in data.get("hosts", []):
            ip = h.get("ip")
            if not ip or not re.match(r"^[0-9a-fA-F:.]+$", ip):
                continue
            mac = h.get("mac") if h.get("mac") and re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", h["mac"]) else None
            extra = {k: h.get(k) for k in ("mdns", "netbios", "ssdp") if h.get(k)}
            cur.execute("""INSERT INTO hosts (scan_id, ip, mac, hostname, vendor, os_guess, extra)
                           VALUES (%s, %s, %s, %s, %s, %s, %s)
                           ON CONFLICT (scan_id, ip) DO NOTHING RETURNING id""",
                        (sid, ip, mac, h.get("hostname"), h.get("vendor"), h.get("os"),
                         psycopg2.extras.Json(extra) if extra else None))
            row = cur.fetchone()
            if not row:
                continue
            svcs = {}
            for p in h.get("ports", []):
                m = re.match(r"^(\d+)(?:/(\w+))?", str(p.get("port", "")))
                if m:
                    key = (int(m.group(1)), (m.group(2) or "tcp")[:4])
                    svcs[key] = (row["id"], *key, p.get("service"), p.get("version"))
            if svcs:
                psycopg2.extras.execute_values(cur, """INSERT INTO services
                    (host_id, port, protocol, service, version) VALUES %s""", list(svcs.values()))
        return True
    return bool(_run(fn, False))


# ── reading ──────────────────────────────────────────────────────────────────
def list_scans(limit: int = 100) -> list[dict]:
    def fn(cur):
        cur.execute("""SELECT s.scan_ref, s.kind, s.target, s.mode, s.scan_type, s.status, s.risk_score,
                              s.severity_counts, s.started_at, s.finished_at, s.elapsed_s,
                              (SELECT count(*) FROM findings f WHERE f.scan_id = s.id) AS findings,
                              (SELECT count(*) FROM hosts h WHERE h.scan_id = s.id) AS hosts
                       FROM scans s ORDER BY s.started_at DESC LIMIT %s""", (limit,))
        return [_jsonable(r) for r in cur.fetchall()]
    return _run(fn, [])


def get_scan(ref: str) -> dict | None:
    def fn(cur):
        cur.execute("SELECT * FROM scans WHERE scan_ref = %s", (ref,))
        scan = cur.fetchone()
        if not scan:
            return None
        sid = scan["id"]
        cur.execute("""SELECT severity, category, title, description, affected_component, remediation,
                              cvss_score, cve_ids, fingerprint
                       FROM findings WHERE scan_id = %s
                       ORDER BY array_position(ARRAY['CRITICAL','HIGH','MEDIUM','LOW','INFO']::varchar[], severity), id""",
                    (sid,))
        findings = cur.fetchall()
        cur.execute("""SELECT host(h.ip) AS ip, h.mac::text AS mac, h.hostname, h.vendor, h.os_guess,
                              coalesce(json_agg(json_build_object('port', s.port, 'protocol', s.protocol,
                                       'service', s.service, 'version', s.version) ORDER BY s.port)
                                       FILTER (WHERE s.port IS NOT NULL), '[]') AS services
                       FROM hosts h LEFT JOIN services s ON s.host_id = h.id
                       WHERE h.scan_id = %s GROUP BY h.id ORDER BY h.ip""", (sid,))
        hosts = cur.fetchall()
        cur.execute("""SELECT kind, value, source, (SELECT string_agg(host(x), ',') FROM unnest(resolved_ip) x) AS ip, status, detail
                       FROM scan_targets WHERE scan_id = %s ORDER BY id""", (sid,))
        targets = cur.fetchall()
        cur.execute("""SELECT cred_type, cred_name, host, result, detail FROM scan_credential_use
                       WHERE scan_id = %s ORDER BY id""", (sid,))
        logins = cur.fetchall()
        # compare with the previous finished scan of the same kind and target
        cur.execute("""SELECT id, scan_ref, started_at FROM scans
                       WHERE kind = %s AND target IS NOT DISTINCT FROM %s AND started_at < %s
                         AND status = 'complete' ORDER BY started_at DESC LIMIT 1""",
                    (scan["kind"], scan["target"], scan["started_at"]))
        prev = cur.fetchone()
        diff = None
        if prev:
            cur.execute("SELECT DISTINCT fingerprint FROM findings WHERE scan_id = %s", (prev["id"],))
            before = {r["fingerprint"] for r in cur.fetchall()}
            now = {f["fingerprint"] for f in findings}
            cur.execute("SELECT DISTINCT ON (fingerprint) severity, title, fingerprint FROM findings WHERE scan_id = %s",
                        (prev["id"],))
            resolved = [r for r in cur.fetchall() if r["fingerprint"] not in now]
            diff = {"previous": prev["scan_ref"], "previous_at": prev["started_at"],
                    "new": sum(1 for f in findings if f["fingerprint"] not in before),
                    "resolved": resolved}
            for f in findings:
                f["is_new"] = f["fingerprint"] not in before
        scan.pop("id", None)
        return _jsonable({"scan": scan, "findings": findings, "hosts": hosts, "targets": targets, "logins": logins, "diff": diff})
    return _run(fn)


def _jsonable(obj):
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat(timespec="seconds")
    if obj.__class__.__name__ == "Decimal":
        return float(obj)
    return obj


def _parse_time(s):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s))
        return dt if dt.tzinfo else dt.astimezone()
    except ValueError:
        return None


# ── import old reports ───────────────────────────────────────────────────────
def import_reports() -> tuple[int, int]:
    """Load panel/reports/*.json and discovery/reports/*/findings.json. Safe to re-run."""
    host_n = net_n = 0
    for p in sorted((APP_DIR / "reports").glob("*.json")):
        try:
            d = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        if "scan_id" in d and "findings" in d and save_host_scan(d, str(p.with_name(p.stem + "_dashboard.html"))):
            host_n += 1
    for p in sorted((REPO / "discovery" / "reports").glob("*/findings.json")):
        if p.parent.is_symlink():
            continue
        try:
            d = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        has_lan = bool(d.get("hosts"))
        kind = "network" if has_lan or not d.get("cloud") else "cloud"
        if save_network_scan(d, kind=kind, ref=p.parent.name, report_path=str(p.parent / "dashboard.html")):
            net_n += 1
    return host_n, net_n


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "status"
    if cmd == "migrate":
        try:
            done = migrate()
        except Exception as e:  # noqa: BLE001
            print(f"migrate failed: {e}")
            return 1
        print("applied: " + (", ".join(done) if done else "nothing - already up to date"))
        return 0
    if cmd == "import":
        if not ready():
            print(f"database not ready: {_state['error']}")
            return 1
        h, n = import_reports()
        print(f"imported {h} host scan(s) and {n} network/cloud scan(s)")
        return 0
    if cmd == "status":
        st = status()
        if st["ok"]:
            print(f"connected - migrations: {', '.join(st['migrations'])}")
        else:
            print(f"not ready - {st['error']}")
        return 0 if st["ok"] else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
