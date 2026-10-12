"""
Device manager: the glue between the web API, the drivers and PostgreSQL.

- Credentials live only in the connected driver object, in this process's memory.
  They are never written to the database, a file, or the activity log.
- Apply runs *exactly* the plan the user previewed (kept here by id), never a
  re-built one, so what was reviewed is what is sent.
- Before every apply a full configuration backup is stored in config_backups.
- Every preview, apply and rollback is written to config_changes and user_activity.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import threading
import time
import uuid
from dataclasses import asdict

import db
from . import catalog
from .base import DeviceError, PinMismatch, PinRequired, Plan, Step, ValidationError, v_address, v_port, v_text

# vendor → "module:Class"; a vendor whose module cannot load (missing paramiko, …) is reported, not fatal
DRIVER_PATHS = {
    "fortinet": "devices.fortinet:FortiGate",
    "cisco": "devices.cisco:CiscoCLI",
    "paloalto": "devices.paloalto:PanOS",
    "checkpoint": "devices.checkpoint:CheckPoint",
}
PLAN_TTL = 15 * 60

SESSIONS: dict[int, object] = {}        # device id → connected driver
PENDING: dict[str, dict] = {}           # plan id → {"device", "wizard", "plan", "params", "at"}
LOCK = threading.RLock()


def driver_class(vendor: str):
    path = DRIVER_PATHS.get(vendor)
    if not path:
        raise DeviceError(f"unknown vendor {vendor}")
    mod, cls = path.split(":")
    try:
        return getattr(importlib.import_module(mod), cls)
    except ImportError as e:
        raise DeviceError(f"{vendor} support is not available: {e}. Run ./install.sh to install what it needs.") from None


def vendors() -> list[dict]:
    out = []
    for key, v in catalog.CATALOG.items():
        try:
            cls = driver_class(key)
            avail, why, auth = True, "", [f.to_dict() for f in cls.auth_fields]
            fam_auth = {fk: [f.to_dict() for f in getattr(cls, "family_auth", {}).get(fk, cls.auth_fields)]
                        for fk in v["families"]}
            port = cls.default_port
            fam_ports = {fk: getattr(cls, "family_ports", {}).get(fk, port) for fk in v["families"]}
            help_text = (cls.__module__ and importlib.import_module(cls.__module__).__doc__ or "").strip()
        except DeviceError as e:
            avail, why, auth, fam_auth, fam_ports, help_text = False, str(e), [], {}, {}, ""
        out.append({"key": key, "label": v["label"], "available": avail, "why": why,
                    "families": [{"key": fk, "label": f["label"], "api": f["api"], "setup": f.get("setup", ""),
                                  "auth": fam_auth.get(fk, auth), "port": fam_ports.get(fk, 443),
                                  "models": [{"name": m, **info} for m, info in f["models"].items()]}
                                 for fk, f in v["families"].items()],
                    "help": help_text})
    return out


# ── database helpers (errors surface; the device page needs the database) ──
def _q(sql: str, args=(), one=False, many=True):
    if not db.ready():
        raise DeviceError("The device pages need the database. Run ./install.sh, then restart the panel.")
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


def _user_id() -> int:
    return _q("SELECT id FROM users WHERE email = 'local@localhost'", one=True)["id"]


def _J(v):
    import psycopg2.extras
    return psycopg2.extras.Json(v)


# ── devices ──────────────────────────────────────────────────────────────────
def list_devices() -> list[dict]:
    rows = _q("""SELECT d.id, d.name, d.vendor, d.family, d.model, d.address, d.port, d.facts, d.last_seen,
                        d.pin IS NOT NULL AS pinned,
                        (SELECT max(taken_at) FROM config_backups b WHERE b.device_id = d.id) AS last_backup,
                        (SELECT count(*) FROM config_changes c WHERE c.device_id = d.id AND c.status = 'applied') AS changes
                 FROM devices d ORDER BY d.name""")
    for r in rows:
        r["connected"] = r["id"] in SESSIONS
    return rows


def get_device(dev_id: int) -> dict:
    d = _q("SELECT * FROM devices WHERE id = %s", (dev_id,), one=True)
    if not d:
        raise DeviceError("device not found")
    d["connected"] = dev_id in SESSIONS
    return d


def add_device(p: dict) -> int:
    vendor = p.get("vendor", "")
    fams = catalog.families(vendor)
    if not fams:
        raise ValidationError("choose a vendor")
    family = p.get("family") or catalog.find_family(vendor, p.get("model", ""))
    if family not in fams:
        raise ValidationError("choose a device type")
    name = v_text(p.get("name"), 60, "name") or None
    addr = v_address(p.get("address", ""))
    port = v_port(p["port"]) if str(p.get("port") or "").strip() else None
    model = v_text(p.get("model"), 80, "model")
    try:
        row = _q("""INSERT INTO devices (name, vendor, family, model, address, port)
                    VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                 (name or addr, vendor, family, model, addr, port), one=True)
    except Exception as e:  # noqa: BLE001
        if "unique" in str(e).lower():
            raise DeviceError(f"{addr} is already in the device list") from None
        raise
    db.log("device.add", addr, {"vendor": vendor, "family": family, "model": model})
    return row["id"]


def delete_device(dev_id: int) -> None:
    d = get_device(dev_id)
    disconnect(dev_id)
    _q("DELETE FROM devices WHERE id = %s", (dev_id,))
    db.log("device.delete", d["address"], {"name": d["name"]})


def _driver(d: dict, creds: dict | None = None):
    cls = driver_class(d["vendor"])
    return cls(d["address"], d.get("port"), creds or {}, d.get("pin"), d.get("family") or "")


def probe(dev_id: int) -> dict:
    """Fetch the fingerprint to show the user before trusting it (no credentials sent)."""
    d = get_device(dev_id)
    drv = _driver(d)
    fp = drv.probe_fingerprint()
    return {"fingerprint": fp, "kind": drv.pin_kind, "pinned": d.get("pin"), "matches": d.get("pin") == fp}


def trust(dev_id: int, fingerprint: str) -> None:
    d = get_device(dev_id)
    fp = v_text(fingerprint, 200, "fingerprint")
    current = probe(dev_id)["fingerprint"]
    if current != fp:
        raise DeviceError("The device now presents a different fingerprint than the one you confirmed. Check again.")
    _q("UPDATE devices SET pin = %s WHERE id = %s", (fp, dev_id))
    db.log("device.trust", d["address"], {"fingerprint": fp, "replaced": d.get("pin")})


def connect(dev_id: int, creds: dict) -> dict:
    d = get_device(dev_id)
    drv = _driver(d, {k: str(v) for k, v in (creds or {}).items()})
    try:
        drv.connect()
        facts = drv.facts_cache or drv.facts()
    except (PinRequired, PinMismatch):
        raise
    except DeviceError:
        db.log("device.connect.failed", d["address"])
        raise
    with LOCK:
        old = SESSIONS.pop(dev_id, None)
        SESSIONS[dev_id] = drv
    if old:
        try:
            old.close()
        except Exception:  # noqa: BLE001
            pass
    _q("UPDATE devices SET facts = %s, last_seen = now() WHERE id = %s", (_J(facts), dev_id))
    db.log("device.connect", d["address"], {"model": facts.get("model"), "version": facts.get("version")})
    return facts


def disconnect(dev_id: int) -> None:
    with LOCK:
        drv = SESSIONS.pop(dev_id, None)
    if drv:
        try:
            drv.close()
        except Exception:  # noqa: BLE001
            pass


def session(dev_id: int):
    drv = SESSIONS.get(dev_id)
    if not drv:
        raise DeviceError("Not connected. Connect to the device first.")
    return drv


def overview(dev_id: int) -> dict:
    drv = session(dev_id)
    return {"facts": drv.facts(), "interfaces": drv.interfaces()}


def wizards(dev_id: int) -> list[dict]:
    drv = session(dev_id)
    out = []
    for w in drv.wizards():
        if w.applies_to and drv.family not in w.applies_to:
            continue
        wd = w.to_dict()
        for f in wd["fields"]:
            if f["source"] == "interfaces":
                f["options"] = drv.iface_options()
        out.append(wd)
    return out


# ── backups ──────────────────────────────────────────────────────────────────
def take_backup(dev_id: int, reason: str = "manual") -> dict:
    drv = session(dev_id)
    text = drv.backup()
    sha = hashlib.sha256(text.encode()).hexdigest()
    row = _q("""INSERT INTO config_backups (device_id, reason, config, sha256) VALUES (%s, %s, %s, %s)
                RETURNING id, taken_at, sha256""", (dev_id, reason, text, sha), one=True)
    db.log("config.backup", drv.address, {"backup_id": row["id"], "reason": reason, "bytes": len(text)})
    return {**row, "bytes": len(text)}


def list_backups(dev_id: int) -> list[dict]:
    return _q("""SELECT id, taken_at, reason, sha256, length(config) AS bytes FROM config_backups
                 WHERE device_id = %s ORDER BY taken_at DESC LIMIT 50""", (dev_id,))


def get_backup(backup_id: int) -> dict:
    b = _q("""SELECT b.*, d.name AS device_name FROM config_backups b JOIN devices d ON d.id = b.device_id
              WHERE b.id = %s""", (backup_id,), one=True)
    if not b:
        raise DeviceError("backup not found")
    return b


# ── preview / apply / rollback ───────────────────────────────────────────────
def preview(dev_id: int, wizard_id: str, params: dict) -> dict:
    drv = session(dev_id)
    w = drv.wizard(wizard_id)
    clean = {k: v for k, v in (params or {}).items() if not k.startswith("_")}
    names = {o[0] for o in drv.iface_options()}
    for f in w.fields:
        clean.setdefault(f.name, f.default)
        val = clean[f.name]
        if f.required and f.type != "checkbox" and not (val if isinstance(val, list) else str(val).strip()):
            raise ValidationError(f"{f.label} is required")
        if f.source == "interfaces" and names and str(val).strip() and str(val) not in names:
            raise ValidationError(f"{f.label}: the device has no interface called '{val}'")
    plan: Plan = w.build(clean, drv)
    pid = uuid.uuid4().hex
    with LOCK:
        now = time.time()
        for k in [k for k, v in PENDING.items() if now - v["at"] > PLAN_TTL]:
            PENDING.pop(k, None)
        PENDING[pid] = {"device": dev_id, "wizard": w, "plan": plan, "params": clean, "at": now}
    db.log("device.config.preview", drv.address, {"wizard": wizard_id})
    return {"plan_id": pid, "wizard": w.title, **plan.to_dict()}


def _steps_json(steps: list[Step]) -> list[dict]:
    return [asdict(s) for s in steps]


def _steps_from(rows: list[dict]) -> list[Step]:
    return [Step(**r) for r in rows]


def apply(plan_id: str, skip_backup: bool = False) -> dict:
    with LOCK:
        pend = PENDING.pop(plan_id, None)
    if not pend:
        raise DeviceError("This preview has expired or was already applied. Preview it again.")
    dev_id, plan, w = pend["device"], pend["plan"], pend["wizard"]
    drv = session(dev_id)
    vendor_key = f"{drv.vendor}.{w.id}"

    backup_id = None
    if not skip_backup:
        try:
            backup_id = take_backup(dev_id, f"before {w.title}")["id"]
        except DeviceError as e:
            with LOCK:          # let the user decide: put the plan back
                PENDING[plan_id] = pend
            raise DeviceError(f"Could not back up the configuration first, so nothing was changed: {e}. "
                              "Fix the backup, or apply without one.") from None

    results, values = drv.execute(plan.steps)
    ok = bool(results) and all(r["ok"] for r in results) and len(results) == len(plan.steps)
    commit_msg = ""
    if ok and plan.commit:
        try:
            commit_msg = drv.commit()
            results.append({"step": "Commit", "ok": True, "detail": commit_msg or "committed"})
        except DeviceError as e:
            ok = False
            results.append({"step": "Commit", "ok": False, "detail": str(e)})
            try:
                drv.discard()
                results.append({"step": "Discard uncommitted changes", "ok": True, "detail": ""})
            except DeviceError as e2:
                results.append({"step": "Discard uncommitted changes", "ok": False, "detail": str(e2)})
    status = "applied" if ok else "failed"
    done = sum(1 for r in results if r["ok"])
    undo = {"steps": _steps_json(plan.undo), "values": values, "commit": plan.commit} if plan.undo else None
    row = _q("""INSERT INTO config_changes (device_id, user_id, wizard, params, commands, backup_id, status,
                                            result, summary, undo, applied_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now()) RETURNING id""",
             (dev_id, _user_id(), vendor_key, _J(pend["params"]), plan.render(), backup_id, status,
              json.dumps(results), plan.summary, _J(undo) if undo else None), one=True)
    db.log("device.config.apply" if ok else "device.config.failed", drv.address,
           {"wizard": vendor_key, "change_id": row["id"], "steps_ok": done, "steps": len(plan.steps)})
    drv.iface_cache = []
    return {"change_id": row["id"], "ok": ok, "results": results, "backup_id": backup_id,
            "can_undo": bool(plan.undo) and done > 0}


def rollback(change_id: int) -> dict:
    ch = _q("SELECT * FROM config_changes WHERE id = %s", (change_id,), one=True)
    if not ch:
        raise DeviceError("change not found")
    if ch["status"] == "rolled_back":
        raise DeviceError("this change was already rolled back")
    if not ch.get("undo"):
        raise DeviceError("this change has no automatic undo; restore the backup taken before it instead")
    drv = session(ch["device_id"])
    steps = _steps_from(ch["undo"]["steps"])
    values = ch["undo"].get("values") or {}
    if ch["status"] == "failed":
        # Only part of it was applied: undo what we can, one step at a time,
        # skipping steps for objects that were never created.
        results = []
        for st in steps:
            r, _ = drv.execute([st], values)
            if r and not r[0]["ok"] and "missing" in r[0]["detail"]:
                r[0].update(ok=True, detail="skipped - never created")
            results += r
        ok = all(r["ok"] for r in results)
    else:
        results, _ = drv.execute(steps, values)
        ok = bool(results) and all(r["ok"] for r in results) and len(results) == len(steps)
    if ok and ch["undo"].get("commit"):
        try:
            results.append({"step": "Commit", "ok": True, "detail": drv.commit() or "committed"})
        except DeviceError as e:
            ok = False
            results.append({"step": "Commit", "ok": False, "detail": str(e)})
    if ok:
        _q("UPDATE config_changes SET status = 'rolled_back' WHERE id = %s", (change_id,))
    db.log("device.config.rollback", drv.address, {"change_id": change_id, "ok": ok})
    return {"ok": ok, "results": results}


def list_changes(dev_id: int) -> list[dict]:
    return _q("""SELECT c.id, c.created_at, c.wizard, c.summary, c.status, c.commands, c.result, c.backup_id,
                        c.undo IS NOT NULL AS can_undo, u.name AS user_name
                 FROM config_changes c JOIN users u ON u.id = c.user_id
                 WHERE c.device_id = %s ORDER BY c.created_at DESC LIMIT 100""", (dev_id,))
