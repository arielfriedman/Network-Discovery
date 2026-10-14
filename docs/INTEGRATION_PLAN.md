# SentinelScan × Network Discovery — Integration Plan

**Decision:** keep two scan engines, unify them at the **data schema** and the
**dashboard**. Recon (network-discovery, bash) looks outward; SentinelScan
(python) looks inward at one host's posture. One visual language ties them together.

---

## 0. Blocker: the SentinelScan engine is missing from the backup

The project backup on an external drive contained the **14 scan modules** and the **3 reporters**, but **not** the engine
that runs them. Missing files, all imported by every module:

| File | Defines | Why it's needed |
|---|---|---|
| `scanner/base.py` | `Finding`, `Severity`, `ScanModule` | every module does `from .base import ...` |
| `scanner/orchestrator.py` | `ScanSession`, `ScanOrchestrator`, `register_module` | runs modules, collects findings, `to_dict()` |
| `config.py` | `Config` (OS/paths/target) | passed to every module and the server |
| `main.py` | entry point | boot |
| `templates/`, `static/` | Flask live UI (Phase 3) | the served dashboard |

As-is, **nothing runs**. The good news: the exact contract is fully pinned down
by how the reporters and `web_server_phase7.py` use it, so `base.py` and
`orchestrator.py` can be reconstructed precisely (see §2). Check first whether a
newer, complete copy exists (the running machine, `Claude_backup.zip`, another
disk) — that's faster than rebuilding.

---

## 1. The shared findings schema (one contract, both tools emit it)

A single JSON both engines produce and one renderer consumes.

```jsonc
{
  "scan_id": "a1b2c3",
  "kind": "host" | "network",          // NEW — lets one dashboard branch
  "mode": "server" | "workstation",     // host scans
  "scan_type": "quick" | "full",
  "target": "localhost (pve-node-01)",
  "status": "complete",
  "started": "2026-09-23T09:12:04",
  "elapsed_s": 214.7,
  "total_findings": 21,
  "severity_counts": { "CRITICAL":3,"HIGH":6,"MEDIUM":5,"LOW":4,"INFO":3 },
  "modules": [ { "name","display_name","status","finding_count","elapsed_s" } ],
  "findings": [ {
    "id","title","severity","category","description",
    "affected_component","remediation","workaround",
    "cvss_score"|null,"cve_ids":[],"references":[]
  } ]
}
```

- SentinelScan already produces almost exactly this from `ScanSession.to_dict()`.
  Only additions: top-level `kind` and `started`.
- network-discovery emits `{meta, stats, hosts, notable, ...}` today. It keeps
  its host inventory, but can **also** emit a `findings[]` array for the same
  renderer (e.g. "Telnet exposed on 3 hosts" → a Finding). This is the one place
  the two tools meet.

---

## 2. Reconstruct the engine (from the pinned contract)

`base.py`
- `class Severity(Enum)` — values `CRITICAL/HIGH/MEDIUM/LOW/INFO`, each with a
  `sort_order` (CRITICAL=0) and `.value` string. Used by reporters via
  `f.severity.sort_order` and `f.severity.value`.
- `@dataclass Finding` — fields exactly as the schema; plus `.id` and
  `.to_dict()`. Constructor signature is fixed by `web_server_phase7._load()`.
- `class ScanModule` — base with `name`, `display_name`, and a `run(cfg) ->
  Iterator[Finding]` contract (matches `scanner_ports.py`'s `from .base import
  ScanModule` and its generator style).

`orchestrator.py`
- `register_module(cls)` decorator that appends to a module registry (every
  scanner file calls it).
- `class ScanSession` — holds `scan_id, mode, scan_type, target, status,
  findings[], modules[]`, computes `severity_counts`, `total_findings`,
  `elapsed_s`, and `to_dict()` (shape above).
- `class ScanOrchestrator(cfg, emit_fn)` — `.run(session)` iterates registered
  modules, times each, catches errors → module status `done/skipped/error`,
  streams progress via `emit_fn`.

`config.py` — OS detection, tool paths, `reports_dir`, `to_dict()`.

Everything above is inferable with no guesswork; the modules and reporters are
the specification.

---

## 3. The dashboard (replaces the dated `html_report.py`)

`reporters/dashboard.py` — one renderer, ND design system (done as a prototype):
design tokens + light/dark, risk banner, stat tiles, "needs attention first"
notes, two bar charts (by severity, by category), a module-health grid, and a
filterable/sortable findings table with expandable remediation.

- Drop-in: `web_server`'s `/download/<id>/html` calls `generate_dashboard(session)`
  instead of the old `generate_html`. The live results page can serve the same file.
- The same renderer, fed a network-discovery session (`kind:"network"`), shows the
  host table instead of the findings table — **one dashboard, two modes.**
- Keep `pdf_report.py` / `executive.py` for print/stakeholder output; they're fine.

---

## 4. Where the code lives

```
network-discovery/                 (existing bash tool — unchanged engine)
  lib/dashboard.template.html       ← source of the shared design system
  lib/dashboard.py                  ← NEW shared renderer (host + network modes)

sentinelscan/                       (rebuilt python tool)
  scanner/ base.py orchestrator.py  ← reconstructed (§2)
          + the 14 existing modules
  reporters/ dashboard.py           ← imports/mirrors the shared renderer
             pdf_report.py executive.py
  config.py main.py web_server.py templates/ static/
```

The renderer is the shared artifact; each tool imports it. No engine is merged.

---

## 5. Order of work

1. **Recover or rebuild the engine** (§2) — until this exists, SentinelScan can't
   run and can't be tested end-to-end. *Highest priority.*
2. **Lock the schema** (§1) — add `kind`, `started`; confirm `to_dict()` matches.
3. **Land the dashboard renderer** (§3) — prototype already built; wire into
   `web_server` and generate on scan completion.
4. **Teach network-discovery to emit `findings[]`** so the same dashboard renders
   its results in "network" mode.
5. **Optional later:** a "host posture" stage in network-discovery that invokes
   SentinelScan against localhost or a discovered host over SSH, folding results in.

---

## Prototype delivered alongside this plan

- `render_dashboard.py` — the shared renderer (standalone)
- `sample_session.json` — a realistic 21-finding server scan
- `sentinel-dashboard.html` — open it to see the target look
  (also on the Desktop as `sentinel-dashboard-PREVIEW.html`)
