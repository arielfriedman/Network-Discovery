"""
SentinelScan — reporters/html_report.py
Standalone Self-Contained HTML Report Generator
Phase 7 — Report Generator

Generates a single-file HTML report with all CSS and JS embedded inline.
No external dependencies — works fully offline. Includes interactive
severity filters, collapsible finding cards, copy-to-clipboard, and
a print-optimised stylesheet.
"""
from __future__ import annotations
import json
import datetime
import html as html_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.orchestrator import ScanSession


SEV_COLORS = {
    "CRITICAL": ("#e74c3c", "#fff"),
    "HIGH":     ("#e67e22", "#fff"),
    "MEDIUM":   ("#d4a017", "#fff"),
    "LOW":      ("#27ae60", "#fff"),
    "INFO":     ("#7f8c8d", "#fff"),
}


def _esc(s: str) -> str:
    return html_module.escape(str(s) if s else "")


def generate_html(session, output_path: str = None) -> str:
    """
    Generate a complete standalone HTML report.
    Returns the HTML string. Optionally writes to output_path.
    """
    counts   = session.severity_counts
    findings = sorted(session.findings, key=lambda f: f.severity.sort_order)
    total    = session.total_findings
    gen_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Compute risk score
    weights    = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    raw        = sum(counts.get(s, 0) * w for s, w in weights.items())
    max_raw    = total * 10 if total > 0 else 1
    risk_score = min(100, int((raw / max_raw) * 100))
    risk_label = ("CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60
                  else "ELEVATED" if risk_score >= 40 else "MODERATE" if risk_score >= 20
                  else "LOW")
    risk_color = ("#e74c3c" if risk_score >= 80 else "#e67e22" if risk_score >= 60
                  else "#d4a017" if risk_score >= 40 else "#27ae60")

    # Categories for sidebar
    categories = list(dict.fromkeys(f.category for f in findings))

    # Build finding cards HTML
    finding_cards = []
    for i, f in enumerate(findings):
        bg_color, txt_color = SEV_COLORS.get(f.severity.value, ("#888", "#fff"))
        cves_html = ""
        if f.cve_ids:
            cves_html = "".join(
                f'<span class="cve-chip">{_esc(c)}</span>' for c in f.cve_ids[:5])
        rem_html = ""
        if f.remediation:
            lines = _esc(f.remediation).replace("\n", "<br>")
            rem_html = f'<div class="finding-rem"><pre>{lines}</pre></div>'
        wa_html = ""
        if f.workaround:
            wa_html = f'<p class="workaround"><b>⚡ Workaround:</b> {_esc(f.workaround)}</p>'
        cvss_html = (f'<span class="cvss-badge">CVSS {f.cvss_score:.1f}</span>'
                     if f.cvss_score else "")
        refs_html = ""
        if f.references:
            refs_html = "<div class='refs'><b>References:</b> " + " ".join(
                f'<a href="{_esc(r)}" target="_blank">{_esc(r[:60])}</a>'
                for r in f.references[:3]) + "</div>"

        finding_cards.append(f"""
        <div class="finding-card" data-sev="{_esc(f.severity.value)}" data-cat="{_esc(f.category)}" id="f{i}">
          <div class="finding-header" onclick="toggleFinding('f{i}')">
            <span class="sev-badge" style="background:{bg_color};color:{txt_color}">{_esc(f.severity.value)}</span>
            <span class="cat-tag">{_esc(f.category)}</span>
            <span class="finding-title">{_esc(f.title)}</span>
            <div class="finding-meta-inline">
              {cvss_html}
              {cves_html}
            </div>
            <span class="toggle-arrow" id="arrow-f{i}">▼</span>
          </div>
          <div class="finding-body" id="body-f{i}" style="display:none">
            <p class="desc">{_esc(f.description)}</p>
            {"<p><b>🎯 Affected:</b> <code>" + _esc(f.affected_component) + "</code></p>" if f.affected_component else ""}
            {"<div class='rem-section'><p><b>🔧 Remediation:</b></p>" + rem_html + "</div>" if f.remediation else ""}
            {wa_html}
            {refs_html}
            <div class="finding-footer">
              <button class="btn-copy-finding" onclick="copyFinding({i})">📋 Copy</button>
              <span class="finding-id">ID: {_esc(f.id)}</span>
            </div>
          </div>
        </div>""")

    finding_cards_html = "\n".join(finding_cards)

    # Module summary rows
    module_rows = []
    for m in session.modules:
        status = m.get("status", "?")
        status_color = {"done": "#27ae60", "skipped": "#7f8c8d",
                        "error": "#e74c3c"}.get(status, "#2e86ab")
        module_rows.append(f"""
        <tr>
          <td>{_esc(m.get('display_name', m.get('name','?')))}</td>
          <td><span class="status-pill" style="background:{status_color}">{_esc(status.upper())}</span></td>
          <td>{m.get('finding_count',0)}</td>
          <td>{m.get('elapsed_s',0):.1f}s</td>
        </tr>""")
    module_rows_html = "\n".join(module_rows)

    # Severity chart bars
    chart_bars = []
    max_count  = max((counts.get(s, 0) for s in SEV_COLORS), default=1) or 1
    for sev, (color, _) in SEV_COLORS.items():
        cnt  = counts.get(sev, 0)
        pct  = int((cnt / max_count) * 100)
        chart_bars.append(f"""
        <div class="chart-row" onclick="filterSev('{sev}')">
          <span class="chart-label">{sev}</span>
          <div class="chart-bar-wrap">
            <div class="chart-bar" style="width:{pct}%;background:{color}"></div>
          </div>
          <span class="chart-count" style="color:{color}">{cnt}</span>
        </div>""")
    chart_html = "\n".join(chart_bars)

    # Category filter pills
    cat_pills = '<button class="pill active" onclick="filterCat(\'\')">All</button>\n'
    cat_pills += "\n".join(
        f'<button class="pill" onclick="filterCat(\'{_esc(c)}\')">{_esc(c)}</button>'
        for c in categories)

    # JSON for clipboard summary
    summary_json = json.dumps({
        "scan_id":    session.scan_id, "target": session.target,
        "mode":       session.mode,    "scan_type": session.scan_type,
        "total":      total,           "risk_score": risk_score,
        "critical":   counts.get("CRITICAL", 0), "high": counts.get("HIGH", 0),
        "medium":     counts.get("MEDIUM", 0),   "low":  counts.get("LOW", 0),
        "generated":  gen_time,
    })

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SentinelScan Report — {_esc(session.scan_id)}</title>
<style>
/* ── Reset & Base ─────────────────────────────────────────────── */
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0d1117;--panel:#161b22;--card:#1c2128;--hover:#22272e;
  --border:#30363d;--text:#e6edf3;--muted:#8b949e;
  --accent:#2e86ab;--accent-dim:#1a3a5c;
  --c-crit:#e74c3c;--c-high:#e67e22;--c-med:#d4a017;
  --c-low:#27ae60;--c-info:#7f8c8d;
}}
html,body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;
  font-size:14px;line-height:1.5;min-height:100vh}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}
pre{{white-space:pre-wrap;word-break:break-all}}
code{{font-family:'Consolas','Courier New',monospace;font-size:0.9em;
  background:#0d1117;padding:1px 5px;border-radius:3px;color:#a8c7fa}}

/* ── Layout ───────────────────────────────────────────────────── */
.layout{{display:flex;min-height:100vh}}
.sidebar{{width:260px;min-height:100vh;background:var(--panel);
  border-right:1px solid var(--border);position:sticky;top:0;
  height:100vh;overflow-y:auto;flex-shrink:0}}
.main{{flex:1;padding:28px 32px;max-width:1100px}}

/* ── Sidebar ──────────────────────────────────────────────────── */
.sidebar-brand{{padding:20px 16px 16px;border-bottom:1px solid var(--border)}}
.brand-name{{font-size:16px;font-weight:700;color:var(--text)}}
.brand-name b{{color:var(--accent)}}
.sidebar-section{{padding:16px}}
.sidebar-section h4{{font-size:10px;text-transform:uppercase;letter-spacing:.08em;
  color:var(--muted);margin-bottom:10px}}
.chart-row{{display:flex;align-items:center;gap:8px;margin-bottom:6px;
  cursor:pointer;padding:3px 4px;border-radius:4px;transition:.1s}}
.chart-row:hover{{background:var(--hover)}}
.chart-label{{width:60px;font-size:11px;font-weight:600;color:var(--muted)}}
.chart-bar-wrap{{flex:1;background:var(--border);border-radius:3px;height:8px;overflow:hidden}}
.chart-bar{{height:100%;border-radius:3px;transition:width .4s}}
.chart-count{{width:28px;text-align:right;font-size:12px;font-weight:700}}
.sidebar-meta{{padding:12px 16px;border-top:1px solid var(--border);
  font-size:11px;color:var(--muted);line-height:1.8}}
.sidebar-meta b{{color:var(--text)}}

/* ── Header ───────────────────────────────────────────────────── */
.page-header{{margin-bottom:24px}}
.page-header h1{{font-size:24px;font-weight:700}}
.page-header .meta{{color:var(--muted);font-size:13px;margin-top:4px}}
.risk-badge{{display:inline-block;padding:4px 14px;border-radius:20px;
  font-weight:700;font-size:12px;color:#fff;margin-left:8px}}
.header-actions{{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}}
.btn{{padding:8px 16px;border-radius:5px;font-size:13px;font-weight:600;
  cursor:pointer;border:none;transition:.15s;text-decoration:none;display:inline-block}}
.btn-primary{{background:var(--accent);color:#fff}}
.btn-primary:hover{{background:#3da0c9;color:#fff}}
.btn-outline{{background:transparent;border:1px solid var(--accent);color:var(--accent)}}
.btn-outline:hover{{background:var(--accent-dim)}}

/* ── Severity Cards ───────────────────────────────────────────── */
.sev-cards{{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}}
.sev-card{{flex:1;min-width:80px;background:var(--card);border:1px solid var(--border);
  border-radius:8px;padding:14px 10px;text-align:center;cursor:pointer;transition:.15s}}
.sev-card:hover,.sev-card.active{{border-color:currentColor;background:var(--hover)}}
.sev-num{{display:block;font-size:26px;font-weight:700}}
.sev-lbl{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}}
.sev-card.crit{{color:var(--c-crit)}} .sev-card.high{{color:var(--c-high)}}
.sev-card.med{{color:var(--c-med)}}  .sev-card.low{{color:var(--c-low)}}
.sev-card.info{{color:var(--c-info)}} .sev-card.tot{{color:var(--accent)}}

/* ── Filter Bar ───────────────────────────────────────────────── */
.filter-bar{{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:16px}}
.search-input{{flex:1;min-width:200px;background:var(--panel);border:1px solid var(--border);
  border-radius:5px;padding:8px 12px;color:var(--text);font-size:13px;outline:none}}
.search-input:focus{{border-color:var(--accent)}}
.pills{{display:flex;gap:6px;flex-wrap:wrap}}
.pill{{padding:5px 12px;border:1px solid var(--border);border-radius:20px;
  background:transparent;color:var(--muted);font-size:12px;cursor:pointer;transition:.15s}}
.pill:hover,.pill.active{{border-color:var(--accent);color:var(--accent);background:var(--accent-dim)}}

/* ── Finding Cards ────────────────────────────────────────────── */
.findings-wrap{{display:flex;flex-direction:column;gap:8px}}
.finding-card{{background:var(--card);border:1px solid var(--border);
  border-radius:8px;overflow:hidden;transition:.15s}}
.finding-card:hover{{border-color:var(--accent)}}
.finding-header{{display:flex;align-items:center;gap:10px;padding:12px 14px;
  cursor:pointer;flex-wrap:wrap;gap:8px}}
.sev-badge{{padding:3px 9px;border-radius:4px;font-size:10px;font-weight:700;
  letter-spacing:.05em;flex-shrink:0}}
.cat-tag{{background:var(--bg);border:1px solid var(--border);color:var(--muted);
  padding:2px 8px;border-radius:4px;font-size:11px;flex-shrink:0}}
.finding-title{{flex:1;font-size:13px;font-weight:600;min-width:200px}}
.finding-meta-inline{{display:flex;gap:6px;align-items:center;flex-wrap:wrap}}
.cvss-badge{{background:var(--accent-dim);color:var(--accent);padding:2px 7px;
  border-radius:4px;font-size:11px;font-weight:700;font-family:monospace}}
.cve-chip{{background:#1a2a3a;border:1px solid var(--accent);color:var(--accent);
  padding:1px 6px;border-radius:3px;font-size:10px;font-family:monospace}}
.toggle-arrow{{margin-left:auto;font-size:12px;color:var(--muted);flex-shrink:0;
  transition:transform .2s}}
.toggle-arrow.open{{transform:rotate(180deg)}}
.finding-body{{padding:12px 14px 14px;border-top:1px solid var(--border);
  background:var(--bg)}}
.finding-body .desc{{color:var(--muted);font-size:13px;margin-bottom:10px;line-height:1.6}}
.finding-body p{{font-size:12.5px;margin-bottom:6px}}
.finding-rem pre{{background:#090d13;border-left:3px solid var(--accent);
  padding:10px 12px;font-size:11.5px;color:#a8c7fa;border-radius:0 5px 5px 0;
  overflow-x:auto;margin:4px 0 8px}}
.workaround{{background:#1a2d1a;border-left:3px solid var(--c-low);
  padding:8px 12px;border-radius:0 5px 5px 0;font-size:12px;color:#aaddaa}}
.refs{{font-size:11px;margin-top:6px;color:var(--muted)}}
.finding-footer{{display:flex;justify-content:space-between;align-items:center;
  margin-top:10px;padding-top:8px;border-top:1px solid var(--border)}}
.btn-copy-finding{{background:transparent;border:1px solid var(--border);
  color:var(--muted);padding:4px 10px;border-radius:4px;font-size:11px;cursor:pointer}}
.btn-copy-finding:hover{{border-color:var(--accent);color:var(--accent)}}
.finding-id{{font-size:10px;color:var(--muted);font-family:monospace}}
.no-findings{{text-align:center;padding:60px;color:var(--muted)}}

/* ── Module Table ─────────────────────────────────────────────── */
.module-table{{width:100%;border-collapse:collapse;margin-top:8px}}
.module-table th{{background:var(--panel);padding:9px 12px;
  font-size:11px;color:var(--muted);text-transform:uppercase;
  text-align:left;border-bottom:1px solid var(--border)}}
.module-table td{{padding:9px 12px;border-bottom:1px solid var(--border);
  font-size:13px}}
.module-table tr:hover td{{background:var(--hover)}}
.status-pill{{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;
  color:#fff;letter-spacing:.05em}}

/* ── Sections ─────────────────────────────────────────────────── */
.section{{margin-bottom:32px}}
.section-title{{font-size:18px;font-weight:700;margin-bottom:4px}}
.section-sub{{font-size:12px;color:var(--muted);margin-bottom:16px}}
.divider{{border:none;border-top:1px solid var(--border);margin:24px 0}}

/* ── Print ────────────────────────────────────────────────────── */
@media print{{
  .sidebar,.header-actions,.filter-bar,.btn,.toggle-arrow,.btn-copy-finding{{display:none!important}}
  .layout{{display:block}}
  .main{{padding:0}}
  .finding-card{{break-inside:avoid;border:1px solid #ccc}}
  .finding-body{{display:block!important}}
  body{{background:#fff;color:#000}}
  .finding-body .desc,.finding-body p{{color:#333}}
}}
</style>
</head>
<body>
<div class="layout">
<!-- ── SIDEBAR ─────────────────────────────────────────────── -->
<aside class="sidebar">
  <div class="sidebar-brand">
    <div class="brand-name">🛡 Sentinel<b>Scan</b></div>
    <div style="font-size:11px;color:var(--muted);margin-top:4px">Security Audit Report</div>
  </div>
  <div class="sidebar-section">
    <h4>Severity Breakdown</h4>
    {chart_html}
  </div>
  <div class="sidebar-section">
    <h4>Filter by Category</h4>
    <div style="display:flex;flex-direction:column;gap:4px">
      <button class="pill active" onclick="filterCat('')" style="text-align:left">All Categories</button>
      {"".join(f'<button class="pill" onclick="filterCat(\'{_esc(c)}\')" style="text-align:left">{_esc(c)}</button>' for c in categories)}
    </div>
  </div>
  <div class="sidebar-meta">
    <div><b>Scan ID</b><br>{_esc(session.scan_id)}</div>
    <div style="margin-top:8px"><b>Target</b><br>{_esc(session.target)}</div>
    <div style="margin-top:8px"><b>Mode</b><br>{_esc(session.mode.upper())} / {_esc(session.scan_type.upper())}</div>
    <div style="margin-top:8px"><b>Duration</b><br>{session.elapsed_seconds:.1f}s</div>
    <div style="margin-top:8px"><b>Generated</b><br>{_esc(gen_time)}</div>
  </div>
</aside>

<!-- ── MAIN CONTENT ────────────────────────────────────────── -->
<main class="main">
  <!-- Header -->
  <div class="page-header">
    <h1>Security Audit Report
      <span class="risk-badge" style="background:{risk_color}">{risk_label} RISK — {risk_score}/100</span>
    </h1>
    <div class="meta">
      Target: <b>{_esc(session.target)}</b> &nbsp;·&nbsp;
      {_esc(session.mode.upper())} scan &nbsp;·&nbsp;
      {total} finding(s) &nbsp;·&nbsp;
      {session.elapsed_seconds:.1f}s
    </div>
    <div class="header-actions">
      <button class="btn btn-primary" onclick="window.print()">🖨 Print / Save PDF</button>
      <button class="btn btn-outline" onclick="copyReport()">📋 Copy Summary</button>
      <button class="btn btn-outline" onclick="expandAll()">⬇ Expand All</button>
      <button class="btn btn-outline" onclick="collapseAll()">⬆ Collapse All</button>
    </div>
  </div>

  <!-- Severity cards -->
  <div class="sev-cards">
    <div class="sev-card crit" onclick="filterSev('CRITICAL')"><span class="sev-num">{counts.get('CRITICAL',0)}</span><span class="sev-lbl">Critical</span></div>
    <div class="sev-card high" onclick="filterSev('HIGH')"><span class="sev-num">{counts.get('HIGH',0)}</span><span class="sev-lbl">High</span></div>
    <div class="sev-card med"  onclick="filterSev('MEDIUM')"><span class="sev-num">{counts.get('MEDIUM',0)}</span><span class="sev-lbl">Medium</span></div>
    <div class="sev-card low"  onclick="filterSev('LOW')"><span class="sev-num">{counts.get('LOW',0)}</span><span class="sev-lbl">Low</span></div>
    <div class="sev-card info" onclick="filterSev('INFO')"><span class="sev-num">{counts.get('INFO',0)}</span><span class="sev-lbl">Info</span></div>
    <div class="sev-card tot"  onclick="filterSev('')"><span class="sev-num">{total}</span><span class="sev-lbl">Total</span></div>
  </div>

  <!-- Findings section -->
  <div class="section">
    <div class="section-title">Findings & Remediation</div>
    <!-- Filter bar -->
    <div class="filter-bar">
      <input type="text" class="search-input" id="search" placeholder="🔍  Search findings..."
             oninput="applyFilters()"/>
    </div>
    <div id="findings-wrap" class="findings-wrap">
      {finding_cards_html}
    </div>
    <div id="no-findings" class="no-findings" style="display:none">No findings match your filters.</div>
  </div>

  <hr class="divider"/>

  <!-- Modules section -->
  <div class="section">
    <div class="section-title">Scan Module Summary</div>
    <div class="section-sub">{len(session.modules)} module(s) executed in {session.elapsed_seconds:.1f}s</div>
    <table class="module-table">
      <thead><tr><th>Module</th><th>Status</th><th>Findings</th><th>Duration</th></tr></thead>
      <tbody>{module_rows_html}</tbody>
    </table>
  </div>

  <hr class="divider"/>
  <div style="font-size:11px;color:var(--muted);text-align:center;padding:20px 0">
    SentinelScan v1.0 · Confidential — Internal Use Only · Generated {_esc(gen_time)}
  </div>
</main>
</div>

<script>
// ── State ──────────────────────────────────────────────────────────────────
let activeSev = '', activeCat = '';
const SUMMARY = {summary_json};

// ── Toggle finding ──────────────────────────────────────────────────────────
function toggleFinding(id) {{
  const body  = document.getElementById('body-' + id);
  const arrow = document.getElementById('arrow-' + id);
  if (!body) return;
  const open = body.style.display !== 'none';
  body.style.display  = open ? 'none' : 'block';
  arrow.classList.toggle('open', !open);
}}

function expandAll() {{
  document.querySelectorAll('.finding-card').forEach(c => {{
    const id = c.id;
    document.getElementById('body-' + id).style.display = 'block';
    document.getElementById('arrow-' + id).classList.add('open');
  }});
}}
function collapseAll() {{
  document.querySelectorAll('.finding-card').forEach(c => {{
    const id = c.id;
    document.getElementById('body-' + id).style.display = 'none';
    document.getElementById('arrow-' + id).classList.remove('open');
  }});
}}

// ── Filters ────────────────────────────────────────────────────────────────
function filterSev(sev) {{
  activeSev = sev;
  document.querySelectorAll('.sev-card').forEach(c => c.classList.remove('active'));
  applyFilters();
}}
function filterCat(cat) {{
  activeCat = cat;
  document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
  event.target.classList.add('active');
  applyFilters();
}}
function applyFilters() {{
  const search = document.getElementById('search').value.toLowerCase();
  let visible = 0;
  document.querySelectorAll('.finding-card').forEach(card => {{
    const sev   = card.dataset.sev || '';
    const cat   = card.dataset.cat || '';
    const text  = card.innerText.toLowerCase();
    const show  = (!activeSev || sev === activeSev) &&
                  (!activeCat || cat === activeCat) &&
                  (!search    || text.includes(search));
    card.style.display = show ? '' : 'none';
    if (show) visible++;
  }});
  document.getElementById('no-findings').style.display = visible === 0 ? 'block' : 'none';
}}

// ── Copy ────────────────────────────────────────────────────────────────────
function copyReport() {{
  const txt = `SentinelScan Report | ID: ${{SUMMARY.scan_id}} | Target: ${{SUMMARY.target}} | Mode: ${{SUMMARY.mode.toUpperCase()}}
Total: ${{SUMMARY.total}} | CRITICAL: ${{SUMMARY.critical}} | HIGH: ${{SUMMARY.high}} | MEDIUM: ${{SUMMARY.medium}} | LOW: ${{SUMMARY.low}}
Risk Score: ${{SUMMARY.risk_score}}/100 | Generated: ${{SUMMARY.generated}}`;
  navigator.clipboard.writeText(txt).then(() => alert('Report summary copied!'));
}}
function copyFinding(idx) {{
  const card = document.querySelectorAll('.finding-card')[idx];
  if (card) navigator.clipboard.writeText(card.innerText).then(() => alert('Copied!'));
}}

// ── Keyboard ────────────────────────────────────────────────────────────────
document.addEventListener('keydown', e => {{
  if (e.key === 'Escape') {{ filterSev(''); filterCat(''); document.getElementById('search').value=''; applyFilters(); }}
}});
</script>
</body>
</html>"""

    if output_path:
        from pathlib import Path
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(html, encoding="utf-8")

    return html
