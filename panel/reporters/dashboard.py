#!/usr/bin/env python3
"""
SentinelScan — dashboard renderer (prototype)

Takes a scan-session JSON (the shared findings schema) and produces a single
self-contained HTML dashboard, styled to match the network-discovery dashboard:
design tokens, light/dark, stat tiles, notable notes, bar charts, and a
filterable/sortable findings table with expandable remediation.

    python3 render_dashboard.py sample_session.json sentinel-dashboard.html
"""
import sys, json

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelScan Report</title>
<style>
  :root {
    color-scheme: light;
    --plane:#f9f9f7; --surface-1:#fcfcfb; --text-primary:#0b0b0b;
    --text-secondary:#52514e; --text-muted:#898781; --grid:#e1e0d9;
    --baseline:#c3c2b7; --border:rgba(11,11,11,0.10);
    --series-1:#2a78d6; --series-1-soft:#cde2fb;
    --good:#0ca30c; --warning:#fab219; --serious:#ec835a; --critical:#d03b3b;
    --radius:10px;
  }
  @media (prefers-color-scheme: dark) {
    :root:where(:not([data-theme="light"])) {
      color-scheme: dark;
      --plane:#0d0d0d; --surface-1:#1a1a19; --text-primary:#ffffff;
      --text-secondary:#c3c2b7; --text-muted:#898781; --grid:#2c2c2a;
      --baseline:#383835; --border:rgba(255,255,255,0.10);
      --series-1:#3987e5; --series-1-soft:#184f95;
    }
  }
  :root[data-theme="dark"] {
    color-scheme: dark;
    --plane:#0d0d0d; --surface-1:#1a1a19; --text-primary:#ffffff;
    --text-secondary:#c3c2b7; --text-muted:#898781; --grid:#2c2c2a;
    --baseline:#383835; --border:rgba(255,255,255,0.10);
    --series-1:#3987e5; --series-1-soft:#184f95;
  }
  * { box-sizing:border-box; }
  body { margin:0; padding:0 16px 64px; background:var(--plane); color:var(--text-primary);
         font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
  .wrap { max-width:1180px; margin:0 auto; }
  header { padding:28px 0 20px; display:flex; flex-wrap:wrap; gap:16px;
           align-items:flex-start; justify-content:space-between; }
  h1 { margin:0 0 6px; font-size:24px; letter-spacing:-0.01em; }
  .sub { color:var(--text-secondary); font-size:13.5px; }
  .sub code { background:var(--surface-1); border:1px solid var(--border);
              border-radius:5px; padding:1px 6px; font-size:12.5px; }
  button.theme { background:var(--surface-1); color:var(--text-secondary);
     border:1px solid var(--border); border-radius:999px; padding:7px 14px;
     font:inherit; font-size:13px; cursor:pointer; }
  button.theme:hover { color:var(--text-primary); }
  section { margin:26px 0; }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:0.07em;
       color:var(--text-muted); margin:0 0 12px; font-weight:600; }

  /* risk banner */
  .risk { display:flex; align-items:center; gap:18px; background:var(--surface-1);
          border:1px solid var(--border); border-left:5px solid var(--baseline);
          border-radius:var(--radius); padding:16px 20px; }
  .risk .score { font-size:40px; font-weight:680; line-height:1; letter-spacing:-0.02em; }
  .risk .of { color:var(--text-muted); font-size:15px; font-weight:500; }
  .risk .band { font-size:13px; text-transform:uppercase; letter-spacing:0.06em;
                font-weight:700; margin-top:3px; }
  .risk .meter { flex:1; height:10px; border-radius:6px; background:var(--grid);
                 overflow:hidden; min-width:120px; }
  .risk .meter > span { display:block; height:100%; border-radius:6px; }

  /* tiles */
  .tiles { display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); }
  .tile { background:var(--surface-1); border:1px solid var(--border);
          border-radius:var(--radius); padding:16px 18px; }
  .tile .v { font-size:30px; font-weight:650; letter-spacing:-0.02em; line-height:1.1; }
  .tile .k { color:var(--text-secondary); font-size:12.5px; margin-top:4px; }
  .tile.sev .v { color:var(--sv); }

  /* notable */
  .notes { display:flex; flex-direction:column; gap:8px; }
  .note { display:flex; gap:10px; align-items:flex-start; background:var(--surface-1);
          border:1px solid var(--border); border-left:3px solid var(--text-muted);
          border-radius:8px; padding:11px 14px; font-size:14px; }
  .note .ic { flex:none; font-weight:700; font-size:11px; letter-spacing:0.04em;
              padding-top:2px; min-width:58px; }

  /* charts */
  .charts { display:grid; gap:16px; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); }
  .card { background:var(--surface-1); border:1px solid var(--border);
          border-radius:var(--radius); padding:18px 20px 20px; }
  .card h3 { margin:0 0 2px; font-size:15px; font-weight:600; }
  .card .cap { color:var(--text-muted); font-size:12.5px; margin-bottom:16px; }
  .bars { display:flex; flex-direction:column; gap:2px; }
  .row { display:grid; grid-template-columns:minmax(96px,42%) 1fr auto; gap:10px;
         align-items:center; padding:3px 0; }
  .row .lbl { color:var(--text-secondary); font-size:12.5px; white-space:nowrap;
              overflow:hidden; text-overflow:ellipsis; }
  .track { height:16px; position:relative; }
  .track::before { content:""; position:absolute; inset:0; border-left:1px solid var(--baseline); }
  .bar { height:16px; border-radius:0 4px 4px 0; min-width:2px; background:var(--series-1); }
  .num { font-variant-numeric:tabular-nums; font-size:12.5px; color:var(--text-secondary);
         min-width:22px; text-align:right; }
  .empty { color:var(--text-muted); font-size:13px; padding:6px 0; }

  /* module health grid */
  .mods { display:grid; gap:8px; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); }
  .mod { background:var(--surface-1); border:1px solid var(--border); border-radius:8px;
         padding:10px 12px; display:flex; flex-direction:column; gap:3px; }
  .mod .mn { font-size:13px; font-weight:600; }
  .mod .ms { font-size:11.5px; color:var(--text-muted); display:flex; gap:8px; align-items:center; }
  .dot { width:8px; height:8px; border-radius:50%; display:inline-block; }
  .dot.done{background:var(--good)} .dot.skipped{background:var(--text-muted)}
  .dot.error{background:var(--critical)}

  /* controls + table */
  .controls { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:12px; }
  .controls input, .controls select {
     background:var(--surface-1); color:var(--text-primary); border:1px solid var(--border);
     border-radius:8px; padding:8px 11px; font:inherit; font-size:13.5px; }
  .controls input { flex:1; min-width:160px; }
  table { width:100%; border-collapse:collapse; font-size:13.5px; }
  thead th { text-align:left; color:var(--text-muted); font-size:11.5px; text-transform:uppercase;
     letter-spacing:0.05em; font-weight:600; padding:8px 10px; border-bottom:1px solid var(--border);
     cursor:pointer; white-space:nowrap; }
  tbody tr.f { border-bottom:1px solid var(--border); cursor:pointer; }
  tbody tr.f:hover { background:var(--surface-1); }
  tbody td { padding:9px 10px; vertical-align:top; }
  .pill { display:inline-block; font-size:11px; font-weight:700; letter-spacing:0.03em;
          padding:2px 8px; border-radius:999px; color:#fff; white-space:nowrap; }
  .cat { color:var(--text-secondary); }
  .ftitle { font-weight:500; }
  .cvss { font-variant-numeric:tabular-nums; color:var(--text-secondary); }
  .muted { color:var(--text-muted); }
  .arrow { color:var(--text-muted); transition:transform .15s; display:inline-block; }
  tr.open .arrow { transform:rotate(90deg); }
  tr.detail td { padding:0 10px 14px; }
  .detail-box { background:var(--surface-1); border:1px solid var(--border);
     border-radius:8px; padding:14px 16px; }
  .detail-box p { margin:0 0 10px; }
  .detail-box .lab { font-size:11px; text-transform:uppercase; letter-spacing:0.05em;
     color:var(--text-muted); font-weight:600; margin-bottom:3px; }
  .rem { background:var(--plane); border-left:3px solid var(--series-1); border-radius:4px;
     padding:9px 12px; font:12.5px/1.55 ui-monospace,Menlo,Consolas,monospace;
     white-space:pre-wrap; color:var(--text-primary); }
  .wa { background:var(--plane); border-left:3px solid var(--good); border-radius:4px;
     padding:9px 12px; margin-top:8px; font-size:13px; }
  .cve-chip { display:inline-block; background:var(--plane); border:1px solid var(--border);
     border-radius:5px; padding:1px 7px; font-size:11.5px; margin:0 4px 4px 0;
     font-family:ui-monospace,monospace; }
  footer { margin-top:32px; padding-top:16px; border-top:1px solid var(--border);
     color:var(--text-muted); font-size:12.5px; }
  @media (max-width:640px){ th.opt,td.opt{display:none} }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>SentinelScan — Host Security Report</h1>
      <div class="sub" id="meta"></div>
    </div>
    <button class="theme" id="themeBtn">Toggle theme</button>
  </header>

  <section><div class="risk" id="risk"></div></section>

  <section>
    <h2>At a glance</h2>
    <div class="tiles" id="tiles"></div>
  </section>

  <section id="notableSec">
    <h2>Needs attention first</h2>
    <div class="notes" id="notes"></div>
  </section>

  <section>
    <h2>Breakdown</h2>
    <div class="charts" id="charts"></div>
  </section>

  <section>
    <h2>Modules run</h2>
    <div class="mods" id="mods"></div>
  </section>

  <section>
    <h2>All findings</h2>
    <div class="controls">
      <input id="q" placeholder="Search findings, components, CVEs…">
      <select id="sevFilter"><option value="">Any severity</option></select>
      <select id="catFilter"><option value="">Any category</option></select>
    </div>
    <table>
      <thead><tr>
        <th data-sort="sev">Severity</th>
        <th data-sort="category" class="opt">Category</th>
        <th data-sort="title">Finding</th>
        <th data-sort="cvss" class="opt">CVSS</th>
        <th></th>
      </tr></thead>
      <tbody id="rows"></tbody>
    </table>
    <div class="sub" id="count" style="margin-top:10px"></div>
  </section>

  <footer id="foot"></footer>
</div>

<script id="data" type="application/json">/*__SESSION_JSON__*/</script>
<script>
(function(){
  "use strict";
  const D = JSON.parse(document.getElementById("data").textContent);
  const $ = (id)=>document.getElementById(id);
  const esc = (s)=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

  const SEV = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
  const ORDER = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
  const COLOR = {CRITICAL:"var(--critical)",HIGH:"var(--serious)",MEDIUM:"var(--warning)",LOW:"var(--series-1)",INFO:"var(--text-muted)"};

  /* theme */
  try { const t=localStorage.getItem("sentinel-theme"); if(t) document.documentElement.setAttribute("data-theme",t); } catch(e){}
  $("themeBtn").addEventListener("click",()=>{
    const cur=document.documentElement.getAttribute("data-theme");
    const dark=cur?cur==="dark":matchMedia("(prefers-color-scheme: dark)").matches;
    const next=dark?"light":"dark";
    document.documentElement.setAttribute("data-theme",next);
    try{localStorage.setItem("sentinel-theme",next);}catch(e){}
  });

  /* header */
  $("meta").innerHTML =
    `<code>${esc(D.target)}</code> · mode <code>${esc(D.mode)}</code> · <code>${esc(D.scan_type)}</code> scan`+
    `<br>Run ${esc(D.scan_id)} — ${esc((D.started||"").replace("T"," ").slice(0,19))} · `+
    `${esc((D.elapsed_s||0).toFixed ? D.elapsed_s.toFixed(0) : D.elapsed_s)}s`;

  /* risk score: weighted findings / max, capped 100 */
  const c = D.severity_counts||{};
  const W = {CRITICAL:10,HIGH:7,MEDIUM:4,LOW:1,INFO:0};
  const total = D.total_findings || (D.findings||[]).length;
  const raw = SEV.reduce((a,s)=>a+(c[s]||0)*W[s],0);
  const maxRaw = total>0 ? total*10 : 1;
  const score = Math.min(100, Math.round(raw/maxRaw*100));
  const band = score>=80?"CRITICAL":score>=60?"HIGH":score>=40?"ELEVATED":score>=20?"MODERATE":"LOW";
  const bandColor = score>=80?"var(--critical)":score>=60?"var(--serious)":score>=40?"var(--warning)":"var(--good)";
  const rk = $("risk");
  rk.style.borderLeftColor = bandColor;
  rk.innerHTML =
    `<div><div class="score">${score}<span class="of"> / 100</span></div>`+
    `<div class="band" style="color:${bandColor}">${band} risk</div></div>`+
    `<div class="meter"><span style="width:${score}%;background:${bandColor}"></span></div>`;

  /* tiles */
  const tiles = [
    ["Total findings", total, null],
    ["Critical", c.CRITICAL||0, "CRITICAL"],
    ["High", c.HIGH||0, "HIGH"],
    ["Medium", c.MEDIUM||0, "MEDIUM"],
    ["Low", c.LOW||0, "LOW"],
    ["Modules run", (D.modules||[]).filter(m=>m.status==="done").length+"/"+(D.modules||[]).length, null],
  ];
  $("tiles").innerHTML = tiles.map(([k,v,s])=>{
    const style = s?`style="--sv:${COLOR[s]}"`:"";
    const cls = s?"tile sev":"tile";
    return `<div class="${cls}" ${style}><div class="v">${v==null?"—":v}</div><div class="k">${esc(k)}</div></div>`;
  }).join("");

  /* notable: all CRITICAL + HIGH */
  const top = (D.findings||[]).filter(f=>f.severity==="CRITICAL"||f.severity==="HIGH")
              .sort((a,b)=>ORDER[a.severity]-ORDER[b.severity]);
  if(!top.length){ $("notableSec").style.display="none"; }
  else {
    $("notes").innerHTML = top.map(f=>{
      const col=COLOR[f.severity];
      return `<div class="note" style="border-left-color:${col}">`+
        `<span class="ic" style="color:${col}">${esc(f.severity)}</span>`+
        `<span><b>${esc(f.title)}</b> — <span class="muted">${esc(f.affected_component)}</span></span></div>`;
    }).join("");
  }

  /* bar chart helper */
  function barChart(title,cap,rows,unit,colorFn){
    const max=Math.max(1,...rows.map(r=>r.count));
    const total=rows.reduce((a,r)=>a+r.count,0);
    const body = rows.length ? rows.map(r=>{
      const pct=(r.count/max)*100;
      const col=colorFn?colorFn(r.label):"var(--series-1)";
      const share=total?Math.round(r.count/total*100):0;
      return `<div class="row" title="${esc(r.label)}: ${r.count} ${esc(unit)}${r.count===1?"":"s"} · ${share}%">`+
        `<div class="lbl">${esc(r.label)}</div>`+
        `<div class="track"><div class="bar" style="width:${pct.toFixed(1)}%;background:${col}"></div></div>`+
        `<div class="num">${r.count}</div></div>`;
    }).join("") : `<div class="empty">Nothing found.</div>`;
    return `<div class="card"><h3>${esc(title)}</h3><div class="cap">${esc(cap)}</div><div class="bars">${body}</div></div>`;
  }

  const bySev = SEV.map(s=>({label:s,count:c[s]||0})).filter(r=>r.count>0);
  const catMap={};
  (D.findings||[]).forEach(f=>{catMap[f.category]=(catMap[f.category]||0)+1;});
  const byCat = Object.entries(catMap).map(([label,count])=>({label,count})).sort((a,b)=>b.count-a.count);

  $("charts").innerHTML =
    barChart("Findings by severity","Weighted worst-first",bySev,"finding",l=>COLOR[l]) +
    barChart("Findings by category","Which security domains flagged most",byCat,"finding",null);

  /* module health */
  $("mods").innerHTML = (D.modules||[]).map(m=>
    `<div class="mod"><div class="mn">${esc(m.display_name||m.name)}</div>`+
    `<div class="ms"><span class="dot ${esc(m.status)}"></span>${esc(m.status)} · `+
    `${m.finding_count||0} found · ${(m.elapsed_s||0).toFixed(1)}s</div></div>`
  ).join("");

  /* findings table */
  const cats=[...new Set((D.findings||[]).map(f=>f.category))].sort();
  $("catFilter").insertAdjacentHTML("beforeend", cats.map(x=>`<option>${esc(x)}</option>`).join(""));
  $("sevFilter").insertAdjacentHTML("beforeend", SEV.map(x=>`<option>${esc(x)}</option>`).join(""));

  const list0 = (D.findings||[]).map(f=>({...f,
    sev:ORDER[f.severity], cvssn:f.cvss_score==null?-1:f.cvss_score,
    hay:[f.title,f.category,f.description,f.affected_component,f.remediation,(f.cve_ids||[]).join(" ")].filter(Boolean).join(" ").toLowerCase()
  }));
  let sortKey="sev", sortDir=1;

  function detail(f){
    const cves=(f.cve_ids||[]).map(x=>`<span class="cve-chip">${esc(x)}</span>`).join("");
    return `<div class="detail-box">`+
      `<p>${esc(f.description)}</p>`+
      (f.affected_component?`<div class="lab">Affected</div><p><code>${esc(f.affected_component)}</code></p>`:"")+
      (f.remediation?`<div class="lab">Remediation</div><div class="rem">${esc(f.remediation)}</div>`:"")+
      (f.workaround?`<div class="wa"><b>Workaround:</b> ${esc(f.workaround)}</div>`:"")+
      ((f.cvss_score!=null||cves)?`<div class="lab" style="margin-top:10px">Scoring</div><p>`+
         (f.cvss_score!=null?`<span class="cvss">CVSS ${f.cvss_score.toFixed(1)}</span>&nbsp; `:"")+cves+`</p>`:"")+
      `</div>`;
  }

  function render(){
    const q=$("q").value.trim().toLowerCase(), sf=$("sevFilter").value, cf=$("catFilter").value;
    let list=list0.filter(f=>{
      if(q&&!f.hay.includes(q))return false;
      if(sf&&f.severity!==sf)return false;
      if(cf&&f.category!==cf)return false;
      return true;
    });
    list.sort((a,b)=>{
      const x=a[sortKey],y=b[sortKey];
      if(typeof x==="number"&&typeof y==="number")return (x-y)*sortDir;
      return String(x||"").localeCompare(String(y||""))*sortDir;
    });
    $("rows").innerHTML = list.length ? list.map((f,i)=>
      `<tr class="f" data-i="${i}">`+
        `<td><span class="pill" style="background:${COLOR[f.severity]}">${esc(f.severity)}</span></td>`+
        `<td class="opt cat">${esc(f.category)}</td>`+
        `<td class="ftitle">${esc(f.title)}</td>`+
        `<td class="opt cvss">${f.cvss_score==null?'<span class="muted">—</span>':f.cvss_score.toFixed(1)}</td>`+
        `<td><span class="arrow">›</span></td>`+
      `</tr>`+
      `<tr class="detail" data-d="${i}" style="display:none"><td colspan="5">${detail(f)}</td></tr>`
    ).join("") : `<tr><td colspan="5" class="muted" style="padding:20px 10px">No finding matches that filter.</td></tr>`;
    $("count").textContent = `${list.length} of ${list0.length} finding${list0.length===1?"":"s"} shown`;
    $("rows").querySelectorAll("tr.f").forEach(tr=>{
      tr.addEventListener("click",()=>{
        const d=$("rows").querySelector(`tr.detail[data-d="${tr.dataset.i}"]`);
        const open=d.style.display!=="none";
        d.style.display=open?"none":"table-row";
        tr.classList.toggle("open",!open);
      });
    });
  }
  $("q").addEventListener("input",render);
  $("sevFilter").addEventListener("change",render);
  $("catFilter").addEventListener("change",render);
  document.querySelectorAll("th[data-sort]").forEach(th=>{
    th.addEventListener("click",()=>{ const k=th.dataset.sort;
      sortDir=sortKey===k?-sortDir:1; sortKey=k; render(); });
  });
  render();

  $("foot").innerHTML = `Generated offline by SentinelScan. All checks ran on the host itself; `+
    `no data left the machine. Full raw output and PDF/JSON exports sit beside this file.`;
})();
</script>
</body>
</html>
"""


def generate_dashboard(session, output_path: str = None) -> str:
    """Render a scan session (a ScanSession or an already-built dict) to a
    single self-contained HTML dashboard string. Optionally writes to a path."""
    data = session.to_dict() if hasattr(session, "to_dict") else session
    blob = json.dumps(data, separators=(",", ":")).replace("</", "<\\/").replace("<!--", "<\\!--")
    html = TEMPLATE.replace("/*__SESSION_JSON__*/", blob)
    if output_path:
        open(output_path, "w", encoding="utf-8").write(html)
    return html
