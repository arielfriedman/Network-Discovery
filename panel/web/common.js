// Shared by every panel page: top navigation, theme toggle, database status pill.
(function () {
  const here = location.pathname === "/index.html" ? "/" : location.pathname;
  const tabs = [["/", "Scan"], ["/history", "History"], ["/devices", "Devices"], ["/actions", "Actions"]];
  const nav = document.createElement("nav");
  nav.className = "top";
  nav.innerHTML = '<span class="brand">SentinelScan</span>' +
    tabs.map(([href, label]) => `<a class="tab${href === here ? " on" : ""}" href="${href}">${label}</a>`).join("") +
    '<span class="spacer"></span><span class="pill" id="dbPill" title="Database"><span class="dot"></span>Database…</span>' +
    '<button class="theme" id="themeBtn">Toggle theme</button>';
  const wrap = document.querySelector(".wrap") || document.body;
  wrap.insertBefore(nav, wrap.firstChild);

  try { const t = localStorage.getItem("sentinel-theme"); if (t) document.documentElement.setAttribute("data-theme", t); } catch (e) {}
  document.getElementById("themeBtn").onclick = () => {
    const c = document.documentElement.getAttribute("data-theme");
    const dark = c ? c === "dark" : matchMedia("(prefers-color-scheme:dark)").matches;
    const n = dark ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", n);
    try { localStorage.setItem("sentinel-theme", n); } catch (e) {}
  };

  // Every request that changes something carries the panel's per-launch token.
  const TOKEN = (document.querySelector('meta[name="sentinel-token"]') || {}).content || "";
  window.api = async (path, body, method) => {
    const opt = { method: method || (body === undefined ? "GET" : "POST"), headers: {} };
    if (opt.method !== "GET") {
      opt.headers["X-Sentinel-Token"] = TOKEN;
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(body || {});
    }
    const r = await fetch(path, opt);
    let j = {};
    try { j = await r.json(); } catch (e) {}
    if (!r.ok) { const err = new Error(j.error || `HTTP ${r.status}`); err.status = r.status; err.data = j; throw err; }
    return j;
  };

  window.esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  window.fmtTime = s => s ? new Date(s).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";

  // Network drawing of a finished network scan (panel/diagrams.py): preview, .drawio,
  // PNG, PDF (with the draw.io desktop app) and "open in diagrams.net".
  window.openDiagram = async (ref) => {
    const r = encodeURIComponent(ref), base = `/api/diagram/${r}`;
    let cli = false;
    try { cli = (await api("/api/diagram/tools")).drawio_cli; } catch (e) {}
    const m = document.createElement("div");
    m.className = "modal";
    m.innerHTML = `<div class="modal-box" style="width:min(1200px,100%);max-height:92vh;display:flex;flex-direction:column;gap:10px">
      <h2>Network drawing</h2>
      <div style="overflow:auto;border:1px solid var(--border);border-radius:8px;background:#fff;min-height:200px;flex:1">
        <img id="dgImg" alt="Network drawing" src="${base}/svg" style="display:block;max-width:none"></div>
      <div class="row" style="flex-wrap:wrap;gap:8px">
        <a class="btn" href="${base}/drawio" download>Download for draw.io (.drawio)</a>
        <button class="btn ghost" id="dgPng">PNG image</button>
        ${cli ? `<a class="btn ghost" href="${base}/pdf" download>PDF</a>` : ""}
        <button class="btn ghost" id="dgNet">Open in diagrams.net</button>
        <span class="spacer" style="flex:1"></span>
        <button class="btn ghost" id="dgClose">Close</button></div>
      <div class="muted" id="dgMsg" style="font-size:12.5px">The .drawio file opens in the free draw.io desktop app
        (github.com/jgraph/drawio-desktop) or on diagrams.net, where every box can be moved and edited.
        Hover a box in draw.io for its ports and apps. "Open in diagrams.net" opens their website with the
        drawing inside the link (after the #), so it is not uploaded.
        ${cli ? "" : "PDF needs the draw.io desktop app on this machine; the PNG is made in your browser."}</div></div>`;
    document.body.appendChild(m);
    const close = () => m.remove();
    m.addEventListener("click", e => { if (e.target === m) close(); });
    m.querySelector("#dgClose").onclick = close;
    const msg = t => { m.querySelector("#dgMsg").textContent = t; };
    m.querySelector("#dgNet").onclick = async () => {
      try { const j = await api(`${base}/link`); window.open(j.url, "_blank", "noopener"); }
      catch (e) { msg("Could not make the link: " + e.message); }
    };
    m.querySelector("#dgPng").onclick = async () => {
      if (cli) { location.href = `${base}/png`; return; }
      const img = m.querySelector("#dgImg");
      const c = document.createElement("canvas");
      c.width = img.naturalWidth * 2; c.height = img.naturalHeight * 2;
      const g = c.getContext("2d"); g.scale(2, 2); g.drawImage(img, 0, 0);
      c.toBlob(b => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(b); a.download = `sentinelscan-${ref}.png`; a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      }, "image/png");
    };
  };

  fetch("/api/db/status").then(r => r.json()).then(st => {
    const p = document.getElementById("dbPill");
    p.classList.add(st.ok ? "ok" : "bad");
    p.lastChild.textContent = st.ok ? "Database connected" : "No database";
    p.title = st.ok ? "PostgreSQL: scans and activity are being saved" : "PostgreSQL: " + st.error;
    window.DB_OK = st.ok; window.DB_ERROR = st.error;
    document.dispatchEvent(new CustomEvent("dbstatus", { detail: st }));
  }).catch(() => {});
})();
