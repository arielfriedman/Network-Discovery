// Shared by every panel page: top navigation, theme toggle, database status pill.
(function () {
  const here = location.pathname === "/index.html" ? "/" : location.pathname;
  const tabs = [["/", "Scan"], ["/history", "History"], ["/devices", "Devices"]];
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

  window.esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  window.fmtTime = s => s ? new Date(s).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";

  fetch("/api/db/status").then(r => r.json()).then(st => {
    const p = document.getElementById("dbPill");
    p.classList.add(st.ok ? "ok" : "bad");
    p.lastChild.textContent = st.ok ? "Database connected" : "No database";
    p.title = st.ok ? "PostgreSQL: scans and activity are being saved" : "PostgreSQL: " + st.error;
    window.DB_OK = st.ok; window.DB_ERROR = st.error;
    document.dispatchEvent(new CustomEvent("dbstatus", { detail: st }));
  }).catch(() => {});
})();
