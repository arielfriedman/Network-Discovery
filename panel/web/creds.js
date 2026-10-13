// Credential cards for the Scan page (docs/SCAN_BUILDER.md, step 2).
// Secrets live only in this page's memory until the scan starts, then go to
// the panel in the start request and are wiped from the page.
(function () {
  const TYPES = {
    ssh:   { label: "SSH", hosts: true, fields: [
      ["user", "User", "text", "root"],
      ["auth", "Sign in with", "select", [["password", "Password"], ["key", "Private key (paste)"], ["key_path", "Key file on this machine"]]],
      ["password", "Password", "password", "", f => f.auth === "password"],
      ["key", "Private key", "textarea", "-----BEGIN OPENSSH PRIVATE KEY-----", f => f.auth === "key"],
      ["key_path", "Key file path", "text", "~/.ssh/id_ed25519", f => f.auth === "key_path"],
      ["port", "Port", "text", "22"]] },
    snmp:  { label: "SNMP", hosts: true, fields: [
      ["version", "Version", "select", [["2c", "v2c"], ["3", "v3"]]],
      ["community", "Community", "password", "", f => f.version === "2c"],
      ["user", "User", "text", "", f => f.version === "3"],
      ["level", "Security", "select", [["authPriv", "auth + privacy"], ["authNoPriv", "auth only"], ["noAuthNoPriv", "none"]], f => f.version === "3"],
      ["auth_proto", "Auth protocol", "select", [["SHA", "SHA"], ["SHA-256", "SHA-256"], ["SHA-512", "SHA-512"], ["MD5", "MD5"]], f => f.version === "3" && f.level !== "noAuthNoPriv"],
      ["auth_pass", "Auth password", "password", "8+ characters", f => f.version === "3" && f.level !== "noAuthNoPriv"],
      ["priv_proto", "Privacy protocol", "select", [["AES", "AES"], ["AES-256", "AES-256"], ["DES", "DES"]], f => f.version === "3" && f.level === "authPriv"],
      ["priv_pass", "Privacy password", "password", "8+ characters", f => f.version === "3" && f.level === "authPriv"],
      ["port", "Port", "text", "161"]] },
    aws:   { label: "AWS", fields: [
      ["access_key_id", "Access key ID", "text", "AKIA…"], ["secret_access_key", "Secret access key", "password", ""],
      ["session_token", "Session token (optional)", "password", ""], ["region", "Region", "text", "us-east-1"]],
      hint: "IAM user with the ReadOnlyAccess policy." },
    azure: { label: "Azure", fields: [
      ["tenant_id", "Tenant ID", "text", ""], ["client_id", "Client (app) ID", "text", ""],
      ["client_secret", "Client secret", "password", ""], ["subscription", "Subscription (optional)", "text", ""]],
      hint: "Service principal with the Reader role." },
    gcp:   { label: "Google Cloud", fields: [
      ["key_json", "Service account key (JSON)", "textarea", "{ \"type\": \"service_account\", … }"], ["project", "Project (optional)", "text", ""]],
      file: "key_json", hint: "Service account with roles/viewer." },
    k8s:   { label: "Kubernetes", fields: [
      ["kubeconfig", "kubeconfig", "textarea", "apiVersion: v1\nkind: Config\n…"], ["context", "Context (optional)", "text", ""]],
      file: "kubeconfig", hint: "A ServiceAccount bound to the read-only ClusterRole view." },
  };
  const DEFAULTS = { auth: "password", version: "2c", level: "authPriv", auth_proto: "SHA", priv_proto: "AES" };
  const S = { cards: [], saved: [], use: new Set(), pass: "", next: 1 };
  let box = null, types = [], onChange = () => {};

  // which fields show depends on choices like "Sign in with"; untouched
  // selects still count with their default value
  function visible(def, f) { return !def[4] || def[4]({ ...DEFAULTS, ...f }); }

  function cardHTML(c, i) {
    const t = TYPES[c.type];
    const fields = t.fields.filter(d => visible(d, c.fields)).map(d => {
      const [k, label, kind, ph] = d, v = c.fields[k] ?? DEFAULTS[k] ?? "";
      let input;
      if (kind === "select") input = `<select data-c="${i}" data-f="${k}">` + ph.map(([o, l]) => `<option value="${o}" ${o === v ? "selected" : ""}>${l}</option>`).join("") + `</select>`;
      else if (kind === "textarea") input = `<textarea data-c="${i}" data-f="${k}" rows="4" spellcheck="false" autocomplete="off" placeholder="${esc(ph)}">${esc(v)}</textarea>`;
      else input = `<input data-c="${i}" data-f="${k}" type="${kind}" autocomplete="${kind === "password" ? "new-password" : "off"}" spellcheck="false" placeholder="${esc(ph)}" value="${esc(v)}">`;
      return `<label class="cf ${kind === "textarea" ? "wide" : ""}"><span>${label}</span>${input}</label>`;
    }).join("");
    return `<div class="ccard">
      <div class="ccard-h"><b>${t.label}</b>
        <input class="cname" data-c="${i}" data-f="_name" placeholder="Name, e.g. ${t.hosts ? "core switches" : "production"}" value="${esc(c.name)}">
        <button class="x" data-rm="${i}" title="Remove">×</button></div>
      ${t.hosts ? `<label class="cf wide"><span>For hosts (IPs or ranges, blank = any host that offers ${t.label})</span>
        <input data-c="${i}" data-f="_hosts" placeholder="172.16.0.30, 172.16.4.0/24" value="${esc(c.hosts)}"></label>` : ""}
      ${t.hint ? `<div class="muted chint">${t.hint} Leave this card out to use the CLI's own sign-in on this machine.</div>` : ""}
      <div class="cfields">${fields}</div>
      ${t.file ? `<label class="filebtn">Load file…<input type="file" data-load="${i}"></label>` : ""}
      <label class="chk"><input type="checkbox" data-c="${i}" data-f="_save" ${c.save ? "checked" : ""}> Remember in vault</label>
    </div>`;
  }

  function render() {
    if (!box) return;
    const savedHere = S.saved.filter(s => types.includes(s.type));
    const needPass = S.cards.some(c => c.save) || S.use.size;
    box.innerHTML = `
      <div class="cards">${S.cards.map(cardHTML).join("")}</div>
      <div class="cadd"><select id="credType">${types.map(t => `<option value="${t}">${TYPES[t].label}</option>`).join("")}</select>
        <button class="btn ghost" id="credAdd" type="button">Add credential</button></div>
      ${savedHere.length ? `<div class="csaved"><div class="muted">Saved in the vault:</div>` + savedHere.map(s => `
        <label class="chk"><input type="checkbox" data-use="${esc(s.vault_key)}" ${S.use.has(s.vault_key) ? "checked" : ""}>
          ${esc(s.name)} <span class="muted">${TYPES[s.type] ? TYPES[s.type].label : s.type}${s.hosts && s.hosts.length ? " · " + esc(s.hosts.join(", ")) : ""}${s.last_result ? " · last: " + esc(s.last_result) : ""}</span>
          <button class="linkbtn" data-forget="${esc(s.vault_key)}" type="button">forget</button></label>`).join("") + `</div>` : ""}
      ${needPass || savedHere.length ? `<label class="cf"><span>Vault passphrase ${needPass ? "(needed)" : "(to use or forget saved credentials)"}</span>
        <input id="vaultPass" type="password" autocomplete="new-password" value="${esc(S.pass)}"></label>` : ""}
      <div class="muted chint">Passwords are used for this scan only and never written to disk, unless you tick
        <i>Remember in vault</i> (GPG-encrypted). The database keeps only names and results.</div>`;
    box.querySelector("#credAdd").onclick = () => {
      const t = box.querySelector("#credType").value;
      S.cards.push({ type: t, name: "", hosts: "", fields: {}, save: false, id: S.next++ }); render(); onChange();
    };
    box.querySelectorAll("[data-rm]").forEach(b => b.onclick = () => { S.cards.splice(+b.dataset.rm, 1); render(); onChange(); });
    box.querySelectorAll("[data-c]").forEach(el => {
      const ev = el.tagName === "SELECT" || el.type === "checkbox" ? "change" : "input";
      el.addEventListener(ev, () => {
        const c = S.cards[+el.dataset.c], f = el.dataset.f;
        if (f === "_name") c.name = el.value;
        else if (f === "_hosts") c.hosts = el.value;
        else if (f === "_save") { c.save = el.checked; render(); }
        else { c.fields[f] = el.value; if (el.tagName === "SELECT") render(); }
        onChange();
      });
    });
    box.querySelectorAll("[data-load]").forEach(el => el.onchange = async () => {
      const f = el.files[0]; if (!f) return;
      if (f.size > 64 * 1024) { alert("That file is larger than 64 KB."); return; }
      const c = S.cards[+el.dataset.load]; c.fields[TYPES[c.type].file] = await f.text(); render(); onChange();
    });
    box.querySelectorAll("[data-use]").forEach(el => el.onchange = () => {
      el.checked ? S.use.add(el.dataset.use) : S.use.delete(el.dataset.use); render(); onChange();
    });
    box.querySelectorAll("[data-forget]").forEach(b => b.onclick = async ev => {
      ev.preventDefault();
      if (!S.pass) { alert("Type the vault passphrase first."); return; }
      if (!confirm("Remove this credential from the vault?")) return;
      try { await api("/api/credentials/forget", { vault_key: b.dataset.forget, passphrase: S.pass }); }
      catch (e) { alert("Could not remove it: " + e.message); return; }
      S.use.delete(b.dataset.forget); await load();
    });
    const vp = box.querySelector("#vaultPass");
    if (vp) vp.oninput = () => { S.pass = vp.value; onChange(); };
  }

  async function load() {
    try { S.saved = (await (await fetch("/api/credentials")).json()).credentials || []; } catch (e) { S.saved = []; }
    render();
  }

  window.Creds = {
    TYPES,
    mount(el, allowed, cb) { box = el; types = allowed; onChange = cb || (() => {}); render(); if (!S.loaded) { S.loaded = true; load(); } },
    unmount() { box = null; },
    count(allowed) { return S.cards.filter(c => allowed.includes(c.type)).length + [...S.use].length; },
    problems(allowed) {
      const p = [];
      S.cards.filter(c => allowed.includes(c.type)).forEach(c => {
        const t = TYPES[c.type], f = c.fields, n = c.name || t.label;
        if (c.type === "ssh") {
          const a = f.auth || "password";
          if (!f.user) p.push(`${n}: user is missing`);
          if (!f[a]) p.push(`${n}: ${a === "password" ? "password" : a === "key" ? "private key" : "key file path"} is missing`);
        } else if (c.type === "snmp") {
          const g = { ...DEFAULTS, ...f };
          if (g.version === "2c" ? !g.community : !g.user) p.push(`${n}: ${g.version === "2c" ? "community" : "user"} is missing`);
          if (g.version === "3" && g.level !== "noAuthNoPriv" && (g.auth_pass || "").length < 8) p.push(`${n}: auth password needs 8+ characters`);
          if (g.version === "3" && g.level === "authPriv" && (g.priv_pass || "").length < 8) p.push(`${n}: privacy password needs 8+ characters`);
        } else {
          t.fields.filter(d => !/optional/.test(d[1]) && !f[d[0]] && d[0] !== "region").forEach(d => p.push(`${n}: ${d[1]} is missing`));
        }
      });
      if ((S.cards.some(c => allowed.includes(c.type) && c.save) || S.use.size) && !S.pass) p.push("the vault passphrase is needed");
      return p;
    },
    payload(allowed) {
      const sets = S.cards.filter(c => allowed.includes(c.type)).map(c => {
        const f = {};
        TYPES[c.type].fields.forEach(d => {
          const v = c.fields[d[0]] ?? DEFAULTS[d[0]];
          if (d[0] !== "auth" && visible(d, c.fields) && v) f[d[0]] = v;   // only what the card shows
        });
        return { type: c.type, name: c.name, hosts: c.hosts.split(/[\s,]+/).filter(Boolean), fields: f, save: c.save };
      });
      const use = [...S.use].filter(k => S.saved.some(s => s.vault_key === k && allowed.includes(s.type)));
      if (!sets.length && !use.length) return null;
      return { sets, vault: { passphrase: S.pass, use } };
    },
    // after a scan starts: forget every secret this page held
    wipe() {
      S.cards.forEach(c => Object.keys(c.fields).forEach(k => { if (!["user", "auth", "version", "level", "auth_proto", "priv_proto", "port", "region", "tenant_id", "client_id", "subscription", "project", "context", "access_key_id"].includes(k)) c.fields[k] = ""; }));
      S.cards = S.cards.filter(c => !c.save);
      S.pass = ""; render();
      load();
    },
  };
})();
