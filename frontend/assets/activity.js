/* Activity page: what the sensor saw agents do on their hosts. Everything
   from the API goes through esc() — paths and command lines are the
   customer's data. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const COLS = 6;
  const PAGE = 200;

  const state = { events: [], selected: null, scope: "", more: false, timer: null, open: new Set() };

  /* ---------- formatting ---------- */
  function fmtTime(ms) {
    const d = new Date(ms);
    const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    return d.toDateString() === new Date().toDateString() ? time
      : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + time;
  }
  function fmtAge(s) {
    if (s < 90) return s + "s ago";
    if (s < 5400) return Math.round(s / 60) + " min ago";
    return Math.round(s / 3600) + " h ago";
  }
  function fmtDuration(ms) {
    if (ms == null) return "";
    if (ms < 1000) return ms + " ms";
    if (ms < 60000) return (ms / 1000).toFixed(1) + " s";
    return Math.floor(ms / 60000) + "m " + Math.round((ms % 60000) / 1000) + "s";
  }
  const base = (p) => String(p || "").split("/").pop();
  const KIND = { exec: "program", exit: "exit", open: "file", connect: "connect", listen: "listen" };
  const scoreCls = (label) => label === "CRITICAL" || label === "HIGH" ? "crit"
    : label === "POSSIBLE" ? "high" : label === "BENIGN" ? "info" : "low";

  function what(e) {
    switch (e.kind) {
      case "exec":
        return `<span class="mono">${esc((e.argv || [e.exe]).join(" "))}</span>` +
          (e.agent_root ? ' <span class="badge info" title="The agent itself, not something it started">agent</span>' : "");
      case "exit":
        return `exit ${esc(e.status ?? "?")}${e.signal ? " · " + esc(e.signal) : ""}` +
          (e.duration_ms != null ? ` <span class="ag-muted">after ${esc(fmtDuration(e.duration_ms))}</span>` : "");
      case "open":
        return `<span class="mono">${esc(e.path)}</span>`;
      case "connect":
        return `${e.dest_service ? `<b>${esc(e.dest_service)}</b> ` : ""}<span class="mono">${esc(e.daddr)}:${esc(e.dport)}</span>` +
          (e.scope ? ` <span class="ac-scope ac-${esc(e.scope)}">${esc(e.scope)}</span>` : "");
      case "listen":
        return `listening on <span class="mono">${esc(e.saddr)}:${esc(e.sport)}</span>` +
          (e.dest_service ? ` <span class="ag-muted">${esc(e.dest_service)}</span>` : "");
    }
    return `<span class="ag-muted">${esc(e.kind)}</span>`;
  }

  /* ---------- API ---------- */
  async function api(path) {
    const r = await fetch(path, { credentials: "same-origin" });
    const body = await r.json().catch(() => ({}));
    if (r.status === 401) { location.href = body.login || "/login.html?next=/agents/activity"; throw new Error("signed out"); }
    if (r.status === 402) { $("entitleBanner").hidden = false; throw new Error("not entitled"); }
    if (!r.ok) throw new Error(body.error || "HTTP " + r.status);
    return body;
  }

  async function loadMe() {
    try {
      const u = (await api("/agents/api/me")).user;
      $("navUser").textContent = u.username;
      $("navUser").hidden = $("navOut").hidden = false;
      if (!u.agents) $("entitleBanner").hidden = false;
    } catch (_) {}
  }
  $("navOut").addEventListener("click", async (e) => {
    e.preventDefault();
    try { await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" }); } catch (_) {}
    location.href = "/landing.html";
  });

  /* ---------- filters ---------- */
  function query(extra) {
    const q = new URLSearchParams({ hours: $("fHours").value, limit: String(PAGE) });
    if ($("fAgent").value) q.set("agent", $("fAgent").value);
    if ($("fHost").value) q.set("host", $("fHost").value);
    if ($("fKind").value) q.set("kind", $("fKind").value);
    if (state.scope) q.set("scope", state.scope);
    if ($("fAlerts").checked) q.set("alerts", "1");
    Object.entries(extra || {}).forEach(([k, v]) => q.set(k, v));
    return q;
  }
  function fillSelect(sel, counts, allLabel) {
    const keep = sel.value;
    const names = Object.keys(counts).sort();
    sel.innerHTML = `<option value="">${esc(allLabel)}</option>` +
      names.map((n) => `<option value="${esc(n)}">${esc(n)} (${counts[n]})</option>`).join("");
    sel.value = names.includes(keep) ? keep : "";
  }

  async function loadFacets() {
    let d;
    try { d = await api("/agents/api/activity/facets?hours=" + encodeURIComponent($("fHours").value)); }
    catch (_) { return; }
    const f = d.facets;
    fillSelect($("fAgent"), f.agent, "All agents");
    fillSelect($("fHost"), f.host, "All hosts");
    const k = f.kind;
    $("tAll").textContent = Object.values(k).reduce((a, b) => a + b, 0);
    $("tExec").textContent = k.exec || 0;
    $("tOpen").textContent = k.open || 0;
    $("tConnect").textContent = k.connect || 0;
    $("tAlerts").textContent = (f.alerts || {}).events || 0;
    $("tScopes").textContent = ["local", "private", "public"]
      .map((s) => `${f.scope[s] || 0} ${s}`).join(" · ");
    renderSensors(d.sensors);
  }

  function renderSensors(sensors) {
    if (!sensors.length) { $("sensors").innerHTML = ""; return; }
    $("sensors").innerHTML = sensors.map((s) => {
      const stale = s.age_s > 120;
      const agents = Object.entries(s.stats.agents || {}).map(([n, c]) => `${esc(n)} ×${c}`).join(", ");
      const spool = s.stats.spool_batches ? ` · <span class="ac-warn">${s.stats.spool_batches} batches waiting to send</span>` : "";
      return `<span class="ac-sensor ${stale ? "stale" : ""}" title="selenne-sensor ${esc(s.version || "")} on ${esc(s.host)}">
        <i></i><b>${esc(s.host)}</b> · sensor ${stale ? "not seen for " + esc(fmtAge(s.age_s).replace(" ago", "")) : "seen " + esc(fmtAge(s.age_s))}
        · ${agents ? "watching " + agents : "no agent running"}${spool}</span>`;
    }).join("");
  }

  /* ---------- the list ---------- */
  async function loadActivity(older) {
    const extra = older && state.events.length ? { before_ms: state.events[state.events.length - 1].ts_ms } : null;
    let d;
    try { d = await api("/agents/api/activity?" + query(extra)); }
    catch (e) {
      if (e.message !== "signed out")
        $("activity").innerHTML = `<tr><td colspan="${COLS}" class="ag-muted">${
          e.message === "not entitled" ? "—" : "Could not load activity — " + esc(e.message)}</td></tr>`;
      return;
    }
    state.events = older ? state.events.concat(d.events) : d.events;
    state.more = d.more;
    $("updated").textContent = "updated " + new Date().toLocaleTimeString();
    render();
  }

  function render() {
    const rows = state.events;
    $("more").hidden = !state.more;
    const filtered = $("fAgent").value || $("fHost").value || $("fKind").value || state.scope || $("fAlerts").checked;
    $("emptyState").hidden = rows.length > 0 || filtered;
    if (!rows.length) {
      $("activity").innerHTML = `<tr><td colspan="${COLS}" class="ag-muted">${
        filtered ? "Nothing matches these filters in this window." : "No sensor activity in this window."}</td></tr>`;
      return;
    }
    $("activity").innerHTML = groups(rows).map((g) => g.length < GROUP_MIN
      ? g.map((e) => row(e)).join("")
      : groupRow(g) + (state.open.has(g[0].id) ? g.map((e) => row(e, true)).join("") : "")).join("");
  }

  function row(e, inGroup) {
    return `
      <tr data-id="${e.id}" class="${e.id === state.selected ? "selected" : ""}${e.alerts.length ? " ac-flagged" : ""}${inGroup ? " ac-in-group" : ""}">
        <td class="mono ac-time">${esc(fmtTime(e.ts_ms))}</td>
        <td>${esc(e.agent || "—")} <span class="ag-muted">${esc(e.host)}</span></td>
        <td><span class="ac-kind ac-k-${esc(e.kind)}">${esc(KIND[e.kind] || e.kind)}</span></td>
        <td class="mono ac-proc">${esc(base(e.exe) || "?")} <span class="ag-muted">${esc(e.pid)}</span></td>
        <td class="ac-what">${what(e)}</td>
        <td>${e.alerts.map((a) =>
          `<a class="badge ${scoreCls(a.label)}" href="/agents/deviations" title="${esc(a.title)} · ${esc(a.label)}">${esc(a.rule_id)} · ${a.score}</a>`).join(" ")}</td>
      </tr>`;
  }

  // A process reading a whole folder (the CVE agent scans ~160 Wazuh rule
  // files) would bury everything else: consecutive opens by one process in
  // one folder fold into a single row. Anything with an alert never folds.
  const GROUP_MIN = 4;
  const dir = (p) => String(p || "").replace(/\/[^/]*$/, "/");
  function groups(rows) {
    const out = [];
    for (const e of rows) {
      const g = out[out.length - 1];
      const prev = g && g[g.length - 1];
      if (prev && e.kind === "open" && prev.kind === "open" && !e.alerts.length && !prev.alerts.length &&
          e.pid === prev.pid && e.host === prev.host && dir(e.path) === dir(prev.path)) g.push(e);
      else out.push([e]);
    }
    return out;
  }
  function groupRow(g) {
    const first = g[0], last = g[g.length - 1], open = state.open.has(first.id);
    return `
      <tr data-group="${first.id}" class="ac-group">
        <td class="mono ac-time">${esc(fmtTime(first.ts_ms))}</td>
        <td>${esc(first.agent || "—")} <span class="ag-muted">${esc(first.host)}</span></td>
        <td><span class="ac-kind ac-k-open">files</span></td>
        <td class="mono ac-proc">${esc(base(first.exe) || "?")} <span class="ag-muted">${esc(first.pid)}</span></td>
        <td class="ac-what">${open ? "▾" : "▸"} <b>${g.length} files</b> in <span class="mono">${esc(dir(first.path))}</span>
          <span class="ag-muted">over ${esc(fmtDuration(Math.round(first.ts_ms - last.ts_ms)) || "0 ms")}</span></td>
        <td></td>
      </tr>`;
  }

  $("activity").addEventListener("click", (ev) => {
    if (ev.target.closest("a")) return;
    const grp = ev.target.closest("tr[data-group]");
    if (grp) {
      const id = Number(grp.dataset.group);
      state.open.has(id) ? state.open.delete(id) : state.open.add(id);
      render();
      return;
    }
    const tr = ev.target.closest("tr[data-id]");
    if (tr) inspect(Number(tr.dataset.id));
  });

  function kvRows(obj) {
    const keys = Object.keys(obj || {}).sort();
    return keys.map((k) => {
      const v = obj[k];
      return `<tr><td>${esc(k)}</td><td>${esc(typeof v === "string" ? v : JSON.stringify(v, null, 2))}</td></tr>`;
    }).join("");
  }

  function inspect(id) {
    const e = state.events.find((x) => x.id === id);
    if (!e) return;
    state.selected = id;
    document.querySelectorAll("#activity tr").forEach((tr) => tr.classList.toggle("selected", Number(tr.dataset.id) === id));
    const shown = Object.assign({}, e.detail);
    ["kind", "host", "pid", "ppid", "ts_unix_nano"].forEach((k) => delete shown[k]);
    $("inspector").innerHTML = `
      <div class="ag-trace-head">
        <span class="eyebrow">${esc(KIND[e.kind] || e.kind)} · ${esc(e.agent || "")}</span>
        <button class="btn btn-ghost ag-refresh" id="iClose" type="button">✕</button>
      </div>
      <h4 style="margin-top:12px">${what(e)}</h4>
      ${e.alerts.map((a) => `<div style="margin-top:8px"><span class="badge ${scoreCls(a.label)}">${esc(a.rule_id)} · ${a.score} · ${esc(a.label)}</span> ${esc(a.title)}</div>`).join("")}
      <table class="ag-kv">
        <tr><td>time</td><td>${esc(new Date(e.ts_ms).toISOString())}</td></tr>
        <tr><td>host</td><td>${esc(e.host)}</td></tr>
        <tr><td>process</td><td>${esc(e.exe || "?")} (pid ${esc(e.pid)}${e.ppid ? ", parent " + esc(e.ppid) : ""})</td></tr>
        ${e.container_id ? `<tr><td>container</td><td>${esc(e.container_id)}</td></tr>` : ""}
        <tr><td>project</td><td>${esc(e.project)}</td></tr>
      </table>
      <div class="ag-sub">EVERYTHING THE SENSOR SENT</div>
      <table class="ag-kv">${kvRows(shown)}</table>`;
    $("inspector").hidden = false;
    $("iClose").addEventListener("click", () => {
      $("inspector").hidden = true;
      state.selected = null;
      document.querySelectorAll("#activity tr.selected").forEach((tr) => tr.classList.remove("selected"));
    });
  }

  /* ---------- wiring ---------- */
  function reload() { loadActivity(false); }
  ["fAgent", "fHost", "fKind", "fAlerts"].forEach((id) => $(id).addEventListener("change", reload));
  $("fHours").addEventListener("change", () => { loadFacets(); reload(); });
  $("fScope").addEventListener("click", (ev) => {
    const b = ev.target.closest("button[data-scope]");
    if (!b) return;
    state.scope = b.dataset.scope;
    document.querySelectorAll("#fScope button").forEach((x) => x.classList.toggle("on", x === b));
    if (state.scope && $("fKind").value !== "connect") $("fKind").value = "connect";
    reload();
  });
  document.querySelectorAll(".ac-tile").forEach((t) => t.addEventListener("click", () => {
    if (t.dataset.alerts) { $("fAlerts").checked = !$("fAlerts").checked; }
    else { $("fKind").value = t.dataset.kind; }
    reload();
  }));
  $("more").addEventListener("click", () => loadActivity(true));
  $("refresh").addEventListener("click", () => { loadFacets(); reload(); });

  // deep links (a host deviation's "Activity" button): ?agent=&kind=&alerts=1
  const deep = new URLSearchParams(location.search);
  if (deep.get("kind")) $("fKind").value = deep.get("kind");
  if (deep.get("alerts") === "1") $("fAlerts").checked = true;
  if (deep.get("agent")) {   // the menu fills in later; keep the choice until it does
    const o = document.createElement("option");
    o.value = o.textContent = deep.get("agent");
    $("fAgent").appendChild(o);
    $("fAgent").value = deep.get("agent");
  }

  loadMe();
  loadFacets();
  reload();
  // near-live: refresh the newest page while the tab is visible and not paged back
  state.timer = setInterval(() => {
    if (document.hidden || state.events.length > PAGE) return;
    loadFacets();
    reload();
  }, 15000);
})();
