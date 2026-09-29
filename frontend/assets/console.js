/* AI Agents console. Everything rendered from the API goes through esc()
   or textContent — span names and attributes are customer-controlled. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const state = { selectedTrace: null, selectedSpan: null, spans: [], timer: null };

  /* ---------- formatting ---------- */
  function fmtDuration(ms) {
    if (ms == null || !isFinite(ms)) return "—";
    if (ms < 1) return (ms * 1000).toFixed(0) + " µs";
    if (ms < 1000) return ms.toFixed(ms < 10 ? 1 : 0) + " ms";
    if (ms < 60000) return (ms / 1000).toFixed(ms < 10000 ? 2 : 1) + " s";
    return Math.floor(ms / 60000) + "m " + Math.round((ms % 60000) / 1000) + "s";
  }
  function fmtTime(ms) {
    const d = new Date(ms);
    const today = new Date();
    const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    return d.toDateString() === today.toDateString() ? time
      : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + time;
  }
  function spanClass(s) {
    const a = s.attributes || {};
    if (s.status_code === "error") return "k-err";
    if (a["gen_ai.tool.name"] || a["gen_ai.operation.name"] === "execute_tool") return "k-tool";
    if (a["gen_ai.request.model"] || a["gen_ai.system"] || a["gen_ai.provider.name"]) return "k-llm";
    return "k-other";
  }

  /* ---------- API ---------- */
  async function api(path) {
    const r = await fetch(path, { credentials: "same-origin" });
    const body = await r.json().catch(() => ({}));
    if (r.status === 401) { location.href = body.login || "/login.html?next=/agents/"; throw new Error("signed out"); }
    if (r.status === 402) { $("entitleBanner").hidden = false; throw new Error("not entitled"); }
    if (!r.ok) throw new Error(body.error || "HTTP " + r.status);
    return body;
  }

  /* ---------- nav: user chip + sign out (Selenne's session) ---------- */
  async function loadMe() {
    try {
      const d = await api("/agents/api/me");
      const u = d.user;
      $("navUser").textContent = u.username;
      $("navUser").hidden = false;
      $("navOut").hidden = false;
      if (!u.agents) $("entitleBanner").hidden = false;
    } catch (_) { /* api() already redirected or flagged */ }
  }
  $("navOut").addEventListener("click", async (e) => {
    e.preventDefault();
    try { await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" }); } catch (_) {}
    location.href = "/landing.html";
  });

  /* ---------- filters ---------- */
  async function loadProjects() {
    try {
      const d = await api("/agents/api/projects");
      const sel = $("fProject");
      const keep = sel.value;
      sel.innerHTML = '<option value="">All projects</option>' +
        d.projects.map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("");
      sel.value = d.projects.includes(keep) ? keep : "";
    } catch (_) {}
  }

  /* ---------- session list ---------- */
  async function loadSessions() {
    const q = new URLSearchParams({ hours: $("fHours").value, limit: "200" });
    if ($("fProject").value) q.set("project", $("fProject").value);
    let d;
    try { d = await api("/agents/api/sessions?" + q); }
    catch (e) {
      if (e.message !== "signed out" && e.message !== "not entitled")
        $("sessions").innerHTML = `<tr><td colspan="8" class="ag-muted">Could not load sessions — ${esc(e.message)}</td></tr>`;
      else if (e.message === "not entitled")
        $("sessions").innerHTML = '<tr><td colspan="8" class="ag-muted">—</td></tr>';
      return;
    }
    $("updated").textContent = "updated " + new Date().toLocaleTimeString();
    const rows = d.sessions;
    const nothingAtAll = !rows.length && !$("fProject").value && Number($("fHours").value) >= 720;
    $("emptyState").hidden = rows.length > 0;
    if (!rows.length) {
      $("sessions").innerHTML = `<tr><td colspan="8" class="ag-muted">${
        nothingAtAll ? "No sessions yet." : "No sessions in this window — try a wider one."}</td></tr>`;
      return;
    }
    $("sessions").innerHTML = rows.map((s) => `
      <tr data-trace="${esc(s.trace_id)}" class="${s.trace_id === state.selectedTrace ? "selected" : ""}">
        <td class="mono">${esc(fmtTime(s.start_ms))}</td>
        <td>${esc(s.project)}</td>
        <td>${esc(s.service_name || "—")}</td>
        <td class="name">${esc(s.root_name)}</td>
        <td class="num mono">${esc(fmtDuration(s.duration_ms))}</td>
        <td class="num mono">${s.spans}</td>
        <td class="num mono">${s.tool_calls}</td>
        <td>${s.errors ? `<span class="badge crit">${s.errors} error${s.errors > 1 ? "s" : ""}</span>`
                       : '<span class="badge low">ok</span>'}</td>
      </tr>`).join("");
  }
  $("sessions").addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-trace]");
    if (tr) openSession(tr.dataset.trace);
  });

  /* ---------- one session: waterfall + inspector ---------- */
  function orderAsTree(spans) {
    const byId = new Map(spans.map((s) => [s.span_id, s]));
    const children = new Map();
    const roots = [];
    spans.forEach((s) => {
      if (s.parent_span_id && byId.has(s.parent_span_id)) {
        if (!children.has(s.parent_span_id)) children.set(s.parent_span_id, []);
        children.get(s.parent_span_id).push(s);
      } else roots.push(s);   // true roots and orphans (parent not received)
    });
    const out = [];
    const walk = (s, depth) => {
      out.push({ span: s, depth });
      (children.get(s.span_id) || []).sort((a, b) => a.start_ms - b.start_ms)
        .forEach((c) => walk(c, depth + 1));
    };
    roots.sort((a, b) => a.start_ms - b.start_ms).forEach((r) => walk(r, 0));
    return out;
  }

  async function openSession(traceId, spanId) {
    state.selectedTrace = traceId;
    state.selectedSpan = null;
    document.querySelectorAll("#sessions tr").forEach((tr) =>
      tr.classList.toggle("selected", tr.dataset.trace === traceId));
    let d;
    try { d = await api("/agents/api/sessions/" + encodeURIComponent(traceId)); }
    catch (e) { return; }
    state.spans = d.spans;
    const start = Math.min(...d.spans.map((s) => s.start_ms));
    const end = Math.max(...d.spans.map((s) => s.end_ms ?? s.start_ms));
    const total = Math.max(end - start, 0.001);
    const tree = orderAsTree(d.spans);
    const root = tree[0].span;

    $("dProject").textContent = (root.project || "") + (root.service_name ? " · " + root.service_name : "");
    $("dTitle").textContent = root.name;
    $("dMeta").textContent = `${fmtTime(start)} · ${fmtDuration(end - start)} · ${d.spans.length} spans · trace ${traceId}`;
    $("waterfall").innerHTML = tree.map(({ span: s, depth }) => {
      const left = ((s.start_ms - start) / total) * 100;
      const width = (((s.end_ms ?? s.start_ms) - s.start_ms) / total) * 100;
      const tool = (s.attributes || {})["gen_ai.tool.name"];
      return `<div class="wf-row" data-span="${esc(s.span_id)}">
        <div class="wf-name" style="padding-left:${Math.min(depth, 12) * 14}px" title="${esc(s.name)}">
          <b>${esc(s.name)}</b>${tool && tool !== s.name ? ` <span class="ag-muted">· ${esc(tool)}</span>` : ""}</div>
        <div class="wf-track"><div class="wf-bar ${spanClass(s)}" style="left:${left.toFixed(3)}%;width:${width.toFixed(3)}%"></div></div>
        <div class="wf-dur">${esc(fmtDuration(s.end_ms == null ? null : s.end_ms - s.start_ms))}</div>
      </div>`;
    }).join("");
    $("detail").hidden = false;
    inspect(spanId && d.spans.some((s) => s.span_id === spanId) ? spanId : root.span_id);
    $("detail").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  $("waterfall").addEventListener("click", (e) => {
    const row = e.target.closest(".wf-row");
    if (row) inspect(row.dataset.span);
  });
  $("dClose").addEventListener("click", () => {
    $("detail").hidden = true;
    state.selectedTrace = null;
    document.querySelectorAll("#sessions tr.selected").forEach((tr) => tr.classList.remove("selected"));
  });

  function kvRows(obj) {
    const keys = Object.keys(obj || {}).sort();
    if (!keys.length) return '<tr><td colspan="2" class="ag-muted">none</td></tr>';
    return keys.map((k) => {
      const v = obj[k];
      const text = typeof v === "string" ? v : JSON.stringify(v, null, 2);
      return `<tr><td>${esc(k)}</td><td>${esc(text)}</td></tr>`;
    }).join("");
  }

  function inspect(spanId) {
    const s = state.spans.find((x) => x.span_id === spanId);
    if (!s) return;
    state.selectedSpan = spanId;
    document.querySelectorAll(".wf-row").forEach((r) => r.classList.toggle("selected", r.dataset.span === spanId));
    const status = s.status_code === "error"
      ? `<span class="badge crit">error</span>${s.status_message ? " " + esc(s.status_message) : ""}`
      : `<span class="badge low">${esc(s.status_code)}</span>`;
    $("inspector").innerHTML = `
      <span class="eyebrow">${esc(s.kind)} span</span>
      <h4 style="margin-top:10px">${esc(s.name)}</h4>
      <div>${status}</div>
      <table class="ag-kv">
        <tr><td>duration</td><td>${esc(fmtDuration(s.end_ms == null ? null : s.end_ms - s.start_ms))}</td></tr>
        <tr><td>started</td><td>${esc(new Date(s.start_ms).toISOString())}</td></tr>
        <tr><td>span id</td><td>${esc(s.span_id)}</td></tr>
        <tr><td>parent</td><td>${esc(s.parent_span_id || "— (root)")}</td></tr>
        <tr><td>received via</td><td>${esc(s.source)}${s.scope_name && s.scope_name !== s.source ? " · " + esc(s.scope_name) : ""}</td></tr>
      </table>
      <div class="ag-sub">ATTRIBUTES</div>
      <table class="ag-kv">${kvRows(s.attributes)}</table>
      ${(s.events || []).length ? `<div class="ag-sub">EVENTS</div><table class="ag-kv">${
        s.events.map((ev) => `<tr><td>${esc(ev.name)}</td><td>${esc(JSON.stringify(ev.attributes || {}, null, 2))}</td></tr>`).join("")
      }</table>` : ""}
      <div class="ag-sub">RESOURCE</div>
      <table class="ag-kv">${kvRows(s.resource)}</table>`;
  }

  /* ---------- boot ---------- */
  function refreshAll() { loadProjects(); loadSessions(); }
  $("fProject").addEventListener("change", loadSessions);
  $("fHours").addEventListener("change", loadSessions);
  $("refresh").addEventListener("click", refreshAll);

  loadMe();
  refreshAll();
  // Deep link from an alert card: /agents/?trace=<id>&span=<id>
  const deep = new URLSearchParams(location.search);
  if (/^[0-9a-f]{32}$/.test(deep.get("trace") || "")) openSession(deep.get("trace"), deep.get("span"));
  // Near-live without a socket: poll the list while the tab is visible.
  state.timer = setInterval(() => { if (!document.hidden) loadSessions(); }, 15000);
})();
