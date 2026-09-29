/* Agent logs: delivery history (one row per accepted ingest request) and
   the raw feed of spans + sensor events, newest first. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const { api, esc, fmtTime } = window.SA;               // common.js
  const SOURCE = { "otlp-http": "OTLP/HTTP", "otlp-grpc": "OTLP/gRPC", native: "JSON", "host-events": "SENSOR", sensor: "SENSOR" };
  let data = { batches: [], events: [] }, paused = false;
  const filters = { search: "", type: "all", project: "all" };

  async function load() {
    if (paused) return;
    const pill = document.querySelector(".status-pill");
    try {
      data = await api("/agents/api/logs?limit=300");
      const sel = $("fProject"), cur = sel.value;
      const projects = [...new Set(data.batches.map((b) => b.project).concat(data.events.map((e) => e.project)))].sort();
      sel.innerHTML = '<option value="all">all projects</option>' + projects.map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("");
      if (projects.includes(cur)) sel.value = cur;
      render();
      if (pill) pill.innerHTML = '<span class="dot"></span>STREAMING · ' + new Date().toLocaleTimeString();
    } catch (e) {
      if (pill) pill.innerHTML = '<span class="dot" style="background:var(--red);"></span>OFFLINE';
      if (e.message !== "signed out" && e.message !== "not entitled")
        $("feed").innerHTML = `<div class="card ag-muted" style="padding:18px;">Could not load logs — ${esc(e.message)}</div>`;
    }
  }

  function render() {
    const inProject = (x) => filters.project === "all" || x.project === filters.project;
    const batches = data.batches.filter(inProject);
    const events = data.events.filter((e) => inProject(e)
      && (filters.type === "all" || e.type === filters.type)
      && (!filters.search || [e.title, e.origin, e.summary, e.project, e.source].join(" ").toLowerCase().includes(filters.search)));

    const sum = (f) => batches.reduce((n, b) => n + f(b), 0);
    const spanBatches = batches.filter((b) => b.source !== "host-events");
    $("tBatches").textContent = batches.length;
    $("tSources").textContent = [...new Set(batches.map((b) => SOURCE[b.source] || b.source))].join(" · ") || "—";
    $("tSpans").textContent = spanBatches.reduce((n, b) => n + b.accepted, 0);
    $("tNew").textContent = spanBatches.reduce((n, b) => n + b.new, 0) + " new (retries de-duplicated)";
    $("tHost").textContent = batches.filter((b) => b.source === "host-events").reduce((n, b) => n + b.accepted, 0);
    $("tRejected").textContent = sum((b) => b.rejected);

    $("batches").innerHTML = batches.length ? batches.slice(0, 100).map((b) => `
      <tr title="${esc(b.error || "")}">
        <td class="mono">${esc(fmtTime(b.received_ms))}</td>
        <td><span class="badge info">${esc(SOURCE[b.source] || b.source)}</span></td>
        <td>${esc(b.project)}</td>
        <td class="num mono">${b.accepted}</td>
        <td class="num mono">${b.new}</td>
        <td class="num mono">${b.rejected ? `<span class="badge high" title="${esc(b.error || "")}">${b.rejected}</span>` : "0"}</td>
      </tr>`).join("")
      : '<tr><td colspan="6" class="ag-muted">Nothing received yet. <a href="keys.html">Create a key</a> and send your first trace.</td></tr>';

    $("feed").innerHTML = events.length ? events.slice(0, 150).map((e) => {
      const host = e.type === "host";
      const col = e.status === "error" ? "var(--red)" : host ? "var(--violet)" : "var(--cyan)";
      const tag = host ? "SENSOR · " + e.title.toUpperCase() : (SOURCE[e.source] || e.source);
      const link = e.trace_id ? ` <a href="index.html?trace=${encodeURIComponent(e.trace_id)}" class="ag-feed-link">session →</a>` : "";
      return `<div class="card alert-card ag-feed" style="border-left:3px solid ${col}">
        <div class="ag-feed-row">
          <span class="badge ${host ? "med" : e.status === "error" ? "crit" : "info"}" style="font-size:9px;">${esc(tag)}</span>
          <span class="ac-time">${esc(fmtTime(e.ts_ms))}</span>
          <b class="ag-feed-title">${esc(host ? e.origin : e.title)}</b>
          <span class="ag-muted">${esc(host ? e.project : (e.origin || "") + " · " + e.project)}</span>
          <span style="flex:1"></span>${link}
        </div>
        ${e.summary ? `<div class="ac-log" title="click to expand">${esc(e.summary)}</div>` : ""}
      </div>`;
    }).join("")
      : '<div class="card ag-muted" style="padding:18px;">No spans or sensor events match.</div>';
  }

  $("feed").addEventListener("click", (e) => {
    const log = e.target.closest(".ac-log");
    if (log) log.classList.toggle("expanded");
  });
  let t = null;
  $("search").addEventListener("input", (e) => { clearTimeout(t); t = setTimeout(() => { filters.search = e.target.value.trim().toLowerCase(); render(); }, 200); });
  $("fType").addEventListener("change", (e) => { filters.type = e.target.value; render(); });
  $("fProject").addEventListener("change", (e) => { filters.project = e.target.value; render(); });
  $("pauseBtn").addEventListener("click", (e) => { paused = !paused; e.target.textContent = paused ? "▶ Resume" : "⏸ Pause"; if (!paused) load(); });

  load();
  setInterval(() => { if (!document.hidden) load(); }, 10000);
})();
