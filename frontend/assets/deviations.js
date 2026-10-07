/* Deviations — the SIEM Live Alerts page, for AI agents: policy violations
   (reported by the agent, or on its host) and unexplained host activity.
   Data: /agents/api/deviations (this stack's own database — never Selenne's
   alert pipeline). Everything customer-controlled goes through esc(). */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const REFRESH_MS = 15000;
  const SEVS = ["CRITICAL", "HIGH", "POSSIBLE", "NORMAL", "BENIGN"];

  let all = [], rules = {}, benign = new Set(), paused = false;
  const filters = { search: "", period: "all", sev: "all", level: 0, project: "all",
                    agent: "all", sort: "score", hour: null, tag: null, cat: "all" };
  const CATS = { reported: "policy · reported", host: "policy · host", unexplained: "unexplained" };
  let chTime, chSev, chRules, chTags;

  function toast(msg) {
    let t = document.querySelector(".toast");
    if (!t) { t = document.createElement("div"); t.className = "toast"; document.body.appendChild(t); }
    t.textContent = msg;
    requestAnimationFrame(() => t.classList.add("show"));
    clearTimeout(t._h);
    t._h = setTimeout(() => t.classList.remove("show"), 2600);
  }
  const fmtTs = (ms) => new Date(ms).toLocaleString("sv-SE");
  const tierColor = (v) => v === "CRITICAL" || v === "HIGH" ? "var(--red)" : v === "POSSIBLE" ? "var(--amber)"
    : v === "BENIGN" ? "var(--cyan)" : "var(--green)";
  const badgeCls = (v) => v === "CRITICAL" || v === "HIGH" ? "crit" : v === "POSSIBLE" ? "high" : v === "BENIGN" ? "info" : "low";

  async function api(path, opts) {
    const r = await fetch(path, Object.assign({ credentials: "same-origin" }, opts || {}));
    const body = await r.json().catch(() => ({}));
    if (r.status === 401) { location.href = "/login.html?next=/agents/deviations"; throw new Error("signed out"); }
    if (r.status === 402) { $("entitleBanner").hidden = false; throw new Error("not entitled"); }
    if (!r.ok) throw new Error(body.error || "HTTP " + r.status);
    return body;
  }

  /* ---------- nav ---------- */
  api("/agents/api/me").then((d) => {
    $("navUser").textContent = d.user.username; $("navUser").hidden = false; $("navOut").hidden = false;
    if (!d.user.agents) $("entitleBanner").hidden = false;
  }).catch(() => {});
  $("navOut").addEventListener("click", async (e) => {
    e.preventDefault();
    try { await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" }); } catch (_) {}
    location.href = "/landing.html";
  });

  /* ---------- load ---------- */
  async function loadRules() {
    try {
      const d = await api("/agents/api/rules");
      rules = d.rules; benign = new Set(d.benign);
      renderExcBar();
    } catch (_) {}
  }
  async function load() {
    if (paused) return;
    const pill = document.querySelector(".status-pill");
    try {
      const d = await api("/agents/api/deviations?hours=168&limit=1000");
      all = d.alerts;
      refreshDropdown("fProject", "all projects", all.map((a) => a.project));
      refreshDropdown("fAgent", "all agents", all.map((a) => a.agent_name));
      renderAll();
      if (pill) pill.innerHTML = '<span class="dot"></span>STREAMING · ' + new Date().toLocaleTimeString();
    } catch (e) {
      if (pill) pill.innerHTML = '<span class="dot" style="background:var(--red);"></span>OFFLINE';
    }
  }
  function refreshDropdown(id, allLabel, values) {
    const sel = $(id), cur = sel.value;
    const opts = [...new Set(values.filter(Boolean))].sort();
    sel.innerHTML = `<option value="all">${allLabel}</option>` + opts.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join("");
    if ([...sel.options].some((o) => o.value === cur)) sel.value = cur;
  }

  /* ---------- filter + sort ---------- */
  function filtered() {
    const now = Date.now();
    const cut = { "1h": 3600e3, "6h": 6 * 3600e3, "24h": 24 * 3600e3, "7d": 7 * 24 * 3600e3 };
    return all.filter((a) => {
      if (filters.search) {
        const txt = [a.rule_id, a.rule_description, a.full_log, a.agent_name, a.project,
                     (a.groups || []).join(" "), a.evidence_match].join(" ").toLowerCase();
        if (!txt.includes(filters.search)) return false;
      }
      if (filters.cat !== "all" && a.category !== filters.cat) return false;
      if (filters.sev !== "all" && a.anomaly_label !== filters.sev) return false;
      if ((a.level || 0) < filters.level) return false;
      if (filters.project !== "all" && a.project !== filters.project) return false;
      if (filters.agent !== "all" && a.agent_name !== filters.agent) return false;
      if (filters.period !== "all" && now - a.timestamp_ms > cut[filters.period]) return false;
      if (filters.hour != null && new Date(a.timestamp_ms).getHours() !== filters.hour) return false;
      if (filters.tag && !(a.groups || []).includes(filters.tag)) return false;
      return true;
    }).sort((a, b) => filters.sort === "score" ? b.anomaly_score - a.anomaly_score || b.timestamp_ms - a.timestamp_ms
      : filters.sort === "level" ? b.level - a.level || b.timestamp_ms - a.timestamp_ms
      : b.timestamp_ms - a.timestamp_ms);
  }

  function renderAll() {
    const rows = filtered();
    updateReports(rows);
    updateCharts(rows);
    renderStream(rows.slice(0, 100));
  }

  /* ---------- stream (same card markup as the SIEM) ---------- */
  function renderStream(rows) {
    const stream = $("stream");
    if (!rows.length) {
      stream.innerHTML = all.length
        ? '<div class="card" style="text-align:center;padding:34px;color:var(--text-dim);">No deviations match the current filters.</div>'
        : '<div class="card" style="text-align:center;padding:34px;color:var(--text-dim);">No agent alerts yet. Rules run on every trace your agents send — ' +
          '<a href="/agents/">see sessions</a> or <a href="/profile.html#agent-keys">create an ingestion key</a>.</div>';
      return;
    }
    stream.innerHTML = rows.map((a) => {
      const v = a.anomaly_label, col = tierColor(v), isBenign = v === "BENIGN";
      const tags = (a.groups || []).map((g) =>
        `<span class="tag" data-tag="${esc(g)}" title="filter by ${esc(g)}">${esc(g)}</span>`).join("");
      const meta = [
        `<span class="dv-cat dv-${esc(a.category)}">${esc(CATS[a.category] || a.category)}</span>`,
        `<span>🤖 <b>${esc(a.agent_name)}</b></span>`,
        `<span>📁 <b>${esc(a.project)}</b></span>`,
        a.evidence_field ? `<span>🔎 ${esc(a.evidence_field)}</span>` : "",
        a.host ? `<span>🖥 ${esc(a.host)}</span>` : "",
      ].filter(Boolean).join("");
      return `<div class="card alert-card" style="border-left:3px solid ${col}">
        <div class="ac-head">
          <div class="ac-headL">
            <div class="ac-time">${esc(fmtTs(a.timestamp_ms))}</div>
            <div class="ac-title"><span class="ac-rule" style="color:${col}">${esc(a.rule_id)}</span>${esc(a.rule_description)}</div>
          </div>
          <div class="ac-headR">
            <div class="ac-score" style="color:${col}">${a.anomaly_score}<span>/100</span></div>
            <span class="badge ${badgeCls(v)}">${esc(v)} · L${a.level}</span>
          </div>
        </div>
        <div class="ac-meta">${meta}</div>
        <div class="ac-log" title="click to expand">${esc(a.full_log)}</div>
        <div class="ac-foot">
          <div class="ac-tags">${tags}</div>
          <div class="ac-actions">
            <span class="ac-subscore">rules v0</span>
            <button class="ac-btn" data-benign="${esc(a.rule_id)}">${isBenign ? "↩ Unmark" : "🛡 Benign"}</button>
            ${a.trace_id ? `<a class="ac-btn primary" style="text-decoration:none" href="/agents/?trace=${encodeURIComponent(a.trace_id)}&span=${encodeURIComponent(a.span_id || "")}">🔎 Open session</a>`
              : a.session_id ? `<a class="ac-btn primary" style="text-decoration:none" href="/agents/?session=${encodeURIComponent(a.session_id)}">🔎 Open session</a>` : ""}
            ${a.source === "host" ? `<a class="ac-btn" style="text-decoration:none" href="/agents/activity?agent=${encodeURIComponent(a.agent_name || "")}&alerts=1">🛰 Activity</a>` : ""}
          </div>
        </div>
      </div>`;
    }).join("");
  }
  $("stream").addEventListener("click", (e) => {
    const log = e.target.closest(".ac-log");
    if (log) { log.classList.toggle("expanded"); return; }
    const tag = e.target.closest(".tag[data-tag]");
    if (tag) { filters.tag = filters.tag === tag.dataset.tag ? null : tag.dataset.tag; toast(filters.tag ? "Filtered to " + filters.tag : "Category filter cleared"); renderAll(); return; }
    const b = e.target.closest("[data-benign]");
    if (b) toggleBenign(b.dataset.benign);
  });

  /* ---------- benign exceptions ---------- */
  function renderExcBar() {
    $("excBenign").innerHTML = [...benign].sort().map((r) =>
      `<span class="exc-chip benign" title="${esc(rules[r] || "")}">${esc(r)}<button data-unbenign="${esc(r)}">✕</button></span>`).join("")
      || '<span style="color:var(--text-dim);font-size:12px;">none</span>';
  }
  $("excBenign").addEventListener("click", (e) => {
    const b = e.target.closest("[data-unbenign]");
    if (b) toggleBenign(b.dataset.unbenign);
  });
  async function toggleBenign(ruleId) {
    const on = benign.has(ruleId);
    try {
      const d = on
        ? await api("/agents/api/benign-rules/" + encodeURIComponent(ruleId), { method: "DELETE" })
        : await api("/agents/api/benign-rules", { method: "POST", headers: { "Content-Type": "application/json" },
                                                   body: JSON.stringify({ rule_id: ruleId }) });
      benign = new Set(d.benign);
      renderExcBar();
      toast(on ? `${ruleId} scored again` : `${ruleId} marked benign`);
      await load();
    } catch (e) { toast("Could not update: " + e.message); }
  }

  /* ---------- tiles ---------- */
  function updateReports(rows) {
    const t = rows.length || 1;
    const n = (fn) => rows.filter(fn).length;
    const high = n((a) => a.anomaly_label === "CRITICAL" || a.anomaly_label === "HIGH");
    const poss = n((a) => a.anomaly_label === "POSSIBLE");
    const norm = n((a) => a.anomaly_label === "NORMAL");
    const ben = n((a) => a.anomaly_label === "BENIGN");
    $("rTotal").textContent = rows.length;
    $("rHigh").textContent = high; $("rHighPct").textContent = Math.round(high / t * 100) + "% of total";
    $("rPoss").textContent = poss; $("rPossPct").textContent = Math.round(poss / t * 100) + "% of total";
    $("rNorm").textContent = norm; $("rNormPct").textContent = Math.round(norm / t * 100) + "% of total";
    $("rBenign").textContent = ben; $("rBenignPct").textContent = Math.round(ben / t * 100) + "% of total";
    $("rAvg").textContent = rows.length ? Math.round(rows.reduce((s, a) => s + a.anomaly_score, 0) / rows.length) : 0;
    $("rRules").textContent = new Set(rows.map((a) => a.rule_id)).size + " unique rules";
    $("rAgents").textContent = new Set(rows.map((a) => a.agent_name)).size + " agents";
  }

  /* ---------- charts (same look as the SIEM page) ---------- */
  function initCharts() {
    if (!window.Chart) return;
    const gridC = "rgba(255,255,255,.06)", tick = "#9aa6c4";
    const axes = { x: { grid: { color: gridC }, ticks: { color: tick, font: { size: 9 } }, beginAtZero: true },
                   y: { grid: { color: gridC }, ticks: { color: tick, font: { size: 9 } }, beginAtZero: true } };
    chTime = new Chart($("chTime"), { type: "bar", data: { labels: [], datasets: [
      { label: "all", data: [], backgroundColor: "rgba(34,211,238,.55)", borderRadius: 4 },
      { label: "critical/high", data: [], backgroundColor: "rgba(251,113,133,.75)", borderRadius: 4 }] },
      options: { onClick: (e, el) => { if (el[0]) { const h = parseInt(chTime.data.labels[el[0].index]); filters.hour = filters.hour === h ? null : h; toast(filters.hour != null ? "Filtered to hour " + h : "Hour filter cleared"); renderAll(); } },
                 plugins: { legend: { display: false } }, scales: axes } });
    chSev = new Chart($("chSev"), { type: "doughnut", data: { labels: ["Critical", "High", "Possible", "Normal", "Benign"],
      datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: ["#fb7185", "#f43f5e", "#fbbf24", "#34d399", "#22d3ee"], borderColor: "#0b0e1a", borderWidth: 3 }] },
      options: { onClick: (e, el) => { if (el[0]) { const v = SEVS[el[0].index]; filters.sev = filters.sev === v ? "all" : v; $("fSev").value = filters.sev; renderAll(); } },
                 plugins: { legend: { labels: { color: tick, font: { size: 11 } }, position: "bottom" } }, cutout: "60%" } });
    chRules = new Chart($("chRules"), { type: "bar", data: { labels: [], datasets: [{ data: [], backgroundColor: "#a78bfa", borderRadius: 5 }] },
      options: { indexAxis: "y", onClick: (e, el) => { if (el[0]) { const rid = chRules.data.labels[el[0].index]; $("search").value = rid; filters.search = rid.toLowerCase(); renderAll(); } },
                 plugins: { legend: { display: false } }, scales: axes } });
    chTags = new Chart($("chTags"), { type: "bar", data: { labels: [], datasets: [{ data: [], backgroundColor: "#f472b6", borderRadius: 5 }] },
      options: { onClick: (e, el) => { if (el[0]) { const t = chTags.data.labels[el[0].index]; filters.tag = filters.tag === t ? null : t; toast(filters.tag ? "Filtered to " + t : "Category filter cleared"); renderAll(); } },
                 plugins: { legend: { display: false } }, scales: axes } });
  }
  function updateCharts(rows) {
    if (!chTime) return;
    const now = Date.now(), labels = [], allC = [], highC = [];
    for (let i = 23; i >= 0; i--) {
      labels.push(String(new Date(now - i * 3600e3).getHours()).padStart(2, "0") + ":00");
      allC.push(0); highC.push(0);
    }
    rows.forEach((a) => {
      const hoursAgo = (now - a.timestamp_ms) / 3600e3;
      if (hoursAgo < 0 || hoursAgo > 24) return;
      const idx = 23 - Math.floor(hoursAgo);
      if (idx < 0) return;
      allC[idx]++;
      if (a.anomaly_label === "CRITICAL" || a.anomaly_label === "HIGH") highC[idx]++;
    });
    chTime.data.labels = labels; chTime.data.datasets[0].data = allC; chTime.data.datasets[1].data = highC; chTime.update("none");
    chSev.data.datasets[0].data = SEVS.map((s) => rows.filter((a) => a.anomaly_label === s).length); chSev.update("none");
    const count = (keyFn) => { const c = {}; rows.forEach((a) => keyFn(a).forEach((k) => { c[k] = (c[k] || 0) + 1; })); return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 10); };
    const topR = count((a) => [a.rule_id]);
    chRules.data.labels = topR.map((x) => x[0]); chRules.data.datasets[0].data = topR.map((x) => x[1]); chRules.update("none");
    const topT = count((a) => a.groups || []);
    chTags.data.labels = topT.map((x) => x[0]); chTags.data.datasets[0].data = topT.map((x) => x[1]); chTags.update("none");
  }

  /* ---------- filter wiring ---------- */
  let searchTimer = null;
  $("search").addEventListener("input", (e) => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { filters.search = e.target.value.trim().toLowerCase(); renderAll(); }, 200); });
  $("fPeriod").addEventListener("change", (e) => { filters.period = e.target.value; renderAll(); });
  $("fSev").addEventListener("change", (e) => { filters.sev = e.target.value; renderAll(); });
  $("fCat").addEventListener("change", (e) => { filters.cat = e.target.value; renderAll(); });
  $("fLevel").addEventListener("change", (e) => { filters.level = +e.target.value; renderAll(); });
  $("fProject").addEventListener("change", (e) => { filters.project = e.target.value; renderAll(); });
  $("fAgent").addEventListener("change", (e) => { filters.agent = e.target.value; renderAll(); });
  $("fSort").addEventListener("change", (e) => { filters.sort = e.target.value; renderAll(); });
  $("clearBtn").addEventListener("click", () => {
    Object.assign(filters, { search: "", period: "all", sev: "all", level: 0, project: "all", agent: "all", sort: "score", hour: null, tag: null });
    $("search").value = ""; $("fPeriod").value = "all"; $("fSev").value = "all"; $("fLevel").value = "0";
    $("fCat").value = "all"; filters.cat = "all";
    $("fProject").value = "all"; $("fAgent").value = "all"; $("fSort").value = "score";
    renderAll(); toast("Filters cleared");
  });
  $("pauseBtn").addEventListener("click", (e) => { paused = !paused; e.target.textContent = paused ? "▶ Resume" : "⏸ Pause"; if (!paused) load(); });

  initCharts();
  loadRules().then(load);
  setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
})();
