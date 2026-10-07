/* Incidents: a deviation plus its probable cause. Everything from the API
   goes through esc() — tool outputs and command lines are untrusted text. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const badgeCls = (v) => v === "CRITICAL" || v === "HIGH" ? "crit" : v === "POSSIBLE" ? "high" : "low";
  const CAUSE_ICON = { prompt_injection: "☠", tool_output: "🧰", retrieved_content: "📚", web_content: "🌐" };
  const CATS = { reported: "reported by the agent", host: "on the host", unexplained: "never reported" };

  function fmtTime(ms) {
    const d = new Date(ms);
    const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    return d.toDateString() === new Date().toDateString() ? t
      : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + t;
  }
  function gap(ms) {
    if (ms < 1000) return Math.round(ms) + " ms later";
    if (ms < 120000) return (ms / 1000).toFixed(ms < 10000 ? 1 : 0) + " s later";
    return Math.round(ms / 60000) + " min later";
  }

  async function api(path) {
    const r = await fetch(path, { credentials: "same-origin" });
    const body = await r.json().catch(() => ({}));
    if (r.status === 401) { location.href = "/login.html?next=/agents/incidents"; throw new Error("signed out"); }
    if (r.status === 402) { $("entitleBanner").hidden = false; throw new Error("not entitled"); }
    if (!r.ok) throw new Error(body.error || "HTTP " + r.status);
    return body;
  }

  api("/agents/api/me").then((d) => {
    $("navUser").textContent = d.user.username;
    $("navUser").hidden = $("navOut").hidden = false;
    if (!d.user.agents) $("entitleBanner").hidden = false;
  }).catch(() => {});
  $("navOut").addEventListener("click", async (e) => {
    e.preventDefault();
    try { await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" }); } catch (_) {}
    location.href = "/landing.html";
  });

  function sessionLink(inc, e) {
    const q = e && e.trace_id ? `trace=${encodeURIComponent(e.trace_id)}&span=${encodeURIComponent(e.span_id || "")}`
      : `session=${encodeURIComponent(inc.session_id)}`;
    return "/agents/?" + q;
  }

  function causeBlock(inc) {
    const c = inc.cause;
    const said = c.excerpt || c.preview;
    return `
      <div class="in-step in-cause">
        <div class="in-dot">${CAUSE_ICON[c.kind] || "?"}</div>
        <div class="in-body">
          <div class="in-kicker">CAUSE · ${esc(c.label)}</div>
          <div class="in-title">${c.tool ? `output of tool <b>${esc(c.tool)}</b>` : `<b>${esc(c.name)}</b>`}
            ${c.url ? ` from <span class="mono">${esc(c.url)}</span>` : ""}</div>
          ${said ? `<blockquote class="in-quote">${esc(said)}</blockquote>` : ""}
          <div class="ag-muted">${esc(fmtTime(c.ts_ms))} · <a href="/agents/?trace=${encodeURIComponent(c.trace_id)}&span=${encodeURIComponent(c.span_id)}">open this step</a></div>
        </div>
      </div>`;
  }

  function effectBlock(inc, e) {
    return `
      <div class="in-step in-effect">
        <div class="in-dot ${badgeCls(e.label)}">↳</div>
        <div class="in-body">
          <div class="in-kicker">EFFECT · ${esc(gap(e.ts_ms - inc.cause.ts_ms))} · <span class="dv-cat dv-${esc(e.category)}">${esc(CATS[e.category] || e.category)}</span></div>
          <div class="in-title"><span class="badge ${badgeCls(e.label)}">${esc(e.rule_id)} · ${e.score}</span> ${esc(e.title)}
            ${e.source === "host" && e.host ? ` <span class="ag-muted">on ${esc(e.host)}</span>` : ""}</div>
          ${e.excerpt ? `<div class="mono in-excerpt">${esc(e.excerpt)}</div>` : ""}
          <div class="ag-muted">${esc(fmtTime(e.ts_ms))} · <a href="${sessionLink(inc, e)}">open in session</a>
            ${e.source === "host" ? ` · <a href="/agents/activity?agent=${encodeURIComponent(inc.agent || "")}&alerts=1">activity</a>` : ""}</div>
        </div>
      </div>`;
  }

  function render(list) {
    const n = (k) => list.filter((i) => i.cause.kind === k).length;
    $("tTotal").textContent = list.length;
    $("tInjection").textContent = n("prompt_injection");
    $("tTool").textContent = n("tool_output");
    $("tContent").textContent = n("retrieved_content") + n("web_content");
    $("tEffects").textContent = list.reduce((s, i) => s + i.effects.length, 0);
    const agents = [...new Set(list.map((i) => i.agent).filter(Boolean))];
    $("tAgents").textContent = agents.length ? agents.join(", ") : "—";
    if (!list.length) {
      $("incidents").innerHTML = `<div class="card ag-empty"><h3>No incidents in this window</h3>
        <p>An incident appears when a deviation with consequences (score 50 or more) has untrusted input before it in the same session.
        Deviations without one are on the <a href="/agents/deviations">Deviations</a> page.</p></div>`;
      return;
    }
    $("incidents").innerHTML = list.map((inc) => `
      <article class="card in-card" style="border-left:3px solid ${inc.label === "CRITICAL" || inc.label === "HIGH" ? "var(--red)" : "var(--amber)"}">
        <header class="in-head">
          <div>
            <span class="badge ${badgeCls(inc.label)}">${esc(inc.label)} · ${inc.score}</span>
            <b class="in-agent">${esc(inc.agent || "agent")}</b>
            <span class="ag-muted">${esc(inc.cause.label.toLowerCase())} → ${inc.effects.length} effect${inc.effects.length > 1 ? "s" : ""}
              · session ${esc(inc.session_root || inc.session_id.slice(0, 8))}${inc.session_kind === "conversation" ? " (conversation)" : ""}</span>
          </div>
          <div class="ag-muted mono">${esc(fmtTime(inc.last_ms))}</div>
        </header>
        <div class="in-chain">${causeBlock(inc)}${inc.effects.map((e) => effectBlock(inc, e)).join("")}</div>
        <footer class="in-foot"><a class="btn btn-ghost ag-refresh" href="${sessionLink(inc)}">🔎 Open the whole session</a></footer>
      </article>`).join("");
  }

  async function load() {
    try {
      const d = await api("/agents/api/incidents?hours=" + encodeURIComponent($("fHours").value));
      $("updated").textContent = "updated " + new Date().toLocaleTimeString();
      render(d.incidents);
    } catch (e) {
      if (e.message !== "signed out")
        $("incidents").innerHTML = `<div class="card ag-muted" style="padding:24px">${
          e.message === "not entitled" ? "—" : "Could not load incidents — " + esc(e.message)}</div>`;
    }
  }
  $("fHours").addEventListener("change", load);
  $("refresh").addEventListener("click", load);
  load();
  setInterval(() => { if (!document.hidden) load(); }, 30000);
})();
