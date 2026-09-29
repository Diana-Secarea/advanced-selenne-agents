/* Shared by every Selenne Agents page (load it before the page's own script).

   SA.api(path, opts)  JSON API call. If the page is NOT being served by the
                       Agents console — opened as a file, from a static file
                       server, or with the service down — it switches to
                       PREVIEW: a banner says so and SADemo (demo.js) answers
                       with sample data, so the page never renders empty.
   Nav                 fills the signed-in user, wires sign-out, and points
                       every [data-selenne-link] (◈SELENNE → landing page,
                       profile, …) at Selenne — same origin behind nginx,
                       SELENNE_PUBLIC_URL when the console runs on its own
                       port, selenne.app in preview.
   SA.esc / SA.toast / SA.fmtTime / SA.fmtDuration  small helpers. */
(function () {
  "use strict";

  const PREVIEW_SELENNE = "https://selenne.app";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  let preview = location.protocol === "file:";
  let selenneUrl = "";                       // "" = same origin as this page

  function toast(msg) {
    let t = document.querySelector(".toast");
    if (!t) { t = document.createElement("div"); t.className = "toast"; document.body.appendChild(t); }
    t.textContent = msg;
    requestAnimationFrame(() => t.classList.add("show"));
    clearTimeout(t._h);
    t._h = setTimeout(() => t.classList.remove("show"), 2600);
  }

  function fmtDuration(ms) {
    if (ms == null || !isFinite(ms)) return "—";
    if (ms < 1) return (ms * 1000).toFixed(0) + " µs";
    if (ms < 1000) return ms.toFixed(ms < 10 ? 1 : 0) + " ms";
    if (ms < 60000) return (ms / 1000).toFixed(ms < 10000 ? 2 : 1) + " s";
    return Math.floor(ms / 60000) + "m " + Math.round((ms % 60000) / 1000) + "s";
  }
  function fmtTime(ms) {
    const d = new Date(ms), today = new Date();
    const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    return d.toDateString() === today.toDateString() ? time
      : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + time;
  }

  /* ---------- links back into Selenne ---------- */
  function setSelenneLinks() {
    const base = preview ? PREVIEW_SELENNE : selenneUrl;
    document.querySelectorAll("[data-selenne-link]").forEach((a) => {
      a.setAttribute("href", base + a.dataset.selenneLink);
    });
    // The shared SIEM ⇄ AI Agents switcher (product-switch.js) uses absolute
    // same-origin paths; point them at Selenne / this console explicitly.
    document.querySelectorAll(".ps-item").forEach((a) => {
      const isAgents = (a.getAttribute("href") || "").indexOf("/agents") === 0 || a.dataset.agents;
      if (isAgents) { a.dataset.agents = "1"; a.setAttribute("href", preview ? "index.html" : "/agents/"); }
      else a.setAttribute("href", base + "/index.html");
      // The switcher guesses the product from the URL; these pages are
      // always AI Agents, even opened from disk where the path has no /agents.
      a.classList.toggle("active", !!a.dataset.agents);
    });
    const name = document.querySelector(".ps-btn .ps-name");
    if (name) name.textContent = "AI Agents";
  }
  addEventListener("load", () => setSelenneLinks());

  /* ---------- preview mode ---------- */
  function showPreviewBanner(reason) {
    if ($("previewBanner")) return;
    const b = document.createElement("div");
    b.id = "previewBanner";
    b.className = "card ag-banner ag-preview";
    b.innerHTML = "<b>Preview — sample data.</b> <span></span> Start the console " +
      "(<code>docker compose up</code>, then <code>http://127.0.0.1:4319/agents/</code>) " +
      "or open it through Selenne to see your agents' real activity.";
    b.querySelector("span").textContent = "This page is showing made-up data because " + reason + ".";
    const main = document.querySelector("main");
    if (main) main.insertBefore(b, main.firstChild);
  }
  function enterPreview(reason) {
    const first = !preview || !$("previewBanner");
    preview = true;
    if (first) {
      showPreviewBanner(reason);
      setSelenneLinks();
      showUser({ username: "preview", agents: true });
    }
  }

  /* ---------- API ---------- */
  async function api(path, opts) {
    if (preview) { enterPreview("it was opened as a file, not through the console"); return window.SADemo.handle(path, opts); }
    let r;
    try {
      r = await fetch(path, Object.assign({ credentials: "same-origin" }, opts || {}));
    } catch (e) {
      enterPreview("the Selenne Agents service is not reachable");
      return window.SADemo.handle(path, opts);
    }
    if (!(r.headers.get("content-type") || "").includes("application/json")) {
      enterPreview("this page is not being served by the Selenne Agents console");
      return window.SADemo.handle(path, opts);
    }
    const body = await r.json().catch(() => ({}));
    if (r.status === 401) {
      location.href = body.login || "/login.html?next=" + encodeURIComponent(location.pathname);
      throw new Error("signed out");
    }
    if (r.status === 402) {
      const b = $("entitleBanner");
      if (b) b.hidden = false;
      throw new Error("not entitled");
    }
    if (!r.ok) {
      const err = new Error(body.error || "HTTP " + r.status);
      err.status = r.status; err.body = body;
      throw err;
    }
    return body;
  }

  /* ---------- nav: user chip + sign out ---------- */
  function showUser(u) {
    const chip = $("navUser"), out = $("navOut");
    if (chip) { chip.textContent = u.username; chip.hidden = false; }
    if (out) out.hidden = false;
    if (u.agents === false && $("entitleBanner")) $("entitleBanner").hidden = false;
  }
  async function loadMe() {
    try {
      const d = await api("/agents/api/me");
      if (!preview) selenneUrl = d.selenne_url || "";
      setSelenneLinks();
      showUser(d.user);
    } catch (_) { /* api() redirected, flagged, or went to preview */ }
  }
  function wireSignOut() {
    const out = $("navOut");
    if (!out) return;
    out.addEventListener("click", async (e) => {
      e.preventDefault();
      if (preview) { toast("Preview — there is no session to sign out of"); return; }
      let next = selenneUrl + "/landing.html";
      try {
        const r = await fetch("/agents/api/logout", { method: "POST", credentials: "same-origin" });
        const d = await r.json().catch(() => ({}));
        if (d.next) next = d.next;
      } catch (_) {}
      location.href = next;
    });
  }

  window.SA = {
    api, esc, toast, fmtTime, fmtDuration,
    isPreview: () => preview,
  };

  setSelenneLinks();
  wireSignOut();
  loadMe();
})();
