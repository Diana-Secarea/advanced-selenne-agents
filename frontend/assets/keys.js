/* Ingestion keys. Selenne owns them; the console relays these calls to it
   with the signed-in user's session (/agents/api/keys → Selenne /api/keys). */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const { api, esc, toast } = window.SA;                 // common.js
  let raw = "";

  function msg(text, ok) {
    $("akMsg").textContent = text;
    $("akMsg").style.color = ok ? "var(--green)" : "var(--red)";
  }
  function notice(text) {
    $("keysNotice").textContent = text;
    $("keysNotice").hidden = !text;
  }
  const when = (t) => t ? esc(String(t).replace("T", " ").slice(0, 16)) : "never";

  async function load() {
    let d;
    try { d = await api("/agents/api/keys"); }
    catch (e) {
      if (e.message === "signed out" || e.message === "not entitled") return;
      notice(e.message);
      $("keys").innerHTML = '<tr><td colspan="6" class="ag-muted">Keys are unavailable right now.</td></tr>';
      return;
    }
    notice("");
    const keys = d.keys || [];
    $("keys").innerHTML = keys.length ? keys.map((k) => `
      <tr class="${k.active ? "" : "ak-revoked"}">
        <td><b>${esc(k.project)}</b></td>
        <td class="mono">${esc(k.hint)}</td>
        <td>${k.active ? '<span class="badge low">active</span>' : '<span class="badge med">revoked</span>'}</td>
        <td class="mono">${when(k.created_at)}</td>
        <td class="mono">${when(k.last_used_at)}</td>
        <td style="text-align:right">${k.active
          ? `<button class="btn btn-ghost ag-refresh" data-id="${esc(k.id)}" data-project="${esc(k.project)}">Revoke</button>` : ""}</td>
      </tr>`).join("")
      : '<tr><td colspan="6" class="ag-muted">No keys yet — create one above.</td></tr>';
  }

  $("keys").addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-id]");
    if (!b) return;
    if (!confirm(`Revoke the key for "${b.dataset.project}"? Agents using it stop sending within a minute.`)) return;
    try {
      await api("/agents/api/keys/" + encodeURIComponent(b.dataset.id), { method: "DELETE" });
      toast("Key revoked");
      load();
    } catch (err) { toast(err.message); }
  });

  $("akCreate").addEventListener("click", async () => {
    const project = $("akProject").value.trim();
    if (!project) return msg("Name the project first", false);
    try {
      const d = await api("/agents/api/keys", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ project }) });
      raw = d.key;
      $("akKey").textContent = raw;
      $("snipOtel").textContent =
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.selenne.app/v1/traces\n" +
        'OTEL_EXPORTER_OTLP_TRACES_HEADERS="Authorization=Bearer ' + raw + '"\n' +
        "OTEL_SERVICE_NAME=" + d.record.project;
      $("akReveal").hidden = false;
      $("akProject").value = "";
      msg("", true);
      load();
    } catch (err) {
      if (err.message !== "signed out" && err.message !== "not entitled") msg(err.message, false);
    }
  });
  $("akProject").addEventListener("keydown", (e) => { if (e.key === "Enter") $("akCreate").click(); });

  $("akCopy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(raw); toast("Key copied"); }
    catch (_) { toast("Copy failed — select the key and copy it manually"); }
  });
  $("akDone").addEventListener("click", () => {
    raw = "";
    $("akKey").textContent = "";
    $("akReveal").hidden = true;
  });

  load();
})();
