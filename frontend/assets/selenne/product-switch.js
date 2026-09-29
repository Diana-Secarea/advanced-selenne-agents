/* ============================================================
   SELENNE — product switcher (SIEM ⇄ AI Agents)
   One account, two consoles. This sits next to the brand in the nav of
   BOTH products: app.js loads it on every SIEM page, and the Selenne
   Agents console (served at /agents/ by its own container) loads this
   same file from /assets/, so the switcher cannot drift between them.
   Self-contained on purpose — no dependency on app.js.
   ============================================================ */
(function productSwitch() {
  var PRODUCTS = [
    { id: "siem",   name: "SIEM",      href: "/index.html",
      desc: "Endpoints, live alerts, ML engine" },
    { id: "agents", name: "AI Agents", href: "/agents/",
      desc: "Monitor & secure AI agents and chatbots" },
  ];

  function mount() {
    var nav = document.querySelector(".nav");
    if (!nav || nav.querySelector(".product-switch")) return;
    var current = location.pathname.indexOf("/agents") === 0 ? "agents" : "siem";
    var cur = PRODUCTS.filter(function (p) { return p.id === current; })[0];

    var wrap = document.createElement("div");
    wrap.className = "product-switch";
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ps-btn";
    btn.setAttribute("aria-haspopup", "true");
    btn.setAttribute("aria-expanded", "false");
    btn.innerHTML = '<span class="ps-name"></span><span class="ps-caret" aria-hidden="true">▾</span>';
    btn.querySelector(".ps-name").textContent = cur.name;

    var menu = document.createElement("div");
    menu.className = "ps-menu";
    menu.setAttribute("role", "menu");
    menu.hidden = true;
    PRODUCTS.forEach(function (p) {
      var a = document.createElement("a");
      a.className = "ps-item" + (p.id === current ? " active" : "");
      a.href = p.href;
      a.setAttribute("role", "menuitem");
      a.innerHTML = "<b></b><span></span>";
      a.querySelector("b").textContent = p.name;
      a.querySelector("span").textContent = p.desc;
      menu.appendChild(a);
    });

    // The nav is one line and scrolls sideways when narrow, and its
    // backdrop-filter/transform would clip even a fixed child — so the menu
    // lives on <body>, sits under the button, follows it while things
    // scroll, and closes only once the button is off-screen.
    function place() {
      if (menu.hidden) return;
      var r = btn.getBoundingClientRect();
      if (r.bottom < 0 || r.right < 0 || r.left > innerWidth) { setOpen(false); return; }
      menu.style.top = (r.bottom + 8) + "px";
      menu.style.left = Math.max(8, Math.min(r.left, innerWidth - menu.offsetWidth - 8)) + "px";
    }
    function setOpen(open) {
      menu.hidden = !open;
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      place();
    }
    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      setOpen(menu.hidden);
    });
    document.addEventListener("click", function (e) {
      if (!wrap.contains(e.target) && !menu.contains(e.target)) setOpen(false);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") setOpen(false);
    });
    addEventListener("resize", place);
    addEventListener("scroll", place, { passive: true });
    nav.addEventListener("scroll", place, { passive: true });

    wrap.appendChild(btn);
    document.body.appendChild(menu);
    var brand = nav.querySelector(".brand");
    if (brand && brand.nextSibling) nav.insertBefore(wrap, brand.nextSibling);
    else nav.insertBefore(wrap, nav.firstChild);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
  else mount();
})();
