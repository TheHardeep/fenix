/* ============================================================================
   Fenix Docs — Application
   Client-side hierarchical router + markdown renderer + TOC + search + theme.
   ============================================================================ */
(function () {
  "use strict";

  const {
    TABS, GROUPS, PAGES, PAGE_ORDER,
    PATH_TO_ID, PATHS_BY_LENGTH, REDIRECTS,
    DEFAULT_PAGE, DEFAULT_PATH, FIRST_PAGE_OF_TAB,
    FENIX_BROKER_PAGES, PRO_BROKER_PAGES,
  } = window.FENIX_NAV;

  /* Broker logos. Two sets:
     - BROKER_LOGOS (assets/img/brokers-marquee): used by the marquee chips. A
       string = one file for both themes; an object = per-theme files
       (.logo-light/.logo-dark).
     - BROKER_LOGOS_FLAT (assets/img/brokers-grid): the flat single-file set used
       by the broker grid tiles. Filenames differ between the two dirs, so
       they're separate. */
  const BROKER_LOGOS = {
    aliceblue: "aliceblue.svg", angelone: "angelone.svg", anandrathi: "anandrathi.svg",
    dhan: "dhan.svg", finvasia: "finvasia.svg",
    fivepaisa: { light: "fivepaisa_light.svg", dark: "fivepaisa_dark.svg" },
    fyers: "fyers.svg", groww: { light: "groww_light.svg", dark: "groww_dark.svg" },
    iifl: "iifl.svg", kotak: "kotak.svg", kotakneo: "kotakneo.svg",
    kunjee: "kunjee.png", mastertrust: "mastertrust.png",
    motilaloswal: "motilaloswal.svg", symphony: "symphony.svg",
    upstox: "upstox.svg", vpc: "vpc.svg", zerodha: "zerodha.svg",
  };
  const BROKER_LOGOS_FLAT = {
    aliceblue: "aliceblue.svg", angelone: "angelone.svg", anandrathi: "anandrathi.jpeg",
    dhan: "dhan.svg", finvasia: "finvasia.svg", fivepaisa: "fivepaisa.svg",
    fyers: "fyers.svg", groww: "groww.svg",
    iifl: "iifl.svg", kotak: "kotak.svg", kotakneo: "kotakneo.svg",
    kunjee: "kunjee.png", mastertrust: "mastertrust.svg",
    motilaloswal: "motilaloswal.jpeg", symphony: "symphony.svg",
    upstox: "upstox.svg", vpc: "vpc.svg", zerodha: "zerodha.svg",
  };
  const brokerSlug = (id) => id.replace(/^(pro-)?broker-/, "");
  function brokerLogoHTML(slug, cls, dir = "assets/img/brokers-marquee", map = BROKER_LOGOS) {
    const L = map[slug];
    if (!L) return null;
    if (typeof L === "string") return `<img class="${cls}" src="${dir}/${L}" alt="" />`;
    return `<img class="${cls} logo-light" src="${dir}/${L.light}" alt="" />` +
           `<img class="${cls} logo-dark" src="${dir}/${L.dark}" alt="" />`;
  }

  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

  const els = {
    topTabs:    $("#topTabs"),
    sidebarNav: $("#sidebarNav"),
    drawerTabs: $("#drawerTabs"),
    doc:        $("#doc"),
    toc:        $("#toc"),
    tocList:    $("#tocList"),
    pageFoot:   $("#pageFoot"),
    sidebar:    $("#sidebar"),
    scrim:      $("#scrim"),
    menuToggle: $("#menuToggle"),
    themeToggle:$("#themeToggle"),
    searchTrigger: $("#searchTrigger"),
    searchModal:$("#searchModal"),
    searchInput:$("#searchInput"),
    searchResults: $("#searchResults"),
  };

  const mdCache = {};
  let spyObserver = null;
  let cleanupScrollSpy = null;
  let revealObserver = null;

  /* ───────────────────────── Line icons (no emoji) ───────────────────────── */
  const ICON_PATHS = {
    flame:       'M13 2c1 4-3 5-3 9 0 1.4 1 2.4 2 2.4S14 13.5 13.5 12c1.4 1 2.5 2.6 2.5 4.5a4.5 4.5 0 11-9 0C7 9 12 7 13 2z',
    package:     'M21 8l-9-5-9 5 9 5 9-5zM3 8v8l9 5 9-5V8M12 13v8',
    bolt:        'M13 2L4 14h7l-1 8 9-12h-7l1-8z',
    layers:      'M12 3l9 5-9 5-9-5 9-5zM3 14l9 5 9-5',
    fingerprint: 'M5 12a7 7 0 0114 0M8 12a4 4 0 018 0v3M12 12v4M8 16v1M16 15v2',
    link:        'M9 15l6-6M8.5 10.5L7 12a3.5 3.5 0 005 5l1.5-1.5M15.5 13.5L17 12a3.5 3.5 0 00-5-5l-1.5 1.5',
    transform:   'M4 8h13l-3-3M20 16H7l3 3',
    ruler:       'M5 9l4-4 10 10-4 4zM9 9l1.5 1.5M12 12l1.5 1.5',
    braces:      'M9 4H8a2 2 0 00-2 2v3a2 2 0 01-2 2 2 2 0 012 2v3a2 2 0 002 2h1M15 4h1a2 2 0 012 2v3a2 2 0 002 2 2 2 0 00-2 2v3a2 2 0 01-2 2h-1',
    file:        'M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5zM14 3v5h5M9 13h6M9 17h6',
    gauge:       'M4 19a8 8 0 1116 0M12 13l3.5-3.5',
    alert:       'M12 3l9 16H3L12 3zM12 10v4M12 17h.01',
    lock:        'M6 11h12v9H6zM8 11V8a4 4 0 018 0v3M12 15v2',
    ticket:      'M4 9a2 2 0 012-2h12a2 2 0 012 2 2 2 0 000 4 2 2 0 01-2 2H6a2 2 0 01-2-2 2 2 0 000-4zM12 7v2M12 13v2',
    receipt:     'M6 3h12v18l-3-2-3 2-3-2-3 2V3zM9 8h6M9 12h6',
    chart:       'M4 20V4M4 20h16M8 16v-4M12 16V8M16 16v-6',
    wallet:      'M19 7H5a2 2 0 00-2 2v8a2 2 0 002 2h14a2 2 0 002-2v-8a2 2 0 00-2-2zM16 13h.01M3 9.5h18',
    flask:       'M9 3h6M10 3v6l-5 9a2 2 0 002 3h10a2 2 0 002-3l-5-9V3M7 16h10',
    bank:        'M3 10l9-6 9 6H3zM5 10v8M9 10v8M15 10v8M19 10v8M3 20h18',
    puzzle:      'M10 4a2 2 0 014 0v1h3v3h1a2 2 0 010 4h-1v3h-3v1a2 2 0 01-4 0v-1H7v-3H6a2 2 0 010-4h1V8h3V4z',
    building:    'M5 21V5a2 2 0 012-2h6a2 2 0 012 2v16M9 7h2M9 11h2M9 15h2M15 21V11h2a2 2 0 012 2v8M3 21h18',
    broadcast:   'M5 8a8 8 0 000 8M8 11a4 4 0 000 2M16 11a4 4 0 010 2M19 8a8 8 0 010 8M12 11a1 1 0 010 2zM12 13v6',
    bell:        'M6 9a6 6 0 1112 0c0 5 2 6 2 6H4s2-1 2-6zM10 20a2 2 0 004 0',
    target:      'M12 4a8 8 0 100 16 8 8 0 000-16zM12 8a4 4 0 100 8 4 4 0 000-8zM12 12h.01',
    satellite:   'M4 13a8 8 0 008 8M4 9a12 12 0 0112 12M6 4l4 4-3 3-4-4 3-3zM15 9l5-5M17 7a3 3 0 013 3',
    card:        'M3 7a2 2 0 012-2h14a2 2 0 012 2v10a2 2 0 01-2 2H5a2 2 0 01-2-2V7zM3 10h18M7 15h3',
    activity:    'M3 12h4l3 8 4-16 3 8h4',
    book:        'M6 3h13v16H6a2 2 0 00-2 2V5a2 2 0 012-2zM19 19H6',
    history:     'M3.5 12a8.5 8.5 0 109-8.5A8.5 8.5 0 005 6.5M3 4v3h3M12 8v4l3 2',
    dot:         'M12 9a3 3 0 100 6 3 3 0 000-6z',
  };
  function iconSVG(name) {
    const d = ICON_PATHS[name] || ICON_PATHS.dot;
    return `<span class="sl-ic"><svg viewBox="0 0 24 24" aria-hidden="true">${
      `<path d="${d}" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>`
    }</svg></span>`;
  }

  /* ───────────────────────── Theme ───────────────────────── */
  function initTheme() {
    const saved = localStorage.getItem("fenix-theme");
    const theme = saved || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    document.documentElement.setAttribute("data-theme", theme);
    els.themeToggle.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("fenix-theme", next);
    });
  }

  /* ───────────────────────── Top tabs ───────────────────────── */
  function renderTabs(activeTab) {
    els.topTabs.innerHTML = TABS.map(
      (t) => `<a href="#/${FIRST_PAGE_OF_TAB[t.id]}" data-tab="${t.id}" class="${t.id === activeTab ? "active" : ""}">${t.label}</a>`
    ).join("");
  }

  /* ───────────── Mobile drawer section switcher ─────────────
     The top-tabs are hidden under 860px, so the drawer needs its own way to
     reach every tab. Following the Notion Developer Docs mobile pattern, it's
     a custom section dropdown (a styled button + a themed listbox popover —
     a native <select> can't be themed to match the dark glass UI). Picking a
     section swaps the page list in place (section → page) without navigating,
     so users can browse another section's pages without leaving the current
     page until they pick one. */
  let drawerTab = null;        /* section currently shown in the open drawer */
  let drawerMenuOpen = false;  /* is the section popover open? */
  function renderDrawerTabs(activeTab) {
    drawerTab = activeTab;
    drawerMenuOpen = false;
    const label = (TABS.find((t) => t.id === activeTab) || {}).label || "";
    const check = `<svg class="drawer-option-check" viewBox="0 0 16 16" width="15" height="15" aria-hidden="true"><path d="M3.5 8.5l3 3 6-7" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
    els.drawerTabs.innerHTML =
      `<div class="drawer-select-wrap">` +
        `<button type="button" class="drawer-select" id="drawerSelect" aria-haspopup="listbox" aria-expanded="false">` +
          `<span class="drawer-select-label">${label}</span>` +
          `<svg class="drawer-select-chev" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>` +
        `</button>` +
        `<ul class="drawer-menu" id="drawerMenu" role="listbox" aria-label="Documentation section" hidden>` +
          TABS.map((t) => {
            const on = t.id === activeTab;
            return `<li class="drawer-option ${on ? "selected" : ""}" role="option" aria-selected="${on}" data-tab="${t.id}" tabindex="-1"><span>${t.label}</span>${check}</li>`;
          }).join("") +
        `</ul>` +
      `</div>`;
  }

  function openDrawerMenu() {
    const wrap = els.drawerTabs.querySelector(".drawer-select-wrap");
    if (!wrap) return;
    wrap.classList.add("open");
    wrap.querySelector(".drawer-select").setAttribute("aria-expanded", "true");
    wrap.querySelector(".drawer-menu").hidden = false;
    drawerMenuOpen = true;
    const sel = wrap.querySelector(".drawer-option.selected") || wrap.querySelector(".drawer-option");
    if (sel) sel.focus();
  }
  function closeDrawerMenu() {
    const wrap = els.drawerTabs.querySelector(".drawer-select-wrap");
    if (!wrap) { drawerMenuOpen = false; return; }
    const btn = wrap.querySelector(".drawer-select");
    const menu = wrap.querySelector(".drawer-menu");
    const focusWasInMenu = menu && menu.contains(document.activeElement);
    wrap.classList.remove("open");
    btn.setAttribute("aria-expanded", "false");
    menu.hidden = true;
    drawerMenuOpen = false;
    if (focusWasInMenu) btn.focus();   // return focus for keyboard users
  }
  function selectDrawerTab(tab) {
    if (tab && tab !== drawerTab) {
      drawerTab = tab;
      const t = TABS.find((x) => x.id === tab);
      const labelEl = els.drawerTabs.querySelector(".drawer-select-label");
      if (labelEl && t) labelEl.textContent = t.label;
      els.drawerTabs.querySelectorAll(".drawer-option").forEach((o) => {
        const on = o.dataset.tab === tab;
        o.classList.toggle("selected", on);
        o.setAttribute("aria-selected", on ? "true" : "false");
      });
      // Show this section's pages; keep the active highlight only if the
      // current page lives in the section being shown.
      const keep = currentPage && PAGES[currentPage] && PAGES[currentPage].tab === tab ? currentPage : null;
      renderSidebar(tab, keep);
    }
    closeDrawerMenu();
  }

  function initDrawerTabs() {
    // Delegate from the stable container (its contents re-render per page).
    els.drawerTabs.addEventListener("click", (e) => {
      const opt = e.target.closest(".drawer-option");
      if (opt) { selectDrawerTab(opt.dataset.tab); return; }
      if (e.target.closest(".drawer-select")) {
        drawerMenuOpen ? closeDrawerMenu() : openDrawerMenu();
      }
    });
    // Keyboard navigation within the open listbox.
    els.drawerTabs.addEventListener("keydown", (e) => {
      if (!drawerMenuOpen) return;
      const opts = Array.from(els.drawerTabs.querySelectorAll(".drawer-option"));
      const i = opts.indexOf(document.activeElement);
      if (e.key === "ArrowDown")      { e.preventDefault(); (opts[i + 1] || opts[0]).focus(); }
      else if (e.key === "ArrowUp")   { e.preventDefault(); (opts[i - 1] || opts[opts.length - 1]).focus(); }
      else if (e.key === "Home")      { e.preventDefault(); opts[0].focus(); }
      else if (e.key === "End")       { e.preventDefault(); opts[opts.length - 1].focus(); }
      else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); if (opts[i]) selectDrawerTab(opts[i].dataset.tab); }
    });
    // Click outside the dropdown closes it.
    document.addEventListener("click", (e) => {
      if (drawerMenuOpen && !e.target.closest(".drawer-select-wrap")) closeDrawerMenu();
    });
  }

  /* ───────────────────────── Sidebar ─────────────────────────
     Groups are collapsible (Notion-style) with a chevron; the group holding
     the active page is always expanded so you can see where you are. Manual
     collapse state persists across navigation in `collapsedGroups`. */
  const collapsedGroups = new Set();   /* keys: `${tab}:${groupTitle}` */
  function renderSidebar(activeTab, activePageId) {
    const groups = GROUPS.filter((g) => g.tab === activeTab);
    els.sidebarNav.innerHTML = groups
      .map((g) => {
        const key = `${activeTab}:${g.title}`;
        const isActiveGroup = g.pages.some((raw) => raw.id === activePageId);
        if (isActiveGroup) collapsedGroups.delete(key);   // always reveal current
        const collapsed = collapsedGroups.has(key);
        const links = g.pages
          .map((raw) => {
            const p = PAGES[raw.id];
            const active = p.id === activePageId ? "active" : "";
            const ic = p.logo
              ? `<span class="sl-ic sl-logo"><img src="${p.logo}" alt=""></span>`
              : iconSVG(p.icon);
            return `<a class="sidebar-link ${active}" href="#/${p.path}">${ic}<span class="sl-label">${p.title}</span></a>`;
          })
          .join("");
        return (
          `<section class="sidebar-group ${collapsed ? "collapsed" : ""}">` +
            `<button type="button" class="sidebar-group-title" data-group-key="${key}" aria-expanded="${collapsed ? "false" : "true"}">` +
              `<span>${g.title}</span>` +
              `<svg class="sg-chev" viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>` +
            `</button>` +
            `<div class="sidebar-group-pages"><div class="sidebar-group-pages-inner">${links}</div></div>` +
          `</section>`
        );
      })
      .join("");
  }
  function initSidebarGroups() {
    els.sidebarNav.addEventListener("click", (e) => {
      const btn = e.target.closest(".sidebar-group-title");
      if (!btn) return;
      const section = btn.closest(".sidebar-group");
      const collapsed = section.classList.toggle("collapsed");
      btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
      if (collapsed) collapsedGroups.add(btn.dataset.groupKey);
      else collapsedGroups.delete(btn.dataset.groupKey);
    });
  }

  /* ───────────────────────── Markdown helpers ───────────────────────── */
  function slugify(text) {
    return String(text).toLowerCase().trim()
      .replace(/[`'"]/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  const CALLOUT_META = {
    TIP:    { cls: "tip",    title: "Tip",      icon: '<path d="M12 2a7 7 0 00-4 12.7V17a1 1 0 001 1h6a1 1 0 001-1v-2.3A7 7 0 0012 2z" fill="none" stroke="currentColor" stroke-width="2"/><path d="M9 21h6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>' },
    INFO:   { cls: "info",   title: "Note",     icon: '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 11v5M12 8h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>' },
    NOTE:   { cls: "info",   title: "Note",     icon: '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 11v5M12 8h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>' },
    WARN:   { cls: "warn",   title: "Warning",  icon: '<path d="M12 3l9 16H3z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 10v4M12 17h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>' },
    WARNING:{ cls: "warn",   title: "Warning",  icon: '<path d="M12 3l9 16H3z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 10v4M12 17h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>' },
    DANGER: { cls: "danger", title: "Caution",  icon: '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M15 9l-6 6M9 9l6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>' },
  };

  function enhanceDoc(root, path) {
    /* Headings: ids + anchors, and collect for TOC */
    const used = {};
    const headings = [];
    $$("h2, h3, h4", root).forEach((h) => {
      let base = slugify(h.textContent);
      if (!base) base = "section";
      let id = base;
      if (used[base] != null) { used[base]++; id = `${base}-${used[base]}`; } else used[base] = 0;
      h.id = id;
      const a = document.createElement("a");
      a.className = "heading-anchor";
      a.href = `#/${path}/${id}`;
      a.setAttribute("aria-label", "Link to this section");
      a.textContent = "#";
      h.appendChild(a);
      if (h.tagName !== "H4") headings.push({ id, text: h.textContent.replace(/#$/, "").trim(), level: h.tagName });
    });

    /* Code blocks → cards with language label + copy */
    $$("pre > code", root).forEach((code) => {
      const pre = code.parentElement;
      if (pre.closest(".code-card")) return;
      let lang = (code.className.match(/language-([\w-]+)/) || [])[1] || "";
      try {
        if (lang && window.hljs && hljs.getLanguage(lang)) {
          code.innerHTML = hljs.highlight(code.textContent, { language: lang }).value;
        } else if (window.hljs) {
          const r = hljs.highlightAuto(code.textContent);
          code.innerHTML = r.value;
          lang = lang || r.language || "";
        }
      } catch (e) { /* leave as-is */ }
      code.classList.add("hljs");

      const card = document.createElement("div");
      card.className = "code-card";
      const core = document.createElement("div");      /* double-bezel inner core */
      core.className = "code-core";
      const labelMap = { python: "Python", py: "Python", json: "JSON", bash: "Shell", sh: "Shell", shell: "Shell", text: "Text", console: "Console" };
      const label = labelMap[lang.toLowerCase()] || (lang ? lang.toUpperCase() : "Code");
      const head = document.createElement("div");
      head.className = "code-head";
      head.innerHTML =
        `<span class="code-dots"><i></i><i></i><i></i></span>` +
        `<span class="code-lang">${label}</span>` +
        `<button class="copy-btn" type="button"><svg viewBox="0 0 24 24" width="13" height="13"><rect x="9" y="9" width="11" height="11" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M5 15V5a2 2 0 012-2h10" fill="none" stroke="currentColor" stroke-width="2"/></svg><span>Copy</span></button>`;
      pre.parentNode.insertBefore(card, pre);
      card.appendChild(core);
      core.appendChild(head);
      core.appendChild(pre);
      head.querySelector(".copy-btn").addEventListener("click", (e) => {
        const btn = e.currentTarget;
        navigator.clipboard.writeText(code.textContent).then(() => {
          btn.classList.add("copied");
          btn.querySelector("span").textContent = "Copied";
          setTimeout(() => { btn.classList.remove("copied"); btn.querySelector("span").textContent = "Copy"; }, 1500);
        });
      });
    });

    /* Blockquote callouts: > [!TIP] Optional title ... */
    $$("blockquote", root).forEach((bq) => {
      const first = bq.querySelector("p");
      if (!first) return;
      const m = first.innerHTML.match(/^\s*\[!(\w+)\][ \t]*([^\n<]*)/i);
      if (!m) return;
      const meta = CALLOUT_META[m[1].toUpperCase()];
      if (!meta) return;
      const titleOverride = (m[2] || "").trim();
      first.innerHTML = first.innerHTML.replace(/^\s*\[!\w+\][ \t]*[^\n<]*\n?/i, "");
      if (!first.textContent.trim() && !first.children.length) first.remove();
      const div = document.createElement("div");
      div.className = `callout ${meta.cls}`;
      div.innerHTML =
        `<svg class="callout-icon" viewBox="0 0 24 24">${meta.icon}</svg>` +
        `<div class="callout-body"><span class="callout-title">${titleOverride || meta.title}</span></div>`;
      const body = div.querySelector(".callout-body");
      while (bq.firstChild) body.appendChild(bq.firstChild);
      bq.replaceWith(div);
    });

    /* Tables → responsive wrapper */
    $$("table", root).forEach((t) => {
      if (t.closest(".table-wrap")) return;
      const wrap = document.createElement("div");
      wrap.className = "table-wrap";
      t.parentNode.insertBefore(wrap, t);
      wrap.appendChild(t);
    });

    /* External links open in a new tab */
    $$("a[href^='http']", root).forEach((a) => { a.target = "_blank"; a.rel = "noopener"; });

    /* Hand-authored code-tab groups (raw HTML in markdown) */
    initCodeTabs(root);

    return headings;
  }

  function initCodeTabs(root) {
    $$(".code-tabs", root).forEach((group) => {
      if (group.dataset.ready) return;
      group.dataset.ready = "1";
      const tabs = $$(".code-tab", group);
      const panels = $$(".panel", group);
      tabs.forEach((tab, i) => {
        tab.addEventListener("click", () => {
          tabs.forEach((t) => t.classList.remove("active"));
          panels.forEach((p) => p.classList.remove("active"));
          tab.classList.add("active");
          panels[i] && panels[i].classList.add("active");
        });
      });
    });
  }

  /* ───────────────────────── Scroll reveal ───────────────────────── */
  function revealOnScroll(root) {
    if (revealObserver) revealObserver.disconnect();
    const sel = [
      ".page-body > h2", ".page-body > .card-grid", ".page-body > .code-card",
      ".page-body > .callout", ".page-body > .table-wrap", ".page-body > .compare",
      ".page-body > .broker-grid", ".page-body > .cta-band",
    ].join(",");
    const targets = [...new Set([...$$(sel, root), ...$$(".reveal", root)])];
    revealObserver = new IntersectionObserver(
      (entries) => entries.forEach((e) => {
        if (e.isIntersecting) { e.target.classList.add("in"); revealObserver.unobserve(e.target); }
      }),
      { threshold: 0.12, rootMargin: "0px 0px -7% 0px" }
    );
    targets.forEach((el) => { el.classList.add("reveal"); revealObserver.observe(el); });
  }

  /* ───────────────────────── Page widgets (marketing pages) ───────────── */
  /* Declarative hooks wired after markdown is injected (inline <script> in
     markdown does not execute, so behaviour lives here).                    */
  function initPageWidgets(root) {
    /* Copy-to-clipboard pills: [data-copy="text"] */
    $$("[data-copy]", root).forEach((el) => {
      el.addEventListener("click", () => {
        navigator.clipboard && navigator.clipboard.writeText(el.dataset.copy);
        el.classList.add("copied");
        setTimeout(() => el.classList.remove("copied"), 1400);
      });
    });

    /* "Change one word" broker cycler: a .mk-demo with .mk-bchip[data-b] +
       .mk-swap targets. Clicking a chip (or the 2.4s auto-cycle) swaps text. */
    /* Broker marquee: build logo pills from the broker list, then duplicate
       the track once for a seamless -50% loop. Logo-less feeds fall back to a
       name pill. */
    const mqTrack = $(".mk-mq-track", root);
    if (mqTrack && !mqTrack.dataset.looped) {
      if (mqTrack.dataset.brokers) {
        const list = mqTrack.dataset.brokers === "pro" ? PRO_BROKER_PAGES : FENIX_BROKER_PAGES;
        mqTrack.innerHTML = list.map((p) => {
          const slug = brokerSlug(p.id);
          const logo = brokerLogoHTML(slug, "mk-mq-logo");
          return logo
            ? `<span class="mk-mq-item" title="${p.title}">${logo}</span>`
            : `<span class="mk-mq-item"><span class="bt-dot"></span>${p.title}</span>`;
        }).join("");
      }
      mqTrack.dataset.looped = "1";
      mqTrack.innerHTML += mqTrack.innerHTML;
    }

    /* Broker grid tiles: swap the decorative .bt-dot for a small monochrome
       logo glyph when we have a logo for the slug. */
    $$(".broker-tile", root).forEach((tile) => {
      if (tile.dataset.logoed) return;
      const dot = tile.querySelector(".bt-dot");
      if (!dot) return;
      const href = tile.getAttribute("href") || "";
      const m = href.match(/#\/(?:pro|brokers)\/([a-z0-9_-]+)/i);
      if (!m) return;
      const logo = brokerLogoHTML(m[1].toLowerCase(), "bt-logo", "assets/img/brokers-grid", BROKER_LOGOS_FLAT);
      if (!logo) return;
      dot.outerHTML = logo;
      tile.dataset.logoed = "1";
    });

    const demo = $(".mk-demo", root);
    if (demo) {
      const chips = $$(".mk-bchip", demo);
      const swaps = $$(".mk-swap", demo);
      const set = (chip) => {
        const cls = chip.dataset.cls || chip.dataset.b;
        swaps.forEach((s) => (s.textContent = cls));
        chips.forEach((c) => c.classList.toggle("on", c === chip));
      };
      if (chips.length) {
        chips.forEach((c) => c.addEventListener("click", () => { set(c); restart(); }));
        set(chips[0]);
        let i = 0, timer = null;
        const tick = () => { i = (i + 1) % chips.length; set(chips[i]); };
        const restart = () => { if (timer) clearInterval(timer); timer = setInterval(tick, 2400); };
        restart();
      }
    }
  }

  /* ───────────────────────── Premium doc header ───────────────────────── */
  /* Wraps the first H1 (+ intro paragraph) of a docs page in an editorial
     header: eyebrow tag, enlarged title, lede. Marketing pages opt out.    */
  function decorateDocHeader(root, page) {
    const body = $(".page-body", root);
    if (!body) return;
    const h1 = body.querySelector(":scope > h1");
    if (!h1 || h1.dataset.dec) return;
    h1.dataset.dec = "1";
    h1.classList.add("doc-title");

    const head = document.createElement("div");
    head.className = "doc-head reveal";

    /* Broker reference pages: the broker logo BECOMES the title (with the name
       kept as a visually-hidden label), and the eyebrow pill sits below it. */
    const isBrokerPage = page.group === "Broker Adapters" || page.group === "Feed Adapters";
    const logoTitle = isBrokerPage ? brokerLogoHTML(brokerSlug(page.id), "doc-logo-title-img") : null;

    const eb = document.createElement("span");
    eb.className = "eyebrow";
    eb.innerHTML = `<span class="pip"></span>${tabLabel(page.tab)} · ${page.group}`;

    body.insertBefore(head, h1);

    if (logoTitle) {
      const name = h1.textContent;
      h1.classList.add("doc-title-logo");
      h1.innerHTML = logoTitle + `<span class="sr-only">${name}</span>`;
      head.appendChild(h1);   // logo as the title
      head.appendChild(eb);   // eyebrow pill below the logo
    } else {
      head.appendChild(eb);
      head.appendChild(h1);
    }

    const lede = head.nextElementSibling;
    if (lede && lede.tagName === "P") { lede.classList.add("doc-lede"); head.appendChild(lede); }
  }

  /* ───────────────────────── TOC + scroll spy ───────────────────────── */
  function renderTOC(headings, path) {
    if (cleanupScrollSpy) { cleanupScrollSpy(); cleanupScrollSpy = null; }
    if (spyObserver) { spyObserver.disconnect(); spyObserver = null; }
    if (!headings.length) { els.toc.style.visibility = "hidden"; els.tocList.innerHTML = ""; return; }
    els.toc.style.visibility = "visible";
    els.tocList.innerHTML = headings
      .map((h) => `<a href="#/${path}/${h.id}" data-spy="${h.id}" class="${h.level === "H3" ? "h3" : ""}">${h.text}</a>`)
      .join("");

    const map = {};
    els.tocList.querySelectorAll("a").forEach((a) => (map[a.dataset.spy] = a));
    const targets = headings
      .map((h) => ({ ...h, el: document.getElementById(h.id) }))
      .filter((h) => h.el);
    let activeId = "";
    let tick = false;

    function setActive(id) {
      if (!id || id === activeId) return;
      activeId = id;
      els.tocList.querySelectorAll("a").forEach((a) => a.classList.toggle("active", a.dataset.spy === id));
    }

    function updateActiveHeading() {
      tick = false;
      if (!targets.length) return;

      const topOffset = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--top-h")) || 58;
      const readingLine = topOffset + Math.min(120, window.innerHeight * 0.22);
      let current = targets[0];

      for (const target of targets) {
        if (target.el.getBoundingClientRect().top <= readingLine) current = target;
        else break;
      }

      setActive(current.id);
    }

    function queueUpdate() {
      if (tick) return;
      tick = true;
      requestAnimationFrame(updateActiveHeading);
    }

    window.addEventListener("scroll", queueUpdate, { passive: true });
    window.addEventListener("resize", queueUpdate);
    cleanupScrollSpy = () => {
      window.removeEventListener("scroll", queueUpdate);
      window.removeEventListener("resize", queueUpdate);
    };
    updateActiveHeading();
    setTimeout(queueUpdate, 80);
  }

  /* ───────────────────────── Breadcrumb + footer ───────────────────────── */
  function breadcrumbHTML(page) {
    const tab = TABS.find((t) => t.id === page.tab);
    const isHome = page.id === DEFAULT_PAGE;
    let html = `<div class="breadcrumb"><a href="#/${DEFAULT_PATH}">Home</a>`;
    if (!isHome) {
      html += `<span class="sep">›</span><a href="#/${FIRST_PAGE_OF_TAB[page.tab]}">${tab ? tab.label : ""}</a>`;
      html += `<span class="sep">›</span><span>${page.group}</span>`;
      html += `<span class="sep">›</span><span>${page.title}</span>`;
    }
    html += `</div>`;
    return html;
  }

  function renderFooter(pageId) {
    const i = PAGE_ORDER.indexOf(pageId);
    const prev = i > 0 ? PAGES[PAGE_ORDER[i - 1]] : null;
    const next = i < PAGE_ORDER.length - 1 ? PAGES[PAGE_ORDER[i + 1]] : null;
    let html = "";
    html += prev
      ? `<a class="foot-link prev" href="#/${prev.path}"><span class="fl-dir">&lsaquo; Previous</span><span class="fl-title">${prev.title}</span></a>`
      : `<span class="foot-link" style="visibility:hidden"></span>`;
    html += next
      ? `<a class="foot-link next" href="#/${next.path}"><span class="fl-dir">Next &rsaquo;</span><span class="fl-title">${next.title}</span></a>`
      : `<span class="foot-link" style="visibility:hidden"></span>`;
    els.pageFoot.innerHTML = html;
  }

  /* ───────────────────────── Routing ───────────────────────── */
  /* Returns { pageId, anchor } for a resolved route,
     or { redirect } when a legacy/unknown hash should be rewritten.        */
  function parseRoute() {
    const h = location.hash.replace(/^#\/?/, "");
    if (!h) return { pageId: DEFAULT_PAGE, anchor: null };

    if (PATH_TO_ID[h]) return { pageId: PATH_TO_ID[h], anchor: null };

    for (const path of PATHS_BY_LENGTH) {
      if (h.startsWith(path + "/")) return { pageId: PATH_TO_ID[path], anchor: h.slice(path.length + 1) };
    }

    /* Legacy flat slug:  #/<id>  or  #/<id>/<anchor>  → redirect to canonical. */
    const slash = h.indexOf("/");
    const legacyId = slash === -1 ? h : h.slice(0, slash);
    const legacyAnchor = slash === -1 ? "" : h.slice(slash + 1);
    if (REDIRECTS[legacyId]) {
      return { redirect: `#/${REDIRECTS[legacyId]}${legacyAnchor ? "/" + legacyAnchor : ""}` };
    }
    return { redirect: `#/${DEFAULT_PATH}` };
  }

  let currentPage = null;

  async function fetchMarkdown(pageId) {
    if (mdCache[pageId]) return mdCache[pageId];
    const res = await fetch(`content/${pageId}.md`, { cache: "no-cache" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    mdCache[pageId] = text;
    return text;
  }

  function showLoading() {
    els.doc.innerHTML = `<div class="doc-loading"><span class="spinner"></span> Loading…</div>`;
  }

  function showError(pageId, err) {
    const isFile = location.protocol === "file:";
    els.doc.innerHTML =
      `<h1>Couldn’t load this page</h1>` +
      (isFile
        ? `<div class="callout danger"><svg class="callout-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M15 9l-6 6M9 9l6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg><div class="callout-body"><span class="callout-title">Run a local server</span><p>This site loads Markdown with <code>fetch()</code>, which browsers block on <code>file://</code>. Start a tiny static server from the <code>DocsSite</code> folder and open the printed URL:</p><pre><code>python -m http.server 8080</code></pre><p>Then visit <a href="http://localhost:8080">http://localhost:8080</a>.</p></div></div>`
        : `<p class="lede">Could not fetch <code>content/${pageId}.md</code> (${err.message}).</p>`);
    els.tocList.innerHTML = "";
    els.pageFoot.innerHTML = "";
  }

  async function navigate() {
    const route = parseRoute();
    if (route.redirect) { location.replace(route.redirect); return; }

    const { pageId, anchor } = route;
    const page = PAGES[pageId];
    if (!page) { location.replace(`#/${DEFAULT_PATH}`); return; }

    // Same page, just an anchor change → scroll only.
    if (pageId === currentPage) {
      if (anchor) scrollToAnchor(anchor);
      return;
    }

    renderTabs(page.tab);
    renderDrawerTabs(page.tab);
    renderSidebar(page.tab, pageId);
    document.body.classList.toggle("marketing", !!page.marketing);
    document.title = `${page.title} · Fenix Dev Docs`;
    closeSidebar();
    showLoading();

    let md;
    try {
      md = await fetchMarkdown(pageId);
    } catch (err) {
      currentPage = pageId;
      showError(pageId, err);
      return;
    }

    const html = marked.parse(md);
    els.doc.innerHTML = breadcrumbHTML(page) + `<div class="page-body">${html}</div>`;
    els.doc.classList.remove("fade-in"); void els.doc.offsetWidth; els.doc.classList.add("fade-in");
    const headings = enhanceDoc(els.doc, page.path);
    if (!page.marketing) decorateDocHeader(els.doc, page);
    renderTOC(headings, page.path);
    renderFooter(pageId);
    initPageWidgets(els.doc);
    revealOnScroll(els.doc);
    currentPage = pageId;

    if (anchor) scrollToAnchor(anchor);
    else window.scrollTo({ top: 0, behavior: "auto" });
  }

  function scrollToAnchor(id) {
    requestAnimationFrame(() => {
      const el = document.getElementById(id);
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  /* ───────────────────────── Mobile sidebar ───────────────────────── */
  function openSidebar()  {
    // Show the open drawer in sync with the current page's section.
    if (currentPage && PAGES[currentPage]) renderDrawerTabs(PAGES[currentPage].tab);
    els.sidebar.classList.add("open");
    els.scrim.classList.add("show");
    els.menuToggle.setAttribute("aria-expanded", "true");
    document.body.classList.add("nav-open");      // lock background scroll
    els.sidebar.scrollTop = 0;
  }
  function closeSidebar() {
    closeDrawerMenu();
    els.sidebar.classList.remove("open");
    els.scrim.classList.remove("show");
    els.menuToggle.setAttribute("aria-expanded", "false");
    document.body.classList.remove("nav-open");
  }
  function initSidebarToggle() {
    els.menuToggle.addEventListener("click", () => els.sidebar.classList.contains("open") ? closeSidebar() : openSidebar());
    els.scrim.addEventListener("click", closeSidebar);
    // Recoverable: Escape closes the section menu first, then the drawer.
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      if (drawerMenuOpen) closeDrawerMenu();
      else if (els.sidebar.classList.contains("open")) closeSidebar();
    });
    initDrawerTabs();
  }

  /* ───────────────────────── Search ───────────────────────── */
  let searchIndex = [];
  let fullIndexed = false;
  let activeResult = -1;

  function hrefFor(pageId, anchor) {
    const p = PAGES[pageId];
    return anchor ? `#/${p.path}/${anchor}` : `#/${p.path}`;
  }

  function buildBaseIndex() {
    searchIndex = PAGE_ORDER.map((id) => {
      const p = PAGES[id];
      return { page: id, title: p.title, crumb: `${tabLabel(p.tab)} › ${p.group}`, anchor: null, text: p.desc || "", weight: 0 };
    });
  }
  function tabLabel(tabId) { const t = TABS.find((x) => x.id === tabId); return t ? t.label : ""; }

  async function buildFullIndex() {
    if (fullIndexed) return;
    fullIndexed = true;
    await Promise.all(
      PAGE_ORDER.map(async (id) => {
        try {
          const md = await fetchMarkdown(id);
          const p = PAGES[id];
          md.split("\n").forEach((line) => {
            const hm = line.match(/^(#{2,3})\s+(.*)/);
            if (hm) {
              const text = hm[2].replace(/[*`]/g, "").trim();
              searchIndex.push({ page: id, title: text, crumb: `${p.title}`, anchor: slugify(text), text: "", weight: 1 });
            }
          });
          const blob = md.replace(/```[\s\S]*?```/g, " ").replace(/[#*_>`|-]/g, " ").replace(/\s+/g, " ").toLowerCase();
          const base = searchIndex.find((e) => e.page === id && e.weight === 0);
          if (base) base.body = blob;
        } catch (e) {/* ignore */}
      })
    );
  }

  function runSearch(q) {
    q = q.trim().toLowerCase();
    if (!q) {
      renderResults(
        PAGE_ORDER.slice(0, 7).map((id) => ({ page: id, title: PAGES[id].title, crumb: `${tabLabel(PAGES[id].tab)} › ${PAGES[id].group}`, anchor: null })),
        ""
      );
      return;
    }
    const terms = q.split(/\s+/);
    const scored = [];
    searchIndex.forEach((e) => {
      const hay = e.title.toLowerCase();
      let score = 0;
      terms.forEach((t) => {
        if (hay.includes(t)) score += hay.startsWith(t) ? 12 : 8;
        if ((e.text || "").toLowerCase().includes(t)) score += 4;
        if ((e.body || "").includes(t)) score += 1.5;
      });
      if (e.weight === 1) score *= 1.05;
      if (score > 0) scored.push({ e, score });
    });
    scored.sort((a, b) => b.score - a.score);
    const seen = new Set();
    const top = [];
    for (const s of scored) {
      const key = s.e.page + (s.e.anchor || "");
      if (seen.has(key)) continue;
      seen.add(key);
      top.push(s.e);
      if (top.length >= 12) break;
    }
    renderResults(top, q);
  }

  function highlight(text, q) {
    if (!q) return text;
    try {
      const re = new RegExp(`(${q.split(/\s+/).map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`, "ig");
      return text.replace(re, "<mark>$1</mark>");
    } catch (e) { return text; }
  }

  function renderResults(list, q) {
    activeResult = -1;
    if (!list.length) { els.searchResults.innerHTML = `<div class="search-empty">No results for “${q}”.</div>`; return; }
    els.searchResults.innerHTML = list
      .map((e, i) => {
        const href = hrefFor(e.page, e.anchor);
        return `<a class="search-result" data-i="${i}" href="${href}"><div class="sr-crumb">${e.crumb}</div><div class="sr-title">${highlight(e.title, q)}</div>${e.text ? `<div class="sr-snippet">${e.text}</div>` : ""}</a>`;
      })
      .join("");
    $$(".search-result", els.searchResults).forEach((r) =>
      r.addEventListener("click", () => closeSearch())
    );
  }

  function openSearch() {
    els.searchModal.hidden = false;
    els.searchInput.value = "";
    runSearch("");
    setTimeout(() => els.searchInput.focus(), 30);
    buildFullIndex();
  }
  function closeSearch() { els.searchModal.hidden = true; }

  function initSearch() {
    buildBaseIndex();
    els.searchTrigger.addEventListener("click", openSearch);
    els.searchInput.addEventListener("input", (e) => runSearch(e.target.value));
    els.searchModal.addEventListener("click", (e) => { if (e.target === els.searchModal) closeSearch(); });

    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); els.searchModal.hidden ? openSearch() : closeSearch(); }
      if (els.searchModal.hidden) return;
      const results = $$(".search-result", els.searchResults);
      if (e.key === "Escape") closeSearch();
      else if (e.key === "ArrowDown") { e.preventDefault(); activeResult = Math.min(activeResult + 1, results.length - 1); updateActive(results); }
      else if (e.key === "ArrowUp") { e.preventDefault(); activeResult = Math.max(activeResult - 1, 0); updateActive(results); }
      else if (e.key === "Enter") { if (results[activeResult]) { location.hash = results[activeResult].getAttribute("href").slice(1); closeSearch(); } }
    });
  }
  function updateActive(results) {
    results.forEach((r, i) => r.classList.toggle("active", i === activeResult));
    if (results[activeResult]) results[activeResult].scrollIntoView({ block: "nearest" });
  }

  /* ───────────────────────── Boot ───────────────────────── */
  function init() {
    if (window.hljs) hljs.configure({ ignoreUnescapedHTML: true });
    marked.setOptions({ gfm: true, breaks: false, headerIds: false, mangle: false });
    initTheme();
    initSidebarToggle();
    initSidebarGroups();
    initSearch();
    window.addEventListener("hashchange", navigate);
    navigate();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
