/* ============================================================================
   Fenix-Pro — Contact Modal
   Intercepts clicks on [data-contact-cta] (the pricing page CTAs) and opens
   a glass contact modal with plan-tailored copy + WhatsApp/email channels.
   Vanilla, zero dependencies. Init once at boot.
   ============================================================================ */
(function () {
  "use strict";

  const WA_NUM_URL   = "917087451073";       // wa.me — no plus
  const WA_NUM_COPY  = "+917087451073";       // clipboard — with plus
  const WA_NUM_SHOW  = "+91 70874 51073";     // display (grouped)
  const EMAIL        = "contact@hardeep.tech";
  const SITE         = "hardeep.tech";

  const PLAN_COPY = {
    individual: {
      eyebrow: "LET'S TALK · INDIVIDUAL",
      title:   "Start with Individual",
      lede:    "Solo trader plan, ₹599/month. Send a quick note with your broker preferences and I'll get you set up.",
      waText:  "Hi Hardeep, interested in Fenix-Pro Individual.",
      mailSub: "Fenix-Pro Individual inquiry",
    },
    pro: {
      eyebrow: "LET'S TALK · PRO",
      title:   "Start your Pro free trial",
      lede:    "7-day trial on the house. Reach out and I'll get you onboarded the same day.",
      waText:  "Hi Hardeep, I'd like to start the Fenix-Pro 7-day trial.",
      mailSub: "Fenix-Pro trial request",
    },
    team: {
      eyebrow: "LET'S TALK · TEAM",
      title:   "Let's set up your team",
      lede:    "Team plan with custom adapters and direct support channel. Tell me about your stack and I'll scope it with you.",
      waText:  "Hi Hardeep, interested in Fenix-Pro Team plan for our desk.",
      mailSub: "Fenix-Pro Team inquiry",
    },
  };

  /* ---- ultra-light line icons (stroke 1.25) ---- */
  const ICON_WA =
    '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">' +
      '<path d="M4 20l1.3-4.2A8 8 0 1 1 8.4 18.8L4 20z" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/>' +
      '<path d="M9 9.5c0 3 2.5 5.5 5.5 5.5l1.2-1.2-2.1-1-.9.7c-.8-.3-1.5-1-1.8-1.8l.7-.9-1-2.1L9.5 9.5H9z" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/>' +
    '</svg>';
  const ICON_MAIL =
    '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">' +
      '<rect x="3" y="5.5" width="18" height="13" rx="2" fill="none" stroke="currentColor" stroke-width="1.25"/>' +
      '<path d="M3.5 6.5l8.5 6.5 8.5-6.5" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/>' +
    '</svg>';
  const ICON_ARROW =
    '<svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">' +
      '<path d="M7 17L17 7M9 7h8v8" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</svg>';
  const ICON_CLOSE =
    '<svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">' +
      '<path d="M6 6l12 12M18 6L6 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
    '</svg>';
  const ICON_ARROW_TINY =
    '<svg viewBox="0 0 24 24" width="11" height="11" aria-hidden="true" style="vertical-align:-1px;margin-left:4px">' +
      '<path d="M5 12h14M13 5l7 7-7 7" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</svg>';
  const ICON_CLIP =
    '<svg viewBox="0 0 24 24" aria-hidden="true">' +
      '<rect x="9" y="9" width="11" height="11" rx="2" fill="none" stroke="currentColor" stroke-width="1.5"/>' +
      '<path d="M5 15V5a2 2 0 0 1 2-2h10" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
    '</svg>';
  const ICON_CHECK =
    '<svg viewBox="0 0 24 24" aria-hidden="true">' +
      '<path d="M5 12.5l4.5 4.5L19 7" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</svg>';

  let overlay = null;
  let panel = null;
  let titleEl = null;
  let eyebrowEl = null;
  let ledeEl = null;
  let waLink = null;
  let mailLink = null;
  let closeBtn = null;
  let waCopyBtn = null;
  let mailCopyBtn = null;
  let returnFocusEl = null;
  let isOpen = false;

  function build() {
    overlay = document.createElement("div");
    overlay.className = "cm-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-labelledby", "cm-title");
    overlay.hidden = true;

    overlay.innerHTML =
      '<div class="cm-panel">' +
        '<div class="cm-inner">' +
          '<button type="button" class="cm-close" aria-label="Close">' + ICON_CLOSE + '</button>' +
          '<span class="eyebrow cm-eyebrow"><span class="pip"></span><span class="cm-eyebrow-text"></span></span>' +
          '<h2 class="cm-title" id="cm-title"></h2>' +
          '<p class="cm-lede"></p>' +
          '<div class="cm-actions">' +
            '<div class="cm-card cm-wa">' +
              '<a class="cm-card-link" href="#" target="_blank" rel="noopener" aria-label="Open WhatsApp chat"></a>' +
              '<button type="button" class="cm-copy" data-cm-copy="wa" aria-label="Copy WhatsApp number" title="Copy number">' + ICON_CLIP + '</button>' +
              '<div class="cm-channel">' + ICON_WA + '<span>WhatsApp</span></div>' +
              '<div class="cm-value">' + WA_NUM_SHOW + '</div>' +
              '<span class="cm-ic" aria-hidden="true">' + ICON_ARROW + '</span>' +
            '</div>' +
            '<div class="cm-card cm-email">' +
              '<a class="cm-card-link" href="#" aria-label="Compose email to ' + EMAIL + '"></a>' +
              '<button type="button" class="cm-copy" data-cm-copy="email" aria-label="Copy email address" title="Copy email">' + ICON_CLIP + '</button>' +
              '<div class="cm-channel">' + ICON_MAIL + '<span>Email</span></div>' +
              '<div class="cm-value">' + EMAIL + '</div>' +
              '<span class="cm-ic" aria-hidden="true">' + ICON_ARROW + '</span>' +
            '</div>' +
          '</div>' +
          '<div class="cm-include">' +
            '<div class="cm-include-eyebrow">INCLUDE IN YOUR FIRST MESSAGE</div>' +
            '<ul>' +
              '<li>Which broker(s) you trade on</li>' +
              '<li>Approx. ticks/sec you expect</li>' +
              '<li>Where you\'ll run it (laptop, VPS, prod server)</li>' +
            '</ul>' +
          '</div>' +
          '<div class="cm-footer">' +
            '<span>Replies within 24h · Mon–Sat, 10am–8pm IST</span>' +
            '<a href="https://' + SITE + '" target="_blank" rel="noopener">' + SITE + ICON_ARROW_TINY + '</a>' +
          '</div>' +
        '</div>' +
      '</div>';

    document.body.appendChild(overlay);

    panel       = overlay.querySelector(".cm-panel");
    titleEl     = overlay.querySelector(".cm-title");
    eyebrowEl   = overlay.querySelector(".cm-eyebrow-text");
    ledeEl      = overlay.querySelector(".cm-lede");
    waLink      = overlay.querySelector(".cm-wa .cm-card-link");
    mailLink    = overlay.querySelector(".cm-email .cm-card-link");
    closeBtn    = overlay.querySelector(".cm-close");
    waCopyBtn   = overlay.querySelector('[data-cm-copy="wa"]');
    mailCopyBtn = overlay.querySelector('[data-cm-copy="email"]');

    /* Close interactions */
    closeBtn.addEventListener("click", close);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });

    /* Copy buttons */
    waCopyBtn.addEventListener("click",   (e) => { e.stopPropagation(); copyToClipboard(WA_NUM_COPY, waCopyBtn);   });
    mailCopyBtn.addEventListener("click", (e) => { e.stopPropagation(); copyToClipboard(EMAIL,       mailCopyBtn); });

    /* Focus trap + Esc */
    overlay.addEventListener("keydown", (e) => {
      if (!isOpen) return;
      if (e.key === "Escape") { e.preventDefault(); close(); return; }
      if (e.key !== "Tab") return;
      const focusables = focusableEls();
      if (!focusables.length) return;
      const first = focusables[0];
      const last  = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
  }

  function focusableEls() {
    return Array.from(panel.querySelectorAll(
      'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )).filter((el) => el.offsetParent !== null || el === document.activeElement);
  }

  function copyToClipboard(text, btn) {
    if (!btn.dataset.copyLabel) btn.dataset.copyLabel = btn.getAttribute("aria-label") || "Copy";
    const labelCopy = btn.dataset.copyLabel;
    const done = () => {
      btn.classList.add("copied");
      btn.innerHTML = ICON_CHECK;
      btn.setAttribute("aria-label", "Copied");
      setTimeout(() => {
        btn.classList.remove("copied");
        btn.innerHTML = ICON_CLIP;
        btn.setAttribute("aria-label", labelCopy);
      }, 1400);
    };
    const fail = () => { /* silent — no error UI */ };
    try {
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, fallback);
      } else fallback();
    } catch (e) { fallback(); }

    function fallback() {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "absolute";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        done();
      } catch (e) { fail(); }
    }
  }

  function open(plan, originEl) {
    if (!overlay) build();
    const copy = PLAN_COPY[plan] || PLAN_COPY.individual;

    eyebrowEl.textContent = copy.eyebrow;
    titleEl.textContent   = copy.title;
    ledeEl.textContent    = copy.lede;
    waLink.href   = "https://wa.me/" + WA_NUM_URL + "?text=" + encodeURIComponent(copy.waText);
    mailLink.href = "mailto:" + EMAIL +
                    "?subject=" + encodeURIComponent(copy.mailSub) +
                    "&body="    + encodeURIComponent("Hi Hardeep,\n\n");

    returnFocusEl = originEl || document.activeElement;
    overlay.hidden = false;
    overlay.style.display = "flex";
    document.body.classList.add("cm-open");
    /* force reflow so the transition runs from the initial state */
    void overlay.offsetWidth;
    overlay.classList.add("is-open");
    isOpen = true;

    /* Focus the first interactive element after entrance starts */
    setTimeout(() => {
      const first = focusableEls()[0];
      if (first) first.focus();
    }, 30);
  }

  function close() {
    if (!isOpen) return;
    isOpen = false;
    overlay.classList.remove("is-open");
    document.body.classList.remove("cm-open");

    let done = false;
    const finalize = () => {
      if (done) return;
      done = true;
      overlay.hidden = true;
      overlay.style.display = "none";
      panel.removeEventListener("transitionend", onEnd);
      if (returnFocusEl && typeof returnFocusEl.focus === "function") {
        try { returnFocusEl.focus(); } catch (e) {}
      }
    };
    const onEnd = (ev) => { if (ev.target === panel) finalize(); };
    panel.addEventListener("transitionend", onEnd);
    setTimeout(finalize, 400); // fallback if transitionend doesn't fire
  }

  /* Delegated click on any [data-contact-cta] */
  function onDelegatedClick(e) {
    const cta = e.target.closest("[data-contact-cta]");
    if (!cta) return;
    /* Honor middle-click / modifier-click → let the native href win */
    if (e.button !== 0) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    open(cta.getAttribute("data-contact-cta"), cta);
  }

  function init() {
    if (init._wired) return;
    init._wired = true;
    document.addEventListener("click", onDelegatedClick);
  }

  /* Public surface */
  window.FenixContactModal = { init: init, open: open, close: close };

  /* Auto-init at script load (idempotent) */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
