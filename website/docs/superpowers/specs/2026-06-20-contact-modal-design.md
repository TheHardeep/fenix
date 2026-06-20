# Fenix-Pro Pricing — Contact Modal

**Date:** 2026-06-20
**Scope:** `content/pro-pricing.md`, `assets/css/styles.css`, `assets/js/app.js` (plus a small new `assets/js/contact-modal.js`), and `index.html` (cache-bust bumps).
**Goal:** When a visitor clicks any of the three pricing CTAs on the Fenix-Pro pricing page, open a premium in-page contact modal instead of navigating away. The modal displays direct contact channels (WhatsApp and email) tailored to the plan they clicked.

## 1. Behavior

### 1.1 Trigger
Three CTAs on `content/pro-pricing.md` open the modal:

| Plan       | Button label       | `data-contact-cta` value |
|------------|--------------------|--------------------------|
| Individual | Get Started        | `individual`             |
| Pro        | Start Free Trial   | `pro`                    |
| Team       | Contact Us         | `team`                   |

Each `<a class="btn pc-cta">` keeps its existing `href="https://hardeep.tech/projects/fenixpro"` as a no-JS / middle-click fallback. A delegated click handler in `contact-modal.js` listens for `click` events on `[data-contact-cta]`, calls `event.preventDefault()` (only for plain left-clicks — see §4.4), and opens the modal with the plan value as context.

### 1.2 Open / close
- **Open:** populate modal content from the plan (see §2), append `body.modal-open` (locks scroll via `overflow:hidden`), play entrance animation, move focus to the first interactive element inside the modal (the WhatsApp card).
- **Close:** any of —
  - click on the backdrop (outside the panel)
  - press `Esc`
  - click the close button (`.cm-close`, top-right of the panel)

  Closing plays the exit animation, removes `body.modal-open`, and returns focus to the originating CTA button.

- **Re-open:** safe; only one modal instance exists in the DOM, content is repopulated on each open.

### 1.3 Focus management
- Focus trap inside `.cm-panel` while open. Tab order follows DOM order: close button → WhatsApp link → WhatsApp copy → Email link → Email copy → footer link → wraps back to close.
- `aria-modal="true"`, `role="dialog"`, `aria-labelledby` pointing at the modal title element.

### 1.4 Body scroll lock
While open: `<body>` gets `class="modal-open"` which sets `overflow:hidden`. Removed on close. No scrollbar-gap compensation needed (the site uses overlay scrollbars on macOS/iOS and a thin scrollbar on Windows; minor reflow is acceptable and unchanged from existing overlay patterns).

## 2. Modal content (per plan)

The modal is a single component instantiated once. On open, the following fields are filled from a plan map keyed by `data-contact-cta`:

```js
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
```

### 2.1 Static fields (same across plans)
- **WhatsApp number** (display): `+91 70874 51073`
- **WhatsApp number** (for `wa.me` URL, no `+`): `917087451073`
- **WhatsApp number** (for clipboard copy, with `+`): `+917087451073`
- **Email**: `contact@hardeep.tech`
- **"What to include" checklist:**
  - Which broker(s) you trade on
  - Approx. ticks/sec you expect
  - Where you'll run it (laptop, VPS, prod server)
- **Footer line:** "Replies within 24h · Mon–Sat, 10am–8pm IST"
- **Footer link:** `hardeep.tech` → `https://hardeep.tech` (new tab, `rel="noopener"`)

### 2.2 Composed action URLs
- WhatsApp link: `https://wa.me/917087451073?text=` + `encodeURIComponent(PLAN_COPY[plan].waText)`
- Email link: `mailto:contact@hardeep.tech?subject=` + `encodeURIComponent(PLAN_COPY[plan].mailSub)` + `&body=` + `encodeURIComponent("Hi Hardeep,\n\n")`

### 2.3 Copy buttons
Each contact card has a small ghost button labelled "Copy" in its top-right corner:
- WhatsApp Copy → writes the raw number `+917087451073` to clipboard.
- Email Copy → writes `contact@hardeep.tech` to clipboard.

On success the button text morphs to "Copied" for 1400ms, then reverts. Uses `navigator.clipboard.writeText`; on failure (older browser / non-secure context), falls back to a hidden `<textarea>` + `document.execCommand('copy')`. Failure path simply skips the morph and logs to console — no error UI.

## 3. Visual design

Reuses the existing site design tokens — no new palette, font, or icon set.

### 3.1 Layout
- **Overlay:** `position:fixed; inset:0; z-index:60`. Background `rgba(0,0,0,0.55)` with `backdrop-filter: blur(20px) saturate(120%)`. Clicking the overlay (but not its children) closes.
- **Panel** (`.cm-panel`): `position:relative; width:min(560px, calc(100vw - 32px)); margin:auto`. Vertically centered via flex on the overlay (`display:flex; align-items:center; justify-content:center`).
- **Double-bezel:** outer shell `padding:6px; border-radius:28px; background: var(--glass); border:1px solid var(--line); box-shadow: inset 0 1px 0 var(--inset-hi), 0 30px 80px -20px rgba(0,0,0,.6)`. Inner core `padding:28px; border-radius:22px; background: var(--bg-elev); border:1px solid var(--line-2)`.
- **Ember glow:** a `::before` pseudo on `.cm-panel` — top-left, `radial-gradient(circle at 0% 0%, rgba(255,138,76,.22), transparent 60%)`, `pointer-events:none`, `opacity:.9`, `mix-blend-mode:screen`. Echoes the ambient orb field.

### 3.2 Header
- Eyebrow pill: existing `.eyebrow` style (10px, tracked, ember tint).
- Title: 26px, weight 700, `var(--text)`, line-height 1.15.
- Lede: 15px, `var(--text-2)`, line-height 1.55.
- Close button: 32×32 circular `.cm-close`, top-right of inner core, uses an ultra-light X glyph (inline SVG `stroke-width:1.25`). Hover: `bg:rgba(255,255,255,.06)`.

### 3.3 Contact cards (`.cm-actions`)
- Container: `display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:24px`.
- Each card (`.cm-card`) is a **`<div>`** (not an anchor), using the *stretched-link* pattern so the `<a>` and the copy `<button>` can coexist without nesting:
  - Outer shell `padding:4px; border-radius:20px; background:rgba(255,255,255,.03); border:1px solid var(--line); position:relative`.
  - Inner core `padding:18px 16px; border-radius:16px; background:var(--bg); border:1px solid var(--line-2); box-shadow: inset 0 1px 0 var(--inset-hi); display:flex; flex-direction:column; gap:6px; position:relative`.
  - Top row: line icon (24×24) + channel label (12px, tracked, `var(--text-2)`).
  - Value row: the address/number, 17px, weight 600, `var(--text)`.
  - Bottom-right: a button-in-button arrow circle (`.ic`), 28px, `border-radius:999px; background:rgba(255,255,255,.06)`. Contains a 14px line arrow glyph. Decorative.
  - **Main link** (`a.cm-card-link`): visually empty, `position:absolute; inset:0; border-radius:inherit; z-index:1; aria-label="Open WhatsApp" / "Open email"`. Carries the `href` and (for WhatsApp) `target="_blank" rel="noopener"`. Stretches over the card so the whole surface is clickable.
  - Top-right: `.cm-copy` `<button type="button">` ghost button — 11px text, tracked, no border, fades in at 50% opacity, full opacity on card hover or focus. `position:relative; z-index:2` so it sits *above* the stretched link and receives its own clicks without triggering the link.
  - Hover (whole card, including keyboard focus-within): `translateY(-2px)`, ember-tinted border `1px solid var(--ember-edge, rgba(255,138,76,.4))`, inner arrow circle `translateX(2px) translateY(-1px) scale(1.05)`.

`--ember-edge: rgba(255,138,76,.4)` is added to the `:root` block of the contact-modal CSS section if it doesn't already exist elsewhere in `styles.css`.

### 3.4 What-to-include block
- Margin-top:24px. Mini eyebrow "INCLUDE IN YOUR FIRST MESSAGE" (10px, tracked, `var(--text-3)`).
- Three short lines, each prefixed by an ember `•` dot, font-size 13px, `var(--text-2)`.

### 3.5 Footer
- Margin-top:22px, padding-top:18px, top hairline `border-top:1px solid var(--line)`.
- `display:flex; justify-content:space-between; align-items:center`, font-size 12px, `var(--text-3)`.
- Right link uses an inline 12px arrow glyph after the text.

### 3.6 Icons
- WhatsApp: ultra-light line glyph (speech bubble + comma tail), `stroke-width:1.25`, `currentColor`.
- Email: ultra-light envelope, `stroke-width:1.25`, `currentColor`.
- Close X, copy icon if any, arrows: same stroke discipline.

All icons are inline SVG strings stored alongside the modal template in `contact-modal.js` — no new icon set, no dependency. They follow the same ultra-light line aesthetic as the existing `ICON_PATHS` in `app.js`.

## 4. Motion

All easing uses `var(--ember)` = `cubic-bezier(.32,.72,0,1)` (already defined in `styles.css`).

### 4.1 Entrance
- Overlay: opacity `0 → 1` over 220ms ease-out.
- Panel: `opacity:0; transform: translateY(12px) scale(.96)` → `opacity:1; transform: translateY(0) scale(1)` over 360ms with `var(--ember)`.
- Contact cards: stagger reveal — each card starts at `opacity:0; transform:translateY(8px)`, animates to `0/1` with `60ms` increment (`delay: 80ms, 140ms`).

### 4.2 Exit
- Reverse of entrance, 220ms. After the transition ends, the overlay is removed from the live DOM tree (kept hidden via `display:none` between opens to keep one persistent instance — see §5.2).

### 4.3 Hover micro-motion
- Cards: transform + border-color transition `300ms var(--ember)`.
- Arrow circle inside card: transform transition `400ms var(--ember)`.
- Copy button morph "Copy" → "Copied": text swap is instant (no width-animation jank); a 240ms opacity flicker masks the swap.

### 4.4 Reduced motion
Honors the existing site-wide `prefers-reduced-motion: reduce` policy: transforms and blur are stripped on the panel and cards; opacity fades remain so the open/close is still perceivable. Backdrop blur is kept (it's not animated, just a static effect).

### 4.5 Click semantics — when NOT to intercept
The handler calls `preventDefault()` only when the click is a plain primary-button click without modifiers. If any of the following is true, the click falls through to the native `href` (open in new tab / new window / save):
- `event.button !== 0` (not a left click)
- `event.metaKey || event.ctrlKey || event.shiftKey || event.altKey`
- The link has `target="_blank"` *and* the user is middle-clicking (already covered by button check, listed for clarity)

This preserves middle-click and modifier-click behavior — a user who Ctrl-clicks "Get Started" still opens hardeep.tech in a new tab.

## 5. Implementation

### 5.1 Files touched
| File | Change |
|---|---|
| `content/pro-pricing.md` | Add `data-contact-cta="individual\|pro\|team"` to the three `.pc-cta` anchors. Leave `href` and `target="_blank"` intact. |
| `assets/css/styles.css` | New section `/* ============ contact modal ============ */` appended at the end. Tokens reused; no new variables required except optionally `--ember-edge: rgba(255,138,76,.4)` if not already present. |
| `assets/js/contact-modal.js` | **New file.** Exports an `initContactModal()` function that injects the modal DOM once, wires the delegated click handler on `document`, and handles open/close/focus-trap/copy. |
| `assets/js/app.js` | Import / call `initContactModal()` once at boot, after the existing init wiring. |
| `index.html` | Add `<script src="assets/js/contact-modal.js?v=1"></script>` before `app.js`; bump `styles.css` and `app.js` cache-busts. |

### 5.2 Lifecycle
- The modal DOM is built once on first init and appended to `<body>`, hidden via `display:none`.
- Each open: set plan-specific content, set `display:flex`, force a reflow (`void overlay.offsetWidth`), then add an `.is-open` class that triggers the entrance transitions.
- Each close: remove `.is-open` (plays exit), then on `transitionend` of the panel (or a 400ms `setTimeout` fallback in case `transitionend` doesn't fire) set `display:none`.

### 5.3 DOM skeleton (rendered once)

```html
<div class="cm-overlay" role="dialog" aria-modal="true" aria-labelledby="cm-title" hidden>
  <div class="cm-panel">
    <div class="cm-inner">
      <button class="cm-close" aria-label="Close">…</button>
      <div class="cm-eyebrow"></div>
      <h2 class="cm-title" id="cm-title"></h2>
      <p class="cm-lede"></p>
      <div class="cm-actions">
        <div class="cm-card cm-wa">
          <a class="cm-card-link" href="" target="_blank" rel="noopener" aria-label="Open WhatsApp chat"></a>
          <button type="button" class="cm-copy" data-copy="wa" aria-live="polite">Copy</button>
          <div class="cm-channel">…icon… <span>WhatsApp</span></div>
          <div class="cm-value">+91 70874 51073</div>
          <span class="ic" aria-hidden="true">…arrow…</span>
        </div>
        <div class="cm-card cm-email">
          <a class="cm-card-link" href="" aria-label="Compose email to contact@hardeep.tech"></a>
          <button type="button" class="cm-copy" data-copy="email" aria-live="polite">Copy</button>
          <div class="cm-channel">…icon… <span>Email</span></div>
          <div class="cm-value">contact@hardeep.tech</div>
          <span class="ic" aria-hidden="true">…arrow…</span>
        </div>
      </div>
      <div class="cm-include">
        <div class="cm-include-eyebrow">INCLUDE IN YOUR FIRST MESSAGE</div>
        <ul>
          <li>Which broker(s) you trade on</li>
          <li>Approx. ticks/sec you expect</li>
          <li>Where you'll run it (laptop, VPS, prod server)</li>
        </ul>
      </div>
      <div class="cm-footer">
        <span>Replies within 24h · Mon–Sat, 10am–8pm IST</span>
        <a href="https://hardeep.tech" target="_blank" rel="noopener">hardeep.tech →</a>
      </div>
    </div>
  </div>
</div>
```

### 5.4 Public surface
`contact-modal.js` exposes:
- `initContactModal()` — call once at boot. Idempotent.
- (Internal) `openContactModal(plan)` and `closeContactModal()` — not exported; reachable only via the click delegation.

No external dependencies. No framework.

## 6. Responsive

- **≥ 720px:** as specified above, two-column contact cards.
- **< 720px:** contact cards stack (`grid-template-columns: 1fr`). Panel padding shrinks from `28px` to `22px`. Title drops from 26px to 22px. Footer wraps into two stacked rows with `gap:8px`.
- **< 420px:** further reduce panel inner padding to `18px`. Modal is full-width minus `12px` gutters.

## 7. Accessibility

- `role="dialog"`, `aria-modal="true"`, `aria-labelledby="cm-title"` on the overlay container.
- Focus trap implemented by querying focusable elements within `.cm-panel` on open and intercepting `Tab` / `Shift+Tab` at the boundaries.
- Focus returns to the originating CTA on close; the CTA reference is stashed in a closure variable when `openContactModal` is invoked.
- `Esc` closes regardless of focus location inside the modal.
- Close button has `aria-label="Close"`.
- Copy buttons are `<button type="button">`, focusable, with `aria-live="polite"` text swap so screen readers announce "Copied".
- Color contrast checked: title at `var(--text)` on `var(--bg-elev)` passes WCAG AA; lede at `var(--text-2)` passes AA at 15px.

## 8. Out of scope

The following are explicitly excluded from this change:
- Contact form (no Name/Email/Message form, no submission backend).
- Scheduling / Calendly integration.
- Analytics events (no tracking pixels or custom events on open/copy/click).
- Modal usage outside the pricing page (other pages keep their existing CTAs untouched).
- Social media links (Twitter/X, LinkedIn, GitHub).
- Internationalization — copy is English-only, IST hours hard-coded.

## 9. Cache-busting

Per the site's existing convention, after editing the touched files bump the `?v=N` suffix in `index.html`:
- `styles.css` → next version
- `app.js` → next version
- `contact-modal.js` → `?v=1` on first publish

## 10. Acceptance criteria

1. Clicking "Get Started" on the Individual card opens the modal with the *Individual* eyebrow, title, and prefilled WhatsApp/email content. The page does **not** navigate away.
2. Same for "Start Free Trial" (Pro) and "Contact Us" (Team), with their respective copy.
3. Ctrl/Cmd-click on any CTA opens `hardeep.tech` in a new tab (default behavior preserved).
4. Middle-click on any CTA opens `hardeep.tech` in a new tab.
5. Clicking the WhatsApp card opens `https://wa.me/917087451073?text=...` in a new tab with the prefilled plan-specific message.
6. Clicking the email card opens the user's mail client with `mailto:contact@hardeep.tech?subject=...` prefilled.
7. Clicking "Copy" on either card copies the raw value to clipboard and shows the "Copied" state for ~1.4s.
8. `Esc`, backdrop click, and close button all close the modal.
9. After close, focus returns to the originating CTA.
10. The modal stacks to a single column and remains usable below `720px` width.
11. With `prefers-reduced-motion: reduce`, the modal still opens/closes (fade only, no transform / blur animation).
12. No regression to the existing pricing-page layout, table, or FAQ sections.
