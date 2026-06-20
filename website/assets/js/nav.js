/* ============================================================================
   Fenix Docs — Navigation & Site Map
   Single source of truth for tabs, sidebar groups, hierarchical routing,
   legacy redirects, breadcrumbs, prev/next, and the search index.

   URL model (hierarchical):  #/<tab>/<slug>            e.g. #/brokers/zerodha
   Heading anchors:           #/<tab>/<slug>/<anchor>    e.g. #/api/orders/place
   Legacy flat slugs (#/broker-zerodha) auto-redirect to their canonical path.
   ============================================================================ */

const TABS = [
  { id: "guides",   label: "Guides" },
  { id: "concepts", label: "Core Concepts" },
  { id: "api",      label: "Unified API" },
  { id: "brokers",  label: "Brokers" },
  { id: "pro",      label: "Fenix-Pro" },
  { id: "examples", label: "Resources" },
];

/* The 15 fenix broker-adapter reference pages (generated from source). */
/* Per-broker logo files (in /logos). Keys are the slug after `broker-`/`pro-broker-`. */
const BROKER_LOGOS = {
  aliceblue:    "assets/img/brokers-grid/aliceblue.svg",
  angelone:     "assets/img/brokers-grid/angelone.svg",
  anandrathi:   "assets/img/brokers-grid/anandrathi.jpeg",
  dhan:         "assets/img/brokers-grid/dhan.svg",
  finvasia:     "assets/img/brokers-grid/finvasia.svg",
  fivepaisa:    "assets/img/brokers-grid/fivepaisa.svg",
  fyers:        "assets/img/brokers-grid/fyers.svg",
  groww:        "assets/img/brokers-grid/groww.svg",
  iifl:         "assets/img/brokers-grid/iifl.svg",
  kotak:        "assets/img/brokers-grid/kotakneo.svg",
  kotakneo:     "assets/img/brokers-grid/kotakneo.svg",
  kunjee:       "assets/img/brokers-grid/kunjee.png",
  mastertrust:  "assets/img/brokers-grid/mastertrust.svg",
  motilaloswal: "assets/img/brokers-grid/motilaloswal.jpeg",
  symphony:     "assets/img/brokers-grid/symphony.svg",
  upstox:       "assets/img/brokers-grid/upstox.svg",
  vpc:          "assets/img/brokers-grid/vpc.svg",
  zerodha:      "assets/img/brokers-grid/zerodha.svg",
};

const FENIX_BROKER_PAGES = [
  { id: "broker-aliceblue",    title: "AliceBlue" },
  { id: "broker-angelone",     title: "Angel One" },
  { id: "broker-anandrathi",   title: "Anand Rathi" },
  { id: "broker-dhan",         title: "Dhan" },
  { id: "broker-finvasia",     title: "Finvasia" },
  { id: "broker-fivepaisa",    title: "5paisa" },
  { id: "broker-fyers",        title: "Fyers" },
  { id: "broker-groww",        title: "Groww" },
  { id: "broker-iifl",         title: "IIFL" },
  { id: "broker-kotakneo",     title: "Kotak Neo" },
  { id: "broker-mastertrust",  title: "Master Trust" },
  { id: "broker-motilaloswal", title: "Motilal Oswal" },
  { id: "broker-symphony",     title: "Symphony" },
  { id: "broker-upstox",       title: "Upstox" },
  { id: "broker-zerodha",      title: "Zerodha" },
];

/* The 15 fenixpro live-feed adapter reference pages (generated from source). */
const PRO_BROKER_PAGES = [
  { id: "pro-broker-aliceblue",    title: "AliceBlue" },
  { id: "pro-broker-angelone",     title: "Angel One" },
  { id: "pro-broker-finvasia",     title: "Finvasia" },
  { id: "pro-broker-fivepaisa",    title: "5paisa" },
  { id: "pro-broker-fyers",        title: "Fyers" },
  { id: "pro-broker-iifl",         title: "IIFL" },
  { id: "pro-broker-kotak",        title: "Kotak" },
  { id: "pro-broker-kotakneo",     title: "Kotak Neo" },
  { id: "pro-broker-kunjee",       title: "Kunjee" },
  { id: "pro-broker-mastertrust",  title: "Master Trust" },
  { id: "pro-broker-motilaloswal", title: "Motilal Oswal" },
  { id: "pro-broker-symphony",     title: "Symphony" },
  { id: "pro-broker-upstox",       title: "Upstox" },
  { id: "pro-broker-vpc",          title: "VPC" },
  { id: "pro-broker-zerodha",      title: "Zerodha" },
];

/* Each group belongs to a tab and lists its pages in reading order.
   `icon`  → key into the ICONS line-icon set in app.js (no emoji).
   `slug`  → URL segment after the tab (defaults to the page id).        */
const GROUPS = [
  {
    tab: "guides", title: "Get Started",
    pages: [
      { id: "overview",   title: "Overview",     icon: "flame",   slug: "overview", marketing: true, desc: "What Fenix is and the one-API model." },
      { id: "install",    title: "Installation", icon: "package", slug: "installation", desc: "Install from PyPI and verify your setup." },
      { id: "quickstart", title: "Quickstart",   icon: "bolt",    slug: "quickstart",   desc: "Authenticate, load tokens, place an order." },
    ],
  },
  {
    tab: "concepts", title: "Architecture",
    pages: [
      { id: "architecture", title: "Architecture",           icon: "layers",      desc: "The Broker base class and request lifecycle." },
      { id: "describe",     title: "The describe() Method",   icon: "fingerprint", desc: "Every metadata key a broker declares." },
      { id: "api-endpoints",title: "API Endpoints & _API",    icon: "link",        desc: "How URLs are stored and resolved." },
      { id: "maps",         title: "Request / Response Maps", icon: "transform",   desc: "Translating between Fenix and broker formats." },
    ],
  },
  {
    tab: "concepts", title: "Standardization",
    pages: [
      { id: "constants",    title: "Constants & Standards", icon: "ruler",  desc: "Side, Product, OrderType, Validity, and more." },
      { id: "unified-json", title: "Unified JSON Schemas",  icon: "braces", desc: "The shape of every response Fenix returns." },
    ],
  },
  {
    tab: "concepts", title: "Reliability",
    pages: [
      { id: "logging",       title: "Logging & Redaction", icon: "file",  desc: "Verbose logs, response capture, secret redaction." },
      { id: "rate-limiting", title: "Rate Limiting",       icon: "gauge", desc: "Token-bucket throttling per endpoint group." },
      { id: "errors",        title: "Error Handling",      icon: "alert", desc: "The exception hierarchy and HTTP mapping." },
    ],
  },
  {
    tab: "api", title: "Trading",
    pages: [
      { id: "authentication", title: "Authentication",       icon: "lock",    desc: "Generate, reuse, and persist access tokens." },
      { id: "tokens",         title: "Instrument Tokens",    icon: "ticket",  desc: "Download and shape instrument masters." },
      { id: "orders",         title: "Orders",               icon: "receipt", desc: "Place, modify, cancel, and read orders." },
      { id: "positions",      title: "Positions & Holdings", icon: "chart",   desc: "Fetch positions and holdings." },
      { id: "account",        title: "Account & RMS",        icon: "wallet",  desc: "Margins, limits, and profile." },
    ],
  },
  {
    tab: "api", title: "Simulation",
    pages: [
      { id: "paper-mode", title: "Paper Mode", icon: "flask", desc: "Tick-driven simulated trading with no live calls." },
    ],
  },
  {
    tab: "brokers", title: "Reference",
    pages: [
      { id: "brokers",    title: "Supported Brokers", icon: "bank",   slug: "supported", desc: "The 15 brokers Fenix speaks to." },
      { id: "add-broker", title: "Adding a Broker",   icon: "puzzle", slug: "adding",    desc: "Implement an adapter from scratch." },
    ],
  },
  {
    tab: "brokers", title: "Broker Adapters",
    pages: FENIX_BROKER_PAGES.map((p) => {
      const slug = p.id.replace("broker-", "");
      return { ...p, icon: "building", logo: BROKER_LOGOS[slug], slug, desc: `${p.title} adapter reference.` };
    }),
  },
  {
    tab: "pro", title: "Fenix-Pro",
    pages: [
      { id: "pro-overview",   title: "Overview",     icon: "broadcast", slug: "overview", marketing: true, desc: "Real-time market data over WebSocket." },
      { id: "pro-install",    title: "Installation", icon: "package",   slug: "installation", desc: "Install Fenix-Pro from source." },
      { id: "pro-quickstart", title: "Quickstart",   icon: "bolt",      slug: "quickstart",   desc: "Connect a feed in a dozen lines." },
    ],
  },
  {
    tab: "pro", title: "Concepts",
    pages: [
      { id: "pro-callbacks",     title: "Callback Interface", icon: "bell",      slug: "callbacks",     desc: "on_ltp, on_depth, on_order, and friends." },
      { id: "pro-subscriptions", title: "Subscriptions",      icon: "target",    slug: "subscriptions", desc: "subscribe, subscribe_token, subscribe_fno_token." },
      { id: "pro-transports",    title: "Transport Families", icon: "satellite", slug: "transports",    desc: "websocket-client, Socket.IO, asyncio+protobuf." },
      { id: "pro-contracts",     title: "Data Contracts",     icon: "braces",    slug: "contracts",     desc: "The TickData and Order feed schemas." },
      { id: "pro-errors",        title: "Error Model",        icon: "alert",     slug: "errors",        desc: "Feed and bootstrap exceptions." },
    ],
  },
  {
    tab: "pro", title: "Plans",
    pages: [
      { id: "pro-pricing", title: "Pricing & Plans", icon: "card", slug: "pricing", desc: "Individual, Pro, and Team tiers." },
    ],
  },
  {
    tab: "pro", title: "Feed Adapters",
    pages: PRO_BROKER_PAGES.map((p) => {
      const slug = p.id.replace("pro-broker-", "");
      return { ...p, icon: "activity", logo: BROKER_LOGOS[slug], slug, desc: `${p.title} live-feed adapter reference.` };
    }),
  },
  {
    tab: "examples", title: "Recipes",
    pages: [
      { id: "examples",  title: "Cookbook",  icon: "book",    slug: "cookbook",  desc: "Copy-paste recipes for common workflows." },
      { id: "changelog", title: "Changelog", icon: "history", slug: "changelog", desc: "Release notes and version history." },
    ],
  },
];

/* ---- Derived lookups (built once) -------------------------------------- */
const PAGES = {};          /* id  → page entry (with tab, group, path)       */
const PATH_TO_ID = {};     /* "tab/slug" → id                                */
const REDIRECTS = {};      /* legacy flat slug (id) → canonical path         */
const PAGE_ORDER = [];     /* reading order, by id                           */

GROUPS.forEach((g) => {
  g.pages.forEach((p) => {
    const slug = p.slug || p.id;
    const path = `${g.tab}/${slug}`;
    const entry = { ...p, slug, path, tab: g.tab, group: g.title };
    PAGES[p.id] = entry;
    PATH_TO_ID[path] = p.id;
    REDIRECTS[p.id] = path;        /* old #/<id> → new #/<tab>/<slug> */
    PAGE_ORDER.push(p.id);
  });
});

/* Paths sorted longest-first, for prefix-matching the anchor off a route. */
const PATHS_BY_LENGTH = Object.keys(PATH_TO_ID).sort((a, b) => b.length - a.length);

const DEFAULT_PAGE = "overview";
const DEFAULT_PATH = PAGES[DEFAULT_PAGE].path;

const FIRST_PAGE_OF_TAB = {};   /* tab → canonical path of its first page */
GROUPS.forEach((g) => {
  if (!(g.tab in FIRST_PAGE_OF_TAB)) FIRST_PAGE_OF_TAB[g.tab] = PAGES[g.pages[0].id].path;
});

window.FENIX_NAV = {
  TABS, GROUPS, PAGES, PAGE_ORDER,
  PATH_TO_ID, PATHS_BY_LENGTH, REDIRECTS,
  DEFAULT_PAGE, DEFAULT_PATH, FIRST_PAGE_OF_TAB,
  FENIX_BROKER_PAGES, PRO_BROKER_PAGES,
};
