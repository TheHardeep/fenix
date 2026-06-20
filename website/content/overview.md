<div class="mk-hero">
  <div class="mk-halo"></div>
  <div class="mk-hero-grid">
    <div class="mk-hero-copy">
      <span class="eyebrow reveal"><span class="pip"></span>One API · Every Indian broker</span>
      <h1 class="mk-h1 reveal">Change one word.<br /><span class="grad">Trade any broker.</span></h1>
      <p class="mk-lede reveal">A unified Python trading library — one API across 15 Indian brokers for authentication, instrument tokens, orders, positions, and account data, all returned in <b>one consistent shape</b>. Built for algo traders and quant developers.</p>
      <div class="hero-actions reveal">
        <a class="btn primary" href="#/guides/quickstart">Get started <span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></span></a>
        <a class="btn" href="https://github.com/TheHardeep/fenix" target="_blank" rel="noopener">View on GitHub <span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17L17 7M9 7h8v8"/></svg></span></a>
      </div>
      <div class="mk-install reveal" data-copy="pip install fenix"><span class="pr">$</span><span>pip install fenix</span><span class="cp"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 012-2h10"/></svg></span></div>
    </div>
    <div class="mk-shell mk-demo reveal">
      <div class="mk-core">
        <div class="mk-core-bar"><span class="mk-dot r"></span><span class="mk-dot y"></span><span class="mk-dot g"></span><span class="file">strategy.py</span><span class="live">live</span></div>
        <div class="mk-code"><span class="c"># swap one word — the rest never changes</span>
<span class="k">from</span> fenix <span class="k">import</span> <span class="mk-swap">Zerodha</span>
broker = fenix.<span class="mk-swap">Zerodha</span>(<span class="v">config</span>)
broker.<span class="k">authenticate</span>()
broker.<span class="k">place_order</span>(
  symbol=<span class="s">"RELIANCE"</span>, side=Side.BUY,
  qty=<span class="v">1</span>, product=Product.MIS,
)</div>
        <div class="mk-brokers"><span class="mk-bchip" data-b="zerodha" data-cls="Zerodha">Zerodha</span><span class="mk-bchip" data-b="angelone" data-cls="AngelOne">Angel One</span><span class="mk-bchip" data-b="fyers" data-cls="Fyers">Fyers</span><span class="mk-bchip" data-b="upstox" data-cls="Upstox">Upstox</span><span class="mk-bchip" data-b="dhan" data-cls="Dhan">Dhan</span><span class="mk-bchip" data-b="groww" data-cls="Groww">Groww</span><span class="mk-bchip" data-b="finvasia" data-cls="Finvasia">Finvasia</span></div>
      </div>
    </div>
  </div>
</div>

<div class="mk-marquee reveal" aria-label="Supported brokers">
  <div class="mk-mq-track" data-brokers="fenix"></div>
</div>

## Why Fenix

Every Indian broker ships its own REST API with its own URLs, field names, constants for order
side and product type, error envelope, and rate limits. Writing a strategy against one broker
means re-learning all of that for the next. Fenix is an **adapter library**: each broker is a
class that implements the same methods and returns the same dictionaries — a single unified
interface purpose-built for the Indian markets (NSE, BSE, NFO, BFO, MCX, CDS).

<div class="mk-bento reveal">
  <div class="mk-tile lg"><div class="mk-tile-core"><div class="mk-glyph"></div><h3>Learn it once, ship everywhere</h3><p>The same method names, parameters, and return shapes work across every adapter. Porting a strategy to a new broker is a one-line change — not a rewrite.</p><div class="mk-mini"><span class="c"># same call, any broker</span>
broker.<span class="k">fetch_positions</span>()  <span class="c">→ List[Position]</span></div></div></div>
  <div class="mk-tile sm"><div class="mk-tile-core"><div class="mk-glyph"></div><h3>One vocabulary, not fifteen</h3><p>Your code speaks in Fenix constants — <code>Side.BUY</code>, <code>Product.MIS</code>, <code>OrderType.SLM</code> — and each adapter translates to its broker's dialect, with validation.</p></div></div>
  <div class="mk-tile sm"><div class="mk-tile-core"><div class="mk-glyph"></div><h3>Backtest with paper mode</h3><p>Flip one flag and the same strategy runs against a built-in matching engine — realistic fills, positions, and PnL, with no credentials and zero live calls.</p></div></div>
  <div class="mk-tile lg"><div class="mk-tile-core"><div class="mk-glyph"></div><h3>Safe by default</h3><p>Token-bucket rate limiting per endpoint, structured errors with HTTP-status mapping, and automatic redaction of secrets from every log line — so nothing leaks and nothing surprises you.</p></div></div>
</div>

## How it fits together

Every broker derives from a common [`Broker`](#/concepts/architecture) base that owns everything
identical across brokers, while each adapter supplies only what's broker-specific. Your strategy
talks to one unified API — never to a broker's raw endpoints.

<div class="mk-arch reveal">
  <div class="mk-node"><b>Your strategy</b><span>one codebase</span></div>
  <div class="mk-pipe"></div>
  <div class="mk-node hub"><b>Fenix · Unified API</b><span>authenticate · orders · positions · account data</span></div>
  <div class="mk-pipe"></div>
  <div class="mk-fan"><span>Zerodha</span><span>Angel One</span><span>Fyers</span><span>Upstox</span><span>Dhan</span><span>+ 10 more brokers</span></div>
</div>

## Two products, one design

<div class="compare">
  <div class="compare-card">
    <div class="cc-head"><span class="cc-icon"><img src="assets/img/brand/logo-sm.png" alt="Fenix" /></span><div><h3>Fenix</h3><span class="cc-tag">open source · GPLv3</span></div></div>
    <p>The trading library. Auth, instrument tokens, orders, positions, holdings, margins — over REST, with a built-in paper engine.</p>
    <ul>
      <li>Place / modify / cancel orders</li>
      <li>Positions, holdings &amp; RMS</li>
      <li>Paper-trading simulator</li>
    </ul>
    <a class="btn" href="#/guides/quickstart">Explore Fenix <span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></span></a>
  </div>
  <div class="compare-card pro">
    <div class="cc-head"><span class="cc-icon"><img src="assets/img/brand/logo-sm.png" alt="Fenix-Pro" /></span><div><h3>Fenix-Pro <span class="pro-tag">PRO</span></h3><span class="cc-tag">paid · real-time</span></div></div>
    <p>The market-data companion. Live LTP, market depth, and order feeds over WebSocket, normalized to one tick contract.</p>
    <ul>
      <li>15 live-feed adapters</li>
      <li>3 transport families</li>
      <li>Normalized TickData &amp; Order</li>
    </ul>
    <a class="btn" href="#/pro/overview">Explore Fenix-Pro <span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></span></a>
  </div>
</div>

## Supported brokers

Each broker has its own [reference page](#/brokers/supported) documenting every method it supports.

<div class="broker-grid">
  <a class="broker-tile" href="#/brokers/aliceblue"><span class="bt-dot"></span> AliceBlue</a>
  <a class="broker-tile" href="#/brokers/angelone"><span class="bt-dot"></span> Angel One</a>
  <a class="broker-tile" href="#/brokers/anandrathi"><span class="bt-dot"></span> Anand Rathi</a>
  <a class="broker-tile" href="#/brokers/dhan"><span class="bt-dot"></span> Dhan</a>
  <a class="broker-tile" href="#/brokers/finvasia"><span class="bt-dot"></span> Finvasia</a>
  <a class="broker-tile" href="#/brokers/fivepaisa"><span class="bt-dot"></span> 5paisa</a>
  <a class="broker-tile" href="#/brokers/fyers"><span class="bt-dot"></span> Fyers</a>
  <a class="broker-tile" href="#/brokers/groww"><span class="bt-dot"></span> Groww</a>
  <a class="broker-tile" href="#/brokers/iifl"><span class="bt-dot"></span> IIFL</a>
  <a class="broker-tile" href="#/brokers/kotakneo"><span class="bt-dot"></span> Kotak Neo</a>
  <a class="broker-tile" href="#/brokers/mastertrust"><span class="bt-dot"></span> Master Trust</a>
  <a class="broker-tile" href="#/brokers/motilaloswal"><span class="bt-dot"></span> Motilal Oswal</a>
  <a class="broker-tile" href="#/brokers/symphony"><span class="bt-dot"></span> Symphony</a>
  <a class="broker-tile" href="#/brokers/upstox"><span class="bt-dot"></span> Upstox</a>
  <a class="broker-tile" href="#/brokers/zerodha"><span class="bt-dot"></span> Zerodha</a>
</div>

<div class="cta-band">
  <img class="cta-mark" src="assets/img/brand/logo.png" alt="" aria-hidden="true" />
  <h2>Start building in minutes</h2>
  <p>Install from PyPI and place your first unified order today.</p>
  <div class="hero-actions">
    <a class="btn primary" href="#/guides/installation">Install Fenix <span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></span></a>
    <a class="btn" href="#/guides/quickstart">Read the Quickstart <span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></span></a>
  </div>
</div>
