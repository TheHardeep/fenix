<div class="mk-hero">
  <div class="mk-halo"></div>
  <div class="mk-hero-copy">
    <span class="eyebrow reveal"><span class="pip"></span>Fenix-Pro · Real-time market data</span>
    <h1 class="mk-h1 reveal">Live ticks &amp; order feeds,<br /><span class="grad">one WebSocket interface.</span></h1>
    <p class="mk-lede reveal">Fenix-Pro is the real-time companion to Fenix. It hides each broker's WebSocket transport, payload format, and subscription conventions behind a unified, callback-oriented interface — <b>LTP, market depth, and order updates</b>, normalized into one shape across every adapter.</p>
    <div class="hero-actions reveal">
      <a class="btn primary" href="#/pro/quickstart">Get started <span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></span></a>
      <a class="btn" href="#/pro/pricing">View pricing <span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></span></a>
    </div>
  </div>
</div>

<div class="mk-marquee reveal" aria-label="Supported live feeds">
  <div class="mk-mq-track" data-brokers="pro"></div>
</div>

> [!INFO] A separate, paid product
> Fenix-Pro is a distinct package (`fenixpro`) focused on **live market-data connectivity**,
> while [Fenix](#/guides/overview) handles trading (auth, orders, positions). They share design DNA —
> the same broker roster and the same instrument-token shapes — so they compose cleanly. See
> [Pricing & Plans](#/pro/pricing).

## What it does

Every Indian broker exposes live data over a different transport — raw WebSocket, Socket.IO, or
async WebSocket with protobuf frames — each with its own binary framing and subscription
protocol. Fenix-Pro is an **adapter layer** that sits between your application and those feeds:

<div class="fx">
  <div class="fx-row">
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Caller</div>
        <div class="fx-node-title">Your application</div>
        <div class="fx-node-sub">on_ltp · on_depth</div>
      </div>
    </div>
    <div class="fx-edge both">
      <span class="fx-edge-label">callbacks</span>
      <span class="fx-edge-line"></span>
    </div>
    <div class="fx-node accent">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Adapter</div>
        <div class="fx-node-title">fenixpro.&lt;broker&gt;</div>
        <div class="fx-node-sub">connect · subscribe · parse</div>
      </div>
    </div>
    <div class="fx-edge both">
      <span class="fx-edge-label">ws</span>
      <span class="fx-edge-line"></span>
    </div>
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Upstream</div>
        <div class="fx-node-title">Broker WS endpoint</div>
        <div class="fx-node-sub">binary · sio · pb</div>
      </div>
    </div>
  </div>
  <div class="fx-pipe">
    <span class="fx-pipe-label">normalize</span>
    <span class="fx-pipe-line"></span>
  </div>
  <div class="fx-row">
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Output</div>
        <div class="fx-node-title">TickData · Order contracts</div>
        <div class="fx-node-sub">unified Python dicts — broker-agnostic</div>
      </div>
    </div>
  </div>
</div>

You register callbacks, subscribe to instruments (by raw token or by F&O dimensions), and
receive **normalized dictionaries** — you never touch a broker's binary frame format.

## The unified feed model

1. **Construct** the adapter with broker headers or params (and optional `fno_tokens`).
2. **Register callbacks** and open the socket with `start_websocket(...)`.
3. **Subscribe** at one of three levels — `subscribe`, `subscribe_token`, or
   `subscribe_fno_token`.
4. **Receive** normalized ticks/orders through your callbacks.

```python
from fenixpro import zerodha, FeedType

broker = zerodha(headers={"headers": {"api_key": "...", "access_token": "..."}})
broker.start_websocket(on_ltp=lambda tick: print(tick))
broker.subscribe("256265", FeedType.LTP)
```

## Feed types

| `FeedType` | Delivers |
|------------|----------|
| `LTP` | Last traded price ticks. |
| `LTP_DEPTH` | LTP plus top-of-book depth. |
| `DEPTH` | Full market-depth (bid/ask ladders). |
| `ORDER` | Live order-update events. |

## Explore Fenix-Pro

<div class="card-grid">
  <a class="doc-card" href="#/pro/quickstart"><span class="dc-title">Quickstart</span><span class="dc-desc">Stream live ticks in a dozen lines.</span></a>
  <a class="doc-card" href="#/pro/callbacks"><span class="dc-title">Callback Interface</span><span class="dc-desc">The shared start_websocket callback slots.</span></a>
  <a class="doc-card" href="#/pro/subscriptions"><span class="dc-title">Subscriptions</span><span class="dc-desc">Three ways to subscribe to instruments.</span></a>
  <a class="doc-card" href="#/pro/transports"><span class="dc-title">Transport Families</span><span class="dc-desc">WebSocket, Socket.IO, asyncio+protobuf.</span></a>
  <a class="doc-card" href="#/pro/contracts"><span class="dc-title">Data Contracts</span><span class="dc-desc">The TickData and Order schemas.</span></a>
  <a class="doc-card" href="#/pro/pricing"><span class="dc-title">Pricing &amp; Plans</span><span class="dc-desc">Individual, Pro, and Team tiers.</span></a>
</div>

## Supported live feeds

<div class="broker-grid">
  <a class="broker-tile" href="#/pro/aliceblue"><span class="bt-dot"></span> AliceBlue</a>
  <a class="broker-tile" href="#/pro/angelone"><span class="bt-dot"></span> Angel One</a>
  <a class="broker-tile" href="#/pro/finvasia"><span class="bt-dot"></span> Finvasia</a>
  <a class="broker-tile" href="#/pro/fivepaisa"><span class="bt-dot"></span> 5paisa</a>
  <a class="broker-tile" href="#/pro/fyers"><span class="bt-dot"></span> Fyers</a>
  <a class="broker-tile" href="#/pro/iifl"><span class="bt-dot"></span> IIFL</a>
  <a class="broker-tile" href="#/pro/kotak"><span class="bt-dot"></span> Kotak</a>
  <a class="broker-tile" href="#/pro/kotakneo"><span class="bt-dot"></span> Kotak Neo</a>
  <a class="broker-tile" href="#/pro/kunjee"><span class="bt-dot"></span> Kunjee</a>
  <a class="broker-tile" href="#/pro/mastertrust"><span class="bt-dot"></span> Master Trust</a>
  <a class="broker-tile" href="#/pro/motilaloswal"><span class="bt-dot"></span> Motilal Oswal</a>
  <a class="broker-tile" href="#/pro/symphony"><span class="bt-dot"></span> Symphony</a>
  <a class="broker-tile" href="#/pro/upstox"><span class="bt-dot"></span> Upstox</a>
  <a class="broker-tile" href="#/pro/vpc"><span class="bt-dot"></span> VPC</a>
  <a class="broker-tile" href="#/pro/zerodha"><span class="bt-dot"></span> Zerodha</a>
</div>
