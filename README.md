<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/fenix-logo.png" alt="Fenix" width="180">
</p>

<h1 align="center">Fenix</h1>

<p align="center">
  <b>Change one word. Trade any broker.</b><br>
  One unified Python API across <b>15 Indian brokers</b> — authentication, instrument tokens,
  orders, positions, and account data, all returned in one consistent shape.
</p>

<p align="center">
  <a href="https://github.com/TheHardeep/fenix/blob/master/LICENSE"><img alt="License" src="https://img.shields.io/badge/License-GPLv3-blue?color=%234ec820"></a>
  <a href="https://pypi.org/project/fenix/"><img alt="PyPI" src="https://img.shields.io/pypi/v/fenix"></a>
  <img alt="Python" src="https://img.shields.io/pypi/pyversions/fenix">
  <a href="https://fenix.hardeep.tech"><img alt="Docs" src="https://img.shields.io/badge/docs-fenix.hardeep.tech-orange"></a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#features">Features</a> ·
  <a href="#supported-brokers">Brokers</a> ·
  <a href="#unified-vocabulary">Constants</a> ·
  <a href="#paper-trading">Paper Mode</a> ·
  <a href="https://fenix.hardeep.tech">Documentation</a>
</p>

---

Every Indian broker ships its own REST API with its own URLs, field names, constants for order
side and product type, error envelope, and rate limits. Writing a strategy against one broker
means re-learning all of that for the next. **Fenix is an adapter library**: each broker is a
class that implements the same methods and returns the same dictionaries — a single unified
interface purpose-built for the Indian markets (NSE, BSE, NFO, BFO, MCX, CDS).

```python
# swap one word — the rest never changes
from fenix import Zerodha
from fenix import Side, Product

broker = Zerodha()
broker.authenticate(params=creds)
broker.market_order(token_dict=contract, quantity=1, side=Side.BUY, product=Product.MIS, unique_id="entry-1")
```

It is built for **coders, quant developers, technically-skilled traders, and data scientists**
building algorithmic trading systems on top of one stable API.

## Why Fenix

- **Learn it once, ship everywhere.** The same method names, parameters, and return shapes work
  across every adapter. Porting a strategy to a new broker is a one-line change — not a rewrite.
- **One vocabulary, not fifteen.** Your code speaks in Fenix constants — `Side.BUY`,
  `Product.MIS`, `OrderType.SLM` — and each adapter translates to its broker's dialect, with
  validation.
- **Backtest with paper mode.** Flip one flag and the same strategy runs against a built-in
  matching engine — realistic fills, positions, and PnL, with no credentials and zero live calls.
- **Safe by default.** Token-bucket rate limiting per endpoint, structured errors with
  HTTP-status mapping, and automatic redaction of secrets from every log line.

## Install

Fenix 2.0 requires **Python 3.10 or newer** and runs on Windows, macOS, and Linux.

```shell
pip install fenix
```

To install a specific release:

```shell
pip install fenix==2.0.0
```

Verify the installation and inspect the broker registry:

```python
import fenix

print(fenix.__version__)   # 2.0.0
print(fenix.brokers)       # ['AliceBlue', 'AngelOne', 'AnandRathi', ...]
```

## Quickstart

Instantiate a broker, authenticate, download instrument tokens, place an order, and read it
back — all through the unified API. The same code runs against any broker.

```python
from fenix import Zerodha, Side, Validity

# 1 · Instantiate
broker = Zerodha()

# 2 · Authenticate — each broker declares the credentials it needs in `tokenParams`
creds = {
    "user_id":    "YOUR_USER_ID",
    "password":   "YOUR_PASSWORD",
    "totpstr":    "YOUR_TOTP_SECRET",   # the TOTP *seed*, not a 6-digit code
    "api_key":    "YOUR_API_KEY",
    "api_secret": "YOUR_API_SECRET",
}
broker.authenticate(params=creds)

# 3 · Download instrument tokens (reshaped into a standardized lookup)
fno, _ = broker.load_fno_tokens()
contract = fno["Options"]["NFO"]["NIFTY"][0]

# 4 · Place an order — returns a unified order record (same keys for every broker)
order = broker.limit_order(
    token_dict=contract,
    side=Side.BUY,
    price=152.0,
    quantity=75,
    unique_id="entry-1",
)

# 5 · Read it back, then modify or cancel
detail = broker.fetch_order(order["id"])
broker.modify_order(order_id=order["id"], price=151.5, quantity=75)
broker.cancel_order(order_id=order["id"])

# 6 · Inspect positions and account
positions = broker.fetch_net_positions()
holdings  = broker.fetch_holdings()
margins   = broker.fetch_margin_limits()   # unified RMS record
profile   = broker.fetch_profile()
```

> See the [Quickstart guide](https://fenix.hardeep.tech) for the full walkthrough, including
> reusing an authenticated session across runs.

### Order & account methods

| Order entry | Account & order reads |
|-------------|-----------------------|
| `place_order`, `modify_order`, `cancel_order` | `fetch_orderbook`, `fetch_tradebook` |
| `market_order`, `limit_order`, `sl_order`, `slm_order` | `fetch_order`, `fetch_order_history` |
| `market_buy_order`, `market_sell_order` | `fetch_net_positions`, `fetch_day_positions` |
| `limit_buy_order`, `limit_sell_order` | `fetch_holdings`, `fetch_margin_limits` |
| `sl_buy_order`, `slm_sell_order`, … | `fetch_profile` |

## Features

Fenix 2.0 is a ground-up refactor of the broker layer. Highlights:

- 🔁 **Unified, one-line broker swap.** Identical method names, parameters, and return shapes
  across all 15 adapters — port a strategy by changing a single class name.
- 🧱 **One shared base class.** Every adapter subclasses `fenix.base.broker.Broker`, which owns
  the HTTP session, request wrapper, URL building, constant translation, and error mapping. New
  brokers stay thin and consistent.
- 📄 **Built-in paper-mode engine.** An in-process matching engine simulates fills, positions,
  and PnL with no credentials and zero live calls — flip `paper_mode` and the same code runs.
- 🗣️ **One vocabulary.** Fenix constants (`Side`, `Product`, `OrderType`, `Validity`, `Variety`,
  `Status`) are translated per broker with validation — see [Constants](#unified-vocabulary).
- 🚦 **Per-endpoint rate limiting.** Token-bucket throttling defined in each adapter's
  `rateLimits`; requests self-throttle before hitting the broker.
- 🔐 **Secret redaction.** Passwords, tokens, API keys, authorization headers, and TOTP values
  are automatically scrubbed from every log line.
- 🧾 **Structured errors.** Broker error envelopes are mapped to typed Fenix exceptions with
  HTTP-status context.
- 🩺 **Request/response diagnostics.** Every broker keeps the latest HTTP snapshots
  (`last_request_*`, `last_response_*`) — plus paper-mode equivalents.
- ⌨️ **Typed.** Ships a PEP 561 `py.typed` marker so downstream type checkers pick up Fenix's
  annotations.

## Supported Brokers

Fenix 2.0 exposes **15 broker adapters**. Each has its own
[reference page](https://fenix.hardeep.tech) documenting every method it supports.

The **Class** name is the public identifier — it is exactly what `fenix.brokers` lists and what
`broker.describe()["id"]` returns.

| | Broker | Class |
|---|--------|-------|
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/aliceblue.svg" alt="AliceBlue" height="22"> | AliceBlue | `AliceBlue` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/angelone.svg" alt="Angel One" height="22"> | Angel One | `AngelOne` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/anandrathi.jpeg" alt="Anand Rathi" height="22"> | Anand Rathi | `AnandRathi` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/dhan.svg" alt="Dhan" height="22"> | Dhan | `Dhan` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/finvasia.svg" alt="Finvasia" height="22"> | Finvasia / Shoonya | `Finvasia` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/fivepaisa.svg" alt="5paisa" height="22"> | 5paisa | `FivePaisa` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/fyers.svg" alt="Fyers" height="22"> | Fyers | `Fyers` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/groww.svg" alt="Groww" height="22"> | Groww | `Groww` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/iifl.svg" alt="IIFL" height="22"> | IIFL | `Iifl` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/kotakneo.svg" alt="Kotak Neo" height="22"> | Kotak Neo | `KotakNeo` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/mastertrust.svg" alt="Master Trust" height="22"> | Master Trust | `MasterTrust` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/motilaloswal.jpeg" alt="Motilal Oswal" height="22"> | Motilal Oswal | `MotilalOswal` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/symphony.svg" alt="Symphony" height="22"> | Symphony | `Symphony` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/upstox.svg" alt="Upstox" height="22"> | Upstox | `Upstox` |
| <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/brokers/zerodha.svg" alt="Zerodha" height="22"> | Zerodha | `Zerodha` |

```python
import fenix
print(fenix.brokers)   # always reflects exactly what your installed version supports
```

> The deprecated v1 modules `choice`, `kotak`, `kunjee`, and `vpc` were removed in v2.0.

## Unified Vocabulary

Your strategy speaks Fenix constants; each adapter translates them to its broker's dialect and
validates them. The constant classes are top-level exports (`from fenix import Side, Product, …`).

| Constant | Common values |
|----------|---------------|
| `Side` | `BUY`, `SELL` |
| `OrderType` | `MARKET`, `LIMIT`, `SL`, `SLM` |
| `Product` | `MIS`, `NRML`, `CNC`, `MARGIN`, `MTF`, `BO`, `CO` |
| `Validity` | `DAY`, `IOC`, `GTD`, `GTC`, `FOK`, `TTL` |
| `Variety` | `REGULAR`, `STOPLOSS`, `AMO`, `BO`, `CO`, `ICEBERG`, `AUCTION` |
| `Status` | `PENDING`, `OPEN`, `PARTIALLY_FILLED`, `FILLED`, `REJECTED`, `CANCELLED` |
| `ExchangeCode` | `NSE`, `NFO`, `BSE`, `BFO`, `MCX`, `CDS`, … |
| `Root` | `NIFTY`, `BANKNIFTY`, `FINNIFTY`, `SENSEX`, `CRUDEOIL`, … |
| `Option` | `CE`, `PE` |

Returned records also use a fixed key set (`Order`, `Position`, `Profile`, `RMS`), so the same
parsing code works for every broker. Full reference at **[fenix.hardeep.tech](https://fenix.hardeep.tech)**.

## Paper Trading

Paper mode routes supported order entry and account reads through Fenix's in-process matching
engine instead of live broker endpoints — no credentials, zero live calls. Flip one flag and the
exact same code runs against the simulator.

```python
from fenix import AliceBlue, Side, UniqueID

broker = AliceBlue({"paper_mode": True})
broker.authenticate()                      # no-op in paper mode

token = {"Token": 12345, "Symbol": "TESTSTOCK", "Exchange": "NSE"}

order = broker.market_order(
    token_dict=token, quantity=1, side=Side.BUY, unique_id=UniqueID.MARKET_ORDER,
)

broker.on_tick(token=12345, ltp=2500.0)    # feed prices to drive fills

print(broker.fetch_orderbook())
print(broker.fetch_positions())
```

Paper mode supports order books, trade books, order history, positions, holdings, margin limits,
profile data, stop-order validation, and square-off validation.

## How it fits together

Every adapter — `Zerodha`, `AngelOne`, `Fyers`, … — subclasses `fenix.base.broker.Broker`. The
base class owns everything identical across brokers (HTTP session, throttling, the `fetch()`
request wrapper, URL building, constant translation, logging/redaction, error mapping, and the
embedded paper engine), while each subclass supplies only what is broker-specific.

```
  Your strategy            Fenix · Unified API           Brokers
┌────────────────┐          ┌──────────────────────────┐          ┌──────────────────────────┐
│                │          │  authenticate · login    │          │  Zerodha · Angel One     │
│  one codebase  │  ──────▶ │  orders · positions      │  ──────▶ │  Fyers · Upstox · Dhan   │
│                │   call   │  account · paper mode    │   REST   │  … + 10 more brokers     │
└────────────────┘          └──────────────────────────┘          └──────────────────────────┘
```

### Operational features

- **Rate limits.** Adapters define token-bucket buckets in `rateLimits`; requests throttle
  automatically before hitting endpoints. Configure with `enableRateLimit` and
  `rate_limit_padding`.
- **Logging & redaction.** Pass a logger or `verbose=True` to inspect request/response flow.
  Fenix redacts passwords, tokens, API keys, authorization headers, and TOTP values.
- **Diagnostics.** Every broker keeps the latest HTTP snapshots (`last_request_*`,
  `last_response_*`) — and in paper mode, `last_paper_request` / `last_paper_response` /
  `last_paper_interaction`.
- **Typed.** Ships a PEP 561 `py.typed` marker so downstream type checkers pick up Fenix's
  annotations.

## Fenix-Pro — real-time market data

[**Fenix-Pro**](https://fenix.hardeep.tech) is the paid, real-time companion to Fenix. It hides
each broker's WebSocket transport, payload format, and subscription conventions behind a unified,
callback-oriented interface — **LTP, market depth, and order updates**, normalized into one
`TickData` / `Order` shape across 15 live-feed adapters. It shares Fenix's broker roster and
instrument-token shapes, so the two compose cleanly.

## Documentation

Full developer documentation — guides, architecture, the unified API reference, paper mode,
constants, and a reference page per broker — lives at **[fenix.hardeep.tech](https://fenix.hardeep.tech)**.

## License

Fenix is released under the **GNU General Public License v3.0**. See [LICENSE](https://github.com/TheHardeep/fenix/blob/master/LICENSE) for
details.

---

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/TheHardeep/fenix@master/assets/fenix-logo-sm.png" alt="Fenix" width="48"><br>
  <sub>Built for the Indian markets · <a href="https://fenix.hardeep.tech">fenix.hardeep.tech</a></sub>
</p>
