# Paper Mode

Paper mode runs your strategy against a **built-in simulated exchange** instead of the live
broker. There are **no HTTP calls and no credentials** — orders rest in an in-memory matching
engine and fill from the prices you feed it, with realistic position and PnL tracking. The
strategy code is identical to live; you change one flag.

## Enabling paper mode

Construct the broker with `paper_mode=True` (or pass it in `config`). Then `authenticate()`
takes no credentials and returns instantly:

```python
from fenix import Zerodha

broker = Zerodha(paper_mode=True)
broker.authenticate()              # no params, no network — instantly ready
```

Configure the simulated account through [`describe()`](#/describe) keys:

| Key | Default | Effect |
|-----|---------|--------|
| `paper_mode` | `False` | Route order entry and reads to the simulator. |
| `paper_client_id` | `"PAPER001"` | Client id on the simulated profile. |
| `paper_starting_margin` | `1_000_000.0` | Opening available margin. |
| `paper_reject_invalid_stops` | `True` | Reject stops priced through the market on submit. |
| `paper_log_history_size` | `100` | How many interactions the rolling log keeps. |

```python
broker = Zerodha(config={
    "paper_mode": True,
    "paper_starting_margin": 5_000_000.0,
})
```

## How it's wired

When `paper_mode` is on, the broker builds a `PaperExecutionClient` (held as `broker._paper`).
Each order/read method checks `if self.paper_mode and self._paper is not None:` and routes to the
simulator instead of issuing HTTP. The client is backed by two pieces:

<div class="fx">
  <div class="fx-row">
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Order entry</div>
        <div class="fx-node-title">broker.place_order()</div>
      </div>
    </div>
    <div class="fx-edge"><span class="fx-edge-line"></span></div>
    <div class="fx-node accent">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Execution</div>
        <div class="fx-node-title">PaperExecutionClient</div>
      </div>
    </div>
    <div class="fx-edge"><span class="fx-edge-line"></span></div>
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">State</div>
        <div class="fx-node-title">PaperState</div>
        <div class="fx-node-sub">orders · positions · RMS · profile</div>
      </div>
    </div>
  </div>
  <div class="fx-row">
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Tick feed</div>
        <div class="fx-node-title">broker.on_tick()</div>
      </div>
    </div>
    <div class="fx-edge"><span class="fx-edge-line"></span></div>
    <div class="fx-node accent">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Match</div>
        <div class="fx-node-title">MatchingEngine</div>
        <div class="fx-node-sub">one per instrument token</div>
      </div>
    </div>
    <div class="fx-edge"><span class="fx-edge-line"></span></div>
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Drives</div>
        <div class="fx-node-title">fills · positions · PnL</div>
      </div>
    </div>
  </div>
</div>

| Component | Responsibility |
|-----------|----------------|
| `PaperExecutionClient` | Drop-in for the broker's order/read methods; logs, times, and records every interaction. |
| `PaperState` | In-memory orderbook, positions, and synthetic RMS/profile records. |
| `MatchingEngine` | One per instrument token; holds resting orders and the latest tick, and decides fills. |

## The tick feed — `on_tick()`

The simulator has no live market data, so **you** feed it prices. Every price you push can
trigger resting orders to fill. `on_tick()` returns the orders that filled on that tick:

```python
filled = broker.on_tick(token=12345678, ltp=152.0)
for o in filled:
    print("filled", o["id"], "@", o["avgPrice"])
```

`on_tick()` is only valid in paper mode (it raises `InputError` otherwise). It updates the
instrument's matching engine, refreshes the position's LTP, and applies the resulting fills to
the positions book.

## Order lifecycle & matching logic

Order type is [inferred from price/trigger](#/orders) exactly as live. How each type behaves:

| Type | On submit | Fills when |
|------|-----------|-----------|
| **Market** | Fills immediately at the last tick's LTP; if no tick yet, rests `PENDING`. | Next tick if it was pending. |
| **Limit** | Rests `OPEN`. | A tick makes it marketable: buy when `ltp ≤ price`, sell when `ltp ≥ price`. |
| **SL / SL-M** | Rests `PENDING` until triggered. | Buy triggers when `ltp ≥ trigger`, sell when `ltp ≤ trigger`. |

Stops use a **trigger-then-convert** state machine: a pending stop waits for its trigger; once
crossed, an **SL-M** fills at market, while an **SL** converts into a working `LIMIT` order that
then fills when marketable.

```python
broker.limit_order(token_dict=c, side="BUY", price=150.0, quantity=75, unique_id="e-1")
broker.on_tick(c["Token"], ltp=151.0)   # 151 > 150 limit → not yet marketable for a buy
broker.on_tick(c["Token"], ltp=149.5)   # 149.5 ≤ 150 → fills
```

### Invalid-stop rejection

With `paper_reject_invalid_stops=True` (the default), a stop priced through the market on
submission is rejected with [`InvalidOrderError`](#/errors) — so you catch the bug in
simulation instead of discovering it live. For example, a BUY stop whose trigger is at or below
the current LTP is rejected.

### Forcing a result

For deterministic tests you can bypass tick-driven matching with an escape hatch:

```python
broker.place_order(..., extra_params={"force_status": "FILLED"})    # fill immediately
broker.place_order(..., extra_params={"force_status": "REJECTED",
                                      "reject_reason": "test"})       # reject immediately
```

## Positions & PnL

Each fill folds into the positions book: net quantity, weighted-average buy/sell prices, and
**realised PnL** when a fill reduces an open position. Every tick re-marks open positions to
market, so `mtm` (unrealised) and `pnl` (realised + unrealised) stay current:

```python
broker.market_buy_order(token_dict=c, quantity=75, unique_id="e-1")
broker.on_tick(c["Token"], ltp=150.0)     # opens long at 150
broker.on_tick(c["Token"], ltp=166.0)     # re-marks to market

pos = broker.fetch_net_positions()[0]
print(pos["netQty"], pos["mtm"], pos["pnl"])     # 75, 1200.0, 1200.0
```

## Reads, square-off, and account

All the same read methods work and return the same [unified schemas](#/unified-json):

```python
broker.fetch_orderbook()       # every paper order this session
broker.fetch_tradebook()       # the filled ones
broker.fetch_net_positions()   # simulated positions, marked to market
broker.fetch_margin_limits()   # synthetic RMS from paper_starting_margin
broker.fetch_profile()         # synthetic "Paper Trader" profile
```

The simulator also offers `square_off_position()` to flatten by placing an offsetting market
order automatically:

```python
broker._paper.square_off_position(
    symbol=pos["symbol"], token=pos["token"], exchange=pos["exchange"],
    quantity=abs(pos["netQty"]), product="NRML",
)
```

## The interaction log

Every paper operation is recorded with its request, response, status, and duration into a
bounded history (size `paper_log_history_size`). The latest is mirrored onto the broker's
`last_paper_request`, `last_paper_response`, and `last_paper_interaction`, and the live `last_*`
attributes are kept in sync — so [verbose logging](#/logging) reads the same whether you're
live or simulated:

```python
broker = Zerodha(config={"paper_mode": True, "verbose": True})
broker.authenticate()
broker.market_buy_order(token_dict=c, quantity=75, unique_id="e-1")
print(broker.last_paper_interaction["duration_ms"])
```

## A full paper session

```python
from fenix import Zerodha

broker = Zerodha(paper_mode=True)
broker.authenticate()

c = {"Token": 12345678, "Symbol": "NIFTY24500CE", "Exchange": "NFO"}

# Rest a limit buy, then walk the price into it
broker.limit_order(token_dict=c, side="BUY", price=150.0, quantity=75, unique_id="e-1")
broker.on_tick(c["Token"], ltp=151.0)     # not yet
broker.on_tick(c["Token"], ltp=149.5)     # fills

# Mark up and inspect PnL
broker.on_tick(c["Token"], ltp=170.0)
print(broker.fetch_net_positions()[0]["pnl"])
```

> [!TIP] One flag from live
> Because `authenticate()`, the order methods, and the reads all share the same signatures, a
> strategy validated in paper mode runs live by flipping `paper_mode` to `False` and supplying
> real credentials. The only paper-specific call is `on_tick()`, which you replace with your
> live market-data feed.
