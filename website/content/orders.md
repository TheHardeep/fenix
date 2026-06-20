# Orders

Order entry is the core of the unified API. Fenix gives you one `place_order()` workhorse plus
a family of **typed convenience wrappers**, all returning the same [unified order
record](#/unified-json). Reads (`fetch_order`, `fetch_orderbook`, `fetch_tradebook`) and
mutations (`modify_order`, `cancel_order`) round out the surface.

## `place_order()`

The general method. You supply the instrument record (`token_dict` from the
[token maps](#/tokens)), quantity, and the order parameters as [constants](#/constants):

```python
order = broker.place_order(
    token_dict=contract,
    quantity=75,
    side=Side.BUY,
    product=Product.NRML,
    validity=Validity.DAY,
    variety=Variety.REGULAR,
    unique_id="entry-1",
    price=152.0,        # 0.0 ⇒ market
    trigger=0.0,        # > 0 ⇒ stop order
)
```

| Parameter | Type | Notes |
|-----------|------|-------|
| `token_dict` | dict | Instrument record from `load_*_tokens`. |
| `quantity` | int | Must be > 0. |
| `side` | `Side` | `BUY` / `SELL`. |
| `product` | `Product` | `MIS`, `NRML`, `CNC`, … |
| `validity` | `Validity` | `DAY`, `IOC`, … |
| `variety` | `Variety` | `REGULAR`, `STOPLOSS`, … |
| `unique_id` | str | Your tag, echoed back as `userOrderId`. |
| `price` | float | Limit price; `0.0` means market. |
| `trigger` | float | Stop trigger; `> 0` means a stop order. |
| `target` / `stoploss` / `trailing_sl` | float | Bracket-order legs (where supported). |

### Order type is inferred from price & trigger

You rarely pass an `OrderType` explicitly — Fenix derives it:

| `price` | `trigger` | Resolved type |
|---------|-----------|---------------|
| `0` | `0` | `MARKET` |
| `> 0` | `0` | `LIMIT` |
| `0` | `> 0` | `SLM` (stop-loss market) |
| `> 0` | `> 0` | `SL` (stop-loss limit) |

Inputs are validated before anything is sent: quantity must be positive and all price-like
fields non-negative, otherwise [`InputError`](#/errors) is raised.

## Convenience order methods

For readable strategy code, Fenix generates typed wrappers around `place_order()` with the
side, price, and trigger requirements baked in. They come in **side-specific** and
**side-agnostic** flavors:

| Method | Requires | Produces |
|--------|----------|----------|
| `market_buy_order` / `market_sell_order` | — | Market order, side fixed. |
| `limit_buy_order` / `limit_sell_order` | `price` | Limit order, side fixed. |
| `sl_buy_order` / `sl_sell_order` | `price`, `trigger` | SL order, side fixed. |
| `slm_buy_order` / `slm_sell_order` | `trigger` | SL-M order, side fixed. |
| `market_order` | `side` | Market order. |
| `limit_order` | `side`, `price` | Limit order. |
| `sl_order` | `side`, `price`, `trigger` | SL order. |
| `slm_order` | `side`, `trigger` | SL-M order. |

```python
# side baked in — no `side` argument
broker.market_buy_order(token_dict=c, quantity=75, unique_id="mkt-1")
broker.limit_sell_order(token_dict=c, price=168.0, quantity=75, unique_id="tp-1")
broker.slm_buy_order(token_dict=c, trigger=160.0, quantity=75, unique_id="sl-1")

# side-agnostic — pass `side`
broker.limit_order(token_dict=c, side=Side.BUY, price=152.0, quantity=75, unique_id="e-1")
```

Each wrapper enforces its own signature: passing `side` to `limit_buy_order`, or omitting
`price` from `limit_order`, raises a clear `TypeError`. Defaults are `product=Product.MIS`,
`validity=Validity.DAY`, with `variety` set to the wrapper's natural value.

## Capabilities — the `has` registry

Not every broker supports every wrapper. Each convenience method checks `self.has[method_name]`
before running and raises [`NotSupported`](#/errors) if disabled:

```python
print(broker.has["slm_buy_order"])     # True / False for this broker

try:
    broker.slm_buy_order(token_dict=c, trigger=160.0, quantity=75, unique_id="x")
except errors.NotSupported:
    ...   # fall back for brokers without SL-M
```

A broker subclass declares only the capabilities it changes; the rest are inherited and merged
automatically. See [Architecture → Capabilities](#/architecture).

## Reading orders

```python
# Single order by id → unified order record
detail = broker.fetch_order(order["id"])

# Whole orderbook → list of unified order records
orders = broker.fetch_orderbook()

# Only executed orders → list of unified order records
trades = broker.fetch_tradebook()

# Status history of one order
history = broker.fetch_order_history(order["id"])
```

All return the [unified order schema](#/unified-json). Raw, untranslated variants
(`fetch_raw_orderbook`, `fetch_raw_order_history`) are available when you need the broker's
original payload.

```python
for o in broker.fetch_orderbook():
    print(o["symbol"], o["side"], o["status"], o["filled"], "/", o["quantity"])
```

## Modifying an order

Change price, trigger, quantity, type, or validity of a resting order. Omitted fields are left
unchanged:

```python
broker.modify_order(
    order_id=order["id"],
    price=151.5,
    quantity=75,
    order_type=OrderType.LIMIT,
    validity=Validity.DAY,
)
```

Only orders still pending or open can be modified; modifying a filled/cancelled order raises
[`InvalidOrderError`](#/errors), and an unknown id raises `OrderNotFoundError`.

## Cancelling an order

```python
broker.cancel_order(order_id=order["id"])
```

Cancelling an already-terminal order is a safe no-op; an unknown id raises `OrderNotFoundError`.

## A complete order flow

```python
from fenix import Zerodha
from fenix.base.constants import Side

broker = Zerodha()
broker.authenticate(params=creds)
fno, _ = broker.load_fno_tokens()
c = fno["Options"]["NFO"]["NIFTY"][0]

# Entry: limit buy
order = broker.limit_order(token_dict=c, side=Side.BUY, price=152.0,
                           quantity=75, unique_id="entry-1")

# Re-price if not filled
if broker.fetch_order(order["id"])["status"] == "OPEN":
    broker.modify_order(order_id=order["id"], price=153.0)

# Protective stop
broker.slm_sell_order(token_dict=c, trigger=140.0, quantity=75, unique_id="stop-1")
```

> [!TIP] Same code in paper mode
> Every method on this page works identically against the [paper engine](#/paper-mode). Place,
> modify, and cancel resolve instantly; feed prices with `broker.on_tick(token, ltp=...)` to
> trigger fills.
