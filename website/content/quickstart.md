# Quickstart

This page walks the full lifecycle: instantiate a broker, authenticate, download instrument
tokens, place an order, and read it back — all through the unified API. Every broker supports
the same calls, so the same code runs against any of them.

> [!TIP] Try it without risking anything
> Pass `paper_mode=True` when you construct the broker and the exact same code runs against the
> built-in [paper-trading engine](#/paper-mode) — no credentials, no live orders. The snippets
> below note where paper mode differs.

## 1 · Instantiate a broker

Each broker is a class. Construct it once; the instance owns its HTTP session, rate-limit
state, and (after login) your authenticated headers.

```python
from fenix import Zerodha

broker = Zerodha()
print(broker)          # fenix.Zerodha()
```

You can override any [`describe()`](#/describe) setting at construction time by passing a
`config` dict — for example, to turn on verbose logging:

```python
broker = Zerodha(config={"verbose": True})
```

## 2 · Authenticate

Authentication exchanges your broker credentials for a set of request headers that authorize
every subsequent call. Each broker declares exactly which credentials it needs in its
`tokenParams` — inspect them with:

```python
print(broker.tokenParams)
# ['user_id', 'password', 'totpstr', 'api_key', 'api_secret']
```

Provide those values and call `authenticate()`:

```python
creds = {
    "user_id":    "YOUR_USER_ID",
    "password":   "YOUR_PASSWORD",
    "totpstr":    "YOUR_TOTP_SECRET",   # the TOTP *seed*, not a 6-digit code
    "api_key":    "YOUR_API_KEY",
    "api_secret": "YOUR_API_SECRET",
}

headers = broker.authenticate(params=creds)
```

Fenix runs the broker's full login flow (including TOTP two-factor) and stores the result on
the instance, so you don't pass headers around manually. See
[Authentication](#/authentication) for reusing a session across runs.

## 3 · Download instrument tokens

To trade an instrument you need its broker token. Fenix downloads the broker's instrument
master and reshapes it into a standardized lookup. Load the segment you need:

```python
# F&O contracts (NFO + BFO): futures & options
fno, all_fno = broker.load_fno_tokens()

# Cash-market equity (NSE + BSE)
eq, all_eq = broker.load_equity_tokens()
```

The unified maps are organized by segment and symbol. For options you get a list of contracts
per underlying; index in to pick the strike/expiry you want:

```python
nifty_options = fno["Options"]["NFO"]["NIFTY"]
contract = nifty_options[0]      # a single option contract dict
print(contract["Symbol"], contract["StrikePrice"], contract["Expiry"])
```

See [Instrument Tokens](#/tokens) for the full token schema and every `load_*` method.

## 4 · Place an order

Pass the instrument dict to an order method. Fenix offers a `place_order()` workhorse plus
typed convenience wrappers like `limit_order`, `market_buy_order`, and `sl_sell_order`:

```python
order = broker.limit_order(
    token_dict=contract,
    side="BUY",
    price=152.0,
    quantity=75,
    unique_id="entry-1",
)
print(order["id"])
```

The call returns a **unified order record** — the same keys for every broker. See
[Orders](#/orders) for all order types and the response schema.

## 5 · Read it back, then modify or cancel

```python
# Single order by id
detail = broker.fetch_order(order["id"])
print(detail["status"], detail["filled"], detail["avgPrice"])

# The whole orderbook
orders = broker.fetch_orderbook()

# Modify the resting order
broker.modify_order(order_id=order["id"], price=151.5, quantity=75)

# Cancel it
broker.cancel_order(order_id=order["id"])
```

## 6 · Inspect positions and account

```python
positions = broker.fetch_net_positions()
holdings  = broker.fetch_holdings()
margins   = broker.fetch_margin_limits()    # unified RMS record
profile   = broker.fetch_profile()
```

## Putting it together

```python
from fenix import Zerodha

broker = Zerodha()
broker.authenticate(params=creds)

fno, _ = broker.load_fno_tokens()
contract = fno["Options"]["NFO"]["NIFTY"][0]

order = broker.limit_order(
    token_dict=contract, side="BUY",
    price=152.0, quantity=75, unique_id="entry-1",
)

print(broker.fetch_order(order["id"]))
```

> [!INFO] The same script, in paper mode
> Change the first two lines to `broker = Zerodha(paper_mode=True)` and call
> `broker.authenticate()` with no arguments. Feed prices with `broker.on_tick(token, ltp=...)`
> to drive fills. Everything else is identical.

## Where to go next

<div class="card-grid">
  <a class="doc-card" href="#/authentication"><span class="dc-title">Authentication</span><span class="dc-desc">Persist and reuse sessions; understand tokenParams.</span></a>
  <a class="doc-card" href="#/tokens"><span class="dc-title">Instrument Tokens</span><span class="dc-desc">Every load_* method and the token schema.</span></a>
  <a class="doc-card" href="#/orders"><span class="dc-title">Orders</span><span class="dc-desc">All order types and the unified order record.</span></a>
</div>
