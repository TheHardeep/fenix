# Cookbook

Copy-paste recipes for common Fenix workflows. Every snippet uses the unified API, so it runs
against any [supported broker](#/brokers).

## Place a live limit order, end to end

```python
from fenix import Zerodha
from fenix.base.constants import Side

creds = {
    "user_id": "...", "password": "...", "totpstr": "...",
    "api_key": "...", "api_secret": "...",
}

broker = Zerodha()
broker.authenticate(params=creds)

# Load F&O and pick a contract
fno, _ = broker.load_fno_tokens()
contract = fno["Options"]["NFO"]["NIFTY"][0]

# Place a limit buy
order = broker.limit_order(
    token_dict=contract, side=Side.BUY,
    price=152.0, quantity=int(contract["LotSize"]), unique_id="entry-1",
)
print("order id:", order["id"])
print("status:  ", broker.fetch_order(order["id"])["status"])
```

## Reuse a session across runs

Avoid logging in on every run by persisting headers and restoring them next time.

```python
import json
from fenix import Zerodha

SESSION = "session.json"

def get_broker(creds):
    broker = Zerodha()
    try:
        with open(SESSION) as f:
            broker.authenticate(headers=json.load(f))     # restore — no login
    except (FileNotFoundError, KeyError):
        headers = broker.authenticate(params=creds)        # fresh login
        with open(SESSION, "w") as f:
            json.dump(headers, f)
    return broker
```

## Run the same strategy on multiple brokers

```python
from fenix import Zerodha, AngelOne
from fenix.base.constants import Side

def strategy(broker, creds):
    broker.authenticate(params=creds)
    broker.load_fno_tokens()
    c = broker.token_json["Options"]["NFO"]["NIFTY"][0]
    return broker.limit_order(token_dict=c, side=Side.BUY, price=152.0,
                              quantity=75, unique_id="entry-1")

for cls, creds in [(Zerodha, zerodha_creds), (AngelOne, angel_creds)]:
    order = strategy(cls(), creds)
    print(cls.__name__, "→", order["id"])
```

## Bracket: entry + protective stop + target

```python
from fenix.base.constants import Side

c = fno["Options"]["NFO"]["NIFTY"][0]
qty = int(c["LotSize"])

entry  = broker.limit_buy_order(token_dict=c, price=150.0, quantity=qty, unique_id="entry")
stop   = broker.slm_sell_order(token_dict=c, trigger=140.0, quantity=qty, unique_id="stop")
target = broker.limit_sell_order(token_dict=c, price=170.0, quantity=qty, unique_id="target")
```

## Robust order placement with error handling

```python
from fenix import errors

def safe_place(broker, **kwargs):
    try:
        return broker.limit_order(**kwargs)
    except errors.InsufficientFundsError:
        alert("Top up margin"); return None
    except errors.RateLimitExceededError:
        time.sleep(1); return broker.limit_order(**kwargs)
    except errors.AuthenticationError:
        broker.authenticate(params=creds, force=True)
        return broker.limit_order(**kwargs)
    except errors.BrokerError as e:
        log.error("Order failed on %s: %s", e.broker, e.message); return None
```

## Validate a strategy in paper mode

```python
from fenix import Zerodha

broker = Zerodha(paper_mode=True)
broker.authenticate()                       # no credentials needed

c = {"Token": 12345678, "Symbol": "NIFTY24500CE", "Exchange": "NFO"}

broker.limit_order(token_dict=c, side="BUY", price=150.0, quantity=75, unique_id="e-1")
for px in (151.0, 149.5, 160.0, 170.0):     # feed your backtest prices
    filled = broker.on_tick(c["Token"], ltp=px)
    if filled:
        print("filled:", [o["id"] for o in filled])

pos = broker.fetch_net_positions()[0]
print("net", pos["netQty"], "pnl", pos["pnl"])
```

## Snapshot the account

```python
def account_snapshot(broker):
    rms = broker.fetch_margin_limits()
    return {
        "available": rms["marginAvail"],
        "used":      rms["marginUsed"],
        "open_pnl":  sum(p["pnl"] for p in broker.fetch_net_positions()),
        "positions": [p for p in broker.fetch_net_positions() if p["netQty"] != 0],
    }
```

## Verbose debugging with redaction on

```python
broker = Zerodha(config={"verbose": True, "enableLastJsonResponse": True})
broker.authenticate(params=creds)
broker.fetch_orderbook()

# Secrets are masked in the logs; inspect the last exchange afterwards:
print(broker.last_request_method, broker.last_request_url)
print(broker.last_json_response)
```

## Where to go next

<div class="card-grid">
  <a class="doc-card" href="#/orders"><span class="dc-title">Orders</span><span class="dc-desc">Every order type and the unified record.</span></a>
  <a class="doc-card" href="#/paper-mode"><span class="dc-title">Paper Mode</span><span class="dc-desc">The simulator's matching and PnL logic.</span></a>
  <a class="doc-card" href="#/errors"><span class="dc-title">Error Handling</span><span class="dc-desc">The full exception hierarchy.</span></a>
</div>
