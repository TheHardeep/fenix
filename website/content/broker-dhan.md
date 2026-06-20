# Dhan

Dhan broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.Dhan` |
| **`id`** | `Dhan` |
| **Module** | `fenix/dhan.py` |
| **Broker API docs** | [https://dhanhq.co/docs/v2/](https://dhanhq.co/docs/v2/) |
| **Auth params** | `client_id`, `totpstr`, `pin` |
| **Instrument source** | Dhan detailed scrip-master CSV |

The Dhan adapter authenticates through Dhan's token-generation flow, parses the detailed CSV scrip master, and supports regular orders, sliced orders, super orders, forever/GTT orders, positions, holdings, margin, profile, kill switch, and option-chain helpers through the unified Fenix API.

## Authentication

`Dhan.authenticate()` generates the current TOTP from `totpstr`, submits it with your Dhan client id and PIN, then stores the returned access token in request headers.

```python
from fenix import Dhan

broker = Dhan()
headers = broker.authenticate(params={
    "client_id": "1100000000",
    "totpstr": "BASE32_TOTP_SECRET",
    "pin": "123456",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `client_id`, `totpstr`, and `pin`. |
| `headers` | Optional | Reuses a previously authenticated Dhan header dict. |
| `force` | Optional | When `True`, ignores cached headers and regenerates headers. |

Returned headers include `access-token` and `Accept`; the returned dict also includes `user_id`, mapped from Dhan's `dhanClientId`.

## Paper Mode

```python
from fenix import Dhan

broker = Dhan(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens

Dhan publishes one detailed CSV master. The adapter downloads it once per instance, caches the parsed rows, and reuses them across all token loaders.

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

| Method | Filters | Loads |
|--------|---------|-------|
| `load_equity_tokens(data=None)` | `INSTRUMENT == "EQUITY"`, segment `E`, type `ES`/`ETF` | NSE and BSE equity instruments. |
| `load_index_tokens(data=None)` | index rows from the scrip master | NSE and BSE indices under `IDX_I`. |
| `load_fno_tokens(data=None)` | NSE/BSE derivatives rows | NFO and BFO futures/options. |
| `load_cds_tokens(data=None)` | currency derivative rows | CDS and BCD futures/options. |
| `load_mcx_tokens(data=None)` | MCX commodity derivative rows | MCX futures/options. |

`data` can be a pre-parsed list of Dhan CSV row dictionaries. When omitted, the adapter fetches `https://images.dhan.co/api-data/api-scrip-master-detailed.csv`.

```python
equity, equity_by_token = broker.load_equity_tokens()
indices, index_by_token = broker.load_index_tokens()
fno, fno_by_token = broker.load_fno_tokens()
cds, cds_by_token = broker.load_cds_tokens()
mcx, mcx_by_token = broker.load_mcx_tokens()
```

### Token Record Fields

Equity records include `Token`, `Exchange`, `Symbol`, `Segment`, `ScriptName`, `LotSize`, `TickSize`, and `ISIN`.

Derivative records include `Exchange`, `Token`, `Root`, `Symbol`, `LotSize`, `TickSize`, `Expiry`, and `ScriptName`; options also include `StrikePrice` and `Option`.

```python
fno, _ = broker.load_fno_tokens()

nifty_call = fno["Options"]["NFO"]["NIFTY"][0]
print(nifty_call["Token"], nifty_call["Exchange"], nifty_call["StrikePrice"])
```

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for the order choices.

```python
from fenix import Dhan
from fenix.base.constants import Product, Side, Validity, Variety

broker = Dhan()
broker.authenticate(params={
    "client_id": "1100000000",
    "totpstr": "BASE32_TOTP_SECRET",
    "pin": "123456",
})

fno, _ = broker.load_fno_tokens()
contract = fno["Options"]["NFO"]["NIFTY"][0]

order = broker.place_order(
    token_dict=contract,
    quantity=contract["LotSize"],
    side=Side.BUY,
    product=Product.MIS,
    validity=Validity.DAY,
    variety=Variety.REGULAR,
    unique_id="dhan-docs-demo",
    price=0.0,
    trigger=0.0,
)
print(order["id"])
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token_dict` | Yes | Token metadata from `load_*_tokens()`. Must include `Token`, `Exchange`, and usually `Symbol`. |
| `quantity` | Yes | Order quantity. Use a valid lot multiple for derivatives. |
| `side` | Yes | `Side.BUY` or `Side.SELL`. |
| `product` | Yes | `Product.CNC`, `Product.MIS`, `Product.MARGIN`, `Product.MTF`, `Product.CO`, `Product.BO`, or `Product.NRML`. `NRML` maps to Dhan `MARGIN`. |
| `validity` | Yes | `Validity.DAY` or `Validity.IOC`. |
| `variety` | Yes | Unified compatibility value; Dhan-specific order shape is inferred from prices and bracket fields. |
| `unique_id` | Yes | Sent as Dhan `correlationId`. |
| `price` | Optional | Limit price. Use `0.0` for market orders. |
| `trigger` | Optional | Trigger price for stop-loss orders. |
| `target` | Optional | Bracket-order target/profit value. |
| `stoploss` | Optional | Bracket-order stop-loss value. |
| `trailing_sl` | Optional | Bracket-order trailing stop-loss value. |

The adapter returns a unified order-id record:

```python
{"id": "broker-order-id"}
```

## Order Management

```python
order_id = order["id"]

raw_orders = broker.fetch_raw_orderbook()
orders = broker.fetch_orderbook()
same_orders = broker.fetch_orders()
trades = broker.fetch_tradebook()
details = broker.fetch_order(order_id)
history = broker.fetch_order_history(order_id)

by_correlation = broker.fetch_order_by_correlation_id("dhan-docs-demo")
```

| Method | Returns |
|--------|---------|
| `fetch_raw_orderbook()` | Raw Dhan order-book rows, or `[]` when empty. |
| `fetch_orderbook()` | Unified Fenix order records. |
| `fetch_orders()` | Alias for `fetch_orderbook()`. |
| `fetch_tradebook()` | Unified fill-like trade records, or `[]` when empty. |
| `fetch_order(order_id)` | One unified order record, or raises `OrderNotFoundError`. |
| `fetch_order_by_correlation_id(correlation_id)` | One unified order record found by `correlationId`. |
| `fetch_order_history(order_id)` | Current order detail wrapped in a one-item list. |

### Modify, Cancel, Exit

```python
modified = broker.modify_order(
    order_id=order_id,
    price=152.5,
    quantity=75,
)

cancelled = broker.cancel_order(order_id=order_id)
exited = broker.exit_bracket_order(order_id=order_id)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `order_id` | Yes | Broker order id to modify, cancel, or exit. |
| `price` | Optional | Replacement limit price. Existing price is reused when omitted. |
| `trigger` | Optional | Replacement trigger price. Existing trigger is reused when omitted. |
| `quantity` | Optional | Replacement quantity. Existing quantity is reused when omitted. |
| `order_type` | Optional | Replacement order type in Fenix format. Existing type is reused when omitted. |
| `validity` | Optional | Replacement validity. Existing validity is reused when omitted. |
| `raw_order_json` | Optional | Raw order row to avoid refetching the order. |
| `extra_params` | Optional | Reserved for broker-specific extensions. |

`modify_order()`, `cancel_order()`, and `exit_bracket_order()` return unified order-id records.

### Square Off And Slicing

```python
square_off = broker.square_off_position(
    symbol="NIFTY",
    token=int(contract["Token"]),
    exchange=contract["Exchange"],
    quantity=contract["LotSize"],
    product=Product.MIS,
)
```

Dhan has no dedicated square-off endpoint. The adapter flattens the position by placing an opposite market order; positive quantity sells, negative quantity buys. Large orders can use Dhan's native slicing endpoint through the adapter's order payload path when implemented by the caller workflow.

## Super Orders

Dhan super orders manage entry, target, and stop-loss legs together.

```python
super_order = broker.place_super_order(
    token_dict=contract,
    quantity=contract["LotSize"],
    side=Side.BUY,
    product=Product.MIS,
    price=152.0,
    target=160.0,
    stoploss=148.0,
)

broker.modify_super_order(super_order["id"], leg_name="TARGET_LEG", target=161.0)
broker.cancel_super_order(super_order["id"], leg_name="ENTRY_LEG")
super_orders = broker.fetch_super_orders()
```

| Method | Returns |
|--------|---------|
| `place_super_order(token_dict, quantity, side, product, price)` | Unified order-id record. |
| `modify_super_order(order_id, leg_name="ENTRY_LEG")` | Unified order-id record. |
| `cancel_super_order(order_id, leg_name="ENTRY_LEG")` | Unified order-id record. |
| `fetch_super_orders()` | Unified order records with raw `legDetails` preserved in `info`. |

Valid super-order leg names are `ENTRY_LEG`, `TARGET_LEG`, and `STOP_LOSS_LEG`.

## Forever Orders

Forever orders are Dhan GTT orders. Use `order_flag="SINGLE"` for one leg or `order_flag="OCO"` for a one-cancels-other pair.

```python
forever = broker.place_forever_order(
    token_dict=contract,
    quantity=contract["LotSize"],
    side=Side.BUY,
    product=Product.CNC,
    price=152.0,
    trigger=151.5,
)

broker.modify_forever_order(forever["id"], price=153.0, trigger=152.5)
broker.cancel_forever_order(forever["id"])
forever_orders = broker.fetch_forever_orders()
```

| Method | Returns |
|--------|---------|
| `place_forever_order(token_dict, quantity, side, product, price, trigger)` | Unified order-id record. |
| `modify_forever_order(order_id, leg_name="ENTRY_LEG")` | Unified order-id record. |
| `cancel_forever_order(order_id)` | Unified order-id record. |
| `fetch_raw_forever_orders()` | Raw Dhan forever-order rows, or `[]` when empty. |
| `fetch_forever_orders()` | Unified forever-order records. |

## Positions And Account

```python
positions = broker.fetch_net_positions()
holdings = broker.fetch_holdings()
margins = broker.fetch_margin_limits()
profile = broker.fetch_profile()
```

| Method | Returns |
|--------|---------|
| `fetch_day_positions()` | Same as `fetch_net_positions()`; Dhan returns a single net snapshot. |
| `fetch_net_positions()` | Unified Fenix position records, or `[]` when empty. |
| `fetch_holdings()` | Raw Dhan holding rows, or `[]` when empty. |
| `convert_position(token, exchange, position_type, from_product, to_product, quantity)` | `None` after Dhan acknowledges conversion. |
| `exit_all_positions()` | Raw Dhan response after flattening positions and cancelling pending orders. |
| `fetch_margin_limits()` | Unified RMS record. |
| `margin_calculator(token_dict, quantity, side, product, price=0.0, trigger=0.0)` | Raw Dhan margin-calculator response. |
| `fetch_profile()` | Unified profile record. |

## Trader Control And Option Chain

```python
broker.kill_switch(activate=True)    # disable trading for the day
broker.kill_switch(activate=False)   # re-enable trading

expiries = broker.fetch_expiry_list(
    under_token=13,
    under_exchange="IDX_I",
)

chain = broker.fetch_option_chain(
    under_token=13,
    under_exchange="IDX_I",
    expiry="2026-06-25",
)
```

| Method | Returns |
|--------|---------|
| `kill_switch(activate=True)` | Raw Dhan kill-switch response. |
| `fetch_expiry_list(under_token, under_exchange)` | Raw expiry-list response. |
| `fetch_option_chain(under_token, under_exchange, expiry)` | Raw real-time option-chain response. |

## Rate Limits

| Group | Limits |
|-------|--------|
| `orders` | 25 requests/second, 250/minute, and 1,000/hour. |
| `data` | 5 requests/second. |
| `quote` | 1 request/second. |
| `default` | 20 requests/second. |

## Endpoints

| Endpoint | Server | Path |
|----------|--------|------|
| `token` | `auth` | `/generateAccessToken` |
| `orders` | `api` | `/orders` |
| `slice_order` | `api` | `/orders/slicing` |
| `order_by_correlation` | `api` | `/orders/external` |
| `trades` | `api` | `/trades` |
| `super_orders` | `api` | `/super/orders` |
| `forever_orders` | `api` | `/forever/orders` |
| `positions` | `api` | `/positions` |
| `holdings` | `api` | `/holdings` |
| `convert_position` | `api` | `/positions/convert` |
| `fund_limit` | `api` | `/fundlimit` |
| `margin_calculator` | `api` | `/margincalculator` |
| `profile` | `api` | `/profile` |
| `kill_switch` | `api` | `/killswitch` |
| `option_chain` | `api` | `/optionchain` |
| `expiry_list` | `api` | `/optionchain/expirylist` |
| `instruments` | public CSV | `https://images.dhan.co/api-data/api-scrip-master-detailed.csv` |

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
