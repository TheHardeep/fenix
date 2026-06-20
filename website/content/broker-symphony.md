# Symphony

Symphony broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.Symphony` |
| **`id`** | `Symphony` |
| **Module** | `fenix/symphony.py` |
| **Broker API docs** | [https://developers.symphonyfintech.in/doc/interactive](https://developers.symphonyfintech.in/doc/interactive) |
| **Auth params** | `api_key`, `api_secret` |
| **Transport** | Symphony/XTS Interactive API |

The Symphony adapter powers the JM Financial integration. It uses Symphony's HostLookup flow to discover the Interactive API base URL, authenticates with API keys, parses the XTS-style contract master, and exposes orders, positions, holdings, funds, and profile data through the unified Fenix API.

## Authentication

`Symphony.authenticate()` accepts fresh API credentials through `params` or a previously saved authenticated header dict through `headers`.

```python
from fenix import Symphony

broker = Symphony()
headers = broker.authenticate(params={
    "api_key": "your-app-key",
    "api_secret": "your-secret-key",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `api_key` and `api_secret`. |
| `headers` | Optional | Reuses a previously authenticated Symphony header dict. |
| `force` | Optional | When `True`, ignores cached headers and runs the login flow again. |

Authentication first calls `HostLookup` to resolve the Interactive `connectionString` and `uniqueKey`, then exchanges `api_key`, `api_secret`, and that `uniqueKey` for an access token. If HostLookup is unavailable, the adapter uses the statically configured Interactive base and can fall back to `params["uniqueKey"]`.

Returned headers include `Content-Type` and `Authorization`; the returned dict also includes the authenticated `user_id` used internally as `clientID`.

## Paper Mode

Paper mode routes order entry and portfolio reads through the in-process simulator instead of the live Interactive API.

```python
from fenix import Symphony

broker = Symphony(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens

Each loader returns a tuple:

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

`token_json` is grouped by asset class and exchange. `alltoken_json` is a flat lookup keyed as `"{Token}_{Exchange}"`, where `Exchange` is the broker segment code such as `NSECM`, `NSEFO`, or `MCXFO`.

| Method | Data argument | Loads |
|--------|---------------|-------|
| `load_equity_tokens(data=None)` | Optional contract-master blob keyed by `NSE` and/or `BSE`. | NSECM and BSECM equity instruments. |
| `load_index_tokens(data=None)` | Optional index lists keyed by `NSE` and `BSE`. | NSE and BSE indices plus root aliases. |
| `load_fno_tokens(data=None)` | Optional contract-master blob keyed by `NFO` and/or `BFO`. | NSEFO and BSEFO futures/options. |
| `load_mcx_tokens(data=None)` | Optional contract-master blob keyed by `MCX`. | MCXFO futures/options. |
| `load_cds_tokens(data=None)` | Optional contract-master blob keyed by `CDS`. | NSECD currency futures/options. |

```python
equity, equity_by_token = broker.load_equity_tokens()
indices, index_by_token = broker.load_index_tokens()
fno, fno_by_token = broker.load_fno_tokens()
mcx, mcx_by_token = broker.load_mcx_tokens()
cds, cds_by_token = broker.load_cds_tokens()
```

### Token Record Fields

Equity records include fields such as `Exchange`, `Token`, `Symbol`, `DisplayName`, `FreezeQty`, `TickSize`, `LotSize`, `ISIN`, `DetailedDescription`, and `Series`.

Derivative records include `Exchange`, `Token`, `Root`, `Symbol`, `LotSize`, `TickSize`, `Expiry`, and `ScriptName`; options also include `StrikePrice` and `Option`.

```python
fno, _ = broker.load_fno_tokens()

nifty_call = fno["Options"]["NFO"]["NIFTY"][0]
print(nifty_call["Token"], nifty_call["Symbol"], nifty_call["StrikePrice"])
```

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for the order choices.

```python
from fenix import Symphony
from fenix.base.constants import Product, Side, Validity, Variety

broker = Symphony()
broker.authenticate(params={
    "api_key": "your-app-key",
    "api_secret": "your-secret-key",
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
    unique_id="symphony-docs-demo",
    price=0.0,
    trigger=0.0,
)
print(order["id"])
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token_dict` | Yes | Token metadata from `load_*_tokens()`. Must include `Token` and `Exchange`. |
| `quantity` | Yes | Order quantity. Use a valid lot multiple for derivatives. |
| `side` | Yes | `Side.BUY` or `Side.SELL`. |
| `product` | Yes | `Product.MIS`, `Product.NRML`, `Product.CNC`, `Product.CO`, or `Product.BO`. |
| `validity` | Yes | `Validity.DAY` or `Validity.IOC`. |
| `variety` | Yes | Accepted for unified compatibility; bracket behavior is selected by `target`. |
| `unique_id` | Yes | Sent as `orderUniqueIdentifier`. |
| `price` | Optional | Limit price. Use `0.0` for market orders. |
| `trigger` | Optional | Stop price for stop orders. |
| `target` | Optional | Bracket-order square-off target. When set, the adapter posts to `/orders/bracket`. |
| `stoploss` | Optional | Bracket-order stop-loss price. |
| `trailing_sl` | Optional | Bracket-order trailing stop-loss value. |

The adapter returns a unified order-id record:

```python
{"id": "broker-order-id"}
```

## Order Management

Use the read methods for order/trade state, then pass broker order ids into modify or cancel calls.

```python
order_id = order["id"]

raw_orders = broker.fetch_raw_orderbook()
raw_history = broker.fetch_raw_order_history(order_id)

orders = broker.fetch_orderbook()
trades = broker.fetch_tradebook()
same_orders = broker.fetch_orders()
details = broker.fetch_order(order_id)
history = broker.fetch_order_history(order_id)
```

| Method | Returns |
|--------|---------|
| `fetch_raw_orderbook()` | Raw Symphony order-book rows, or `[]` when empty. |
| `fetch_raw_order_history(order_id)` | Raw Symphony history rows for one order. |
| `fetch_orderbook()` | Unified Fenix order records. |
| `fetch_tradebook()` | Unified trade/order records, or `[]` when empty. |
| `fetch_orders()` | Alias for `fetch_orderbook()`. |
| `fetch_order(order_id)` | Latest unified order-history record, or raises `OrderNotFoundError`. |
| `fetch_order_history(order_id)` | Unified order-history records. |

### Modify And Cancel

```python
modified = broker.modify_order(
    order_id=order_id,
    price=152.5,
    quantity=75,
)

cancelled = broker.cancel_order(order_id=order_id)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `order_id` | Yes | Broker order id to modify or cancel. |
| `price` | Optional | Replacement limit price. Existing price is reused when omitted. |
| `trigger` | Optional | Replacement stop price. Existing stop price is reused when omitted. |
| `quantity` | Optional | Replacement quantity. Existing quantity is reused when omitted. |
| `order_type` | Optional | Replacement order type in Fenix format. Existing type is reused when omitted. |
| `validity` | Optional | Replacement validity. Existing validity is reused when omitted. |
| `raw_order_json` | Optional | Raw order-history row to avoid an extra history fetch. |
| `extra_params` | Optional | Reserved for broker-specific extensions. |

Both `modify_order()` and `cancel_order()` return a unified order-id record.

## Positions And Account

```python
day_positions = broker.fetch_day_positions()
net_positions = broker.fetch_net_positions()
holdings = broker.fetch_holdings()
margins = broker.fetch_margin_limits()
profile = broker.fetch_profile()
```

| Method | Returns |
|--------|---------|
| `fetch_day_positions()` | Unified day-wise position records. |
| `fetch_net_positions()` | Unified net-wise position records. |
| `position_convert(position, new_product)` | Decoded broker response after product conversion. |
| `fetch_holdings()` | Raw Symphony holdings payload, or `[]` when empty. |
| `fetch_margin_limits()` | Unified RMS record with raw `info`. |
| `fetch_profile()` | Unified profile record with raw `info`. |

## Rate Limits

| Group | Limit |
|-------|-------|
| `orders` | 10 requests/second shared across place, modify, and cancel. |
| `margin` | 10 requests/second. |
| `post_trade` | 1 request/second. |
| `user` | 1 request/second. |
| `default` | 1 request/second. |

## Endpoints

| Endpoint | Server | Path |
|----------|--------|------|
| `hostlookup` | `hostlookup` | `/hostlookup` |
| `access_token` | `interactive` | `/user/session` |
| `place_order` | `interactive` | `/orders` |
| `place_order_bracket` | `interactive` | `/orders/bracket` |
| `modify_order` | `interactive` | `/orders` |
| `cancel_order` | `interactive` | `/orders` |
| `order_history` | `interactive` | `/orders` |
| `orderbook` | `interactive` | `/orders` |
| `tradebook` | `interactive` | `/orders/trades` |
| `positions` | `interactive` | `/portfolio/positions` |
| `position_convert` | `interactive` | `/portfolio/positions/convert` |
| `holdings` | `interactive` | `/portfolio/holdings` |
| `profile` | `interactive` | `/user/profile` |
| `rms_limits` | `interactive` | `/user/balance` |
| `instruments` | `market_data` | `/instruments/master` |
| `instruments_binary` | `market_data_binary` | `/instruments/master` |
| `indices` | `market_data` | `/instruments/indexlist` |

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
