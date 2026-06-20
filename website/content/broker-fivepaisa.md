# 5paisa

FivePaisa broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.FivePaisa` |
| **`id`** | `FivePaisa` |
| **Module** | `fenix/fivepaisa.py` |
| **Broker API docs** | [https://xstream.5paisa.com/dev-docs](https://xstream.5paisa.com/dev-docs) |
| **Auth params** | `user_id`, `password`, `email`, `web_login_password`, `dob`, `app_name`, `user_key`, `encryption_key` |
| **Instrument source** | 5paisa combined scrip-master CSV |

The 5paisa adapter authenticates with the legacy 5paisa mobile login flow, keeps a JWT auth bundle for subsequent requests, loads the combined scrip-master CSV, and exposes orders, trades, positions, and holdings through the unified Fenix API.

## Authentication

`FivePaisa.authenticate()` calls `create_headers()` internally. It encrypts the web login password, logs in with email, DOB, password, user key, and app name, then stores the returned `ClientCode` and `AccessToken`.

```python
from fenix import FivePaisa

broker = FivePaisa()
headers = broker.authenticate(params={
    "user_id": "50000000",
    "password": "your-pin-or-password",
    "email": "you@example.com",
    "web_login_password": "your-web-login-password",
    "dob": "19900131",
    "app_name": "your-app-name",
    "user_key": "your-user-key",
    "encryption_key": "your-encryption-key",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing all auth params listed above. |
| `headers` | Optional | Reuses a previously authenticated 5paisa auth bundle. |
| `force` | Optional | When `True`, ignores cached headers and logs in again. |

The returned auth bundle includes request `headers`, `json_data`, `client_code`, `access_token`, and `user_key`. `use_headers()` restores that full bundle, not just HTTP headers.

## Paper Mode

```python
from fenix import FivePaisa

broker = FivePaisa(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens

5paisa publishes one combined CSV scrip master. The adapter reads it into a DataFrame and filters rows by exchange, exchange type, series, and contract type.

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

| Method | Filters | Loads |
|--------|---------|-------|
| `load_equity_tokens(data=None)` | `CpType == "XX"`, `ExchType == "C"`, `Series == "EQ"`, `Exch` `N`/`B` | NSE and BSE equity instruments. |
| `load_index_tokens(data=None)` | index rows such as `CpType == "EQ"` plus `SENSEX` | NSE and BSE indices with root aliases. |
| `load_fno_tokens(data=None)` | `ExchType == "D"`, `Exch` `N`/`B` | NSE F&O and BSE F&O futures/options. |
| `load_mcx_tokens(data=None)` | MCX derivative rows | MCX futures/options. |
| `load_cds_tokens(data=None)` | currency derivative rows | CDS and BCD futures/options. |

`data` can be a pre-fetched scrip-master DataFrame. When omitted, the adapter downloads `https://images.5paisa.com/website/scripmaster-csv-format.csv`.

```python
equity, equity_by_token = broker.load_equity_tokens()
indices, index_by_token = broker.load_index_tokens()
fno, fno_by_token = broker.load_fno_tokens()
mcx, mcx_by_token = broker.load_mcx_tokens()
cds, cds_by_token = broker.load_cds_tokens()
```

### Token Record Fields

Equity records contain `Token`, `Exchange`, `Symbol`, `ScriptName`, `LotSize`, and `TickSize`.

Derivative records include `Exchange`, `Token`, `Root`, `Symbol`, `TickSize`, `LotSize`, `Expiry`, and `ScriptName`; options also include `StrikePrice` and `Option`.

```python
fno, _ = broker.load_fno_tokens()

nifty_call = fno["Options"]["NFO"]["NIFTY"][0]
print(nifty_call["Token"], nifty_call["Symbol"], nifty_call["StrikePrice"])
```

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for the order choices.

```python
from fenix import FivePaisa
from fenix.base.constants import Product, Side, Validity, Variety

broker = FivePaisa()
broker.authenticate(params={
    "user_id": "50000000",
    "password": "your-pin-or-password",
    "email": "you@example.com",
    "web_login_password": "your-web-login-password",
    "dob": "19900131",
    "app_name": "your-app-name",
    "user_key": "your-user-key",
    "encryption_key": "your-encryption-key",
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
    unique_id="fivepaisa-docs-demo",
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
| `product` | Yes | `Product.MIS` for intraday or `Product.NRML` for delivery/carry-forward. |
| `validity` | Yes | `Validity.DAY` or `Validity.IOC`. |
| `variety` | Yes | `Variety.REGULAR`, `Variety.STOPLOSS`, `Variety.BO`, or `Variety.AMO`. |
| `unique_id` | Yes | Sent as `RemoteOrderID` or `UniqueOrderIDNormal`. |
| `price` | Optional | Limit price. Use `0.0` for market orders. |
| `trigger` | Optional | Stop-loss trigger price. |
| `target` | Optional | Bracket-order profit limit. When set, the adapter posts a bracket order. |
| `stoploss` | Optional | Bracket-order stop-loss limit. |
| `trailing_sl` | Optional | Bracket-order trailing stop-loss value. |

The adapter returns a unified order-id record.

```python
{"id": "exchange-order-id"}
```

## Order Management

```python
order_id = order["id"]

raw_orders = broker.fetch_raw_orderbook()
raw_trades = broker.fetch_raw_tradebook()

orders = broker.fetch_orderbook()
trades = broker.fetch_tradebook()
enriched_orders = broker.fetch_orders()
details = broker.fetch_order(order_id)
```

| Method | Returns |
|--------|---------|
| `fetch_raw_orderbook(headers=None)` | Raw 5paisa order-book response. |
| `fetch_raw_tradebook(headers=None)` | Raw 5paisa trade-book response. |
| `fetch_orderbook(headers=None)` | Unified order records. |
| `fetch_tradebook(headers=None, default=True)` | Unified trade records, or a dict keyed by order id when `default=False`. |
| `fetch_orders(headers=None)` | Unified order book enriched with average prices from the trade book. |
| `fetch_order(order_id, key_to_check="ExchOrderID")` | One unified order record. Use `key_to_check="BrokerOrderId"` to search by broker id. |
| `fetch_tradebook_order(order_id)` | One trade-book record, or the raw fill rate when `default=False`. |

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
| `order_id` | Yes | Exchange order id to modify or cancel. |
| `price` | Optional | Replacement limit price. Existing rate is reused when omitted. |
| `trigger` | Optional | Replacement stop-loss trigger price. |
| `quantity` | Optional | Replacement quantity. Existing quantity is reused when omitted. |
| `order_type` | Optional | Accepted for compatibility, but 5paisa modify does not use it. |
| `validity` | Optional | Accepted for compatibility, but 5paisa modify does not use it. |
| `headers` | Optional | Alternate auth bundle. The cached bundle is used when omitted. |

Both methods return the unified order record after the broker acknowledges the operation.

## Positions And Holdings

```python
positions = broker.fetch_positions()
holdings = broker.fetch_holdings()
```

| Method | Returns |
|--------|---------|
| `fetch_positions(headers=None)` | Unified day/net position records. |
| `fetch_holdings(headers=None)` | Raw 5paisa holdings response. |

This adapter does not define separate `fetch_profile()` or `fetch_margin_limits()` methods.

## Rate Limits

| Group | Limit |
|-------|-------|
| `default` | 10 requests/second. |

## Endpoints

| Endpoint | Server | Path |
|----------|--------|------|
| `access_token` | `api` | `/V4/LoginRequestMobileNewbyEmail` |
| `place_order` | `api` | `/V1/PlaceOrderRequest` |
| `bo_order` | `api` | `/BracketOrderRequest` |
| `modify_order` | `api` | `/V1/ModifyOrderRequest` |
| `cancel_order` | `api` | `/V1/CancelOrderRequest` |
| `orderbook` | `api` | `/V2/OrderBook` |
| `tradebook` | `api` | `/V1/TradeBook` |
| `positions` | `api` | `/V4/NetPosition` |
| `holdings` | `api` | `/V3/Holding` |
| `instruments` | `market_data` | `https://images.5paisa.com/website/scripmaster-csv-format.csv` |

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
