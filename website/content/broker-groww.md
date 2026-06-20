# Groww

Groww broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.Groww` |
| **`id`** | `Groww` |
| **Module** | `fenix/groww.py` |
| **Broker API docs** | [https://groww.in/trade-api/docs/python-sdk](https://groww.in/trade-api/docs/python-sdk) |
| **Auth params** | `api_key` + `api_secret`, or `totp_token` + `totpstr` |
| **Instrument source** | Groww combined instrument-master CSV |

The Groww adapter authenticates through Groww's token endpoint, downloads the combined instrument CSV, maps cash, F&O, commodity, positions, margins, and profile responses into Fenix contracts, and exposes Groww order entry through the unified order interface.

## Authentication

`Groww.authenticate()` can reuse existing headers or request a new Bearer token. It supports two credential pairs:

| Credential pair | Description |
|-----------------|-------------|
| `api_key`, `api_secret` | Approval-key flow. The adapter creates the timestamp checksum and exchanges it for an access token. |
| `totp_token`, `totpstr` | TOTP flow. The adapter generates the current TOTP from `totpstr` and exchanges it for an access token. |

```python
from fenix import Groww

broker = Groww()
headers = broker.authenticate(params={
    "api_key": "your-groww-api-key",
    "api_secret": "your-groww-api-secret",
})
```

```python
headers = broker.authenticate(params={
    "totp_token": "your-groww-totp-token",
    "totpstr": "BASE32TOTPSECRET",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing one complete credential pair. |
| `headers` | Optional | Previously authenticated headers. Must include `Authorization`, `Content-Type`, `Accept`, `x-client-id`, and `x-api-version`. |
| `force` | Optional | When `True`, ignores cached headers and requests a fresh token. |

The returned headers are cached on the broker and include `Authorization: Bearer <token>` plus Groww client metadata headers.

## Paper Mode

```python
from fenix import Groww

broker = Groww(config={"paper_mode": True})
broker.authenticate()
```

In paper mode, authentication stores `{"paper": "true"}` and order, order-book, position, holding, margin, and profile calls are routed to the paper broker when available.

## Instrument Tokens

Groww publishes one combined CSV at `https://growwapi-assets.groww.in/instruments/instrument.csv`. The adapter downloads it once per broker instance, caches the parsed rows, and filters those rows for each loader.

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

| Method | Filters | Loads |
|--------|---------|-------|
| `load_equity_tokens(data=None)` | `instrument_type == "EQ"` | NSE and BSE cash equity instruments. |
| `load_index_tokens(data=None)` | `instrument_type == "IDX"` | NSE and BSE index records. |
| `load_fno_tokens(data=None)` | `segment == "FNO"`, `exchange` `NSE`/`BSE`, `instrument_type` `FUT`/`CE`/`PE` | NFO and BFO futures/options. |
| `load_mcx_tokens(data=None)` | `exchange == "MCX"`, `instrument_type` `FUT`/`CE`/`PE` | MCX futures/options. |

`data` can be supplied as pre-parsed CSV rows, which is useful if you want to download the instrument master once and feed it into multiple loaders.

```python
rows = broker._fetch_instruments()

equity, equity_by_token = broker.load_equity_tokens(rows)
indices, index_by_token = broker.load_index_tokens(rows)
fno, fno_by_token = broker.load_fno_tokens(rows)
mcx, mcx_by_token = broker.load_mcx_tokens(rows)
```

### Token Record Fields

Equity records contain `Token`, `Exchange`, `Segment`, `Symbol`, `ScriptName`, `LotSize`, `TickSize`, and `ISIN`.

Derivative records include `Token`, `Exchange`, `Segment`, `Root`, `Symbol`, `TickSize`, `LotSize`, `Expiry`, and `ScriptName`. Option records also include `StrikePrice` and `Option`.

```python
fno, _ = broker.load_fno_tokens()

nifty_call = fno["Options"]["NFO"]["NIFTY"][0]
print(nifty_call["Symbol"], nifty_call["Token"], nifty_call["StrikePrice"])
```

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for side, product, validity, and variety. Groww infers the order type from `price` and `trigger`.

```python
from fenix import Groww
from fenix.base.constants import Product, Side, Validity, Variety

broker = Groww()
broker.authenticate(params={
    "api_key": "your-groww-api-key",
    "api_secret": "your-groww-api-secret",
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
    unique_id="groww-docs-demo",
    price=0.0,
    trigger=0.0,
)
print(order["id"])
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token_dict` | Yes | Token metadata from `load_*_tokens()`. Must include `Exchange`, `Segment`, and `Symbol`. |
| `quantity` | Yes | Order quantity. Use a valid lot multiple for derivatives. |
| `side` | Yes | `Side.BUY` or `Side.SELL`. |
| `product` | Yes | `Product.CNC`, `Product.MIS`, `Product.NRML`, `Product.MTF`, `Product.CO`, or `Product.BO`. |
| `validity` | Yes | `Validity.DAY`, `Validity.IOC`, `Validity.GTC`, or `Validity.GTD`. |
| `variety` | Yes | Accepted for the shared broker interface. Groww infers AMO from the order window. |
| `unique_id` | Yes | Sent as Groww `order_reference_id`. |
| `price` | Optional | Limit price. Use `0.0` with no trigger for a market order. |
| `trigger` | Optional | Stop trigger. Combining `price` and `trigger` creates a stop-limit order. |
| `target`, `stoploss`, `trailing_sl` | Optional | Validated, but not supported through Groww regular order entry. Supplying any of these raises `NotSupported`. |

The adapter returns a unified order-id record:

```python
{"id": "groww-order-id", "info": {"groww_order_id": "groww-order-id"}}
```

## Order Management

```python
order_id = order["id"]

raw_orders = broker.fetch_raw_orderbook()
orders = broker.fetch_orderbook()
trades = broker.fetch_tradebook()
order_trades = broker.fetch_trades(order_id=order_id, segment=contract["Segment"])
details = broker.fetch_order(order_id)
history = broker.fetch_order_history(order_id)
```

| Method | Returns |
|--------|---------|
| `fetch_raw_orderbook()` | Raw Groww order rows from `order_list`. |
| `fetch_orderbook()` | List of unified order records. |
| `fetch_trades(order_id, segment)` | Unified fill records for one order and segment. |
| `fetch_tradebook()` | Unified fill records aggregated by walking filled orders and fetching their trades. |
| `fetch_order(order_id)` | One unified order record from the current order book. Raises `OrderNotFoundError` when absent. |
| `fetch_order_history(order_id)` | Single-item list containing the current order state, because Groww does not expose a status timeline endpoint here. |

### Modify And Cancel

Groww modify and cancel calls require the order segment. The adapter can resolve it by refetching the order book, or you can pass the raw order row when you already have it.

```python
modified = broker.modify_order(
    order_id=order_id,
    price=151.25,
    quantity=contract["LotSize"],
)

cancelled = broker.cancel_order(
    order_id=order_id,
    extra_params={"segment": contract["Segment"]},
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `order_id` | Yes | Groww order id to modify or cancel. |
| `price` | Optional | Replacement limit price. Existing price is reused when omitted. |
| `trigger` | Optional | Replacement trigger price. Existing trigger is reused when omitted. |
| `quantity` | Optional | Replacement quantity. Existing quantity is reused when omitted. |
| `order_type` | Optional | Replacement order type. Existing order type is reused when omitted. |
| `validity` | Optional | Accepted for the shared broker interface, but not sent by this adapter. |
| `raw_order_json` | Optional | Raw Groww order row for `modify_order()`, avoiding a fresh order-book lookup. |
| `extra_params` | Optional | For `cancel_order()`, pass `{"segment": "FNO"}` or `{"order": unified_order}` to avoid a lookup. |

Both methods return the unified order-id record from Groww's acknowledgement.

## Square Off

Groww does not define a separate square-off endpoint in this adapter. `square_off_position()` places an opposite-side market order using the sign of `quantity`.

```python
square_off = broker.square_off_position(
    symbol=contract["Symbol"],
    token=contract["Token"],
    exchange=contract["Exchange"],
    quantity=contract["LotSize"],
    product=Product.MIS,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `symbol` | Yes | Groww trading symbol. |
| `token` | Yes | Exchange token. Retained for interface parity. |
| `exchange` | Yes | Fenix or Groww-native exchange value. The adapter derives the Groww exchange and segment. |
| `quantity` | Yes | Signed net quantity. Positive quantities are closed with SELL; negative quantities are closed with BUY. |
| `product` | Optional | Defaults to `Product.MIS`. |

## Positions And Account

```python
day_positions = broker.fetch_day_positions()
net_positions = broker.fetch_net_positions()
holdings = broker.fetch_holdings()
limits = broker.fetch_margin_limits()
profile = broker.fetch_profile()
```

| Method | Returns |
|--------|---------|
| `fetch_day_positions()` | Same records as `fetch_net_positions()`. Groww returns one net position snapshot. |
| `fetch_net_positions()` | Unified position records parsed from Groww `positions`. |
| `fetch_holdings()` | Raw Groww holding rows. |
| `fetch_margin_limits()` | Unified RMS limits record. |
| `fetch_profile()` | Unified profile record. |

## Rate Limits

| Group | Limit |
|-------|-------|
| `orders` | 10 requests/second and 250 requests/minute. |
| `live_data` | 10 requests/second and 300 requests/minute. |
| `default` | 20 requests/second and 500 requests/minute. |

## Endpoints

| Endpoint | Server | Path |
|----------|--------|------|
| `token` | `api` | `/token/api/access` |
| `place_order` | `api` | `/order/create` |
| `modify_order` | `api` | `/order/modify` |
| `cancel_order` | `api` | `/order/cancel` |
| `order_list` | `api` | `/order/list` |
| `order_detail` | `api` | `/order/detail` |
| `order_status` | `api` | `/order/status` |
| `trades` | `api` | `/order/trades` |
| `positions` | `api` | `/positions/user` |
| `position_symbol` | `api` | `/positions/trading-symbol` |
| `holdings` | `api` | `/holdings/user` |
| `margins` | `api` | `/margins/detail/user` |
| `profile` | `api` | `/user/detail` |
| `instruments` | `instruments` | `/instruments/instrument.csv` |

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
