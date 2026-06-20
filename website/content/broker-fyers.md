# Fyers

Fyers broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.Fyers` |
| **`id`** | `Fyers` |
| **Module** | `fenix/fyers.py` |
| **Broker API docs** | [https://myapi.fyers.in/docsv3](https://myapi.fyers.in/docsv3) |
| **Auth params** | `user_id`, `pin`, `totpstr`, `api_key`, `api_secret`, `redirect_uri` |
| **Instrument source** | FYERS public symbol master JSON files |

The Fyers adapter handles the FYERS OTP, TOTP, PIN, auth-code, and access-token flow, downloads segment-specific symbol masters, and maps FYERS orders, trades, positions, and profile data into the unified Fenix contracts.

## Authentication

`Fyers.authenticate()` can reuse existing headers or log in from credentials. A full login sends the encoded FYERS user id, verifies the current TOTP, verifies the PIN, requests an auth code, then exchanges it for the final trading access token.

```python
from fenix import Fyers

broker = Fyers()
headers = broker.authenticate(params={
    "user_id": "YA00000",
    "pin": "1234",
    "totpstr": "BASE32TOTPSECRET",
    "api_key": "your-app-id-100",
    "api_secret": "your-api-secret",
    "redirect_uri": "https://your-redirect-url",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing all auth params listed above. |
| `headers` | Optional | Previously authenticated headers. Must include `Authorization`. |
| `force` | Optional | When `True`, ignores cached headers and logs in again. |

The returned header is stored on the broker and has this form:

```python
{"Authorization": "api_key:access_token"}
```

## Paper Mode

```python
from fenix import Fyers

broker = Fyers(config={"paper_mode": True})
broker.authenticate()
```

In paper mode, authentication stores `{"paper": "true"}` and order, position, holding, and profile calls are routed to the paper broker when available.

## Instrument Tokens

FYERS publishes one JSON symbol master per exchange segment. The adapter downloads the required segment masters and converts each record into Fenix token dictionaries.

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

| Method | Downloads | Loads |
|--------|-----------|-------|
| `load_equity_tokens(data=None)` | `NSE_CM`, `BSE_CM` | NSE and BSE cash equity instruments. |
| `load_index_tokens(data=None)` | `NSE_CM`, `BSE_CM` | NSE and BSE index records where `symbolDesc == "INDEX"`. |
| `load_fno_tokens(data=None)` | `NSE_FO`, `BSE_FO` | NFO and BFO futures/options. |
| `load_mcx_tokens(data=None)` | `MCX_COM` | MCX commodity futures/options. |
| `load_ncx_tokens(data=None)` | `NSE_COM` | NSE commodity futures/options. |
| `load_cds_tokens(data=None)` | `NSE_CD` | Currency derivative futures/options. |

`data` can be supplied as a dict keyed by the FYERS segment name. When omitted, the adapter downloads from `https://public.fyers.in/sym_details/{segment}_sym_master.json`.

```python
equity, equity_by_token = broker.load_equity_tokens()
indices, index_by_token = broker.load_index_tokens()
fno, fno_by_token = broker.load_fno_tokens()
mcx, mcx_by_token = broker.load_mcx_tokens()
ncx, ncx_by_token = broker.load_ncx_tokens()
cds, cds_by_token = broker.load_cds_tokens()
```

### Token Record Fields

Equity records contain `Exchange`, `Token`, `Exchange_Token`, `Symbol`, `ScriptName`, `TickSize`, `LotSize`, `FreezeQty`, `Leverage`, `ISIN`, and `DetailedDescription`.

Derivative records include `Exchange`, `Token`, `Exchange_Token`, `Root`, `Symbol`, `TickSize`, `LotSize`, `Expiry`, and `ScriptName`. Option records also include `StrikePrice` and `Option`.

```python
fno, _ = broker.load_fno_tokens()

nifty_call = fno["Options"]["NFO"]["NIFTY"][0]
print(nifty_call["Symbol"], nifty_call["Token"], nifty_call["StrikePrice"])
```

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for side, product, validity, and variety. The adapter resolves the FYERS order type from `price` and `trigger`.

```python
from fenix import Fyers
from fenix.base.constants import Product, Side, Validity, Variety

broker = Fyers()
broker.authenticate(params={
    "user_id": "YA00000",
    "pin": "1234",
    "totpstr": "BASE32TOTPSECRET",
    "api_key": "your-app-id-100",
    "api_secret": "your-api-secret",
    "redirect_uri": "https://your-redirect-url",
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
    unique_id="fyers-docs-demo",
    price=0.0,
    trigger=0.0,
    order_tag="docs-demo",
)
print(order["id"])
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token_dict` | Yes | Token metadata from `load_*_tokens()`. Must include `Symbol`. |
| `quantity` | Yes | Order quantity. Use a valid lot multiple for derivatives. |
| `side` | Yes | `Side.BUY` or `Side.SELL`. |
| `product` | Yes | `Product.MIS`, `Product.NRML`, `Product.CNC`, `Product.MARGIN`, `Product.MTF`, `Product.BO`, or `Product.CO`. |
| `validity` | Yes | `Validity.DAY` or `Validity.IOC`. |
| `variety` | Yes | `Variety.REGULAR`, `Variety.STOPLOSS`, `Variety.AMO`, or `Variety.BO`. `Variety.AMO` sends `offlineOrder=True`. |
| `unique_id` | Yes | Fallback value for FYERS `orderTag`. |
| `price` | Optional | Limit price. Use `0.0` with no trigger for a market order. |
| `trigger` | Optional | Stop trigger. Combining `price` and `trigger` creates a stop-limit order. |
| `target` | Optional | Bracket-order target value, sent as `takeProfit`. |
| `stoploss` | Optional | Bracket or cover stop-loss value, sent as `stopLoss`. |
| `trailing_sl` | Optional | Validated for compatibility, but not sent in the FYERS payload. |
| `order_tag` | Optional | FYERS order tag. Ignored for `Product.BO` and `Product.CO`. |

The adapter returns the unified order-id record:

```python
{"id": "broker-order-id", "info": {"s": "ok", "id": "broker-order-id"}}
```

## Multi-Order And GTT

`place_multi_order()` posts up to 10 already-built FYERS order payloads. It is useful when you want direct control over the FYERS request body.

```python
payload = broker._build_place_order_payload(
    token_dict=contract,
    quantity=contract["LotSize"],
    side=Side.BUY,
    product=Product.MIS,
    validity=Validity.DAY,
    variety=Variety.REGULAR,
    unique_id="basket-1",
)

response = broker.place_multi_order([payload])
```

`place_gtt_order()` creates a FYERS single-leg GTT order. Supplying all leg-2 fields creates an OCO GTT order.

```python
gtt = broker.place_gtt_order(
    token_dict=contract,
    quantity=contract["LotSize"],
    side=Side.BUY,
    product=Product.CNC,
    price=150.0,
    trigger=149.5,
    order_tag="gtt-demo",
)
```

| GTT parameter | Required | Description |
|---------------|----------|-------------|
| `token_dict` | Yes | Token metadata with the FYERS `Symbol`. |
| `quantity` | Yes | Leg-1 quantity. Must be greater than zero. |
| `side` | Yes | `Side.BUY` or `Side.SELL`. |
| `product` | Yes | Product sent as FYERS `productType`. |
| `price` | Yes | Leg-1 order price. Must be greater than zero. |
| `trigger` | Yes | Leg-1 trigger price. Must be greater than zero. |
| `order_tag` | Optional | FYERS GTT order tag. |
| `leg2_price`, `leg2_trigger`, `leg2_quantity` | Optional | Provide all three to create an OCO second leg. |

## Order Management

```python
order_id = order["id"]

raw_orders = broker.fetch_raw_orderbook()
orders = broker.fetch_orderbook()
trades = broker.fetch_tradebook()
details = broker.fetch_order(order_id)
```

| Method | Returns |
|--------|---------|
| `fetch_raw_orderbook()` | Raw FYERS order-book response. |
| `fetch_orderbook()` | List of unified order records from `orderBook`. |
| `fetch_tradebook()` | List of unified trade records from `tradeBook`. |
| `fetch_order(order_id)` | One unified order record. Raises `OrderNotFoundError` when FYERS returns no matching order. |

### Modify And Cancel

```python
modified = broker.modify_order(
    order_id=order_id,
    price=151.25,
    quantity=contract["LotSize"],
)

cancelled = broker.cancel_order(order_id=order_id)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `order_id` | Yes | FYERS order id to modify or cancel. |
| `price` | Optional | Replacement limit price, sent as `limitPrice`. |
| `trigger` | Optional | Replacement trigger price, sent as `stopPrice`. |
| `quantity` | Optional | Replacement quantity, sent as `qty`. |
| `order_type` | Optional | Replacement Fenix order type. Converted to FYERS `type`. |
| `validity` | Optional | Accepted for the shared broker interface, but not sent by this adapter. |
| `raw_order_json` | Optional | Reserved for broker-specific extensions. |
| `extra_params` | Optional | Reserved for broker-specific extensions. |

`modify_order()` acknowledges the PATCH request and then fetches the updated order. `cancel_order()` sends the DELETE request and then fetches the cancelled order by the id returned from FYERS.

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
| `fetch_day_positions()` | Unified position records parsed from FYERS `netPositions`. |
| `fetch_net_positions()` | Same records as `fetch_day_positions()`. |
| `fetch_holdings()` | Raw FYERS holdings response. |
| `fetch_margin_limits()` | Raw FYERS funds or RMS limits response. |
| `fetch_profile()` | Unified profile record parsed from FYERS profile `data`. |

## Rate Limits

| Group | Limit |
|-------|-------|
| `default` | 10 requests/second, 200 requests/minute, and 10000 requests/day. |

## Endpoints

| Endpoint | Server | Path |
|----------|--------|------|
| `login_otp` | `auth` | `/vagator/v2/send_login_otp_v2` |
| `verify_totp` | `auth` | `/vagator/v2/verify_otp` |
| `verify_pin` | `auth` | `/vagator/v2/verify_pin_v2` |
| `token` | `api_v3` | `/token` |
| `validate_authcode` | `api_v3` | `/validate-authcode` |
| `place_order` | `api_v3` | `/orders/sync` |
| `place_multi_order` | `api_v3` | `/multi-order/sync` |
| `place_gtt_order` | `api_v3` | `/gtt/orders/sync` |
| `modify_order` | `api_v3` | `/orders` |
| `cancel_order` | `api_v3` | `/orders` |
| `orderbook` | `api_v3` | `/orders` |
| `tradebook` | `api_v3` | `/tradebook` |
| `positions` | `api_v3` | `/positions` |
| `holdings` | `api_v3` | `/holdings` |
| `rms_limits` | `api_v3` | `/funds` |
| `profile` | `api_v3` | `/profile` |
| `instruments` | `market_data` | `/exch_seg_sym_master.json` |

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
