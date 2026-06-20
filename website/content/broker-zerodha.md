# Zerodha

Zerodha (Kite Connect) broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.Zerodha` |
| **`id`** | `Zerodha` |
| **Module** | `fenix/zerodha.py` |
| **Broker API docs** | [https://kite.trade/docs/connect/v3](https://kite.trade/docs/connect/v3) |
| **Auth params** | `user_id`, `password`, `totpstr`, `api_key`, `api_secret` |
| **Rate limit groups** | `order`, `modify`, `quote`, `historical`, `default` (see below) |
| **Instrument source** | Kite Connect `/instruments` CSV dump |

The Zerodha adapter drives the Kite Connect v3 login flow (session capture → password → TOTP → connect-finish → checksum exchange) to obtain an access token, parses the single Kite Connect instruments CSV in-process, and exposes orders, positions, holdings, RMS limits, and profile through the unified Fenix API.

## Authentication

`Zerodha.authenticate()` walks the six-step Kite Connect login:

1. `GET /connect/login?api_key=…&v=3` to capture the OAuth session id query string.
2. Warm up `/api/connect/session` with that id.
3. `POST /api/login` with `user_id`+`password` to obtain a `request_id`.
4. `POST /api/twofa` with the current TOTP from `totpstr` to complete 2FA.
5. `GET /connect/finish` and parse `request_token` from the redirect URL.
6. SHA-256 `api_key + request_token + api_secret` to form `checksum`, then `POST /session/token` to exchange it for an `access_token`.

```python
from fenix import Zerodha

broker = Zerodha()
headers = broker.authenticate(params={
    "user_id": "AB1234",
    "password": "your-kite-password",
    "totpstr": "BASE32_TOTP_SECRET",
    "api_key": "your-kite-api-key",
    "api_secret": "your-kite-api-secret",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `user_id`, `password`, `totpstr`, `api_key`, and `api_secret`. |
| `headers` | Optional | Reuses a previously authenticated Kite header dict. |
| `force` | Optional | When `True`, ignores cached headers and runs the login flow again. |

Returned headers contain `X-Kite-Version: 3`, `User-Agent`, `Authorization: token {api_key}:{access_token}`, and the convenience keys `user_id`, `api_key`, and `access_token`.

## Paper Mode

Paper mode routes order entry and portfolio reads through the in-process simulator instead of the live Kite Connect API.

```python
from fenix import Zerodha

broker = Zerodha(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens

Kite Connect publishes one CSV instruments dump that covers every segment. The adapter downloads it once per call (or accepts pre-fetched CSV text via `data`) and filters in-process for each asset class.

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

`token_json` is grouped by asset class and exchange. `alltoken_json` is a flat lookup keyed as `"{exchange_token}_{exchange}"`, for example `"53001_NFO"` or `"256265_NSE"`.

| Method | `data` argument | Loads |
|--------|-----------------|-------|
| `load_equity_tokens(data=None)` | Optional raw CSV text | NSE and BSE equity instruments. |
| `load_index_tokens(data=None)` | Optional raw CSV text | NSE, BSE, and MCX indices (segment `INDICES`). |
| `load_fno_tokens(data=None)` | Optional raw CSV text | NFO and BFO futures/options (segments `NFO-FUT`/`NFO-OPT`/`BFO-FUT`/`BFO-OPT`). |
| `load_mcx_tokens(data=None)` | Optional raw CSV text | MCX futures/options (segments `MCX-FUT`/`MCX-OPT`). |
| `load_cds_tokens(data=None)` | Optional raw CSV text | CDS currency futures/options (segments `CDS-FUT`/`CDS-OPT`). |
| `load_nco_tokens(data=None)` | Optional raw CSV text | NCO commodity futures/options (segments `NCO-FUT`/`NCO-OPT`). |

```python
equity, equity_by_token = broker.load_equity_tokens()
indices, index_by_token = broker.load_index_tokens()
fno, fno_by_token = broker.load_fno_tokens()
mcx, mcx_by_token = broker.load_mcx_tokens()
cds, cds_by_token = broker.load_cds_tokens()
nco, nco_by_token = broker.load_nco_tokens()
```

### Token Record Fields

Equity and index records contain `Token` (Kite numeric `instrument_token`), `ExToken` (the `exchange_token`), `Exchange` (`NSE`, `BSE`, `MCX`), `Symbol`, `ScriptName`, plus `LotSize` and `TickSize` for equity rows.

Futures records contain:

| Field | Description |
|-------|-------------|
| `Token` | Kite numeric `instrument_token` used by the order APIs. |
| `ExToken` | Exchange-level token. |
| `Exchange` | Kite segment string such as `NFO-FUT`, `MCX-OPT`, etc. |
| `Root` | Contract root, such as `NIFTY` or `CRUDEOIL`. |
| `Symbol` | Kite `tradingsymbol`. |
| `LotSize` | Exchange lot size. |
| `TickSize` | Minimum price tick. |
| `Expiry` | Expiry date as `YYYY-MM-DD`. |
| `ScriptName` | Human-readable contract label. |

Options include the same fields plus `StrikePrice` and `Option` (Kite `instrument_type`, e.g. `CE`/`PE`).

```python
fno, _ = broker.load_fno_tokens()

nifty_call = fno["Options"]["NFO"]["NIFTY"][0]
print(nifty_call["Token"], nifty_call["Symbol"], nifty_call["StrikePrice"])
```

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for the order choices. The URL `variety` segment (`regular`, `amo`, `co`, `iceberg`, `auction`) is derived from the `variety` argument.

```python
from fenix import Zerodha
from fenix.base.constants import Product, Side, Validity, Variety

broker = Zerodha()
broker.authenticate(params={
    "user_id": "AB1234",
    "password": "your-kite-password",
    "totpstr": "BASE32_TOTP_SECRET",
    "api_key": "your-kite-api-key",
    "api_secret": "your-kite-api-secret",
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
    unique_id="zerodha-docs-demo",
    price=0.0,
    trigger=0.0,
)
print(order["id"])
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token_dict` | Yes | Token metadata from `load_*_tokens()`. Must include `Exchange` and `Symbol` (used as Kite `tradingsymbol`). |
| `quantity` | Yes | Order quantity. Use a valid lot multiple for derivatives. |
| `side` | Yes | `Side.BUY` or `Side.SELL`. |
| `product` | Yes | `Product.MIS`, `Product.CNC`, or `Product.NRML`. |
| `validity` | Yes | `Validity.DAY`, `Validity.IOC`, or `Validity.TTL`. |
| `variety` | Yes | `Variety.REGULAR`, `Variety.STOPLOSS`, `Variety.AMO`, `Variety.CO`, `Variety.ICEBERG`, or `Variety.AUCTION`. |
| `unique_id` | Yes | Client-provided order tag, sent as Kite `tag`. |
| `price` | Optional | Limit price. Use `0.0` for market orders. |
| `trigger` | Optional | Stop-loss trigger price. Use `0.0` when not applicable. |
| `target` | Optional | Not supported. Any non-zero `target`/`stoploss`/`trailing_sl` raises `InputError` because Kite Connect no longer supports bracket orders. |
| `stoploss` | Optional | Not supported (see above). |
| `trailing_sl` | Optional | Not supported (see above). |

The adapter returns a unified order-id record:

```python
{"id": "broker-order-id"}
```

Place and cancel calls are throttled under the `order` rate-limit group; modifications use the dedicated `modify` group; everything else uses `default`.

## Order Management

Use the read methods for order/trade state, then pass broker order ids into modify or cancel calls.

```python
order_id = order["id"]

raw_orders = broker.fetch_raw_orderbook()
raw_history = broker.fetch_raw_order_history(order_id)

orders = broker.fetch_orderbook()
trades = broker.fetch_tradebook()
details = broker.fetch_order(order_id)
history = broker.fetch_order_history(order_id)
```

| Method | Returns |
|--------|---------|
| `fetch_raw_orderbook()` | Raw Kite Connect order-book rows. |
| `fetch_raw_order_history(order_id)` | Raw Kite Connect history rows for one order. |
| `fetch_orderbook()` | Unified Fenix order records. |
| `fetch_tradebook()` | Unified Fenix trade records. |
| `fetch_order(order_id)` | Latest unified order record (from the last history row), or raises `OrderNotFoundError`. |
| `fetch_order_history(order_id)` | Unified order-history records. |

### Modify And Cancel

```python
broker.modify_order(
    order_id=order_id,
    price=152.5,
    quantity=75,
)

broker.cancel_order(order_id=order_id)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `order_id` | Yes | Broker order id to modify or cancel. |
| `price` | Optional | Replacement limit price. Existing price is reused when omitted. |
| `trigger` | Optional | Replacement stop trigger. Existing trigger is reused when omitted. |
| `quantity` | Optional | Replacement quantity. Existing quantity is reused when omitted. |
| `order_type` | Optional | Replacement order type in Fenix format. Existing type is reused when omitted. |
| `validity` | Optional | Replacement validity. Existing validity is reused when omitted. |
| `raw_order_json` | Optional (`modify_order`) | Raw history row to skip the order-history refetch. |
| `extra_params` | Optional | On `cancel_order`, pass `extra_params={"variety": "regular"}` to skip the history lookup used to discover the order's variety. |

Both `modify_order()` and `cancel_order()` return `None`; Kite Connect acknowledges the change without returning a normalized order record. Both methods refetch the order history (when not handed a `raw_order_json`/`variety`) to discover the variety segment needed for the URL path `/orders/{variety}/{order_id}`.

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
| `fetch_raw_positions()` | Raw Kite positions payload keyed by `day` and `net`. |
| `fetch_day_positions()` | Unified Fenix position records derived from the `day` bucket (`day_buy_*`/`day_sell_*`). |
| `fetch_net_positions()` | Unified Fenix position records derived from the `net` bucket. |
| `fetch_holdings()` | Unified Fenix position records for long-term holdings. |
| `fetch_margin_limits()` | Raw Kite Connect `user/margins` payload. |
| `fetch_profile()` | Unified profile record with client id, name, email, enabled exchanges, and raw `info`. |

## Rate Limits

| Group | Limit |
|-------|-------|
| `quote` | 1 request/second. |
| `historical` | 3 requests/second. |
| `order` | 10/second, 400/minute, 5,000/day (shared across place + cancel). |
| `modify` | 25 requests/day. |
| `default` | 10 requests/second. |

## Endpoints

**Servers**

| Name | Base URL |
|------|----------|
| `api` | `https://api.kite.trade` |
| `auth` | `https://kite.zerodha.com` |
| `connect` | `https://kite.trade` |

**Paths**

| Endpoint | Server | Path |
|----------|--------|------|
| `api_session` | `connect` | `/connect/login` |
| `session` | `auth` | `/api/connect/session` |
| `login` | `auth` | `/api/login` |
| `twofa` | `auth` | `/api/twofa` |
| `connect_finish` | `auth` | `/connect/finish` |
| `token_url` | `api` | `/session/token` |
| `place_order` | `api` | `/orders` |
| `tradebook` | `api` | `/trades` |
| `holdings` | `api` | `/portfolio/holdings` |
| `positions` | `api` | `/portfolio/positions` |
| `rms_limits` | `api` | `/user/margins` |
| `profile` | `api` | `/user/profile` |
| `instruments` | `api` | `/instruments` |

Modify and cancel paths are derived at runtime as `/orders/{variety}/{order_id}` against the `api` server.

## Error Mapping

Kite Connect returns documented `*Exception` error types that the adapter maps to Fenix exception classes:

| Code | Maps to | Meaning |
|------|---------|---------|
| `TokenException` | `AuthenticationError` | Session expired or invalidated; user must re-login. |
| `UserException` | `PermissionDeniedError` | User-account related errors. |
| `OrderException` | `InvalidOrderError` | Order placement failures or corrupt fetches. |
| `InputException` | `InputError` | Missing required fields or bad parameter values. |
| `MarginException` | `InsufficientFundsError` | Insufficient funds for the order. |
| `HoldingException` | `InsufficientHoldingsError` | Insufficient holdings for the sell order. |
| `NetworkException` | `NetworkError` | API could not communicate with the OMS. |
| `DataException` | `ResponseError` | API could not understand the OMS response. |
| `GeneralException` | `BrokerError` | Unclassified server-side error. |

Undocumented errors are classified by message content: session/expired/invalidated wording → `AuthenticationError`, permission/not allowed → `PermissionDeniedError`, insufficient fund/margin → `InsufficientFundsError`, insufficient holding/quantity → `InsufficientHoldingsError`, "order not found"/"does not exist"/"not in your order book" → `OrderNotFoundError`, invalid/bad value → `InvalidOrderError`.

The adapter also tolerates the concatenated-document responses Kite occasionally emits (a documented error object glued to an empty success blob) — `_split_concatenated_json` walks the body with `json.JSONDecoder` and prefers the error object over the trailing success payload.

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
