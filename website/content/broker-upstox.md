# Upstox

Upstox broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.Upstox` |
| **`id`** | `Upstox` |
| **Module** | `fenix/upstox.py` |
| **Broker API docs** | [https://upstox.com/developer/api-documentation/open-api](https://upstox.com/developer/api-documentation/open-api) |
| **Auth params** | `api_key`, `api_secret`, `redirect_uri`, `totpstr`, `mobile_no`, `pin` |
| **Rate limit groups** | `orders` and `default`: 50/sec (default) or 10/sec (orders), 500/min, 2,000/30min |
| **Instrument source** | Single gzipped CSV master (`complete.csv.gz`) |

The Upstox adapter drives the OAuth2 authorization-code flow through a headless browser (Edge → Chrome → Firefox fallback) to obtain an access token, parses the single gzipped CSV instrument master, and exposes orders, positions, holdings, funds, and profile through the unified Fenix API.

## Authentication

`Upstox.authenticate()` launches a headless Selenium session against Upstox's login dialog. It enters your `mobile_no`, generates the current TOTP from `totpstr`, types the `pin`, captures the `code` from the post-login redirect URL, then exchanges it at `/v2/login/authorization/token` along with your `api_key`/`api_secret`/`redirect_uri` for an access token.

```python
from fenix import Upstox

broker = Upstox()
headers = broker.authenticate(params={
    "api_key": "your-api-key",
    "api_secret": "your-api-secret",
    "redirect_uri": "https://your-registered-redirect",
    "totpstr": "BASE32_TOTP_SECRET",
    "mobile_no": "9999999999",
    "pin": "123456",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `api_key`, `api_secret`, `redirect_uri`, `totpstr`, `mobile_no`, and `pin`. |
| `headers` | Optional | Reuses a previously authenticated Upstox header dict. |
| `force` | Optional | When `True`, ignores cached headers and runs the OAuth2 flow again. |

Returned headers contain `Authorization: Bearer <access_token>` and `Accept: application/json`. The headless browser tries Edge, then Chrome, then Firefox via Selenium — at least one of those WebDrivers must be installed locally.

## Paper Mode

Paper mode routes order entry and portfolio reads through the in-process simulator instead of the live Upstox API.

```python
from fenix import Upstox

broker = Upstox(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens

Upstox publishes one gzipped CSV master that covers every segment. The adapter downloads it once per call (or accepts pre-parsed rows via `data`) and filters in-process for each asset class.

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

`token_json` is grouped by asset class and exchange. `alltoken_json` is a flat lookup keyed as `"{exchange_prefix}_{exchange_token}"`, for example `"NFO_53001"` or `"NSE_26000"`.

| Method | `data` argument | Loads |
|--------|-----------------|-------|
| `load_equity_tokens(data=None)` | Optional pre-parsed master rows | NSE_EQ and BSE_EQ equity instruments. |
| `load_index_tokens(data=None)` | Optional pre-parsed master rows | NSE_INDEX and BSE_INDEX indices. |
| `load_fno_tokens(data=None)` | Optional pre-parsed master rows | NSE_FO and BSE_FO futures and options. |
| `load_cds_tokens(data=None)` | Optional pre-parsed master rows | NCD_FO and BCD_FO currency derivatives. |
| `load_ncx_tokens(data=None)` | Optional pre-parsed master rows | NSE commodity (NCX) futures and options. |
| `load_mcx_tokens(data=None)` | Optional pre-parsed master rows | MCX futures and options (including index variants). |

```python
equity, equity_by_token = broker.load_equity_tokens()
indices, index_by_token = broker.load_index_tokens()
fno, fno_by_token = broker.load_fno_tokens()
cds, cds_by_token = broker.load_cds_tokens()
ncx, ncx_by_token = broker.load_ncx_tokens()
mcx, mcx_by_token = broker.load_mcx_tokens()
```

### Token Record Fields

Equity records contain `Token` (Upstox `instrument_key`, e.g. `"NSE_EQ|INE002A01018"`), `ExchangeToken`, `Exchange` (`NSE_EQ` or `BSE_EQ`), `Symbol`, `TickSize`, and `LotSize`.

Index records contain `Exchange`, `Token`, `Symbol`, `ExchangeCode`, and `ScriptName`.

Futures records contain:

| Field | Description |
|-------|-------------|
| `Exchange` | Upstox exchange code such as `NSE_FO`, `BSE_FO`, `MCX_FO`, `NCD_FO`, or `BCD_FO`. |
| `Token` | Upstox `instrument_key` used by the order APIs. |
| `Root` | Contract root, resolved through the equity-name lookup so symbols like `NIFTY` and `RELIANCE` are normalized. |
| `Symbol` | Upstox trading symbol. |
| `TickSize` | Minimum price tick. |
| `LotSize` | Exchange lot size. |
| `Expiry` | Expiry date as `YYYY-MM-DD`. |
| `ExchangeCode` | Raw numeric `exchange_token` from the master. |
| `ScriptName` | Human-readable contract label. |

Options include the same fields plus `StrikePrice` and `Option`.

```python
fno, _ = broker.load_fno_tokens()

nifty_call = fno["Options"]["NFO"]["NIFTY"][0]
print(nifty_call["Token"], nifty_call["Symbol"], nifty_call["StrikePrice"])
```

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for the order choices. The Upstox order API takes `instrument_token` from `token_dict["Token"]`.

```python
from fenix import Upstox
from fenix.base.constants import Product, Side, Validity, Variety

broker = Upstox()
broker.authenticate(params={
    "api_key": "your-api-key",
    "api_secret": "your-api-secret",
    "redirect_uri": "https://your-registered-redirect",
    "totpstr": "BASE32_TOTP_SECRET",
    "mobile_no": "9999999999",
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
    unique_id="upstox-docs-demo",
    price=0.0,
    trigger=0.0,
)
print(order["id"])
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token_dict` | Yes | Token metadata from `load_*_tokens()`. Must include `Token` (the Upstox `instrument_key`). |
| `quantity` | Yes | Order quantity. Use a valid lot multiple for derivatives. |
| `side` | Yes | `Side.BUY` or `Side.SELL`. |
| `product` | Yes | `Product.MIS`, `Product.NRML`, `Product.CNC`, or `Product.CO`. `Product.BO` maps to `MIS` on the Upstox side. |
| `validity` | Yes | `Validity.DAY` or `Validity.IOC`. |
| `variety` | Yes | `Variety.REGULAR`, `Variety.STOPLOSS`, `Variety.BO`, or `Variety.AMO`. AMO sets `is_amo=true` in the payload. |
| `unique_id` | Yes | Client-provided order tag, sent as Upstox `tag`. |
| `price` | Optional | Limit price. Use `0.0` for market orders. |
| `trigger` | Optional | Stop-loss trigger price. Use `0.0` when not applicable. |
| `target` | Optional | Not supported. Passing a non-zero value raises `InputError` because Upstox does not place bracket orders through this endpoint. |
| `stoploss` | Optional | Reserved; ignored by the place-order payload. |
| `trailing_sl` | Optional | Reserved; ignored by the place-order payload. |

The adapter returns a unified order-id record:

```python
{"id": "broker-order-id"}
```

Place/modify/cancel calls are throttled under the `orders` rate-limit group; everything else uses `default`.

## Order Management

Use the read methods for order/trade state, then pass broker order ids into modify or cancel calls.

```python
order_id = order["id"]

raw_orders = broker.fetch_raw_orderbook()
raw_order = broker.fetch_raw_order(order_id)
raw_history = broker.fetch_raw_order_history(order_id)

orders = broker.fetch_orderbook()
trades = broker.fetch_tradebook()
details = broker.fetch_order(order_id)
history = broker.fetch_order_history(order_id)
```

| Method | Returns |
|--------|---------|
| `fetch_raw_orderbook()` | Raw Upstox order-book rows. |
| `fetch_raw_order(order_id)` | Raw Upstox order detail from `/order/details`. |
| `fetch_raw_order_history(order_id)` | Raw Upstox history rows for one order. |
| `fetch_orderbook()` | Unified Fenix order records. |
| `fetch_orders()` | Alias for `fetch_orderbook()`. |
| `fetch_tradebook()` | Unified Fenix trade records (today's trades). |
| `fetch_order(order_id)` | One unified order record from `/order/details`. |
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
| `raw_order_json` | Optional (`modify_order`) | Pre-fetched raw order row to skip the history refetch. |
| `extra_params` | Optional (`modify_order`) | Reserved for broker-specific extensions. |

`modify_order()` and `cancel_order()` return the refetched unified order record (they call `fetch_order(order_id)` after the broker acknowledges the change). `modify_order()` auto-zeroes `price`/`trigger_price` based on the resulting order type (LIMIT clears trigger, SL-M clears price, MARKET clears both).

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
| `fetch_raw_positions()` | Raw Upstox position rows from `/portfolio/short-term-positions`. |
| `fetch_day_positions()` | Unified Fenix position records keyed off the `day_buy_*`/`day_sell_*` fields. |
| `fetch_net_positions()` | Unified Fenix position records keyed off the cumulative `buy_*`/`sell_*` fields. |
| `fetch_holdings()` | Raw Upstox long-term holdings payload. |
| `fetch_margin_limits()` | Raw Upstox funds-and-margin payload from the v3 endpoint. |
| `fetch_profile()` | Unified profile record with client id, name, email, enabled exchanges, and raw `info`. |

## Endpoints

**Servers**

| Name | Base URL |
|------|----------|
| `auth` | `https://api.upstox.com` |
| `api` | `https://api.upstox.com/v2` |
| `api_v3` | `https://api.upstox.com/v3` |
| `market_data` | `https://assets.upstox.com` |

**Paths**

| Endpoint | Server | Path |
|----------|--------|------|
| `token_dialog` | `auth` | `/v2/login/authorization/dialog` |
| `token_exchange` | `auth` | `/v2/login/authorization/token` |
| `place_order` | `api` | `/order/place` |
| `modify_order` | `api` | `/order/modify` |
| `cancel_order` | `api` | `/order/cancel` |
| `order_history` | `api` | `/order/history` |
| `single_order` | `api` | `/order/details` |
| `orderbook` | `api` | `/order/retrieve-all` |
| `tradebook` | `api` | `/order/trades/get-trades-for-day` |
| `positions` | `api` | `/portfolio/short-term-positions` |
| `holdings` | `api` | `/portfolio/long-term-holdings` |
| `rms_limits` | `api_v3` | `/user/get-funds-and-margin` |
| `profile` | `api` | `/user/profile` |
| `instruments` | `market_data` | `/market-quote/instruments/exchange/complete.csv.gz` |

## Error Mapping

Upstox returns documented `UDAPI*` error codes that the adapter maps to Fenix exception classes:

| Code | Maps to | Meaning |
|------|---------|---------|
| `UDAPI10000` | `InputError` | Unsupported API request (bad URL or characters). |
| `UDAPI10005` | `RateLimitExceededError` | API rate limit exceeded. |
| `UDAPI100015` | `InputError` | API version missing from request headers. |
| `UDAPI100016` | `AuthenticationError` | Invalid credentials. |
| `UDAPI100036` / `UDAPI100038` | `InputError` | Invalid input to the API. |
| `UDAPI100050` | `AuthenticationError` | Invalid access token. |
| `UDAPI100067` | `PermissionDeniedError` | Endpoint not permitted with an extended token. |
| `UDAPI100073` | `PermissionDeniedError` | `client_id` is inactive. |
| `UDAPI100500` | `BrokerError` | Unexpected server-side error. |

Undocumented errors are classified by message content: session/token/login/expired → `AuthenticationError`, insufficient funds/margin → `InsufficientFundsError`, insufficient quantity/holding → `InsufficientHoldingsError`, "order not found" → `OrderNotFoundError`, order/price/quantity wording → `InvalidOrderError`.

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
