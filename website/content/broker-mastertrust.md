# Master Trust

MasterTrust broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.MasterTrust` |
| **`id`** | `MasterTrust` |
| **Module** | `fenix/mastertrust.py` |
| **Broker API docs** | [https://tradeapi.mastertrust.co.in](https://tradeapi.mastertrust.co.in) |
| **Auth params** | `user_id`, `password`, `totpstr`, `client_id`, `client_secret` |
| **Rate limit group** | `default` (rate limiting disabled in `describe()`) |
| **Instrument source** | MasterSwift contracts JSON (`/contracts.json`) and Compact CSV (`/contract/Compact`) |

The MasterTrust adapter runs the MasterSwift OAuth2 + TOTP login flow against the auth server, parses the contracts JSON for equity, index, and NSE F&O instruments along with a zipped CSV for BFO derivatives, and exposes orders (including bracket orders), positions, holdings, margin, and profile through the unified Fenix API.

## Authentication

`MasterTrust.authenticate()` drives the full MasterSwift OAuth2 flow: it starts an `OAuth2Session` with your `client_id`, walks the login → 2FA (TOTP) → consent redirects, then exchanges the returned authorization code for an access token using your `client_secret`.

```python
from fenix import MasterTrust

broker = MasterTrust()
headers = broker.authenticate(params={
    "user_id": "MT12345",
    "password": "your-login-password",
    "totpstr": "BASE32_TOTP_SECRET",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `user_id`, `password`, `totpstr`, `client_id`, and `client_secret`. |
| `headers` | Optional | Reuses a previously authenticated MasterTrust header dict. |
| `force` | Optional | When `True`, ignores cached headers and runs the OAuth2 flow again. |

Returned headers contain `Authorization` as `Bearer <access_token>`, merged with the session auth context (`user_id`). The `user_id` is sent as the `client_id` query parameter on every authenticated trade/portfolio request.

## Paper Mode

Paper mode routes order entry and portfolio reads through the in-process simulator instead of the live MasterTrust API.

```python
from fenix import MasterTrust

broker = MasterTrust(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens

MasterTrust publishes equity, index, and NSE F&O instruments through the MasterSwift contracts JSON endpoint, and BFO derivatives as a zipped CSV via the Compact endpoint. Each loader hits the segments it needs and merges them into the unified token maps.

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

`token_json` is grouped by asset class and exchange. `alltoken_json` is a flat lookup keyed as `"{Token}_{Exchange}"`, for example `"26000_NSE"`.

| Method | Required `data` keys when passing pre-fetched data | Loads |
|--------|----------------------------------------------------|-------|
| `load_equity_tokens(data=None)` | `NSE`, `NSE-OTH`, `BSE` | NSE and BSE equity instruments. |
| `load_index_tokens(data=None)` | `NSE-IND`, `BSE-IND` | NSE and BSE index instruments. |
| `load_fno_tokens(data=None)` | `NSE-OPT`, `NSE-FUT`, `BFO` | NSE F&O JSON rows plus the BFO Compact CSV (passed as bytes under `BSE`). |
| `load_mcx_tokens(data=None)` | `MCX` | MCX futures and options. |
| `load_cds_tokens(data=None)` | `NSE-OPT`, `NSE-FUT` | Currency derivatives filtered to the `CDS` exchange. |

```python
equity, equity_by_token = broker.load_equity_tokens()
indices, index_by_token = broker.load_index_tokens()
fno, fno_by_token = broker.load_fno_tokens()
mcx, mcx_by_token = broker.load_mcx_tokens()
cds, cds_by_token = broker.load_cds_tokens()
```

### Token Record Fields

Equity and index records contain `Token`, `Exchange` (such as `NSE` or `BSE`), `Symbol`, `ScriptName`, and `ExchangeCode`. Equity records additionally include `LotSize` when the contract master exposes it.

Futures records contain:

| Field | Description |
|-------|-------------|
| `Exchange` | MasterTrust exchange code such as `NFO`, `BFO`, `MCX`, or `CDS`. |
| `Token` | Broker instrument token. |
| `Root` | Contract root, such as `NIFTY` or `CRUDEOIL`. |
| `Symbol` | MasterTrust trading symbol. |
| `LotSize` | Exchange lot size. |
| `TickSize` | Minimum price tick (BFO only). |
| `Expiry` | Expiry date as `YYYY-MM-DD`. |
| `ExchangeCode` | Numeric MasterTrust exchange code (when present). |
| `ScriptName` | Human-readable contract label. |

Options include the same fields plus `StrikePrice` and `Option`.

```python
fno, _ = broker.load_fno_tokens()

nifty_call = fno["Options"]["NFO"]["NIFTY"][0]
print(nifty_call["Token"], nifty_call["Symbol"], nifty_call["StrikePrice"])
```

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for the order choices. When `target` is non-zero, the request is routed to the bracket-order endpoint with `square_off_value`, `stop_loss_value`, and `trailing_stop_loss` populated.

```python
from fenix import MasterTrust
from fenix.base.constants import Product, Side, Validity, Variety

broker = MasterTrust()
broker.authenticate(params={
    "user_id": "MT12345",
    "password": "your-login-password",
    "totpstr": "BASE32_TOTP_SECRET",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
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
    unique_id="mastertrust-docs-demo",
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
| `product` | Yes | `Product.NRML`, `Product.MIS`, `Product.CNC`, or `Product.CO`. |
| `validity` | Yes | `Validity.DAY` or `Validity.IOC`. |
| `variety` | Yes | `Variety.REGULAR`, `Variety.STOPLOSS`, `Variety.AMO`, or `Variety.BO`. |
| `unique_id` | Yes | Client-provided order tag, sent as MasterTrust `user_order_id`. |
| `price` | Optional | Limit price. Use `0.0` for market orders. |
| `trigger` | Optional | Stop-loss trigger price. Use `0.0` when not applicable. |
| `target` | Optional | Bracket-order target/profit value. When set, the request is sent to the bracket-order endpoint. |
| `stoploss` | Optional | Bracket-order stop-loss value. Sent as `stop_loss_value` when `target` is set. |
| `trailing_sl` | Optional | Bracket-order trailing stop-loss amount. Sent as `trailing_stop_loss`; `is_trailing` is set when non-zero. |

The adapter returns a unified order-id record:

```python
{"id": "broker-order-id"}
```

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
| `fetch_raw_orderbook()` | Raw MasterTrust order-book rows, concatenated from the `completed` and `pending` views. |
| `fetch_raw_order(order_id)` | One raw order row from the current order book, or raises `OrderNotFoundError`. |
| `fetch_raw_order_history(order_id)` | Raw MasterTrust history rows for one order. |
| `fetch_orderbook()` | Unified Fenix order records. |
| `fetch_tradebook()` | Unified Fenix trade records. |
| `fetch_order(order_id)` | One unified order record from the order book, or raises `OrderNotFoundError`. |
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
| `raw_order_json` | Optional (`modify_order`) | Raw order row to avoid an extra order-book fetch. |

`modify_order()` and `cancel_order()` return unified order-id records. `modify_order()` automatically falls back to `fetch_raw_order()` when `raw_order_json` is not provided to populate broker-side fields.

## Positions And Account

```python
positions = broker.fetch_net_positions()
holdings = broker.fetch_holdings()
margins = broker.fetch_margin_limits()
profile = broker.fetch_profile()
```

| Method | Returns |
|--------|---------|
| `fetch_day_positions()` | Unified Fenix position records for the current trading day (`type=live`). |
| `fetch_net_positions()` | Unified Fenix position records across the account's open history (`type=historical`). |
| `fetch_holdings()` | Unified Fenix holding records (parsed through the position parser). |
| `fetch_margin_limits()` | Unified RMS record with `marginUsed`, `marginAvail`, `cashMargin`, `variableMargin`, `spanMargin`, `collateral`, and raw `info`. |
| `fetch_profile()` | Unified profile record with client id, name, email, mobile, PAN, address, bank details, account status, and raw `info`. |

## Endpoints

**Servers**

| Name | Base URL |
|------|----------|
| `api` | `https://masterswift-beta.mastertrust.co.in/api/v1` |
| `auth` | `https://masterswift-beta.mastertrust.co.in` |
| `market_data` | `https://masterswift.mastertrust.co.in/api/v2` |
| `compact` | `https://masterswift-beta.mastertrust.co.in/api/v1` |

**Paths**

| Endpoint | Server | Path |
|----------|--------|------|
| `auth` | `auth` | `/oauth2/auth` |
| `auth_token` | `auth` | `/oauth2/token` |
| `place_order` | `api` | `/orders` |
| `place_bracket_order` | `api` | `/orders/bracket` |
| `modify_order` | `api` | `/orders` |
| `cancel_order` | `api` | `/orders` |
| `order_history` | `api` | `/order` |
| `orderbook` | `api` | `/orders` |
| `tradebook` | `api` | `/trades` |
| `positions` | `api` | `/positions` |
| `holdings` | `api` | `/holdings` |
| `rms_limits` | `api` | `/funds/view` |
| `profile` | `api` | `/user/profile` |
| `instruments` | `market_data` | `/contracts.json` |
| `instruments_compact` | `compact` | `/contract/Compact` |

OAuth2 redirects land on the registered `redirect_uri` `http://127.0.0.1/getCode`, which the adapter captures internally to exchange for the access token.

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
