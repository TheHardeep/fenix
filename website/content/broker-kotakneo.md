# Kotak Neo

KotakNeo broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.KotakNeo` |
| **`id`** | `KotakNeo` |
| **Module** | `fenix/kotakneo.py` |
| **Broker API docs** | [https://documenter.getpostman.com/view/21534797/UzBnqmpD](https://documenter.getpostman.com/view/21534797/UzBnqmpD) |
| **Auth params** | `consumer_key`, `mobile_no`, `ucc`, `totpstr`, `mpin` |
| **Rate limit group** | `default`: 10 requests per second |
| **Instrument source** | KotakNeo lapi scrip-master CSVs (per-segment, dated) |

The KotakNeo adapter runs the TOTP trade-API login flow (`tradeApiLogin` → `tradeApiValidate`), resolves every trade and report endpoint against the per-session `baseUrl` returned by validate, and exposes orders, positions, holdings, margin, and profile through the unified Fenix API.

## Authentication

`KotakNeo.authenticate()` runs the two-step TOTP login: it generates the current TOTP from `totpstr`, posts it to `tradeApiLogin` to obtain a view token, then exchanges it via `tradeApiValidate` with your `mpin` to receive the session `Sid`/`Auth` pair, per-session `baseUrl`, and `hsServerId`.

```python
from fenix import KotakNeo

broker = KotakNeo()
headers = broker.authenticate(params={
    "consumer_key": "your-consumer-key",
    "mobile_no": "+919999999999",
    "ucc": "ABCDE",
    "totpstr": "BASE32_TOTP_SECRET",
    "mpin": "123456",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `consumer_key`, `mobile_no`, `ucc`, `totpstr`, and `mpin`. |
| `headers` | Optional | Reuses a previously authenticated KotakNeo header dict. |
| `force` | Optional | When `True`, ignores cached headers and runs the login flow again. |

Returned headers contain `Sid`, `Auth`, `neo-fin-key`, `Content-Type`, and `accept`, merged with the session auth context (`baseUrl`, `serverId`). The `serverId` is sent as the `sId` query parameter on every authenticated request, and the `baseUrl` is the root for all trade and report endpoints.

## Paper Mode

Paper mode routes order entry and portfolio reads through the in-process simulator instead of the live KotakNeo API.

```python
from fenix import KotakNeo

broker = KotakNeo(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens

KotakNeo publishes one CSV per segment under a date-prefixed path on its lapi scrip-master server. The adapter downloads the segments needed by each loader and parses them with the standard-library `csv` module.

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

`token_json` is grouped by asset class and exchange. `alltoken_json` is a flat lookup keyed as `"{Token}_{Exchange}"`, for example `"26000_nse_cm"`.

| Method | Required `data` keys when passing pre-fetched data | Loads |
|--------|----------------------------------------------------|-------|
| `load_equity_tokens(data=None)` | `NSE`, `BSE` | NSE and BSE equity instruments. |
| `load_index_tokens(data=None)` | `NSE`, `BSE` | NSE and BSE index instruments. |
| `load_fno_tokens(data=None)` | `NFO`, `BFO` | NSE F&O and BSE F&O futures/options. |

```python
equity, equity_by_token = broker.load_equity_tokens()
indices, index_by_token = broker.load_index_tokens()
fno, fno_by_token = broker.load_fno_tokens()
```

`data` accepts a dict of pre-parsed scrip-master rows (lists of CSV row dicts as produced by the adapter's CSV reader). When omitted, each loader downloads the needed segments itself.

### Token Record Fields

Equity and index records contain `Token`, `Exchange` (KotakNeo segment code such as `nse_cm` or `bse_cm`), `Symbol`, and `ScriptName`. Equity records additionally include `LotSize` and `TickSize`.

Futures records contain:

| Field | Description |
|-------|-------------|
| `Exchange` | KotakNeo segment code such as `nse_fo` or `bse_fo`. |
| `Token` | Broker instrument token. |
| `Root` | Contract root, such as `NIFTY` or `BANKEX`. |
| `Symbol` | KotakNeo trading symbol. |
| `TickSize` | Minimum price tick. |
| `LotSize` | Exchange lot size. |
| `Expiry` | Expiry date as `YYYY-MM-DD`. |
| `ScriptName` | Human-readable contract label. |

Options include the same fields plus `StrikePrice` and `Option`.

```python
fno, _ = broker.load_fno_tokens()

nifty_call = fno["Options"]["NFO"]["NIFTY"][0]
print(nifty_call["Token"], nifty_call["Symbol"], nifty_call["StrikePrice"])
```

NFO expiry timestamps in the KotakNeo scrip master are offset by ten years; the adapter corrects them transparently so `Expiry` reflects the true contract expiry.

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for the order choices.

```python
from fenix import KotakNeo
from fenix.base.constants import Product, Side, Validity, Variety

broker = KotakNeo()
broker.authenticate(params={
    "consumer_key": "your-consumer-key",
    "mobile_no": "+919999999999",
    "ucc": "ABCDE",
    "totpstr": "BASE32_TOTP_SECRET",
    "mpin": "123456",
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
    unique_id="kotakneo-docs-demo",
    price=0.0,
    trigger=0.0,
)
print(order["id"])
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token_dict` | Yes | Token metadata from `load_*_tokens()`. Must include `Token`, `Exchange`, and `Symbol`. |
| `quantity` | Yes | Order quantity. Use a valid lot multiple for derivatives. |
| `side` | Yes | `Side.BUY` or `Side.SELL`. |
| `product` | Yes | `Product.MIS`, `Product.NRML`, `Product.CNC`, or `Product.CO`. |
| `validity` | Yes | `Validity.DAY`, `Validity.IOC`, or `Validity.GTC`. |
| `variety` | Yes | `Variety.REGULAR` or `Variety.AMO`. AMO is sent through KotakNeo's after-market flag. |
| `unique_id` | Yes | Client-provided order tag, sent as KotakNeo `ig`. |
| `price` | Optional | Limit price. Use `0.0` for market orders. |
| `trigger` | Optional | Stop-loss trigger price. Use `0.0` when not applicable. |
| `target` | Optional | Not supported. Passing a non-zero value raises `InputError` because the KotakNeo adapter does not place bracket orders. |
| `stoploss` | Optional | Reserved; ignored by the place-order payload. |
| `trailing_sl` | Optional | Reserved; ignored by the place-order payload. |

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
details = broker.fetch_order(order_id)
history = broker.fetch_order_history(order_id)
```

| Method | Returns |
|--------|---------|
| `fetch_raw_orderbook()` | Raw KotakNeo order-book rows, or `[]` when empty. |
| `fetch_raw_order_history(order_id)` | Raw KotakNeo history rows for one order. |
| `fetch_orderbook()` | Unified Fenix order records. |
| `fetch_orders()` | Alias for `fetch_orderbook()`. |
| `fetch_tradebook()` | Unified Fenix fill records, or `[]` when empty. |
| `fetch_order(order_id)` | One unified order record built from the latest history row, or raises `OrderNotFoundError`. |
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
| `raw_order_json` | Optional | Raw order-history row to avoid an extra history fetch. |
| `extra_params` | Optional (`modify_order`) / Optional (`cancel_order`) | On `cancel_order`, pass `extra_params={"order": order}` with a raw order row to skip the history refetch. Reserved for `modify_order`. |

`modify_order()` and `cancel_order()` return unified order-id records. Both methods automatically refetch the order history to populate broker-side fields when `raw_order_json` (or `extra_params["order"]`) is not provided, and raise `OrderNotFoundError` when the id has no history.

## Positions And Account

```python
positions = broker.fetch_net_positions()
holdings = broker.fetch_holdings()
margins = broker.fetch_margin_limits()
profile = broker.fetch_profile()
```

| Method | Returns |
|--------|---------|
| `fetch_day_positions()` | Unified Fenix position records, or `[]` when empty. |
| `fetch_net_positions()` | Same as `fetch_day_positions()`; KotakNeo returns one positions snapshot. |
| `fetch_holdings()` | Raw KotakNeo holding rows, or `[]` when empty. |
| `fetch_margin_limits()` | Unified RMS record with `marginUsed`, `marginAvail`, and raw `info`. |
| `fetch_profile()` | Unified profile record built from the `tradeApiValidate` payload (client id, name, PAN via `kId`, account status, and raw `info`). |

`fetch_profile()` raises `AuthenticationError` when called after restoring a session through `use_headers()` instead of a fresh `authenticate()`, because KotakNeo exposes no standalone profile endpoint — the profile fields only arrive in the validate response.

## Endpoints

**Servers**

| Name | Base URL |
|------|----------|
| `login` | `https://mis.kotaksecurities.com` |
| `scrip_master` | `https://lapi.kotaksecurities.com/wso2-scripmaster/v1/prod` |

**Paths**

Auth paths resolve against the `login` server. Trade and report paths hang off the per-session `baseUrl` returned by `tradeApiValidate`.

| Endpoint | Server | Path |
|----------|--------|------|
| `totp_login` | `login` | `/login/1.0/tradeApiLogin` |
| `totp_validate` | `login` | `/login/1.0/tradeApiValidate` |
| `place_order` | session `baseUrl` | `/quick/order/rule/ms/place` |
| `modify_order` | session `baseUrl` | `/quick/order/vr/modify` |
| `cancel_order` | session `baseUrl` | `/quick/order/cancel` |
| `orderbook` | session `baseUrl` | `/quick/user/orders` |
| `tradebook` | session `baseUrl` | `/quick/user/trades` |
| `order_history` | session `baseUrl` | `/quick/order/history` |
| `positions` | session `baseUrl` | `/quick/user/positions` |
| `holdings` | session `baseUrl` | `/portfolio/v1/holdings` |
| `limits` | session `baseUrl` | `/quick/user/limits` |
| `margin` | session `baseUrl` | `/quick/user/check-margin` |
| `instruments` | `scrip_master` | `/{YYYY-MM-DD}/transformed/{segment}.csv` |

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
