# Angel One

AngelOne broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.AngelOne` |
| **`id`** | `AngelOne` |
| **Module** | `fenix/angelone.py` |
| **Broker API docs** | [https://smartapi.angelbroking.com/docs](https://smartapi.angelbroking.com/docs) |
| **Auth params** | `user_id`, `pin`, `totpstr`, `api_key` |
| **Instrument source** | Angel One OpenAPI scrip master |

The Angel One adapter implements the [unified Fenix API](#/orders): authenticate with SmartAPI credentials, load instrument tokens from the Angel One scrip master, place/modify/cancel orders, and read order, position, holding, margin, and profile records in the standard Fenix shape.

## Authentication

`AngelOne.authenticate()` accepts either fresh credentials through `params` or a previously saved authenticated header dict through `headers`.

```python
from fenix import AngelOne

broker = AngelOne()
headers = broker.authenticate(params={
    "user_id": "A123456",
    "pin": "1234",
    "totpstr": "BASE32_TOTP_SECRET",
    "api_key": "your-smartapi-key",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `user_id`, `pin`, `totpstr`, and `api_key`. |
| `headers` | Optional | Reuses a previously authenticated Angel One header dict. |
| `force` | Optional | When `True`, ignores cached headers and runs the login flow again. |

Returned headers contain the fields used on later requests: `Authorization`, `X-PrivateKey`, `x-client-code`, `x-feed-token`, client IP/MAC headers, and SmartAPI source/user headers.

## Paper Mode

Paper mode routes order entry and portfolio reads through the in-process simulator instead of the live Angel One API.

```python
from fenix import AngelOne

broker = AngelOne(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens

Each loader returns a tuple:

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

`token_json` is grouped by asset class and exchange. `alltoken_json` is a flat lookup keyed as `"{Token}_{Exchange}"`, for example `"26000_NSE"`.

Angel One's scrip master is one flat JSON list. If you pass `data`, pass that pre-fetched list; the loader filters rows by `exch_seg` and `instrumenttype`.

| Method | Filters | Loads |
|--------|---------|-------|
| `load_equity_tokens(data=None)` | `exch_seg` `NSE`/`BSE`, blank `instrumenttype` | NSE and BSE equity instruments. |
| `load_index_tokens(data=None)` | `instrumenttype == "AMXIDX"` | NSE, BSE, MCX, and NCDEX index instruments. |
| `load_fno_tokens(data=None)` | `exch_seg` `NFO`/`BFO`, `FUTSTK`, `FUTIDX`, `OPTSTK`, `OPTIDX` | NSE F&O and BSE F&O futures/options. |
| `load_mcx_tokens(data=None)` | `exch_seg == "MCX"`, `FUTIDX`, `FUTCOM`, `OPTIDX`, `OPTFUT` | MCX futures/options. |
| `load_cds_tokens(data=None)` | `exch_seg == "CDS"`, currency futures/options series | Currency derivatives. |
| `load_ncx_tokens(data=None)` | `exch_seg == "NCDEX"` | NCDEX commodity futures. |
| `load_nco_tokens(data=None)` | `exch_seg == "NCO"` | NCO commodity futures/options. |

```python
equity, equity_by_token = broker.load_equity_tokens()
indices, index_by_token = broker.load_index_tokens()
fno, fno_by_token = broker.load_fno_tokens()
mcx, mcx_by_token = broker.load_mcx_tokens()
cds, cds_by_token = broker.load_cds_tokens()
ncx, ncx_by_token = broker.load_ncx_tokens()
nco, nco_by_token = broker.load_nco_tokens()
```

### Token Record Fields

Equity records contain:

| Field | Description |
|-------|-------------|
| `Token` | Angel One instrument token. |
| `Exchange` | Exchange code such as `NSE` or `BSE`. |
| `Symbol` | Angel One trading symbol. |
| `ScriptName` | Human-readable script name. |
| `LotSize` | Lot size from the scrip master. |
| `TickSize` | Tick size normalized from paise to rupees. |

Derivative records include `Root`, `Expiry`, and `ScriptName`; options also include `StrikePrice` and `Option`.

```python
fno, _ = broker.load_fno_tokens()

nifty_call = fno["Options"]["NFO"]["NIFTY"][0]
print(nifty_call["Token"], nifty_call["Symbol"], nifty_call["StrikePrice"])
```

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for the order choices.

```python
from fenix import AngelOne
from fenix.base.constants import Product, Side, Validity, Variety

broker = AngelOne()
broker.authenticate(params={
    "user_id": "A123456",
    "pin": "1234",
    "totpstr": "BASE32_TOTP_SECRET",
    "api_key": "your-smartapi-key",
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
    unique_id="angelone-docs-demo",
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
| `product` | Yes | `Product.CNC`, `Product.NRML`, `Product.MIS`, `Product.MARGIN`, or `Product.BO`. |
| `validity` | Yes | `Validity.DAY` or `Validity.IOC`. |
| `variety` | Yes | `Variety.REGULAR`, `Variety.STOPLOSS`, `Variety.AMO`, or `Variety.BO`. |
| `unique_id` | Yes | Client order tag sent as `ordertag`. Angel One rejects tags longer than 20 characters. |
| `price` | Optional | Limit price. Use `0.0` for market orders. |
| `trigger` | Optional | Stop-loss trigger price. Use `0.0` when not applicable. |
| `target` | Optional | Bracket-order square-off/target value. When set, Angel One receives a `ROBO` order. |
| `stoploss` | Optional | Bracket-order stop-loss value. |
| `trailing_sl` | Optional | Bracket-order trailing stop-loss value. |

For stop-loss limit/market orders, the adapter automatically changes `Variety.REGULAR` to `Variety.STOPLOSS`, because Angel One requires the stop-loss variety for SL and SLM order types.

The adapter returns a unified order-id record:

```python
{"id": "broker-order-id"}
```

## Order Management

Use the read methods for order/trade state, then pass broker order ids into modify or cancel calls.

```python
order_id = order["id"]

raw_orders = broker.fetch_raw_orderbook()
orders = broker.fetch_orderbook()
trades = broker.fetch_tradebook()
same_orders = broker.fetch_orders()
details = broker.fetch_order(order_id)
```

| Method | Returns |
|--------|---------|
| `fetch_raw_orderbook()` | Raw Angel One order-book rows, or `[]` when empty. |
| `fetch_orderbook()` | Unified Fenix order records. |
| `fetch_tradebook()` | Unified fill-like trade records, or `[]` when empty. |
| `fetch_orders()` | Alias for `fetch_orderbook()`. |
| `fetch_order(order_id)` | One unified order record, or raises `OrderNotFoundError`. |

### Modify And Cancel

```python
modified = broker.modify_order(
    order_id=order_id,
    price=152.5,
    quantity=75,
)

broker.cancel_order(order_id=order_id)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `order_id` | Yes | Broker order id to modify. |
| `price` | Optional | Replacement limit price. Existing price is reused when omitted. |
| `trigger` | Optional | Replacement trigger price. Existing trigger is reused when omitted. |
| `quantity` | Optional | Replacement quantity. Existing quantity is reused when omitted. |
| `order_type` | Optional | Replacement order type in Fenix format. Existing type is reused when omitted. |
| `validity` | Optional | Replacement validity. Existing validity is reused when omitted. |
| `raw_order_json` | Optional | Raw order-book row to avoid refetching the order book. |
| `extra_params` | Optional | Reserved for broker-specific extensions. |

`modify_order()` returns a unified order-id record for the modified order. `cancel_order()` returns `None`; pass `extra_params={"order": order}` only when you already have the normalized order record and want to reuse its Angel One `variety`.

## Positions And Account

| Method | Parameters | Returns |
|--------|------------|---------|
| `fetch_day_positions()` | None | Unified Fenix position records, or `[]` when empty. |
| `fetch_net_positions()` | None | Same result as `fetch_day_positions()`. |
| `fetch_holdings()` | None | Raw Angel One holding rows from the `holdings` field, or `[]` when empty. |
| `fetch_margin_limits()` | None | Unified RMS record with `marginUsed`, `marginAvail`, and raw `info`. |
| `fetch_profile()` | None | Unified profile record with client id, name, email, mobile, enabled exchanges, and raw `info`. |

```python
positions = broker.fetch_net_positions()
holdings = broker.fetch_holdings()
margins = broker.fetch_margin_limits()
profile = broker.fetch_profile()
```

## Rate Limits

Angel One uses endpoint-specific token buckets:

| Group | Limits |
|-------|--------|
| `auth` | 1 request/second and 1,000/hour. |
| `orders` | 20 requests/second, 500/minute, and 1,000/hour. |
| `post_trade` | 1 request/second. |
| `user` | 3 requests/second. |
| `funds` | 2 requests/second. |
| `market` | 10 requests/second, 500/minute, and 1,000/hour. |
| `historical` | 3 requests/second, 180/minute, and 5,000/hour. |
| `default` | 1 request/second. |

## Endpoints

| Endpoint | Server | Path |
|----------|--------|------|
| `token` | `rest` | `/rest/auth/angelbroking/jwt/v1/generateTokens` |
| `session` | `rest` | `/rest/auth/angelbroking/user/v1/loginByPassword` |
| `logout` | `rest` | `/rest/secure/angelbroking/user/v1/logout` |
| `place_order` | `rest` | `/rest/secure/angelbroking/order/v1/placeOrder` |
| `modify_order` | `rest` | `/rest/secure/angelbroking/order/v1/modifyOrder` |
| `cancel_order` | `rest` | `/rest/secure/angelbroking/order/v1/cancelOrder` |
| `orderbook` | `rest` | `/rest/secure/angelbroking/order/v1/getOrderBook` |
| `tradebook` | `rest` | `/rest/secure/angelbroking/order/v1/getTradeBook` |
| `positions` | `rest` | `/rest/secure/angelbroking/order/v1/getPosition` |
| `holdings` | `rest` | `/rest/secure/angelbroking/portfolio/v1/getAllHolding` |
| `profile` | `rest` | `/rest/secure/angelbroking/user/v1/getProfile` |
| `funds` | `rest` | `/rest/secure/angelbroking/user/v1/getRMS` |
| `ltp` | `rest` | `/rest/secure/angelbroking/order/v1/getLtpData` |
| `historical` | `rest` | `/rest/secure/angelbroking/historical/v1/getCandleData` |
| `instruments` | `market` | `/OpenAPI_File/files/OpenAPIScripMaster.json` |

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
