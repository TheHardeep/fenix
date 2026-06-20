# AliceBlue

AliceBlue broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.AliceBlue` |
| **`id`** | `AliceBlue` |
| **Module** | `fenix/aliceblue.py` |
| **Broker API docs** | [https://ant.aliceblueonline.com/productdocumentation](https://ant.aliceblueonline.com/productdocumentation) |
| **Auth params** | `user_id`, `password`, `totpstr`, `api_key`, `api_secret` |
| **Rate limit group** | `default`: 1,800 requests per 900 seconds |

The AliceBlue adapter implements the [unified Fenix API](#/orders): authenticate once, load instrument tokens, place or modify orders, and read positions/account data using the same normalized records used by the other Fenix brokers.

## Authentication

`AliceBlue.authenticate()` accepts either fresh login credentials through `params` or previously saved request headers through `headers`.

```python
from fenix import AliceBlue

broker = AliceBlue()
headers = broker.authenticate(params={
    "user_id": "AB123456",
    "password": "your-login-password",
    "totpstr": "BASE32_TOTP_SECRET",
    "api_key": "your-api-key",
    "api_secret": "your-api-secret",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `user_id`, `password`, `totpstr`, `api_key`, and `api_secret`. |
| `headers` | Optional | Reuses a previously authenticated AliceBlue header dict. |
| `force` | Optional | When `True`, ignores cached headers and runs the login flow again. |

Returned headers contain the fields AliceBlue needs for later REST calls: `ID`, `AccessToken`, `Authorization`, `X-SAS-Version`, `User-Agent`, `Content-Type`, and `susertoken`.

## Paper Mode

Paper mode routes order entry and portfolio reads through the in-process simulator instead of the live AliceBlue API.

```python
from fenix import AliceBlue

broker = AliceBlue(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens

AliceBlue token loaders return a tuple:

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

`token_json` is grouped by asset class and exchange. `alltoken_json` is a flat lookup keyed as `"{Token}_{Exchange}"`, for example `"26000_NSE"`.

| Method | Required `data` keys when passing pre-fetched data | Loads |
|--------|----------------------------------------------------|-------|
| `load_equity_tokens(data=None)` | `NSE`, `BSE` | NSE and BSE equity instruments. |
| `load_index_tokens(data=None)` | `NSE`, `BSE`, `MCX` | NSE, BSE, and MCX index instruments. |
| `load_fno_tokens(data=None)` | `NFO`, `BFO` | NSE F&O and BSE F&O futures/options. |
| `load_mcx_tokens(data=None)` | `MCX` | MCX futures, options, and indices. |
| `load_cds_tokens(data=None)` | `CDS`, `BCD` | Currency derivatives for CDS and BCD. |

```python
equity, equity_by_token = broker.load_equity_tokens()
indices, index_by_token = broker.load_index_tokens()
fno, fno_by_token = broker.load_fno_tokens()
mcx, mcx_by_token = broker.load_mcx_tokens()
cds, cds_by_token = broker.load_cds_tokens()
```

### Token Record Fields

Futures records contain:

| Field | Description |
|-------|-------------|
| `Exchange` | AliceBlue exchange code such as `NFO`, `BFO`, or `MCX`. |
| `Token` | Broker instrument token. |
| `Root` | Contract root, such as `NIFTY` or `CRUDEOIL`. |
| `Symbol` | AliceBlue trading symbol. |
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

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for the order choices.

```python
from fenix import AliceBlue
from fenix.base.constants import Product, Side, Validity, Variety

broker = AliceBlue()
broker.authenticate(params={
    "user_id": "AB123456",
    "password": "your-login-password",
    "totpstr": "BASE32_TOTP_SECRET",
    "api_key": "your-api-key",
    "api_secret": "your-api-secret",
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
    unique_id="aliceblue-docs-demo",
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
| `product` | Yes | `Product.MIS`, `Product.NRML`, `Product.CNC`, `Product.CO`, or `Product.BO`. |
| `validity` | Yes | `Validity.DAY` or `Validity.IOC`. |
| `variety` | Yes | `Variety.REGULAR`, `Variety.STOPLOSS`, `Variety.BO`, or `Variety.AMO`. |
| `unique_id` | Yes | Client order tag, sent as both `orderTag` and `apiOrderSource`. |
| `price` | Optional | Limit price. Use `0.0` for market orders. |
| `trigger` | Optional | Stop-loss trigger price. Use `0.0` when not applicable. |
| `target` | Optional | Bracket-order target price. When set, AliceBlue receives a bracket order payload. |
| `stoploss` | Optional | Bracket-order stop-loss price. |
| `trailing_sl` | Optional | Bracket-order trailing stop-loss amount. |

The adapter returns a unified order-id record:

```python
{"id": "broker-order-id"}
```

## Order Management

Use the read methods for order/trade state, then pass broker order ids into modify, cancel, square-off, or bracket-order exit calls.

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
| `fetch_raw_orderbook()` | Raw AliceBlue order-book rows, or `[]` when empty. |
| `fetch_raw_order_history(order_id)` | Raw AliceBlue history rows for one order. |
| `fetch_orderbook()` | Unified Fenix order records. |
| `fetch_tradebook()` | Unified Fenix trade records, or `[]` when empty. |
| `fetch_order(order_id)` | One unified order record, or raises `OrderNotFoundError`. |
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
| `order_id` | Yes | Broker order id to modify. |
| `price` | Optional | Replacement limit price. Existing price is reused when omitted. |
| `trigger` | Optional | Replacement stop trigger. Existing trigger is reused when omitted. |
| `quantity` | Optional | Replacement quantity. Existing quantity is reused when omitted. |
| `order_type` | Optional | Replacement order type in Fenix format. Existing type is reused when omitted. |
| `validity` | Optional | Replacement validity. Existing validity is reused when omitted. |
| `raw_order_json` | Optional | Raw order-history row to avoid an extra history fetch. |
| `extra_params` | Optional | Reserved for broker-specific extensions. |

`modify_order()` returns `None` after AliceBlue acknowledges the modification. `cancel_order()` also returns `None`; pass `extra_params={"order": order}` only when you already have the normalized order record and want to avoid a refetch.

### Square Off And Bracket Exit

```python
square_off = broker.square_off_position(
    symbol="NIFTY",
    token=26000,
    exchange="NSE",
    quantity=50,
)

closed = broker.exit_bracket_order(order_id)
```

`square_off_position()` returns a unified order-id record. `exit_bracket_order()` returns the unified order record after the bracket-order exit request.

## Positions And Account

| Method | Parameters | Returns |
|--------|------------|---------|
| `fetch_day_positions()` | None | Raw AliceBlue intraday position rows, or `[]` when empty. |
| `fetch_net_positions()` | None | Raw AliceBlue net position rows, or `[]` when empty. |
| `fetch_holdings()` | None | Raw AliceBlue holdings, or `[]` when empty. |
| `fetch_margin_limits()` | None | Unified RMS record with `marginUsed`, `marginAvail`, and raw `info`. |
| `fetch_profile()` | None | Unified profile record with client id, name, email, mobile, enabled exchanges, and raw `info`. |

```python
positions = broker.fetch_net_positions()
holdings = broker.fetch_holdings()
margins = broker.fetch_margin_limits()
profile = broker.fetch_profile()
```

## Endpoints

| Endpoint | Server | Path |
|----------|--------|------|
| `get_user_details` | `api` | `/sso/getUserDetails` |
| `verify_user` | `auth` | `/omk/auth/access/client/verify` |
| `get_enc_key` | `auth` | `/omk/auth/access/client/enckey` |
| `validate` | `auth` | `/omk/auth/access/v1/pwd/validate` |
| `verify_totp` | `auth` | `/omk/auth/access/topt/verify` |
| `place_order` | `order_api` | `open-api/od/v1/orders/placeorder` |
| `modify_order` | `order_api` | `open-api/od/v1/orders/modify` |
| `cancel_order` | `order_api` | `open-api/od/v1/orders/cancel` |
| `orderbook` | `api` | `/api/placeOrder/fetchOrderBook` |
| `tradebook` | `api` | `/api/placeOrder/fetchTradeBook` |
| `order_history` | `order_api` | `open-api/od/v1/orders/history` |
| `positions` | `api` | `/api/positionAndHoldings/positionBook` |
| `holdings` | `api` | `/api/positionAndHoldings/holdings` |
| `sqoff_position` | `api` | `/api/positionAndHoldings/sqrOofPosition` |
| `rms_limits` | `api` | `/api/limits/getRmsLimits` |
| `profile` | `api` | `/api/customer/accountDetails` |
| `instruments` | `market_data` | `/contract_master` |

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
