# Finvasia

Finvasia broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.Finvasia` |
| **`id`** | `Finvasia` |
| **Module** | `fenix/finvasia.py` |
| **Broker API docs** | [https://www.shoonya.com/api-documentation](https://www.shoonya.com/api-documentation) |
| **Auth params** | `user_id`, `password`, `api_key`, `vendor_code`, `totpstr` |
| **Transport** | Shoonya/Noren REST API |

The Finvasia adapter logs in to Shoonya, stores the returned `susertoken` as a session `jKey`, reads zipped exchange symbol masters, and exposes orders, positions, holdings, limits, and profile data through the unified Fenix API.

## Authentication

`Finvasia.authenticate()` hashes your password, hashes `user_id|api_key` as the app key, generates the current TOTP from `totpstr`, and posts a Shoonya `QuickAuth` request.

```python
from fenix import Finvasia

broker = Finvasia()
headers = broker.authenticate(params={
    "user_id": "FA00000",
    "password": "your-password",
    "api_key": "your-api-key",
    "vendor_code": "your-vendor-code",
    "totpstr": "BASE32_TOTP_SECRET",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `user_id`, `password`, `api_key`, `vendor_code`, and `totpstr`. |
| `headers` | Optional | Reuses a previously authenticated Finvasia header/session dict. |
| `force` | Optional | When `True`, ignores cached headers and runs login again. |

Returned headers include `uid`, `jKey`, `payload`, and `access_token`. The adapter uses `payload` internally to encode authenticated Shoonya `jData=<json>&jKey=<token>` requests.

## Paper Mode

```python
from fenix import Finvasia

broker = Finvasia(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens

Finvasia publishes zipped text/CSV symbol masters per exchange through `/EXCH_symbols.txt.zip`. Each loader downloads the required exchange files, normalizes rows, and returns:

```python
token_json, alltoken_json = broker.load_fno_tokens()
```

| Method | Downloads | Loads |
|--------|-----------|-------|
| `load_equity_tokens(data=None)` | `NSE_symbols.txt.zip`, `BSE_symbols.txt.zip` | NSE and BSE cash instruments. |
| `load_index_tokens(data=None)` | `NSE_symbols.txt.zip` | NSE index instruments. |
| `load_fno_tokens(data=None)` | `NFO_symbols.txt.zip`, `BFO_symbols.txt.zip` | NSE F&O and BSE F&O futures/options. |
| `load_mcx_tokens(data=None)` | `MCX_symbols.txt.zip` | MCX futures, options, and indices. |
| `load_cds_tokens(data=None)` | `CDS_symbols.txt.zip` | CDS and BCD currency futures/options. |
| `load_ncx_tokens(data=None)` | `NCX_symbols.txt.zip` | NCX commodity futures. |

`data` can be a dict of pre-fetched response objects keyed by exchange. When omitted, the adapter downloads the zipped masters directly.

```python
equity, equity_by_token = broker.load_equity_tokens()
indices, index_by_token = broker.load_index_tokens()
fno, fno_by_token = broker.load_fno_tokens()
mcx, mcx_by_token = broker.load_mcx_tokens()
cds, cds_by_token = broker.load_cds_tokens()
ncx, ncx_by_token = broker.load_ncx_tokens()
```

### Token Record Fields

Equity records include the raw Shoonya columns plus normalized `Symbol` and `ScriptName`. The adapter moves Shoonya `TradingSymbol` into `Symbol` and keeps the display script under `ScriptName`.

Derivative records include `Exchange`, `Token`, `Root`, `Symbol`, `Expiry`, `StrikePrice` for options, `Option`, and `ScriptName`.

```python
fno, _ = broker.load_fno_tokens()

nifty_call = fno["Options"]["NFO"]["NIFTY"][0]
print(nifty_call["Token"], nifty_call["Symbol"], nifty_call["StrikePrice"])
```

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for the order choices.

```python
from fenix import Finvasia
from fenix.base.constants import Product, Side, Validity, Variety

broker = Finvasia()
broker.authenticate(params={
    "user_id": "FA00000",
    "password": "your-password",
    "api_key": "your-api-key",
    "vendor_code": "your-vendor-code",
    "totpstr": "BASE32_TOTP_SECRET",
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
    unique_id="finvasia-docs-demo",
    price=0.0,
    trigger=0.0,
)
print(order["id"])
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token_dict` | Yes | Token metadata from `load_*_tokens()`. Must include `Exchange` and `Symbol`. |
| `quantity` | Yes | Order quantity. Use a valid lot multiple for derivatives. |
| `side` | Yes | `Side.BUY` or `Side.SELL`. |
| `product` | Yes | `Product.MIS`, `Product.NRML`, `Product.CNC`, `Product.CO`, or `Product.BO`. |
| `validity` | Yes | `Validity.DAY`, `Validity.IOC`, or `EOS`. |
| `variety` | Yes | Accepted for unified compatibility. |
| `unique_id` | Yes | Sent as Shoonya `remarks`. |
| `price` | Optional | Limit price. Use `0.0` for market orders. |
| `trigger` | Optional | Trigger price for stop orders. |
| `target` | Optional | Bracket-order target price. |
| `stoploss` | Optional | Bracket-order stop-loss price. |
| `trailing_sl` | Optional | Bracket-order trailing stop-loss amount. |

The adapter returns a unified order-id record:

```python
{"id": "noren-order-number"}
```

## Order Management

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
| `fetch_raw_orderbook()` | Raw Shoonya order-book rows, or `[]` when empty. |
| `fetch_raw_order_history(order_id)` | Raw order-history rows for one order. |
| `fetch_raw_orderhistory(order_id)` | Backward-compatible alias for `fetch_raw_order_history()`. |
| `fetch_orderbook()` | Unified Fenix order records. |
| `fetch_tradebook()` | Unified trade records, or `[]` when empty. |
| `fetch_order(order_id)` | First unified row from the order history. |
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
| `trigger` | Optional | Replacement trigger price. Existing trigger is reused when omitted. |
| `quantity` | Optional | Replacement quantity. Existing quantity is reused when omitted. |
| `order_type` | Optional | Replacement order type in Fenix format. Existing type is reused when omitted. |
| `validity` | Optional | Replacement validity. Existing validity is reused when omitted. |

Both methods return the unified order record after the broker acknowledges the operation.

## Positions And Account

```python
positions = broker.fetch_positions()
day_positions = broker.fetch_day_positions()
net_positions = broker.fetch_net_positions()
holdings = broker.fetch_holdings()
limits = broker.fetch_margin_limits()
profile = broker.fetch_profile()
```

| Method | Returns |
|--------|---------|
| `fetch_positions()` | Unified Finvasia position rows, or `[]` when empty. |
| `fetch_day_positions()` | Same as `fetch_positions()`; Finvasia returns day and net quantities together. |
| `fetch_net_positions()` | Same as `fetch_positions()`. |
| `fetch_holdings()` | Raw account holdings, or `[]` when empty. |
| `fetch_margin_limits()` | Raw Shoonya limits payload. |
| `fetch_profile()` | Unified profile record. |

## Rate Limits

The Finvasia adapter has rate limiting disabled in `describe()`:

```python
enableRateLimit = False
rateLimits = {}
```

## Endpoints

| Endpoint | Server | Path |
|----------|--------|------|
| `access_token` | `rest` | `/NorenWClientTP/QuickAuth` |
| `place_order` | `rest` | `/NorenWClientTP/PlaceOrder` |
| `modify_order` | `rest` | `/NorenWClientTP/ModifyOrder` |
| `cancel_order` | `rest` | `/NorenWClientTP/CancelOrder` |
| `order_history` | `rest` | `/NorenWClientTP/SingleOrdHist` |
| `orderbook` | `rest` | `/NorenWClientTP/OrderBook` |
| `tradebook` | `rest` | `/NorenWClientTP/TradeBook` |
| `positions` | `rest` | `/NorenWClientTP/PositionBook` |
| `holdings` | `rest` | `/NorenWClientTP/Holdings` |
| `profile` | `rest` | `/NorenWClientTP/ClientDetails` |
| `rms_limits` | `rest` | `/NorenWClientTP/Limits` |
| `instruments` | `rest` | `/EXCH_symbols.txt.zip` |

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
