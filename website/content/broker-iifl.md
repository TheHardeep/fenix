# IIFL

IIFL broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.Iifl` |
| **`id`** | `Iifl` |
| **Module** | `fenix/iifl.py` |
| **Broker API docs** | [https://ttblaze.iifl.com/doc/interactive/](https://ttblaze.iifl.com/doc/interactive/) |
| **Market-data API docs** | [https://ttblaze.iifl.com/doc/marketdata](https://ttblaze.iifl.com/doc/marketdata) |
| **Auth params** | `api_key`, `api_secret` |
| **Instrument source** | IIFL XTS index list and contract-master text |

The IIFL adapter uses the XTS Interactive API for login, orders, portfolio, account, and profile calls, and the XTS Market Data API for index lists and contract masters. It maps IIFL order, trade, position, and profile responses into the unified Fenix contracts.

## Authentication

`Iifl.authenticate()` logs in with the IIFL app key and secret key, stores the returned interactive token, and keeps the returned `userID` as auth context for calls that require `clientID`.

```python
from fenix import Iifl

broker = Iifl()
headers = broker.authenticate(params={
    "api_key": "your-app-key",
    "api_secret": "your-secret-key",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `api_key` and `api_secret`. |
| `headers` | Optional | Previously authenticated headers. Must include `Content-type` and `authorization`. |
| `force` | Optional | When `True`, ignores cached headers and logs in again. |

The returned dict includes both the request headers and `user_id` context:

```python
{
    "Content-type": "application/json",
    "authorization": "interactive-token",
    "user_id": "client-id"
}
```

## Paper Mode

```python
from fenix import Iifl

broker = Iifl(config={"paper_mode": True})
broker.authenticate()
```

In paper mode, authentication stores `{"paper": "true"}` and order, order-book, position, holding, margin, and profile calls are routed to the paper broker when available.

## Instrument Tokens

IIFL uses two market-data sources. Index tokens are fetched from `/instruments/indexlist`; equities and derivatives are parsed from `/instruments/master` contract-master text.

```python
token_json, alltoken_json = broker.load_fno_tokens(data=None)
```

| Method | Source | Loads |
|--------|--------|-------|
| `load_index_tokens(data=None)` | `indexlist` for exchange segments `1` and `11` | NSE and BSE indices, including root aliases for `BANKNIFTY`, `NIFTY`, `FINNIFTY`, and `MIDCPNIFTY`. |
| `load_equity_tokens(data=None)` | Contract master for `NSECM`, `BSECM` | NSE and BSE equity instruments. |
| `load_fno_tokens(data=None)` | Contract master for `NSEFO`, `BSEFO` | NSE and BSE F&O futures/options. |
| `load_mcx_tokens(data=None)` | Contract master for `MCXFO` | MCX futures/options. |
| `load_cds_tokens(data=None)` | Contract master for `NSECD` | Currency derivative futures/options. |

`data` can be supplied to avoid fetching from the broker. Index data must be keyed by `NSE` and `BSE`; contract-master data should be keyed by the segment names used by the loader, such as `NFO`, `BFO`, `MCX`, `CDS`, or `BCD`.

```python
indices, index_by_token = broker.load_index_tokens()
equity, equity_by_token = broker.load_equity_tokens(data=None)
fno, fno_by_token = broker.load_fno_tokens(data=None)
mcx, mcx_by_token = broker.load_mcx_tokens(data=None)
cds, cds_by_token = broker.load_cds_tokens(data=None)
```

### Token Record Fields

Index records contain `Symbol`, `Token`, and `Exchange`.

Equity records contain `Exchange`, `Token`, `Symbol`, `DisplayName`, `FreezeQty`, `TickSize`, `LotSize`, `ISIN`, `DetailedDescription`, `Series`, `PriceNumerator`, and `PriceDenominator`.

Derivative records include `Exchange`, `Token`, `Root`, `Symbol`, `FreezeQty`, `TickSize`, `LotSize`, `Expiry`, `PriceNumerator`, `PriceDenominator`, and `DisplayName`. Option records also include `StrikePrice` and `Option`.

```python
fno, _ = broker.load_fno_tokens(data=None)

nifty_call = fno["Options"]["NSE"]["NIFTY"][0]
print(nifty_call["Symbol"], nifty_call["Token"], nifty_call["StrikePrice"])
```

## Placing Orders

`place_order()` accepts a token record from a loader and Fenix constants/strings for side, product, validity, and variety. IIFL receives `exchangeInstrumentID`, `exchangeSegment`, `limitPrice`, `stopPrice`, quantity, side, order type, product type, time-in-force, and `orderUniqueIdentifier`.

```python
from fenix import Iifl
from fenix.base.constants import Product, Side, Validity, Variety

broker = Iifl()
broker.authenticate(params={
    "api_key": "your-app-key",
    "api_secret": "your-secret-key",
})

fno, _ = broker.load_fno_tokens(data=None)
contract = fno["Options"]["NSE"]["NIFTY"][0]

order = broker.place_order(
    token_dict=contract,
    quantity=int(contract["LotSize"]),
    side=Side.BUY,
    product=Product.MIS,
    validity=Validity.DAY,
    variety=Variety.REGULAR,
    unique_id="iifl-docs-demo",
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
| `product` | Yes | `Product.MIS`, `Product.NRML`, `Product.CNC`, or `Product.CO`. |
| `validity` | Yes | `Validity.DAY` or `Validity.IOC`. |
| `variety` | Yes | Accepted for the shared broker interface. `Variety.BO` is rejected. |
| `unique_id` | Yes | Sent as `orderUniqueIdentifier`. |
| `price` | Optional | Limit price. Use `0.0` with no trigger for a market order. |
| `trigger` | Optional | Stop trigger. Combining `price` and `trigger` creates a stop-limit order. |
| `target`, `stoploss`, `trailing_sl` | Optional | Not available through this adapter. Supplying any of them raises `InputError`. |

The adapter returns the IIFL app order id:

```python
{"id": "app-order-id"}
```

## Order Management

```python
order_id = order["id"]

raw_orders = broker.fetch_raw_orderbook()
raw_history = broker.fetch_raw_orderhistory(order_id)

orders = broker.fetch_orderbook()
trades = broker.fetch_tradebook()
details = broker.fetch_order(order_id)
history = broker.fetch_order_history(order_id)
```

| Method | Returns |
|--------|---------|
| `fetch_raw_orderbook()` | Raw IIFL order-book response. |
| `fetch_raw_orderhistory(order_id)` | Raw order history for one `appOrderID`. |
| `fetch_orderbook()` | Unified order records parsed from `result`. |
| `fetch_tradebook()` | Unified trade records parsed from `/orders/trades`. |
| `fetch_order(order_id)` | Latest unified order record from the order history. |
| `fetch_order_history(order_id)` | Unified history records for one order. |

### Modify And Cancel

```python
modified = broker.modify_order(
    order_id=order_id,
    price=151.25,
    quantity=int(contract["LotSize"]),
)

cancelled = broker.cancel_order(order_id=order_id)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `order_id` | Yes | IIFL `AppOrderID` to modify or cancel. |
| `price` | Optional | Replacement limit price. Existing `OrderPrice` is reused when omitted. |
| `trigger` | Optional | Replacement stop price. Existing `OrderStopPrice` is reused when omitted. |
| `quantity` | Optional | Replacement quantity. Existing `OrderQuantity` is reused when omitted. |
| `order_type` | Optional | Replacement Fenix order type. Existing `OrderType` is reused when omitted. |
| `validity` | Optional | Replacement validity. Existing `TimeInForce` is reused when omitted. |
| `raw_order_json` | Optional | Raw IIFL order-history row to avoid a fresh history lookup. |
| `extra_params` | Optional | Reserved for broker-specific extensions. |

`modify_order()` sends a `PUT /orders` request with `clientID` from the auth context and then fetches the updated order. `cancel_order()` sends `DELETE /orders` with `appOrderID` and then fetches the cancelled order.

## Positions And Account

```python
day_positions = broker.fetch_day_positions()
net_positions = broker.fetch_net_positions()
all_positions = broker.fetch_positions()
holdings = broker.fetch_holdings()
limits = broker.fetch_margin_limits()
profile = broker.fetch_profile()
```

| Method | Returns |
|--------|---------|
| `fetch_day_positions()` | Unified position records for `dayOrNet=DayWise`. |
| `fetch_net_positions()` | Unified position records for `dayOrNet=NetWise`. |
| `fetch_positions()` | Day and net positions combined into one list. |
| `fetch_holdings()` | Raw IIFL holdings response for the authenticated `clientID`. |
| `fetch_margin_limits()` | Raw IIFL balance or RMS limits response for the authenticated `clientID`. |
| `fetch_profile()` | Unified profile record parsed from `/user/profile`. |

## Rate Limits

| Group | Limit |
|-------|-------|
| `orders` | 10 requests/second. |
| `post_trade` | 1 request/second. |
| `portfolio` | 1 request/second. |
| `account` | 1 request/second. |
| `auth` | 1 request/second. |
| `market_data` | 1 request/second. |
| `default` | 1 request/second. |

## Endpoints

| Endpoint | Server | Path |
|----------|--------|------|
| `access_token` | `interactive` | `/user/session` |
| `place_order` | `interactive` | `/orders` |
| `modify_order` | `interactive` | `/orders` |
| `cancel_order` | `interactive` | `/orders` |
| `orderbook` | `interactive` | `/orders` |
| `tradebook` | `interactive` | `/orders/trades` |
| `positions` | `interactive` | `/portfolio/positions` |
| `holdings` | `interactive` | `/portfolio/holdings` |
| `rms_limits` | `interactive` | `/user/balance` |
| `profile` | `interactive` | `/user/profile` |
| `index_data` | `market_data` | `/instruments/indexlist` |
| `instruments` | `market_data` | `/instruments/master` |

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter.
