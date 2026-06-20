# Anand Rathi

Anand Rathi broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.AnandRathi` |
| **`id`** | `AnandRathi` |
| **Module** | `fenix/anandrathi.py` |
| **Inherits** | `fenix.Symphony` |
| **Broker API docs** | [https://algozy.rathi.com/doc/interactive](https://algozy.rathi.com/doc/interactive) |
| **Market-data docs** | [https://algozy.rathi.com/doc/marketdata/](https://algozy.rathi.com/doc/marketdata/) |
| **Auth params** | `api_key`, `api_secret` |

Anand Rathi exposes a Symphony-compatible Interactive API at Anand Rathi hosts. The adapter inherits the Symphony implementation for authentication, token parsing, orders, positions, holdings, margin, profile, error handling, and rate limits. It overrides only the broker identity, endpoint hosts, HostLookup fallback behavior, and bulk token download.

For the shared method contracts, see [Symphony](#/broker-symphony). This page documents what changes for Anand Rathi and shows the same calls using `AnandRathi`.

## What Differs From Symphony

| Area | Anand Rathi behavior |
|------|----------------------|
| Broker id | `describe()` returns `AnandRathi` instead of `Symphony`. |
| Interactive host | Starts at `https://algozy.rathi.com/HOSTLOOKUP`, then rewrites to the HostLookup `connectionString` after authentication. |
| Market-data host | Uses `https://algozy.rathi.com/apimarketdata`. |
| HostLookup fallback | If `/hostlookup` is unreachable, the adapter falls back to documented Anand Rathi hostlookup endpoints. |
| Token bulk download | `download_tokens()` requests NSECM, BSECM, NSEFO, BSEFO, MCXFO, and NSECD in one contract-master call. |

Everything else is inherited from `Symphony`.

## Authentication

`AnandRathi.authenticate()` uses the inherited Symphony login flow: HostLookup resolves the Interactive base URL and `uniqueKey`, then the adapter exchanges your API keys for an access token.

```python
from fenix import AnandRathi

broker = AnandRathi()
headers = broker.authenticate(params={
    "api_key": "your-app-key",
    "api_secret": "your-secret-key",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `api_key` and `api_secret`. |
| `headers` | Optional | Reuses a previously authenticated header dict. |
| `force` | Optional | When `True`, ignores cached headers and runs the login flow again. |

If the primary HostLookup call fails, Anand Rathi falls back to its first documented hostlookup pair from `anandrathi.py`.

## Paper Mode

```python
from fenix import AnandRathi

broker = AnandRathi(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens

You can use the inherited loaders exactly like Symphony:

```python
equity, equity_by_token = broker.load_equity_tokens()
fno, fno_by_token = broker.load_fno_tokens()
mcx, mcx_by_token = broker.load_mcx_tokens()
cds, cds_by_token = broker.load_cds_tokens()
```

Anand Rathi also provides `download_tokens()` to download all supported contract-master segments in one request.

```python
equity, options, futures, all_tokens = broker.download_tokens()

nifty_call = options["NFO"]["NIFTY"][0]
print(nifty_call["Token"], nifty_call["Symbol"], nifty_call["StrikePrice"])
```

`download_tokens()` requests these segments together:

| Segment | Loaded into |
|---------|-------------|
| `NSECM`, `BSECM` | `equity` |
| `NSEFO`, `BSEFO` | `options` and `futures` |
| `MCXFO` | `options` and `futures` |
| `NSECD` | `options` and `futures` |

It returns:

| Return value | Contents |
|--------------|----------|
| `equity` | NSE and BSE maps from the inherited equity parser. |
| `options` | Combined `NFO`, `BFO`, `MCX`, and `CDS` option maps. |
| `futures` | Combined `NFO`, `BFO`, `MCX`, and `CDS` futures maps. |
| `all_tokens` | Flat `"{Token}_{Exchange}"` lookup from every loaded segment. |

## Placing Orders

Order entry is inherited from Symphony. Use token records from `load_*_tokens()` or `download_tokens()`.

```python
from fenix import AnandRathi
from fenix.base.constants import Product, Side, Validity, Variety

broker = AnandRathi()
broker.authenticate(params={
    "api_key": "your-app-key",
    "api_secret": "your-secret-key",
})

equity, options, futures, all_tokens = broker.download_tokens()
contract = options["NFO"]["NIFTY"][0]

order = broker.place_order(
    token_dict=contract,
    quantity=contract["LotSize"],
    side=Side.BUY,
    product=Product.MIS,
    validity=Validity.DAY,
    variety=Variety.REGULAR,
    unique_id="anandrathi-docs-demo",
    price=0.0,
    trigger=0.0,
)
print(order["id"])
```

The `place_order()` parameters and return shape are the same as [Symphony](#/broker-symphony).

## Order Management

```python
order_id = order["id"]

orders = broker.fetch_orderbook()
trades = broker.fetch_tradebook()
details = broker.fetch_order(order_id)
history = broker.fetch_order_history(order_id)

modified = broker.modify_order(order_id=order_id, price=152.5, quantity=75)
cancelled = broker.cancel_order(order_id=order_id)
```

| Method | Returns |
|--------|---------|
| `fetch_raw_orderbook()` | Raw inherited Symphony/XTS order rows, or `[]` when empty. |
| `fetch_raw_order_history(order_id)` | Raw inherited history rows for one order. |
| `fetch_orderbook()` | Unified Fenix order records. |
| `fetch_tradebook()` | Unified trade/order records. |
| `fetch_orders()` | Alias for `fetch_orderbook()`. |
| `fetch_order(order_id)` | Latest unified order-history record. |
| `fetch_order_history(order_id)` | Unified order-history records. |
| `modify_order(order_id, price=None, quantity=None)` | Unified order-id record for the modified order. |
| `cancel_order(order_id)` | Unified order-id record for the cancelled order. |

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
| `fetch_day_positions()` | Unified day-wise position records. |
| `fetch_net_positions()` | Unified net-wise position records. |
| `position_convert(position, new_product)` | Decoded broker response after product conversion. |
| `fetch_holdings()` | Raw holdings payload, or `[]` when empty. |
| `fetch_margin_limits()` | Unified RMS record with raw `info`. |
| `fetch_profile()` | Unified profile record with raw `info`. |

## Endpoints

Anand Rathi inherits Symphony endpoint paths and changes only the hosts.

| Server | Base URL |
|--------|----------|
| `interactive` | `https://algozy.rathi.com/HOSTLOOKUP` before login; HostLookup `connectionString` after login. |
| `market_data` | `https://algozy.rathi.com/apimarketdata` |
| `hostlookup` | `https://algozy.rathi.com` |

The inherited paths include `/user/session`, `/orders`, `/orders/bracket`, `/orders/trades`, `/portfolio/positions`, `/portfolio/holdings`, `/user/profile`, `/user/balance`, and `/instruments/master`.

---

See [Symphony](#/broker-symphony) for the full inherited method contract.
