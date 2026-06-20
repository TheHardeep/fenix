# Constants & Standards

Standardization is the heart of Fenix. Instead of memorizing each broker's strings for order
side, product type, validity, and so on, you write your strategy against **one shared
vocabulary** of constants. Adapters translate these to and from each broker's format via the
[request/response maps](#/maps).

All constants live in `fenix.base.constants` and are re-exported at the top level:

```python
from fenix import constants
from fenix.base.constants import Side, Product, OrderType, Validity, Variety
```

> [!TIP] They're plain string classes
> Each "constant" is a class attribute holding a string — `Side.BUY == "BUY"`. You can pass the
> constant or the literal string interchangeably, but using the constant makes typos a
> validation error instead of a silent bug.

## Order-entry constants

These describe *how* an order is placed. They are the values you pass to
[order methods](#/orders).

### `Side`

| Constant | Value |
|----------|-------|
| `Side.BUY` | `"BUY"` |
| `Side.SELL` | `"SELL"` |

### `OrderType`

| Constant | Value | Meaning |
|----------|-------|---------|
| `OrderType.MARKET` | `"MARKET"` | Fill at the prevailing market price. |
| `OrderType.LIMIT` | `"LIMIT"` | Rest until the price reaches your limit. |
| `OrderType.SL` | `"SL"` | Stop-loss limit — triggers, then works as a limit. |
| `OrderType.SLM` | `"SLM"` | Stop-loss market — triggers, then fills at market. |

Order type is usually *inferred* from the `price`/`trigger` you supply rather than passed
explicitly — see [Orders](#/orders).

### `Product`

| Constant | Value | Typical meaning |
|----------|-------|-----------------|
| `Product.CNC` | `"CNC"` | Cash & carry (delivery) for equity. |
| `Product.NRML` | `"NRML"` | Normal / carry-forward for F&O. |
| `Product.MIS` | `"MIS"` | Margin intraday square-off. |
| `Product.MARGIN` | `"MARGIN"` | Margin product. |
| `Product.MTF` | `"MTF"` | Margin trading facility. |
| `Product.BO` | `"BO"` | Bracket order. |
| `Product.CO` | `"CO"` | Cover order. |
| `Product.SM` | `"SM"` | Super multiple. |

### `Validity`

| Constant | Value | Meaning |
|----------|-------|---------|
| `Validity.DAY` | `"DAY"` | Valid for the trading day. |
| `Validity.IOC` | `"IOC"` | Immediate or cancel. |
| `Validity.GTD` | `"GTD"` | Good till date. |
| `Validity.GTC` | `"GTC"` | Good till cancelled. |
| `Validity.FOK` | `"FOK"` | Fill or kill. |
| `Validity.TTL` | `"TTL"` | Time to live. |

### `Variety`

| Constant | Value |
|----------|-------|
| `Variety.REGULAR` | `"REGULAR"` |
| `Variety.STOPLOSS` | `"STOPLOSS"` |
| `Variety.AMO` | `"AMO"` |
| `Variety.BO` | `"BO"` |
| `Variety.CO` | `"CO"` |
| `Variety.ICEBERG` | `"ICEBERG"` |
| `Variety.AUCTION` | `"AUCTION"` |

## Market & instrument constants

### `ExchangeCode`

The segment codes Fenix uses across token maps, orders, and positions.

| Constant | Value | Segment |
|----------|-------|---------|
| `ExchangeCode.NSE` | `"NSE"` | NSE equity |
| `ExchangeCode.NFO` | `"NFO"` | NSE F&O |
| `ExchangeCode.BSE` | `"BSE"` | BSE equity |
| `ExchangeCode.BFO` | `"BFO"` | BSE F&O |
| `ExchangeCode.MCX` | `"MCX"` | Multi Commodity Exchange |
| `ExchangeCode.CDS` | `"NCD"` | Currency derivatives |
| `ExchangeCode.NCO` | `"NCO"` | NSE commodities |
| `ExchangeCode.BCD` | `"BCD"` | BSE currency derivatives |

### `Root`

Underlying root symbols for index and commodity derivatives — used when downloading F&O
[tokens](#/tokens) and expiry dates.

| Group | Constants |
|-------|-----------|
| Indices | `Root.NF` (NIFTY), `Root.BNF` (BANKNIFTY), `Root.FNF` (FINNIFTY), `Root.MIDCPNF` (MIDCPNIFTY), `Root.SENSEX`, `Root.BANKEX` |
| Commodities | `Root.GOLD`, `Root.GOLDM`, `Root.SILVER`, `Root.SILVERM`, `Root.COPPER`, `Root.ZINC`, `Root.CRUDEOIL`, `Root.CRUDEOILM`, `Root.NATURALGAS`, `Root.NATGASMINI` |

### `Option` & `WeeklyExpiry`

```python
Option.CE   # "CE"  — call
Option.PE   # "PE"  — put

WeeklyExpiry.CURRENT  # "CURRENT"
WeeklyExpiry.NEXT     # "NEXT"
WeeklyExpiry.FAR      # "FAR"
```

## Status constants

`Status` is the unified set of order states. Every broker's own status strings are mapped onto
these via [`STANDARD_MAPS`](#/maps).

| Constant | Value |
|----------|-------|
| `Status.PENDING` | `"PENDING"` |
| `Status.OPEN` | `"OPEN"` |
| `Status.PARTIALLY_FILLED` | `"PARTIALLYFILLED"` |
| `Status.FILLED` | `"FILLED"` |
| `Status.REJECTED` | `"REJECTED"` |
| `Status.CANCELLED` | `"CANCELLED"` |
| `Status.MODIFIED` | `"MODIFIED"` |

## Response-key constants

Fenix also standardizes the **keys** of every dictionary it returns. The classes `Order`,
`Position`, `Profile`, and `RMS` hold those key names, so you can reference fields symbolically
instead of with raw strings:

```python
from fenix.base.constants import Order, Position

detail = broker.fetch_order(order_id)
print(detail[Order.STATUS], detail[Order.AVG_PRICE])   # same as detail["status"], ["avgPrice"]
```

The full field lists for each are documented on the [Unified JSON Schemas](#/unified-json) page.

## Default order tags — `UniqueID`

Every order takes a caller-supplied `unique_id` tag that is echoed back on the order record.
`UniqueID` provides sensible defaults:

```python
UniqueID.DEF_ORDER     # "FenixOrder"
UniqueID.MARKET_ORDER  # "MarketOrder"
UniqueID.LIMIT_ORDER   # "LIMITOrder"
UniqueID.SL_ORDER      # "SLOrder"
UniqueID.SLM_ORDER     # "SLMOrder"
```

> [!INFO] One vocabulary, every broker
> Because all of these constants are translated at the adapter boundary, your strategy code
> never contains a broker-specific string. Switching from `Zerodha` to `AngelOne` changes the
> class you instantiate — not a single `Side`, `Product`, or `Status` reference.
