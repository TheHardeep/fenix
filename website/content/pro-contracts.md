# Data Contracts

The core value of Fenix-Pro is normalization: each adapter decodes a different native frame
format and converges the result onto **shared dictionary keys**. Two contracts define those
keys — `TickData` for market data and `Order` for order events — both in
`fenixpro.base.constants`.

```python
from fenixpro import TickData, Order
```

## TickData

Market-data ticks normalize toward these keys. Depending on the [feed type](#/pro-overview) and
broker, a tick carries a subset (an LTP tick won't include depth ladders).

```json
{
  "exchange": "NFO",
  "token": 12345,
  "ltp": 221.35,
  "perc_change": 1.8,
  "volume": 1500,
  "open": 210.0, "high": 225.0, "low": 208.5, "close": 217.0,
  "avgPrice": 219.4,
  "oi": 4200000,
  "bidprice_lst": [221.30, 221.25],
  "bidqty_lst": [100, 75],
  "askprice_lst": [221.40, 221.45],
  "askqty_lst": [120, 80],
  "feedtime": "...",
  "info": { }
}
```

| Key (`TickData.…`) | Field | Meaning |
|--------------------|-------|---------|
| `EXCHANGE` / `TOKEN` | `exchange` / `token` | Instrument identity. |
| `LTP` | `ltp` | Last traded price. |
| `PERCCHANGE` | `perc_change` | Percent change. |
| `VOLUME` | `volume` | Traded volume. |
| `OPEN` / `HIGH` / `LOW` / `CLOSE` | OHLC | Session OHLC. |
| `AVGPRICE` | `avgPrice` | Average traded price. |
| `OI` / `POI` / `TOI` | open interest | OI and prev/total OI variants. |
| `BIDPRICELST` / `BIDQTYLST` | `bidprice_lst` / `bidqty_lst` | Bid ladder (depth feeds). |
| `ASKPRICELST` / `ASKQTYLST` | `askprice_lst` / `askqty_lst` | Ask ladder (depth feeds). |
| `BIDPRICE` / `ASKPRICE` / `BIDQTY` / `ASKQTY` | top of book | Best bid/ask. |
| `LCLIMIT` / `UCLIMIT` | `lc` / `uc` | Lower/upper circuit limits. |
| `BUYDEPTH` / `SELLDEPTH` | `buydepth` / `selldepth` | Aggregated depth. |
| `FEEDTIME` | `feedtime` | Feed timestamp. |
| `INFO` | `info` | Broker-specific extras. |

> [!INFO] Read defensively
> Not every adapter populates every key — deep-depth normalization is still converging across
> adapters. Reference fields through `tick.get("oi")` rather than assuming presence, and lean on
> `info` for anything broker-specific.

## Order

Where an adapter implements order-feed parsing, order events normalize toward these keys — the
same vocabulary as [Fenix's unified order record](#/unified-json), so order updates from the
live feed line up with the trading side.

```json
{
  "id": "250619000142",
  "userOrderId": "entry-1",
  "timestamp": "...",
  "symbol": "NIFTY26JUN24500CE",
  "token": 12345,
  "side": "BUY",
  "type": "LIMIT",
  "avgPrice": 152.0,
  "price": 152.0,
  "triggerPrice": 0.0,
  "quantity": 75,
  "filled": 75,
  "remaining": 0,
  "status": "FILLED",
  "product": "NRML",
  "exchange": "NFO",
  "validity": "DAY",
  "info": { }
}
```

| Key (`Order.…`) | Field |
|-----------------|-------|
| `ID` / `USERID` | `id` / `userOrderId` |
| `SYMBOL` / `TOKEN` | `symbol` / `token` |
| `SIDE` / `TYPE` | `side` / `type` |
| `AVGPRICE` / `PRICE` / `TRIGGERPRICE` | prices |
| `QUANTITY` / `FILLEDQTY` / `REMAININGQTY` | quantities |
| `STATUS` | `status` |
| `PRODUCT` / `EXCHANGE` / `VALIDITY` | classification |
| `INFO` | `info` |

## Shared enums

Fenix-Pro reuses the same constant families as Fenix for `Side`, `OrderType`, `Product`,
`Validity`, `Status`, `ExchangeCode`, and `Root`, plus the feed-specific `FeedType`
(`LTP`, `LTP_DEPTH`, `DEPTH`, `ORDER`). See [Fenix Constants](#/constants) for the shared set.
