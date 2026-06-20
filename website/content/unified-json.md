# Unified JSON Schemas

Every read method in Fenix returns the **same dictionary shape regardless of broker**. A
Zerodha order and an AngelOne order come back with identical keys, so your parsing code is
written once. This page is the reference for each unified record.

The keys are defined as constants (`Order`, `Position`, `Profile`, `RMS`) in
[`fenix.base.constants`](#/constants), so you can index either by the constant or the literal
string — `record[Order.STATUS]` is the same as `record["status"]`.

> [!INFO] The `info` escape hatch
> Every unified record carries an `info` key holding broker-specific context (and, for
> [paper mode](#/paper-mode), `{"broker": ..., "mode": "paper"}`). When you need a field Fenix
> doesn't standardize, reach into `info` — nothing from the broker is lost.

## Order record

Returned by `place_order` (id only), `fetch_order`, `fetch_orderbook`, `fetch_tradebook`, and
the order convenience methods. Full shape:

```json
{
  "id": "250619000142",
  "userOrderId": "entry-1",
  "timestamp": "2026-06-19 09:18:42",
  "symbol": "NIFTY26JUN24500CE",
  "token": 12345678,
  "side": "BUY",
  "type": "LIMIT",
  "avgPrice": 0.0,
  "price": 152.0,
  "triggerPrice": 0.0,
  "targetPrice": 0.0,
  "stoplossPrice": 0.0,
  "trailingStoploss": 0.0,
  "quantity": 75,
  "filled": 0,
  "remaining": 75,
  "cancelleldQty": 0,
  "status": "OPEN",
  "rejectReason": "",
  "disclosedQuantity": 0,
  "product": "NRML",
  "segment": "NFO",
  "exchange": "NFO",
  "validity": "DAY",
  "variety": "REGULAR",
  "info": { "broker": "Zerodha" }
}
```

| Key (`Order.…`) | Field | Type | Notes |
|-----------------|-------|------|-------|
| `ID` | `id` | str | Broker order id. |
| `USER_ID` | `userOrderId` | str | Your `unique_id` tag, echoed back. |
| `TIMESTAMP` | `timestamp` | datetime | Order time (parsed). |
| `SYMBOL` | `symbol` | str | Trading symbol. |
| `TOKEN` | `token` | int | Instrument token. |
| `SIDE` | `side` | `Side` | `BUY` / `SELL`. |
| `TYPE` | `type` | `OrderType` | `MARKET` / `LIMIT` / `SL` / `SLM`. |
| `AVG_PRICE` | `avgPrice` | float | Average fill price. |
| `PRICE` | `price` | float | Limit price. |
| `TRIGGER_PRICE` | `triggerPrice` | float | Stop trigger. |
| `TARGET_PRICE` | `targetPrice` | float | Bracket target. |
| `STOPLOSS_PRICE` | `stoplossPrice` | float | Bracket stop-loss. |
| `TRAILING_STOPLOSS` | `trailingStoploss` | float | Bracket trailing SL. |
| `QUANTITY` | `quantity` | int | Ordered quantity. |
| `FILLED_QTY` | `filled` | int | Filled quantity. |
| `REMAINING_QTY` | `remaining` | int | Unfilled quantity. |
| `CANCELLED_QTY` | `cancelleldQty` | int | Cancelled quantity. |
| `STATUS` | `status` | `Status` | Unified status. |
| `REJECT_REASON` | `rejectReason` | str | Reason if rejected. |
| `DISCLOSED_QUANTITY` | `disclosedQuantity` | int | Iceberg disclosed qty. |
| `PRODUCT` | `product` | `Product` | Product type. |
| `SEGMENT` | `segment` | str | Segment. |
| `EXCHANGE` | `exchange` | `ExchangeCode` | Exchange. |
| `VALIDITY` | `validity` | `Validity` | Validity. |
| `VARIETY` | `variety` | `Variety` | Variety. |
| `INFO` | `info` | dict | Broker-specific extras. |

## Position record

Returned by `fetch_day_positions`, `fetch_net_positions`, and (as holdings)
`fetch_holdings`.

```json
{
  "symbol": "NIFTY26JUN24500CE",
  "token": 12345678,
  "netQty": 75,
  "avgPrice": 150.4,
  "mtm": 1170.0,
  "pnl": 1170.0,
  "buyQty": 75,
  "buyPrice": 150.4,
  "sellQty": 0,
  "sellPrice": 0.0,
  "ltp": 166.0,
  "product": "NRML",
  "exchange": "NFO",
  "info": { "broker": "Zerodha" }
}
```

| Key (`Position.…`) | Field | Notes |
|--------------------|-------|-------|
| `SYMBOL` / `TOKEN` | `symbol` / `token` | Instrument identity. |
| `NET_QTY` | `netQty` | Signed net position (negative = short). |
| `AVG_PRICE` | `avgPrice` | Average price of the open quantity. |
| `MTM` | `mtm` | Mark-to-market on the open quantity. |
| `PNL` | `pnl` | Total PnL (realised + unrealised). |
| `BUY_QTY` / `BUY_PRICE` | `buyQty` / `buyPrice` | Cumulative buys and their average. |
| `SELL_QTY` / `SELL_PRICE` | `sellQty` / `sellPrice` | Cumulative sells and their average. |
| `LTP` | `ltp` | Last traded price. |
| `PRODUCT` / `EXCHANGE` | `product` / `exchange` | Product and exchange. |
| `INFO` | `info` | Broker-specific extras. |

## RMS / margin record

Returned by `fetch_margin_limits`.

```json
{
  "marginUsed": 48250.0,
  "marginAvail": 951750.0,
  "cashMargin": 1000000.0,
  "spanMargin": 0.0,
  "variableMargin": 0.0,
  "collateral": 0.0,
  "info": { "broker": "Zerodha" }
}
```

| Key (`RMS.…`) | Field |
|---------------|-------|
| `MARGINUSED` | `marginUsed` |
| `MARGINAVAIL` | `marginAvail` |
| `CASHMARGIN` | `cashMargin` |
| `SPANMARGIN` | `spanMargin` |
| `VARIABLEMARGIN` | `variableMargin` |
| `COLLATERAL` | `collateral` |
| `INFO` | `info` |

## Profile record

Returned by `fetch_profile`.

```json
{
  "clientId": "AB1234",
  "name": "Paper Trader",
  "emailId": "trader@example.com",
  "mobileNo": "9000000000",
  "pan": "ABCDE1234F",
  "address": "…",
  "bankName": "…",
  "bankBranchName": "…",
  "bankAccNo": "…",
  "exchangesEnabled": ["NSE", "BSE", "NFO", "BFO", "MCX", "NCD"],
  "enabled": true,
  "info": { "broker": "Zerodha" }
}
```

| Key (`Profile.…`) | Field |
|-------------------|-------|
| `CLIENT_ID` | `clientId` |
| `NAME` | `name` |
| `EMAIL_ID` | `emailId` |
| `MOBILE_NO` | `mobileNo` |
| `PAN` | `pan` |
| `ADDRESS` | `address` |
| `BANK_NAME` / `BANK_BRANCH_NAME` / `BANK_ACC_NO` | bank details |
| `EXCHANGES_ENABLED` | `exchangesEnabled` |
| `ENABLED` | `enabled` |
| `INFO` | `info` |

## Reading records symbolically

Because the keys are constants, your code stays readable and refactor-safe:

```python
from fenix.base.constants import Order, Status

for o in broker.fetch_orderbook():
    if o[Order.STATUS] == Status.OPEN:
        print(o[Order.SYMBOL], o[Order.REMAINING_QTY], "@", o[Order.PRICE])
```
