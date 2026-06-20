# Positions & Holdings

Read your open exposure and settled holdings through unified methods that return the
[Position schema](#/unified-json) — identical keys for every broker.

## Positions

| Method | Returns |
|--------|---------|
| `fetch_day_positions()` | Intraday positions for the current session. |
| `fetch_net_positions()` | Net positions (carry-forward + intraday). |
| `fetch_raw_positions()` | The broker's original, untranslated position payload. |

```python
positions = broker.fetch_net_positions()
for p in positions:
    print(p["symbol"], p["netQty"], "avg", p["avgPrice"], "pnl", p["pnl"])
```

Each record is a [unified Position](#/unified-json) with signed `netQty` (negative = short),
average price, mark-to-market `mtm`, total `pnl`, buy/sell legs, and the last traded price
`ltp`.

```json
{
  "symbol": "NIFTY26JUN24500CE",
  "netQty": 75,
  "avgPrice": 150.4,
  "ltp": 166.0,
  "mtm": 1170.0,
  "pnl": 1170.0,
  "product": "NRML",
  "exchange": "NFO",
  "info": { "broker": "Zerodha" }
}
```

### Computing portfolio PnL

Because every broker returns the same `pnl` field, aggregate logic is broker-agnostic:

```python
total_pnl = sum(p["pnl"] for p in broker.fetch_net_positions())
open_legs = [p for p in broker.fetch_net_positions() if p["netQty"] != 0]
```

## Holdings

`fetch_holdings()` returns your settled, delivery holdings in the same Position-shaped schema:

```python
holdings = broker.fetch_holdings()
for h in holdings:
    print(h["symbol"], h["netQty"], "ltp", h["ltp"], "pnl", h["pnl"])
```

> [!INFO] Positions vs holdings
> **Positions** are the day's open exposure (intraday and carry-forward derivatives/equity).
> **Holdings** are securities that have settled into your demat account. In
> [paper mode](#/paper-mode), which doesn't model T+1 settlement, holdings mirror positions.

## Squaring off

To flatten a position, place an offsetting order on the opposite side for the quantity you hold
— using the [order methods](#/orders):

```python
p = broker.fetch_net_positions()[0]
side = "SELL" if p["netQty"] > 0 else "BUY"
broker.market_order(
    token_dict=broker.alltoken_json[f"{p['token']}_{p['exchange']}"],
    side=side, quantity=abs(p["netQty"]), unique_id="sqoff-1",
)
```

In paper mode there is a dedicated `square_off_position()` helper on the simulator — see
[Paper Mode](#/paper-mode).
