# Subscriptions

Once the socket is open, you subscribe to instruments at one of **three levels** — from raw
broker tokens up to conceptual F&O dimensions. Each has a matching `unsubscribe_*`.

| Method | Subscribe by | Best for |
|--------|--------------|----------|
| `subscribe(...)` | A raw broker-native instrument identifier. | Quick, broker-specific subscriptions. |
| `subscribe_token(...)` | A token dict (`Token`, `Exchange`, …). | Portable, instrument-master driven code. |
| `subscribe_fno_token(...)` | F&O dimensions (root, option, strike, expiry). | Strategy code that thinks in contracts. |

## `subscribe(...)`

The lowest level — pass the broker's native token and a [feed type](#/pro-overview):

```python
from fenixpro import FeedType
broker.subscribe("256265", FeedType.LTP)
broker.unsubscribe("256265")
```

Signatures differ slightly by broker (some need an exchange code), reflecting each broker's
native protocol.

## `subscribe_token(...)`

Subscribe with a **token dict** — the same instrument-record shape Fenix's
[`load_*_tokens`](#/tokens) produces. This keeps your code portable across brokers:

```python
broker.subscribe_token(
    {"Exchange": "NSEFO", "Token": 26000},
    FeedType.LTP,
)
```

Some adapters need extra keys on the dict — for example, the Fyers adapter also expects
`Segment` and `Symbol` to build its subscription symbol.

## `subscribe_fno_token(...)`

The highest level — subscribe by **trading dimensions** (root, option, strike, expiry) instead
of raw tokens. The adapter resolves the dimensions to a broker token using the `fno_tokens`
lookup you supplied at construction:

```python
from fenixpro import zerodha, FeedType, Root, WeeklyExpiry

broker = zerodha(headers=headers, fno_tokens=fno_tokens)
broker.start_websocket(on_ltp=on_ltp)

broker.subscribe_fno_token(
    root="NIFTY",
    option="CE",
    strike_price="24500",
    expiry=WeeklyExpiry.CURRENT,
    feedtype=FeedType.LTP,
)
```

### The `fno_tokens` structure

`subscribe_fno_token` / `unsubscribe_fno_token` assume a nested lookup keyed by
`expiry → root → option → strike → instrument`:

```python
fno_tokens = {
    "<expiry>": {
        "<root>": {
            "<option>": {           # "CE" / "PE"
                "<strike_price>": {
                    "Token": "<broker instrument token>",
                    "Exchange": "<broker exchange code>",
                    "Segment": "<optional, broker specific>",
                    "Symbol": "<optional, broker specific>",
                }
            }
        }
    }
}
```

This is the structure Fenix's [F&O token loaders](#/tokens) are designed to feed, so the two
packages compose: load tokens with Fenix, subscribe to them with Fenix-Pro.

> [!TIP] Pick the level that fits your code
> Use `subscribe_fno_token` when your strategy reasons about strikes and expiries,
> `subscribe_token` when you already hold instrument records, and `subscribe` for one-off
> broker-native subscriptions.

## Unsubscribing

Each subscribe has a mirror:

```python
broker.unsubscribe("256265")
broker.unsubscribe_token({"Exchange": "NSEFO", "Token": 26000})
broker.unsubscribe_fno_token(root="NIFTY", option="CE", strike_price="24500",
                             expiry=WeeklyExpiry.CURRENT)
```
