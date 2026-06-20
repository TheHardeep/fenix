# Symphony — Live Feed

Symphony (JM Financial · SmartWeb) live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.symphony` |
| **`id`** | `symphony` |
| **Module** | `fenixpro/symphony.py` |
| **Extends** | [`fenixpro.iifl`](#/pro/iifl) |
| **Transport** | `socketio` · JSON events (XTS) |
| **Base URL** | `https://smartweb.jmfinancialservices.in` |
| **Auth params** | `api_key`, `api_secret` |
| **Feed types** | `LTP`, `DEPTH` |

Symphony exposes the XTS market-data API on JM Financial's SmartWeb host, so the Fenix-Pro
adapter is a thin subclass of [`iifl`](#/pro/iifl): it inherits the full Socket.IO connect,
subscribe, and parser flow and overrides only the `base` URL.

## Construction

Identical to IIFL — pass `params` with the SmartWeb market-data API key/secret, and the parent
class handles login, header building, and Socket.IO connect.

```python
from fenixpro import symphony, FeedType

broker = symphony(
    params={"api_key": "...", "api_secret": "..."},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | One of `params`/`headers` is required | Dict with `api_key` and `api_secret`. |
| `headers` | Optional | Pre-built XTS headers dict. |
| `fno_tokens` | Optional | Output of `Symphony.load_fno_tokens()` — enables `subscribe_fno_token`. |

## Starting the feed

```python
broker.start_websocket(
    on_ltp=on_ltp,
    on_depth=on_depth,
    on_open=lambda: print("connected"),
)
```

See [IIFL → Starting the feed](#/pro/iifl) for the full callback table — every slot, default,
and behavior is inherited.

## Subscribing

```python
broker.subscribe(26000, exchange=1, feedtype=FeedType.LTP)
broker.subscribe_token(equity_token_dict, FeedType.LTP)
broker.subscribe_fno_token(
    root="NIFTY", option="CE", strike_price="24500",
    feedtype=FeedType.LTP,
)
```

See [IIFL → Subscribing](#/pro/iifl) for the parameter reference. Subscribes are XTS REST
calls to `POST {base}/apimarketdata/instruments/subscription` (`PUT` to unsubscribe).

## Tick payloads

| Callback | Socket.IO event | Fields delivered |
|----------|-----------------|------------------|
| `on_ltp` | `1512-json-full`, `1505-json-partial` | `exchange`, `token`, `ltp`, `feedtime`. |
| `on_depth` | `1502-json-full` | 5-level `bidprice_lst`, `bidqty_lst`, `askprice_lst`, `askqty_lst`, plus `ltp`, `pc`, `volume`. |

See [Data Contracts](#/pro-contracts) for the full key reference.

## Closing the feed

The Socket.IO client manages its own lifecycle — call `disconnect()` on the underlying client
to stop, or simply let the process exit.

---

_See [Callback Interface](#/pro-callbacks), [Subscriptions](#/pro-subscriptions), and
[Data Contracts](#/pro-contracts) for the shared feed model used by every Fenix-Pro adapter._
