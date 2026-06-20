# Kotak — Live Feed

Kotak Securities (wstreamer) live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.kotak` |
| **`id`** | `kotak` |
| **Module** | `fenixpro/kotak.py` |
| **Transport** | `socketio` · JSON events |
| **WebSocket endpoint** | `https://wstreamer.kotaksecurities.com/feed` |
| **Auth params** | `consumer_key`, `consumer_secret` |
| **Feed types** | `LTP`, `DEPTH` |

The Kotak adapter exchanges the API consumer key/secret for a bearer token via the
`/feed/auth/token` REST endpoint, then connects a Socket.IO client to the wstreamer feed with
the bearer carried in the `Authorization` header.

## Construction

Pass a headers dict containing `consumer_key` and `consumer_secret`. The constructor calls
`create_headers()` immediately, exchanging them for an access token and assembling the
Socket.IO `Authorization: Bearer …` header.

```python
from fenixpro import kotak, FeedType

broker = kotak(
    headers={"consumer_key": "...", "consumer_secret": "..."},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `headers` | Yes | Dict with `consumer_key` and `consumer_secret` keys. |
| `fno_tokens` | Optional | Output of fenix's Kotak `load_fno_tokens()` — enables `subscribe_fno_token`. |

## Starting the feed

```python
broker.start_websocket(
    on_ltp=on_ltp,
    on_depth=on_depth,
    on_open=lambda: print("connected"),
)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `on_ltp` | `None` | LTP updates — `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | `None` | Reserved for top-of-book quotes. |
| `on_depth` | `None` | Touchline updates — `token`, `ltp`, `pc`, `volume`, `bidprice_lst`, `bidqty_lst`, `askprice_lst`, `askqty_lst`. |
| `on_order` | `None` | Reserved for order updates. |
| `on_open` | `None` | Fires when Socket.IO emits `connect`. |
| `on_close` | `None` | Fires when Socket.IO emits `disconnect`. |
| `on_error` | `None` | Fires on Socket.IO `connect_error`. |
| `run_thread` | `True` | When `False`, the call blocks via `socketio.Client.wait()`. |

The same `getdata` event drives both `on_ltp` and `on_depth` — they parse different slices of
the same row.

## Subscribing

Kotak subscribes by emitting the `pageload` Socket.IO event with the instrument token.

```python
broker.subscribe(26000)                                     # raw token
broker.subscribe_token(equity_token_dict, FeedType.LTP)     # token record from load_*_tokens
broker.subscribe_fno_token(
    root="NIFTY", option="CE", strike_price="24500",
    feedtype=FeedType.LTP,
)
```

| Method | Parameters | Purpose |
|--------|------------|---------|
| `subscribe(instrument)` | `instrument`: int/str token (or list) | Emits `pageload` with `{"inputtoken": "<token>"}`. |
| `subscribe_token(token_dict, feedtype=…)` | `token_dict` containing `Token` | Reads `Token` from the dict and calls `subscribe(...)`. |
| `subscribe_fno_token(root, option, strike_price, expiry=…, feedtype=…)` | Standard F&O dimensions | Looks the contract up in `fno_tokens` and subscribes. |

## Unsubscribing

```python
broker.unsubscribe_token(equity_token_dict, FeedType.LTP)
broker.unsubscribe_fno_token(root="NIFTY", option="CE", strike_price="24500")
```

## Tick payloads

The wstreamer `getdata` event delivers a positional list — the adapter slots the
relevant indices into the unified contract:

| Callback | Fields delivered |
|----------|------------------|
| `on_ltp` | `exchange`, `token`, `ltp`, `feedtime`. |
| `on_depth` | Adds `pc`, `volume`, plus top-of-book `bidprice_lst`, `bidqty_lst`, `askprice_lst`, `askqty_lst`. |

See [Data Contracts](#/pro-contracts) for the full key reference.

## Closing the feed

The Socket.IO client manages its own lifecycle — call `disconnect()` on the underlying client
to stop, or simply let the process exit.

---

_See [Callback Interface](#/pro-callbacks), [Subscriptions](#/pro-subscriptions), and
[Data Contracts](#/pro-contracts) for the shared feed model used by every Fenix-Pro adapter._
