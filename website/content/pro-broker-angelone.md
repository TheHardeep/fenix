# Angel One — Live Feed

Angel One (SmartAPI smart-stream) live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.angelone` |
| **`id`** | `angelone` |
| **Module** | `fenixpro/angelone.py` |
| **Transport** | `websocket-client` · binary frames |
| **WebSocket endpoint** | `wss://smartapisocket.angelone.in/smart-stream` |
| **Auth headers** | SmartAPI smart-stream headers (`Authorization`, `x-api-key`, `x-client-code`, `x-feed-token`) |
| **Feed types** | `LTP`, `LTP_DEPTH`, `DEPTH` |
| **Ping** | `ping_interval=30s`, payload `ping` |

The Angel One adapter opens a raw WebSocket against the SmartAPI smart-stream endpoint with
authentication carried as request headers, then decodes Angel's fixed-size binary frames into
normalized [TickData](#/pro-contracts) dictionaries.

## Construction

Pass the SmartAPI headers dict (typically produced by Fenix's `AngelOne.authenticate()`).
Optionally pass `fno_tokens` so `subscribe_fno_token(...)` can resolve `(root, option, strike)`.

```python
from fenixpro import angelone, FeedType

broker = angelone(
    headers={"headers": {"Authorization": "Bearer ...", "x-api-key": "...",
                          "x-client-code": "AB1234", "x-feed-token": "..."}},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `headers` | Yes | Dict shaped as `{"headers": {…SmartAPI smart-stream headers…}}` — sent as the WebSocket request headers. |
| `fno_tokens` | Optional | Output of `AngelOne.load_fno_tokens()` — enables `subscribe_fno_token`. |

## Starting the feed

```python
broker.start_websocket(
    on_ltp=on_ltp,
    on_ltp_depth=on_ltp_depth,
    on_depth=on_depth,
    on_open=lambda: print("connected"),
)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `on_ltp` | `None` | Fires on 51-byte LTP packets — `exchange`, `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | `None` | Fires on 123-byte quote packets — adds `avgprice`, `volume`. |
| `on_depth` | `None` | Fires on 379-byte full-mode packets — 5-level bid/ask plus stats. |
| `on_order` | `None` | Reserved for order updates. |
| `on_open` | `None` | Fires after the socket opens. |
| `on_close` | `None` | Receives `(close_status_code, close_msg)`. |
| `on_error` | `None` | Receives the transport/parse error. |
| `run_thread` | `True` | Run the read loop on a daemon thread. |

The subscribe `mode` is derived from the registered callbacks: register `on_ltp` for LTP mode
(1), `on_ltp_depth` for quote mode (2), or `on_depth` for snap-quote mode (3).

## Subscribing

```python
broker.subscribe(26000, exchange=1, feedtype=FeedType.LTP)        # raw token + numeric exchange
broker.subscribe_token(equity_token_dict, FeedType.LTP)           # token record from load_*_tokens
broker.subscribe_fno_token(
    root="NIFTY", option="CE", strike_price="24500",
    feedtype=FeedType.LTP_DEPTH,
)
```

| Method | Parameters | Purpose |
|--------|------------|---------|
| `subscribe(instrument, exchange, feedtype)` | `instrument`: int/str token (or list); `exchange`: numeric SmartAPI segment (`1`=NSE, `2`=NFO, `3`=BSE, `4`=BFO, `5`=MCX, `7`=NCO, `13`=CDS); `feedtype`: `FeedType.*` | Sends SmartAPI `{action:1, params:{mode, tokenList:[…]}}` frame. |
| `subscribe_token(token_dict, feedtype=…)` | `token_dict` from `AngelOne.load_*_tokens()` | Maps `Exchange` to its numeric code via `sock_exchange` and delegates to `subscribe(...)`. |
| `subscribe_fno_token(root, option, strike_price, expiry=…, feedtype=…)` | Standard F&O dimensions | Looks the contract up in `fno_tokens` and subscribes. |

## Unsubscribing

```python
broker.unsubscribe(26000, exchange=1, feedtype=FeedType.LTP)
broker.unsubscribe_token(equity_token_dict, FeedType.LTP)
broker.unsubscribe_fno_token(root="NIFTY", option="CE", strike_price="24500")
```

## Tick payloads

Smart-stream frames are length-coded — the adapter dispatches by packet length:

| Callback | Packet size | Fields delivered |
|----------|-------------|------------------|
| `on_ltp` | 51 bytes | `exchange`, `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | 123 bytes | Adds `avgprice`, `volume`. |
| `on_depth` | 379 bytes | 5-level bid/ask price/qty plus `ltp`, `pc`, `volume`, `feedtime`. |

See [Data Contracts](#/pro-contracts) for the full key reference.

## Closing the feed

```python
broker.close_websocket()
```

`close_websocket()` signals the stop event, closes the underlying WebSocket, and joins the
reader thread.

---

_See [Callback Interface](#/pro-callbacks), [Subscriptions](#/pro-subscriptions), and
[Data Contracts](#/pro-contracts) for the shared feed model used by every Fenix-Pro adapter._
