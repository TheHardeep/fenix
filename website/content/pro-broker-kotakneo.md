# Kotak Neo — Live Feed

Kotak Neo (HSM) live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.kotakneo` |
| **`id`** | `kotakneo` |
| **Module** | `fenixpro/kotakneo.py` |
| **Transport** | `websocket-client` · HSM binary frames |
| **WebSocket endpoint** | `wss://mlhsm.kotaksecurities.com` |
| **Auth headers** | Kotak Neo HSM session headers |
| **Feed types** | `LTP`, `LTP_DEPTH`, `DEPTH` |
| **Ping** | `ping_interval=30s`, payload `ping` |

The Kotak Neo adapter opens an HSM binary WebSocket using request-header authentication, then
decodes fixed-size binary frames into normalized [TickData](#/pro-contracts) dictionaries.

## Construction

Pass the headers dict produced by Fenix's `KotakNeo.authenticate()` — the dict's inner
`headers` value is sent as WebSocket request headers so the HSM endpoint can authenticate the
connection.

```python
from fenixpro import kotakneo, FeedType

broker = kotakneo(
    headers={"headers": {"Authorization": "Bearer ...", "sid": "...", "Auth": "..."}},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `headers` | Yes | Dict shaped as `{"headers": {…HSM auth headers…}}` — passed to the WebSocket constructor. |
| `fno_tokens` | Optional | Output of `KotakNeo.load_fno_tokens()` — enables `subscribe_fno_token`. |

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
| `on_depth` | `None` | Fires on 379-byte full packets — 5-level bid/ask plus stats. |
| `on_order` | `None` | Reserved for order updates. |
| `on_open` | `None` | Fires after the socket opens. |
| `on_close` | `None` | Receives `(close_status_code, close_msg)`. |
| `on_error` | `None` | Receives the transport/parse error. |
| `run_thread` | `True` | Run the read loop on a daemon thread. |

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
| `subscribe(instrument, exchange, feedtype)` | `instrument`: int/str token (or list); `exchange`: numeric segment (`1`=NSE, `2`=NFO, `3`=BSE, `4`=BFO, `5`=MCX, `7`=NCO, `13`=CDS); `feedtype`: `FeedType.*` | Sends the HSM `{action:1, params:{mode, tokenList:[…]}}` request. |
| `subscribe_token(token_dict, feedtype=…)` | `token_dict` from `KotakNeo.load_*_tokens()` | Maps `Exchange` to its numeric code via `sock_exchange` and delegates to `subscribe(...)`. |
| `subscribe_fno_token(root, option, strike_price, expiry=…, feedtype=…)` | Standard F&O dimensions | Looks the contract up in `fno_tokens` and subscribes. |

The `mode` is derived from the registered callbacks: `on_ltp` selects mode 1, `on_ltp_depth`
selects mode 2, `on_depth` selects mode 3.

## Unsubscribing

```python
broker.unsubscribe(26000, exchange=1, feedtype=FeedType.LTP)
broker.unsubscribe_token(equity_token_dict, FeedType.LTP)
broker.unsubscribe_fno_token(root="NIFTY", option="CE", strike_price="24500")
```

## Tick payloads

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
