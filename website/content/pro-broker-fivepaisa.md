# 5paisa — Live Feed

5paisa (OpenFeed) live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.fivepaisa` |
| **`id`** | `fivepaisa` |
| **Module** | `fenixpro/fivepaisa.py` |
| **Transport** | `websocket-client` · OpenFeed JSON frames |
| **WebSocket endpoint** | `wss://openfeed.5paisa.com/Feeds/api/chat?Value1={access_token}|{client_code}` |
| **Auth params** | `access_token`, `client_code` |
| **Feed types** | `LTP`, `LTP_DEPTH`, `DEPTH` |
| **Ping** | `ping_interval=30s`, payload `ping` |

The 5paisa adapter encodes the access token and client code directly into the OpenFeed URL,
opens the WebSocket, and parses MarketFeedV3 / MarketDepthService frames into normalized
[TickData](#/pro-contracts) dictionaries.

## Construction

Pass a headers dict containing `access_token` and `client_code` (returned by Fenix's
`FivePaisa.authenticate()`). Optionally pass `fno_tokens` so `subscribe_fno_token(...)` can
resolve `(root, option, strike)`.

```python
from fenixpro import fivepaisa, FeedType

broker = fivepaisa(
    headers={"access_token": "...", "client_code": "5P12345"},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `headers` | Yes | Dict with `access_token` and `client_code` keys — both are baked into the WebSocket URL. |
| `fno_tokens` | Optional | Output of `FivePaisa.load_fno_tokens()` — enables `subscribe_fno_token`. |

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
| `on_ltp` | `None` | LTP packets — `exchange`, `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | `None` | Quote packets — adds `avgprice`, `volume`. |
| `on_depth` | `None` | Market-depth frames — 5-level bid/ask plus `ltp`, `pc`, `volume`. |
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
| `subscribe(instrument, exchange, feedtype)` | `instrument`: int/str token (or list); `exchange`: numeric segment (`1`=NSE, `2`=NFO, `3`=BSE, `4`=BFO, `5`=MCX, `7`=NCO, `13`=CDS); `feedtype`: `FeedType.*` | Builds the OpenFeed `Method`/`Operation`/`ClientCode`/`MarketFeedData` payload and sends it. |
| `subscribe_token(token_dict, feedtype=…)` | `token_dict` from `FivePaisa.load_*_tokens()` | Maps `Exchange` to its numeric code via `sock_exchange` and delegates to `subscribe(...)`. |
| `subscribe_fno_token(root, option, strike_price, expiry=…, feedtype=…)` | Standard F&O dimensions | Looks the contract up in `fno_tokens` and subscribes. |

## Unsubscribing

```python
broker.unsubscribe(26000, exchange=1, feedtype=FeedType.LTP)
broker.unsubscribe_token(equity_token_dict, FeedType.LTP)
broker.unsubscribe_fno_token(root="NIFTY", option="CE", strike_price="24500")
```

## Tick payloads

| Callback | Frame source | Fields delivered |
|----------|--------------|------------------|
| `on_ltp` | OpenFeed LTP packet | `exchange`, `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | OpenFeed quote packet | Adds `avgprice`, `volume`. |
| `on_depth` | MarketDepthService | 5-level bid/ask price/qty pairs plus `ltp`, `pc`, `volume`. |

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
