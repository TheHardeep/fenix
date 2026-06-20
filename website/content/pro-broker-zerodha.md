# Zerodha — Live Feed

Zerodha (Kite Connect) live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.zerodha` |
| **`id`** | `zerodha` |
| **Module** | `fenixpro/zerodha.py` |
| **Transport** | `websocket-client` · binary frames |
| **WebSocket endpoint** | `wss://ws.kite.trade?api_key=…&access_token=…` |
| **Auth headers** | `api_key`, `access_token` |
| **Feed types** | `LTP`, `LTP_DEPTH`, `DEPTH` |
| **Ping** | `ping_interval=2.5s` |

The Zerodha adapter opens a raw WebSocket to Kite Connect's tick endpoint, decodes Kite's
length-prefixed binary frames in-process, and dispatches normalized
[TickData](#/pro-contracts) dictionaries through your callbacks.

## Construction

Pass the headers dict produced by Fenix's `Zerodha.authenticate()` (or any equivalent dict that
nests `api_key` and `access_token` under `headers`). Optionally pass `fno_tokens` so the
`subscribe_fno_token(...)` shortcut can resolve `(root, option, strike)` into the right
instrument token.

```python
from fenixpro import zerodha, FeedType

broker = zerodha(
    headers={"headers": {"api_key": "your-kite-api-key", "access_token": "..."}},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `headers` | Yes | Dict shaped as `{"headers": {"api_key": "...", "access_token": "..."}}`. |
| `fno_tokens` | Optional | Output of `Zerodha.load_fno_tokens()` — enables `subscribe_fno_token`. |

## Starting the feed

Register only the callbacks you care about. Every slot is optional.

```python
broker.start_websocket(
    on_ltp=lambda tick: print(tick["token"], tick["ltp"]),
    on_open=lambda: print("connected"),
    on_close=lambda code, msg: print("closed", code, msg),
)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `on_ltp` | `None` | Fires on 8-byte LTP packets — payload includes `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | `None` | Fires on 28-byte quote packets — adds `open`/`high`/`low`/`close`. |
| `on_depth` | `None` | Fires on 184-byte full packets — adds 5-level bid/ask ladders. |
| `on_order` | `None` | Reserved for order updates. |
| `on_open` | `None` | Fires after the socket handshake completes. |
| `on_close` | `None` | Receives `(close_status_code, close_msg)`. |
| `on_error` | `None` | Receives the transport/parse error. |
| `run_thread` | `True` | When `True`, the read loop runs on a daemon thread so your code stays synchronous. |

## Subscribing

Three subscription entry points cover every common shape — pick the one that matches the data
you already have.

```python
broker.subscribe("256265", FeedType.LTP)                     # raw instrument_token
broker.subscribe_token(equity_token_dict, FeedType.LTP)      # token record from load_*_tokens
broker.subscribe_fno_token(                                  # F&O shortcut
    root="NIFTY", option="CE", strike_price="24500",
    feedtype=FeedType.LTP_DEPTH,
)
```

| Method | Parameters | Purpose |
|--------|------------|---------|
| `subscribe(instrument, feedtype)` | `instrument`: token (int/str) or list of tokens; `feedtype`: `FeedType.*` | Direct subscribe — sends Kite's `{"a":"mode","v":["ltp"\|"quote"\|"full", [tokens]]}` frame. |
| `subscribe_token(token_dict, exchange=…, feedtype=…)` | `token_dict` from `Zerodha.load_*_tokens()` | Reads `Token` from the dict and calls `subscribe(...)`. |
| `subscribe_fno_token(root, option, strike_price, expiry=…, feedtype=…)` | Standard F&O dimensions | Looks the contract up in `fno_tokens` and subscribes. |

The mode string is derived from the feed type: `FeedType.LTP → "ltp"`,
`FeedType.LTP_DEPTH → "quote"`, `FeedType.DEPTH → "full"`.

## Unsubscribing

Each subscribe call has a matching unsubscribe.

```python
broker.unsubscribe("256265", FeedType.LTP)
broker.unsubscribe_token(equity_token_dict, FeedType.LTP)
broker.unsubscribe_fno_token(root="NIFTY", option="CE", strike_price="24500")
```

## Tick payloads

Packet length determines which parser runs, so each callback sees a predictable shape:

| Callback | Packet size | Fields delivered |
|----------|-------------|------------------|
| `on_ltp` | 8 bytes | `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | 28 bytes | `token`, `ltp`, `open`, `high`, `low`, `close`, `feedtime`, raw `info`. |
| `on_depth` | 184 bytes | `token`, `ltp`, `open`, `high`, `low`, `close`, `bidprice_lst`, `bidqty_lst`, `askprice_lst`, `askqty_lst`, `feedtime`. |

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
