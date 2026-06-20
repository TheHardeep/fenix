# Fyers — Live Feed

Fyers HSM v1.5 live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.fyers` |
| **`id`** | `fyers` |
| **Module** | `fenixpro/fyers.py` |
| **Transport** | `websocket-client` · HSM length-coded binary frames |
| **WebSocket endpoint** | `wss://socket.fyers.in/hsm/v1-5/prod` |
| **Auth params** | `Authorization` JWT (HSM key extracted in-process) |
| **Feed types** | `LTP`, `LTP_DEPTH`, `DEPTH` |
| **Ping** | `ping_interval=10s`, payload `ping` |

The Fyers adapter decodes the JWT `Authorization` token to recover the HSM session key,
opens the HSM v1.5 binary WebSocket, sends the access-token and full-mode handshake frames,
then dispatches Fyers's snapshot / lite / full data frames into your callbacks.

## Construction

Pass the headers dict produced by Fenix's `Fyers.authenticate()` — the JWT must live at
`headers["headers"]["Authorization"]` so the adapter can extract the HSM key from its
base64-encoded payload.

```python
from fenixpro import fyers, FeedType

broker = fyers(
    headers={"headers": {"Authorization": "eyJhbGciOi..."}},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `headers` | Yes | Dict shaped as `{"headers": {"Authorization": "<JWT>"}}`. |
| `fno_tokens` | Optional | Output of `Fyers.load_fno_tokens()` — enables `subscribe_fno_token`. |

## Starting the feed

```python
broker.start_websocket(
    on_ltp=on_ltp,
    on_ltp_depth=on_ltp_depth,
    on_open=lambda: print("connected"),
)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `on_ltp` | `None` | LTP/index frames — `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | `None` | Adds `avgprice`, `bidqty`, `bidprice`, `askqty`, `askprice`, `volume`. |
| `on_depth` | `None` | Full snapshot frames. |
| `on_order` | `None` | Reserved for order updates. |
| `on_open` | `None` | Fires after the HSM access-token + full-mode handshake completes. |
| `on_close` | `None` | Receives `(close_status_code, close_msg)`. |
| `on_error` | `None` | Receives the transport/parse error. |
| `run_thread` | `True` | Run the read loop on a daemon thread. |

## Subscribing

Fyers requires a token record (the adapter formats the `feed|exchange|token` topic string from
the record's `Token`, `Exchange`, `Segment`, and `Symbol` fields, with `INDEX` symbols routed
through the built-in `index_loader`).

```python
broker.subscribe_token(equity_token_dict, FeedType.LTP)
broker.subscribe_fno_token(
    root="NIFTY", option="CE", strike_price="24500",
    feedtype=FeedType.LTP_DEPTH,
)
```

| Method | Parameters | Purpose |
|--------|------------|---------|
| `subscribe_token(token_dict, feedtype=…)` | `token_dict` from `Fyers.load_*_tokens()` containing `Token`, `Exchange`, `Segment`, `Symbol` | Builds the HSM topic and sends a binary subscribe frame. |
| `subscribe_fno_token(root, option, strike_price, expiry=…, feedtype=…)` | Standard F&O dimensions | Looks the contract up in `fno_tokens` and subscribes. |
| `sub_unsub(symbols, request_type)` | Pre-built topic strings | Lower-level entry point used by both `subscribe_*` methods. |

Feed type maps to the topic prefix: `FeedType.LTP → "sf"` for instruments / `"if"` for indices,
`FeedType.DEPTH → "dp"`.

## Unsubscribing

```python
broker.unsubscribe_token(equity_token_dict, FeedType.LTP)
broker.unsubscribe_fno_token(root="NIFTY", option="CE", strike_price="24500")
```

## Tick payloads

Fyers's binary feed splits each frame into snapshot + lite/full data sections. The adapter
caches each topic's divisor on first sight and applies it consistently to following frames.

| Callback | Data section | Fields delivered |
|----------|--------------|------------------|
| `on_ltp` | Lite (`L`) or full (`U`) | `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | Full (`U`) | Adds `avgprice`, `bidqty`, `bidprice`, `askqty`, `askprice`, `volume`. |
| `on_depth` | Full (`U`) | 5-level depth with quantity / price / orders per level. |

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
