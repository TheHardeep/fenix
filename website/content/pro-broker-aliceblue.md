# AliceBlue — Live Feed

AliceBlue (NorenWS) live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.aliceblue` |
| **`id`** | `aliceblue` |
| **Module** | `fenixpro/aliceblue.py` |
| **Transport** | `websocket-client` · NorenWS JSON frames |
| **WebSocket endpoint** | `wss://ws1.aliceblueonline.com/NorenWS/` |
| **Auth headers** | `ID`, `susertoken` (NorenWS session) |
| **Feed types** | `LTP`, `LTP_DEPTH`, `DEPTH`, `ORDER` |
| **Ping** | `ping_interval=3s`, payload `{"t":"h"}` |

The AliceBlue adapter logs in to the NorenWS socket session via the
`/api/ws/createSocketSess` REST endpoint, opens the underlying WebSocket, and dispatches
normalized [TickData](#/pro-contracts) and [Order](#/pro-contracts) dictionaries through your
callbacks — including live order updates.

## Construction

Pass the headers dict produced by Fenix's `AliceBlue.authenticate()` (anything that nests `ID`
and `susertoken` under `headers`). The constructor runs `ws_login()` immediately, so the
socket session is ready by the time you call `start_websocket(...)`.

```python
from fenixpro import aliceblue, FeedType

broker = aliceblue(
    headers={"headers": {"ID": "AB123456", "susertoken": "..."}},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `headers` | Yes | Dict shaped as `{"headers": {"ID": "...", "susertoken": "..."}}`. |
| `fno_tokens` | Optional | Output of `AliceBlue.load_fno_tokens()` — enables `subscribe_fno_token`. |

## Starting the feed

```python
broker.start_websocket(
    on_ltp=on_ltp,
    on_depth=on_depth,
    on_order=on_order,
    on_open=lambda: print("connected"),
)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `on_ltp` | `None` | LTP/touchline updates — `exchange`, `token`, `ltp`, `pc`, `feedtime`. |
| `on_ltp_depth` | `None` | Top-of-book quote updates — adds `volume`, `bidqty`, `bidprice`, `askqty`, `askprice`. |
| `on_depth` | `None` | Full 5-level market depth. |
| `on_order` | `None` | Live order updates as a normalized [Order](#/pro-contracts) dict. |
| `on_open` | `None` | Fires after the NorenWS auth handshake (`{"t":"c"}` exchange) succeeds. |
| `on_close` | `None` | Receives `(close_status_code, close_msg)`. |
| `on_error` | `None` | Receives the transport/parse error or a NorenWS error frame. |
| `run_thread` | `True` | Run the read loop on a daemon thread. |

## Subscribing

```python
broker.subscribe("NSE|26000", FeedType.LTP)             # NorenWS "EXCHANGE|TOKEN" string
broker.subscribe_token(equity_token_dict, FeedType.LTP) # token record from load_*_tokens
broker.subscribe_fno_token(
    root="NIFTY", option="CE", strike_price="24500",
    feedtype=FeedType.LTP_DEPTH,
)
```

| Method | Parameters | Purpose |
|--------|------------|---------|
| `subscribe(instrument, feedtype)` | `instrument`: `"EXCHANGE\|TOKEN"` string (or list); `feedtype`: `FeedType.*` | Sends NorenWS `{"t":"t"\|"d"\|"o", "k":"…"}`. Pass `FeedType.ORDER` to subscribe to the order feed for `actid = ID`. |
| `subscribe_token(token_dict, feedtype=…)` | `token_dict` containing `Exchange` and `Token` | Builds the `EXCHANGE\|TOKEN` string and calls `subscribe(...)`. |
| `subscribe_fno_token(root, option, strike_price, expiry=…, feedtype=…)` | Standard F&O dimensions | Looks the contract up in `fno_tokens` and subscribes. |

Multiple instruments are joined with `#` (NorenWS's list separator) automatically when you
pass a list.

## Unsubscribing

```python
broker.unsubscribe("NSE|26000", FeedType.LTP)
broker.unsubscribe_token(equity_token_dict, FeedType.LTP)
broker.unsubscribe_fno_token(root="NIFTY", option="CE", strike_price="24500")
```

## Tick payloads

NorenWS sends JSON frames; the adapter dispatches by frame type (`t`) and parser:

| Callback | NorenWS frame | Fields delivered |
|----------|---------------|------------------|
| `on_ltp` | `tk` / `tf` | `exchange`, `token`, `ltp`, `pc`, `feedtime`. |
| `on_ltp_depth` | `tk` / `tf` | Adds `volume`, `bidqty`, `bidprice`, `askqty`, `askprice`. |
| `on_depth` | `dk` / `df` | 5-level `bidprice_lst`, `bidqty_lst`, `askprice_lst`, `askqty_lst`, plus `ltp`, `pc`, `volume`. |
| `on_order` | `om` | Normalized [Order](#/pro-contracts) with `id`, `status`, `filled`, `quantity`, `side`, `product`, etc. |

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
