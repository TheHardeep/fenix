# Finvasia — Live Feed

Finvasia (Shoonya NorenWSTP) live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.finvasia` |
| **`id`** | `finvasia` |
| **Module** | `fenixpro/finvasia.py` |
| **Transport** | `websocket-client` · NorenWS JSON frames |
| **WebSocket endpoint** | `wss://api.shoonya.com/NorenWSTP/` |
| **Auth headers** | `uid`, `access_token` (NorenWS session) |
| **Feed types** | `LTP`, `LTP_DEPTH`, `DEPTH`, `ORDER` |
| **Ping** | `ping_interval=3s`, payload `{"t":"h"}` |

The Finvasia adapter sends a NorenWS `{"t":"c"}` connect handshake with `uid`, `actid`, and
`susertoken` on open, then dispatches JSON ticks and live order updates into your callbacks.

## Construction

Pass a headers dict that exposes `uid` and `access_token` at the top level (the shape returned
by Fenix's `Finvasia.authenticate()`). Optionally pass `fno_tokens` so the F&O subscribe
shortcut can resolve `(root, option, strike)`.

```python
from fenixpro import finvasia, FeedType

broker = finvasia(
    headers={"uid": "AB1234", "access_token": "..."},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `headers` | Yes | Dict with `uid` and `access_token` keys (used as Shoonya `uid`, `actid`, and `susertoken`). |
| `fno_tokens` | Optional | Output of `Finvasia.load_fno_tokens()` — enables `subscribe_nfo_token`. |

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
| `on_depth` | `None` | 5-level market depth. |
| `on_order` | `None` | Live order updates as a normalized [Order](#/pro-contracts) dict. |
| `on_open` | `None` | Fires after the NorenWS auth handshake succeeds. |
| `on_close` | `None` | Receives `(close_status_code, close_msg)`. |
| `on_error` | `None` | Receives the transport error or a NorenWS `ck` error frame. |
| `run_thread` | `True` | Run the read loop on a daemon thread. |

## Subscribing

```python
broker.subscribe("NSE|26000", FeedType.LTP)                # NorenWS "EXCHANGE|TOKEN" string
broker.subscribe_token(equity_token_dict, FeedType.LTP)    # token record from load_*_tokens
broker.subscribe_nfo_token(
    root="NIFTY", option="CE", strike_price="24500",
    feedtype=FeedType.LTP_DEPTH,
)
```

| Method | Parameters | Purpose |
|--------|------------|---------|
| `subscribe(instrument, feedtype)` | `instrument`: `"EXCHANGE\|TOKEN"` string (or list, joined with `#`); `feedtype`: `FeedType.*` | Sends NorenWS `{"t":"t"\|"d"\|"o", "k":"…"}`. `FeedType.ORDER` subscribes to the order feed for `actid = uid`. |
| `subscribe_token(token_dict, feedtype=…)` | `token_dict` containing `Exchange` and `Token` | Builds the `EXCHANGE\|TOKEN` string and calls `subscribe(...)`. |
| `subscribe_nfo_token(root, option, strike_price, expiry=…, feedtype=…)` | Standard F&O dimensions | Looks the contract up in `fno_tokens` and subscribes. |

## Unsubscribing

```python
broker.unsubscribe("NSE|26000", FeedType.LTP)
broker.unsubscribe_token(equity_token_dict, FeedType.LTP)
broker.unsubscribe_nfo_token(root="NIFTY", option="CE", strike_price="24500")
```

## Tick payloads

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
