# Master Trust — Live Feed

Master Trust (MasterSwift) live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.mastertrust` |
| **`id`** | `mastertrust` |
| **Module** | `fenixpro/mastertrust.py` |
| **Transport** | `websocket-client` · binary frames |
| **WebSocket endpoint** | `wss://masterswift-beta.mastertrust.co.in/ws/v1/feeds` |
| **Feed types** | `LTP`, `LTP_DEPTH`, `DEPTH` |
| **Ping** | `ping_interval=10s`, payload `{"a":"h","v":[],"m":""}` |

The Master Trust adapter opens a binary WebSocket against MasterSwift's `/ws/v1/feeds`
endpoint, parses fixed-size binary frames with per-exchange price divisors, and dispatches
normalized [TickData](#/pro-contracts) dictionaries through your callbacks.

## Construction

Pass the headers dict produced by Fenix's `MasterTrust.authenticate()`. Optionally pass
`fno_tokens` so `subscribe_fno_token(...)` can resolve `(root, option, strike)`.

```python
from fenixpro import mastertrust, FeedType

broker = mastertrust(
    headers={"headers": {"Authorization": "Bearer ..."}},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `headers` | Yes | Authenticated headers dict produced by Fenix's `MasterTrust.authenticate()`. |
| `fno_tokens` | Optional | Output of `MasterTrust.load_fno_tokens()` — enables `subscribe_fno_token`. |

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
| `on_ltp` | `None` | Fires on 42/46-byte compact frames — `exchange`, `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | `None` | Fires on 102-byte market-data frames — adds `avgprice`, `volume`, top-of-book. |
| `on_depth` | `None` | Fires on 166-byte snap-quote frames — 5-level bid/ask plus `avgprice`, `volume`. |
| `on_order` | `None` | Reserved for order updates. |
| `on_open` | `None` | Fires after the socket opens. |
| `on_close` | `None` | Receives `(close_status_code, close_msg)`. |
| `on_error` | `None` | Receives the transport/parse error. |
| `run_thread` | `True` | Run the read loop on a daemon thread. |

## Subscribing

`sub_unsub` is the single primitive — both subscribe and unsubscribe go through it with a
different `sub` value. Wrappers exist for the standard token shapes.

```python
broker.subscribe_token(equity_token_dict, FeedType.LTP)
broker.subscribe_fno_token(
    root="NIFTY", option="CE", strike_price="24500",
    feedtype=FeedType.LTP_DEPTH,
)
```

| Method | Parameters | Purpose |
|--------|------------|---------|
| `sub_unsub(token, sub, exchange=…, feedtype=…)` | `token`: int; `sub`: `"subscribe"`/`"unsubscribe"`; `exchange`: `ExchangeCode.*`; `feedtype`: `FeedType.*` | Sends MasterSwift `{"a":sub, "v":[[exchange, token]], "m":"compact_marketdata"\|"marketdata"\|"full_snapquote"}`. |
| `subscribe_token(token_dict, feedtype=…)` | `token_dict` from `MasterTrust.load_*_tokens()` containing `Exchange` and `Token` | Maps `Exchange` to its numeric code via `sock_exchange` and calls `sub_unsub("subscribe", …)`. |
| `subscribe_fno_token(root, option, strike_price, expiry=…, feedtype=…)` | Standard F&O dimensions | Looks the contract up in `fno_tokens` and subscribes. |

The mode string comes from the feed type: `FeedType.LTP → "compact_marketdata"`,
`FeedType.LTP_DEPTH → "marketdata"`, `FeedType.DEPTH → "full_snapquote"`.

## Unsubscribing

```python
broker.unsubscribe_token(equity_token_dict, FeedType.LTP)
broker.unsubscribe_fno_token(root="NIFTY", option="CE", strike_price="24500")
```

## Tick payloads

Frame length determines which parser runs:

| Callback | Packet size | Fields delivered |
|----------|-------------|------------------|
| `on_ltp` | 42 / 46 bytes | `exchange`, `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | 102 bytes | Adds `avgprice`, `bidqty`, `bidprice`, `askqty`, `askprice`, `volume`. |
| `on_depth` | 166 bytes | 5-level `bidprice_lst`, `bidqty_lst`, `askprice_lst`, `askqty_lst`, plus `ltp`, `avgprice`, `volume`. |

Prices are divided by per-segment divisors (NSE/NFO/BSE/BFO/MCX use `100`, CDS uses `10000000`).

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
