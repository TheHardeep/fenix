# Upstox — Live Feed

Upstox v2 live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.upstox` |
| **`id`** | `upstox` |
| **Module** | `fenixpro/upstox.py` |
| **Transport** | `websockets` (asyncio) + `protobuf` |
| **WebSocket endpoint** | Authorized redirect from `GET https://api.upstox.com/v2/feed/market-data-feed/authorize` |
| **Auth headers** | Upstox v2 bearer headers |
| **Feed types** | `LTP`, `DEPTH` |

The Upstox adapter is the most specialized in Fenix-Pro: it asks the v2 REST API for an
authorized WebSocket redirect URL, opens an **async** connection with `websockets.connect(...)`,
and decodes Upstox's **protobuf** market-data frames (`upstox_feed_pb2`) into normalized
[TickData](#/pro-contracts) dictionaries. The asyncio loop runs on a worker thread so the
public API stays synchronous.

## Construction

Pass the headers dict produced by Fenix's `Upstox.authenticate()` — the bearer-equipped
`headers["headers"]` is sent to the `market-data-feed/authorize` endpoint to mint the WebSocket
URL.

```python
from fenixpro import upstox, FeedType

broker = upstox(
    headers={"headers": {"Authorization": "Bearer ...", "Accept": "application/json"}},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `headers` | Yes | Authenticated headers dict. The constructor calls `endpoint_generator()` to fetch the authorized redirect URL. |
| `fno_tokens` | Optional | Output of `Upstox.load_fno_tokens()` — enables `subscribe_fno_token`. |

## Starting the feed

```python
broker.start_websocket(
    on_ltp=on_ltp,
    on_depth=on_depth,
    on_open=lambda broker: print("connected"),
)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `on_ltp` | `None` | LTPC frames — `exchange`, `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | `None` | Reserved for top-of-book quotes. |
| `on_depth` | `None` | Full-feed frames — `bidprice_lst`, `bidqty_lst`, `askprice_lst`, `askqty_lst`, plus `ltp`. |
| `on_order` | `None` | Reserved for order updates. |
| `on_open` | `None` | Fires after `websockets.connect(...)` succeeds (receives the adapter instance). |
| `on_close` | `None` | Fires when `ConnectionClosed` is observed. |
| `on_error` | `None` | Receives the transport/parse error. |
| `run_thread` | `True` | When `True`, the asyncio loop runs on a worker thread; when `False`, the call blocks via `asyncio.run(...)`. |

## Subscribing

Upstox subscribes use Upstox's `instrumentKey` strings (e.g. `"NSE_EQ|INE002A01018"`).

```python
broker.subscribe("NSE_INDEX|Nifty 50", FeedType.LTP)
broker.subscribe_token(equity_token_dict, FeedType.LTP)
broker.subscribe_fno_token(
    root="NIFTY", option="CE", strike_price="24500",
    feedtype=FeedType.LTP,
)
```

| Method | Parameters | Purpose |
|--------|------------|---------|
| `subscribe(instrument, feedtype)` | `instrument`: Upstox instrument key (or list); `feedtype`: `FeedType.*` | Sends `{"guid":"…","method":"sub","data":{"mode":"ltpc"\|"full","instrumentKeys":[…]}}`. |
| `subscribe_token(token_dict, feedtype=…)` | `token_dict` from `Upstox.load_*_tokens()` containing `Token` (the instrument key) | Reads the key from the dict and calls `subscribe(...)`. |
| `subscribe_fno_token(root, option, strike_price, expiry=…, feedtype=…)` | Standard F&O dimensions | Looks the contract up in `fno_tokens` and subscribes. |

The mode string maps from the feed type: `FeedType.LTP → "ltpc"`, `FeedType.DEPTH → "full"`.

## Unsubscribing

```python
broker.unsubscribe_token(equity_token_dict, FeedType.LTP)
broker.unsubscribe_fno_token(root="NIFTY", option="CE", strike_price="24500")
```

## Tick payloads

Each incoming WebSocket message is a protobuf `FeedResponse`. The adapter walks the `feeds`
map and dispatches by the embedded payload shape:

| Payload shape | Callback | Fields delivered |
|---------------|----------|------------------|
| `ltpc` | `on_ltp` | `exchange`, `token`, `ltp`, `feedtime`. |
| `ff.marketFF` / `ff.indexFF` | `on_depth` | Adds `bidprice_lst`, `bidqty_lst`, `askprice_lst`, `askqty_lst`. |

The `exchange` value is derived from the prefix of the instrument key (`NSE_INDEX`, `NSE_EQ`,
`NSE_FO`, `BSE_EQ`, `BSE_FO`, `BCD_FO`, `MCX_FO`, `MCX_INDEX`, `NCD_FO`).

See [Data Contracts](#/pro-contracts) for the full key reference.

## Closing the feed

Closing is handled by the async `__on_close_callback` when the WebSocket reports
`ConnectionClosed`. To stop cleanly, close the underlying `websockets` client (or terminate the
worker thread) from your own code.

---

_See [Callback Interface](#/pro-callbacks), [Subscriptions](#/pro-subscriptions),
[Transport Families](#/pro-transports), and [Data Contracts](#/pro-contracts) for the shared
feed model used by every Fenix-Pro adapter._
