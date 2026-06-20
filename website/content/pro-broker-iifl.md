# IIFL — Live Feed

IIFL Markets (XTS API · TT Blaze) live market-data adapter for the Fenix-Pro feed interface.

| | |
|---|---|
| **Class** | `fenixpro.iifl` |
| **`id`** | `iifl` |
| **Module** | `fenixpro/iifl.py` |
| **Transport** | `socketio` · JSON events |
| **WebSocket endpoint** | `https://ttblaze.iifl.com/?token=…&userID=…&publishFormat=JSON&broadcastMode=Full` |
| **Auth params** | `api_key`, `api_secret` |
| **Auth headers** | `Content-Type`, `authorization` |
| **Feed types** | `LTP`, `DEPTH` |

The IIFL adapter is the canonical **XTS / Socket.IO** implementation in Fenix-Pro — five other
adapters (Kunjee, Kotak, Motilal Oswal, Symphony, VPC) subclass it and override only the base
URL. It bootstraps an access token over REST, then connects a Socket.IO client and listens for
`1502-json-full`, `1512-json-full`, and `1505-json-partial` events.

## Construction

Provide either the REST credentials (`params`) so the adapter can mint a fresh access token,
or pass a pre-built `headers` dict if you already have one.

```python
from fenixpro import iifl, FeedType

broker = iifl(
    params={"api_key": "...", "api_secret": "..."},
    fno_tokens=fno_tokens,
)
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | One of `params`/`headers` is required | Dict with `api_key` and `api_secret` — the adapter calls `/apimarketdata/auth/login` and builds the headers. |
| `headers` | Optional | Pre-built headers dict, e.g. `{"headers": {"authorization": "..."}, "user_id": "..."}`. |
| `fno_tokens` | Optional | Output of `IIFL.load_fno_tokens()` — enables `subscribe_fno_token`. |

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
| `on_ltp` | `None` | LTP / partial-quote events — `exchange`, `token`, `ltp`, `feedtime`. |
| `on_ltp_depth` | `None` | Reserved for top-of-book quotes. |
| `on_depth` | `None` | Full-depth events — `bidprice_lst`, `bidqty_lst`, `askprice_lst`, `askqty_lst`. |
| `on_order` | `None` | Reserved for order updates. |
| `on_open` | `None` | Fires when Socket.IO emits `connect`. |
| `on_close` | `None` | Fires when Socket.IO emits `disconnect`. |
| `on_error` | `None` | Fires on Socket.IO `error`. |
| `run_thread` | `True` | When `False`, the call blocks via `socketio.Client.wait()`. |

## Subscribing

Subscribes are XTS REST `POST /apimarketdata/instruments/subscription` calls; the broker pushes
matching events back over Socket.IO.

```python
broker.subscribe(26000, exchange=1, feedtype=FeedType.LTP)         # raw token + XTS segment
broker.subscribe_token(equity_token_dict, FeedType.LTP)            # token record from load_*_tokens
broker.subscribe_fno_token(
    root="NIFTY", option="CE", strike_price="24500",
    feedtype=FeedType.LTP,
)
```

| Method | Parameters | Purpose |
|--------|------------|---------|
| `subscribe(instrument, exchange, feedtype)` | `instrument`: int/str token (or list); `exchange`: numeric XTS segment (`1`=NSECM, `11`=BSECM, `2`=NSEFO, `12`=BSEFO, `3`=NSECD, `51`=MCXFO); `feedtype`: `FeedType.*` | Sends XTS `{"instruments":[…], "xtsMessageCode": 1512\|1502}`. |
| `subscribe_token(token_dict, feedtype=…)` | `token_dict` with `Exchange` and `Token` | Maps `Exchange` to its numeric XTS segment via `sock_exchange` and delegates to `subscribe(...)`. |
| `subscribe_fno_token(root, option, strike_price, expiry=…, feedtype=…)` | Standard F&O dimensions | Looks the contract up in `fno_tokens` and subscribes. |

## Unsubscribing

```python
broker.unsubscribe(26000, exchange=1, feedtype=FeedType.LTP)
broker.unsubscribe_token(equity_token_dict, FeedType.LTP)
broker.unsubscribe_fno_token(root="NIFTY", option="CE", strike_price="24500")
```

Unsubscribe is a `PUT` against the same XTS subscription endpoint.

## Tick payloads

| Callback | Socket.IO event | Fields delivered |
|----------|-----------------|------------------|
| `on_ltp` | `1512-json-full`, `1505-json-partial` | `exchange`, `token`, `ltp`, `feedtime`. |
| `on_depth` | `1502-json-full` | 5-level `bidprice_lst`, `bidqty_lst`, `askprice_lst`, `askqty_lst`, plus `ltp`, `pc`, `volume`. |

See [Data Contracts](#/pro-contracts) for the full key reference.

## Closing the feed

The Socket.IO client manages its own lifecycle — call `disconnect()` on the underlying client
to stop, or simply let the process exit.

---

_See [Callback Interface](#/pro-callbacks), [Subscriptions](#/pro-subscriptions), and
[Data Contracts](#/pro-contracts) for the shared feed model used by every Fenix-Pro adapter._
