# Fenix-Pro Quickstart

Connect to a broker's live feed, subscribe to an instrument, and receive normalized ticks. The
shape of the call is the same for every adapter — only the credentials differ.

## 1 · Construct the adapter

Adapters take broker credentials as either ready-made `headers` or `params`. Adapters that can
self-bootstrap (the IIFL family, Kotak) accept `params` and build their own session.

```python
from fenixpro import zerodha, FeedType

broker = zerodha(headers={
    "headers": {
        "api_key": "<kite-api-key>",
        "access_token": "<kite-access-token>",
    }
})
```

> [!TIP] Reuse your Fenix session
> The `access_token` / headers a Fenix-Pro adapter needs are exactly what
> [`fenix` authentication](#/authentication) already produces. Authenticate once with Fenix,
> then hand the headers to the matching Fenix-Pro adapter.

## 2 · Register callbacks and open the socket

`start_websocket(...)` stores your callback functions and opens the transport on a background
thread. Provide only the callbacks you care about:

```python
def on_ltp(tick):
    print("tick:", tick["token"], tick["ltp"])

def on_error(error):
    print("error:", error)

broker.start_websocket(on_ltp=on_ltp, on_error=on_error)
```

See [Callback Interface](#/pro-callbacks) for every callback slot.

## 3 · Subscribe

Subscribe by raw broker token, by a token dict, or by F&O dimensions — see
[Subscriptions](#/pro-subscriptions):

```python
# Raw broker token + feed type
broker.subscribe("256265", FeedType.LTP)
```

Ticks now stream into `on_ltp`, normalized to the [TickData contract](#/pro-contracts):

```python
{
    "exchange": "NSE",
    "token": 256265,
    "ltp": 221.35,
    "volume": 1500,
    "feedtime": "...",
}
```

## 4 · Stop

Adapters that implement it expose `close_websocket()`:

```python
broker.close_websocket()
```

## Full example

```python
from fenixpro import zerodha, FeedType

broker = zerodha(headers={"headers": {"api_key": "...", "access_token": "..."}})

broker.start_websocket(
    on_ltp=lambda tick: print("ltp", tick["token"], tick["ltp"]),
    on_error=lambda err: print("err", err),
)
broker.subscribe("256265", FeedType.LTP)
```

## Self-bootstrapping adapter (IIFL family)

`iifl` and its derivatives can create their own session headers from API credentials, and
support subscribing by token dict:

```python
from fenixpro import iifl, FeedType

broker = iifl(params={"api_key": "<marketdata-key>", "api_secret": "<marketdata-secret>"})
broker.start_websocket(on_ltp=lambda tick: print(tick))
broker.subscribe_token({"Exchange": "NSEFO", "Token": 26000}, FeedType.LTP)
```

## Next steps

<div class="card-grid">
  <a class="doc-card" href="#/pro-callbacks"><span class="dc-title">Callback Interface</span><span class="dc-desc">All callback slots and their payloads.</span></a>
  <a class="doc-card" href="#/pro-subscriptions"><span class="dc-title">Subscriptions</span><span class="dc-desc">subscribe vs token vs F&O token.</span></a>
  <a class="doc-card" href="#/pro-contracts"><span class="dc-title">Data Contracts</span><span class="dc-desc">The full TickData and Order keys.</span></a>
</div>
