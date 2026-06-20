# Callback Interface

Fenix-Pro is callback-oriented. You hand `start_websocket(...)` the functions to call when data
arrives, and the adapter invokes them with **normalized dictionaries** as feed events stream in.

## `start_websocket(...)`

The shared entry point. Pass only the callbacks you need — all slots are optional:

```python
broker.start_websocket(
    on_ltp=on_ltp,
    on_ltp_depth=on_ltp_depth,
    on_depth=on_depth,
    on_order=on_order,
    on_open=on_open,
    on_close=on_close,
    on_error=on_error,
)
```

## Callback slots

| Callback | Fires on | Payload |
|----------|----------|---------|
| `on_ltp` | Each last-traded-price tick. | A [TickData](#/pro-contracts) dict. |
| `on_ltp_depth` | LTP-with-depth ticks. | A TickData dict including top-of-book. |
| `on_depth` | Full market-depth updates. | A TickData dict with bid/ask ladders. |
| `on_order` | Order-update events. | An [Order](#/pro-contracts) dict. |
| `on_open` | The socket connecting. | Connection event. |
| `on_close` | The socket closing. | Close event. |
| `on_error` | A transport or parse error. | The error/exception. |

```python
def on_ltp(tick):
    print(tick["token"], tick["ltp"], tick["volume"])

def on_depth(tick):
    print("bids", tick["bidprice_lst"], "asks", tick["askprice_lst"])

def on_order(order):
    print(order["id"], order["status"], order["filled"], "/", order["quantity"])

def on_error(err):
    log.warning("feed error: %s", err)
```

## Lifecycle

<div class="fx">
  <div class="fx-row">
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">1 · Construct</div>
        <div class="fx-node-title">construct(headers / params, fno_tokens?)</div>
      </div>
    </div>
  </div>
  <div class="fx-pipe"><span class="fx-pipe-line"></span></div>
  <div class="fx-row">
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">2 · Open</div>
        <div class="fx-node-title">start_websocket(callbacks) &nbsp;→&nbsp; on_open</div>
      </div>
    </div>
  </div>
  <div class="fx-pipe"><span class="fx-pipe-line"></span></div>
  <div class="fx-row">
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">3 · Subscribe</div>
        <div class="fx-node-title">subscribe · subscribe_token · subscribe_fno_token</div>
      </div>
    </div>
  </div>
  <div class="fx-pipe"><span class="fx-pipe-label">live frames decoded &amp; normalized</span><span class="fx-pipe-line"></span></div>
  <div class="fx-row">
    <div class="fx-node accent">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">4 · Stream &nbsp;·&nbsp; repeats</div>
        <div class="fx-node-title">on_ltp · on_ltp_depth · on_depth · on_order</div>
      </div>
    </div>
  </div>
  <div class="fx-pipe"><span class="fx-pipe-line"></span></div>
  <div class="fx-row">
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">5 · Close</div>
        <div class="fx-node-title">close_websocket() &nbsp;→&nbsp; on_close</div>
      </div>
    </div>
  </div>
</div>

> [!TIP] Read the contract, code to the intent
> Every callback delivers a normalized dictionary that follows the shared
> [TickData / Order contracts](#/pro-contracts). The contract is the source of truth — read keys
> through `.get(...)` and your code works identically across every adapter in the suite.

## Isolating callback failures

Adapter parsers are permissive by design — a bad frame is caught so the feed loop keeps running
without interruption. The shared `safe()` wrapper below lets you give *your own* callbacks the
same property: one bad payload simply logs and the next tick arrives as usual.

```python
def safe(fn):
    def wrapped(payload):
        try:
            fn(payload)
        except Exception:
            log.exception("callback failed")
    return wrapped

broker.start_websocket(on_ltp=safe(on_ltp), on_error=on_error)
```
