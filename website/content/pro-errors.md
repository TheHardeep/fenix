# Error Model

Fenix-Pro centralizes HTTP/bootstrap error handling in `Base.fetch()` and exposes a small set of
exception types in `fenixpro.base.errors`. Feed-loop parsing is deliberately more permissive so
a single bad frame never kills a live stream.

```python
from fenixpro import errors
```

## Exception types

| Exception | Raised when |
|-----------|-------------|
| `BrokerError` | Base class; HTTP, SSL, redirect, or uncategorized request failures during bootstrap. |
| `NetworkError` | A network-level failure reaching the broker. |
| `RequestTimeout` | A bootstrap request timed out. |
| `ResponseError` | A response wasn't in the expected format. |
| `TokenDownloadError` | An instrument/token download failed. |
| `InputError` | Bad parameters supplied to an adapter. |
| `MethodUndefinedError` | Signals a method that an adapter intentionally leaves to its parent or a future build. |

## Bootstrap errors are normalized

`Base.fetch()` is the single shared HTTP abstraction — used by adapters that make REST calls
before opening a feed (login, session/bearer token, authorized WebSocket URL). It converts
low-level failures into the types above:

- timeouts → `RequestTimeout`
- network failures → `NetworkError`
- HTTP / SSL / redirect / uncategorized → `BrokerError`

```python
from fenixpro import iifl, errors

try:
    broker = iifl(params={"api_key": "...", "api_secret": "..."})
    broker.start_websocket(on_ltp=on_ltp)
except errors.NetworkError:
    reconnect_later()
except errors.BrokerError as e:
    log.error("bootstrap failed: %s", e)
```

## Feed-loop errors are permissive

Inside the live loop, parser paths are shielded with `try/except` so a single malformed frame
never kills the stream — the loop keeps running and the next tick arrives as usual. Surface
anything you want to observe through the `on_error` callback you register with
`start_websocket(...)`.

```python
def safe(fn):
    def wrapped(payload):
        try:
            fn(payload)
        except Exception:
            log.exception("callback error")
    return wrapped

broker.start_websocket(on_ltp=safe(on_ltp), on_error=lambda e: log.info("feed: %s", e))
```

See [Callback Interface → Isolating callback failures](#/pro-callbacks) for the recommended
`safe()` wrapper pattern.
