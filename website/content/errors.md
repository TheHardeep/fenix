# Error Handling

Fenix raises a small, well-organized hierarchy of exceptions. Every error derives from
`BrokerError`, so a single `except BrokerError` catches anything the library can throw — while
the specific subclasses let you handle distinct failures precisely. All errors are importable
from `fenix.errors` (and the top-level `fenix` package).

## The exception hierarchy

<div class="fx-tree">
  <div class="fx-tree-core">
    <div class="fx-tree-row root">
      <div class="fx-tree-label">BrokerError</div>
      <div class="fx-tree-desc">base — catch this to catch everything</div>
    </div>
    <div class="fx-tree-row" data-depth="1">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="stub s1"></span>NetworkError</div>
      <div class="fx-tree-desc">transport-level failure</div>
    </div>
    <div class="fx-tree-row" data-depth="2">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="rail r2"></span><span class="stub s2"></span>RequestTimeoutError</div>
      <div class="fx-tree-desc">the request timed out</div>
    </div>
    <div class="fx-tree-row last" data-depth="2">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="rail r2"></span><span class="stub s2"></span>DDoSProtectionError</div>
      <div class="fx-tree-desc">tripped the broker's DDoS protection</div>
    </div>
    <div class="fx-tree-row last" data-depth="3">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="rail r3"></span><span class="stub s3"></span>RateLimitExceededError</div>
      <div class="fx-tree-desc"><span class="fx-tree-tag">HTTP 429</span> too many requests</div>
    </div>
    <div class="fx-tree-row" data-depth="1">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="stub s1"></span>AuthenticationError</div>
      <div class="fx-tree-desc"><span class="fx-tree-tag">HTTP 401</span> invalid / expired session</div>
    </div>
    <div class="fx-tree-row" data-depth="1">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="stub s1"></span>PermissionDeniedError</div>
      <div class="fx-tree-desc"><span class="fx-tree-tag">HTTP 403</span> not allowed</div>
    </div>
    <div class="fx-tree-row" data-depth="1">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="stub s1"></span>InsufficientFundsError</div>
      <div class="fx-tree-desc">not enough margin / funds</div>
    </div>
    <div class="fx-tree-row last" data-depth="2">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="rail r2"></span><span class="stub s2"></span>InsufficientHoldingsError</div>
      <div class="fx-tree-desc">not enough holdings to sell</div>
    </div>
    <div class="fx-tree-row" data-depth="1">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="stub s1"></span>InvalidOrderError</div>
      <div class="fx-tree-desc">order rejected as malformed</div>
    </div>
    <div class="fx-tree-row last" data-depth="2">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="rail r2"></span><span class="stub s2"></span>OrderNotFoundError</div>
      <div class="fx-tree-desc">the order id doesn't exist</div>
    </div>
    <div class="fx-tree-row" data-depth="1">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="stub s1"></span>InputError</div>
      <div class="fx-tree-desc"><span class="fx-tree-tag">HTTP 400 / 422</span> bad parameters from your side</div>
    </div>
    <div class="fx-tree-row" data-depth="1">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="stub s1"></span>ResponseError</div>
      <div class="fx-tree-desc">broker response wasn't in the expected format</div>
    </div>
    <div class="fx-tree-row last" data-depth="2">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="rail r2"></span><span class="stub s2"></span>TokenDownloadError</div>
      <div class="fx-tree-desc">instrument-master download failed</div>
    </div>
    <div class="fx-tree-row last" data-depth="1">
      <div class="fx-tree-label"><span class="rail r1"></span><span class="stub s1"></span>NotSupported</div>
      <div class="fx-tree-desc">the broker doesn't implement this operation</div>
    </div>
  </div>
</div>

| Exception | Raise condition |
|-----------|-----------------|
| `BrokerError` | Base class for everything Fenix raises. |
| `NetworkError` | Connection reset, SSL failure, DNS, or 5xx server error. |
| `RequestTimeoutError` | The request exceeded its timeout. |
| `RateLimitExceededError` | HTTP 429 — you exceeded the broker's rate limit. |
| `AuthenticationError` | Session invalid or expired (HTTP 401). |
| `PermissionDeniedError` | Action not permitted for the account (HTTP 403). |
| `InsufficientFundsError` | Not enough margin/funds for the order. |
| `InsufficientHoldingsError` | Selling more than you hold. |
| `InvalidOrderError` | Order malformed or rejected by the exchange. |
| `OrderNotFoundError` | The referenced order id does not exist. |
| `InputError` | Bad parameters (HTTP 400/422) — also raised by [map validation](#/maps). |
| `ResponseError` | The response could not be parsed as expected. |
| `TokenDownloadError` | The instrument master failed to download/parse. |
| `NotSupported` | The broker disabled this capability (see [`has`](#/orders)). |

## Rich error context

Every `BrokerError` carries structured attributes describing the failure, so you can inspect or
log it programmatically — not just read a string:

```python
from fenix import errors

try:
    broker.place_order(...)
except errors.BrokerError as e:
    print(e.broker)        # "Zerodha"
    print(e.status_code)   # 400
    print(e.error_code)    # "InputException"
    print(e.message)       # human-readable summary
    print(e.payload)       # decoded response body
    print(e.url, e.method) # request that failed
    print(e.response)      # raw requests.Response, when available
```

| Attribute | Description |
|-----------|-------------|
| `message` | Human-readable description. |
| `broker` | Id of the broker that raised it. |
| `error_code` | Broker-specific error code, when available. |
| `status_code` | HTTP status of the offending response. |
| `payload` | Decoded response body associated with the error. |
| `url` / `method` | The request that triggered the error. |
| `response` | The raw `requests.Response`, when available. |

## How HTTP errors become Fenix errors

When a response returns a 4xx/5xx, `fetch()` routes it through `handle_http_error()`, which
builds an error *context* (status, reason, decoded payload, extracted error code/message) and
maps the **status code to the most specific error class**:

| HTTP status | Fenix error |
|-------------|-------------|
| 400, 422 | `InputError` |
| 401 | `AuthenticationError` |
| 403 | `PermissionDeniedError` |
| 404 | `ResponseError` |
| 408 | `RequestTimeoutError` |
| 429 | `RateLimitExceededError` |
| ≥ 500 | `NetworkError` |
| other | `BrokerError` |

Adapters declare `ERROR_CODE_KEYS` and `ERROR_MESSAGE_KEYS` so the base class can dig the
broker's own error code and message out of the response payload — recursively, across nested
dicts and lists — to produce a precise message like:

```text
Zerodha HTTP 400 POST https://api.kite.trade/orders/regular - InputException: Invalid price
```

### Broker-specific overrides

A broker can override `handle_http_error()` to map its documented error codes directly to the
richest class. Zerodha, for example, maps `TokenException → AuthenticationError`,
`MarginException → InsufficientFundsError`, `HoldingException → InsufficientHoldingsError`, and
so on — so you can catch the *meaning* of the failure, not just the status code.

## Capability errors — `NotSupported`

Operations a broker doesn't offer raise `NotSupported` rather than failing cryptically. The
auto-generated [order convenience methods](#/orders) check the [`has`](#/architecture) registry
first:

```python
try:
    broker.slm_buy_order(token_dict=c, trigger=100.0, quantity=75, unique_id="x")
except errors.NotSupported:
    # this broker doesn't support SL-M buy orders — fall back
    ...
```

## A practical handler

Catch from most specific to least specific:

```python
from fenix import errors

try:
    order = broker.limit_order(token_dict=c, side="BUY", price=152.0,
                               quantity=75, unique_id="entry-1")
except errors.InsufficientFundsError:
    notify("Top up margin")
except errors.RateLimitExceededError:
    backoff_and_retry()
except errors.AuthenticationError:
    re_login()
except errors.InputError as e:
    log.error("Bad order params: %s", e.message)
except errors.BrokerError as e:          # catch-all safety net
    log.exception("Order failed on %s: %s", e.broker, e.message)
```
