# Architecture

Fenix is built around one idea: **a single base class holds everything that is identical
across brokers, and each broker subclass supplies only what is different.** This page explains
how that base class is wired and what happens on every request.

## The `Broker` base class

Every adapter — `Zerodha`, `AngelOne`, `Fyers`, … — subclasses `fenix.base.broker.Broker`.
The base class provides the shared machinery:

| Responsibility | Provided by the base class |
|----------------|----------------------------|
| HTTP session | A persistent `requests` session created in `__init__` (`reset_session()` to rebuild). |
| Throttling | Token-bucket [rate limiting](#/rate-limiting) via `throttle()` inside `fetch()`. |
| Request wrapper | `fetch()` — throttles, logs, sends, captures the response, and maps errors. |
| URL building | [`get_url()`](#/api-endpoints) resolves a named endpoint from `_API`. |
| Translation | [`_format_for_broker()` / `_parse_from_broker()`](#/maps) convert constants. |
| Logging | [Verbose logging and secret redaction](#/logging). |
| Errors | [HTTP-status → exception mapping](#/errors) and `handle_http_error()`. |
| Capabilities | The `has` registry and auto-generated [order convenience methods](#/orders). |
| Paper mode | An embedded [`PaperExecutionClient`](#/paper-mode) when `paper_mode=True`. |

A broker subclass therefore stays small: it declares its [`describe()`](#/describe) metadata,
its [`_API`](#/api-endpoints) endpoints, its [translation maps](#/maps), and implements the
request-builders and response-parsers for each unified method.

## Metadata-driven construction

A broker configures itself from its own `describe()` dictionary. When you instantiate a broker,
`__init__` merges `describe()` with any `config` overrides you pass and applies the result:

```python
def __init__(self, config=None):
    description = self.describe()
    if config:
        description = {**description, **config}

    self.id            = description.get("id", "Broker")
    self.tokenParams   = description.get("tokenParams", {})
    self.enableRateLimit = description.get("enableRateLimit", True)
    self.rateLimits    = description.get("rateLimits", {})
    self.verbose       = bool(description.get("verbose", False))
    # … logging flags, redaction keys, proxies, paper-mode setup …
```

Because construction is data-driven, **anything in `describe()` can be overridden per
instance** simply by passing `config`:

```python
broker = Zerodha(config={
    "verbose": True,            # turn on request/response logging
    "enableRateLimit": True,    # keep throttling on
    "paper_mode": True,         # route orders to the simulator
})
```

See [The describe() Method](#/describe) for every key you can set.

## Per-instance vs shared state

`_API` is defined once on the class, but adapters that rewrite endpoints at runtime (for
example, resolving a dynamic host) must not corrupt other instances. So each instance gets a
**private shallow copy** of the `_API` shell and its own `servers` dict, while the larger
read-only `paths` map stays shared with the class:

```python
cls_api = type(self)._API
self._API = dict(cls_api)
if "servers" in cls_api:
    self._API["servers"] = deepcopy(cls_api["servers"])
```

Authenticated headers (`self._headers`), auth context (`self._auth_context`), token maps
(`self.token_json`, `self.alltoken_json`), and the rate-limit buckets are all **per-instance** —
so two `Zerodha()` objects can hold two different logins without interfering.

## The request lifecycle

Almost every unified method ends up calling `fetch()`. Here is the path a single request
takes from your call to a parsed result:

<div class="fx">
  <div class="fx-row">
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Caller</div>
        <div class="fx-node-title">your call</div>
        <div class="fx-node-sub">place_order() · fetch_orderbook() · …</div>
      </div>
    </div>
  </div>
  <div class="fx-pipe"><span class="fx-pipe-line"></span></div>
  <div class="fx-row">
    <div class="fx-node accent">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Core</div>
        <div class="fx-node-title">fetch()</div>
        <div class="fx-steps">
          <div class="fx-step"><span class="fx-step-n">1</span><span><b>throttle(endpoint_group)</b> — block until the token bucket allows it</span></div>
          <div class="fx-step"><span class="fx-step-n">2</span><span>record <b>last_request_*</b> (method, url, body, …)</span></div>
          <div class="fx-step"><span class="fx-step-n">3</span><span><b>_log_http_request()</b> → redacted verbose log</span></div>
          <div class="fx-step"><span class="fx-step-n">4</span><span><b>session.request(...)</b> → the actual HTTP call</span></div>
          <div class="fx-step"><span class="fx-step-n">5</span><span><b>on_rest_response()</b> → unwrap / decrypt hook</span></div>
          <div class="fx-step"><span class="fx-step-n">6</span><span>capture <b>last_http / json_response</b> + headers</span></div>
          <div class="fx-step"><span class="fx-step-n">7</span><span><b>_log_http_response()</b> → redacted verbose log</span></div>
          <div class="fx-step"><span class="fx-step-n">8</span><span><b>raise_for_status()</b> → HTTPError on 4xx / 5xx</span></div>
        </div>
      </div>
    </div>
  </div>
  <div class="fx-pipe"><span class="fx-pipe-label">Response</span><span class="fx-pipe-line"></span></div>
  <div class="fx-row">
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Parse</div>
        <div class="fx-node-title">_parse_* &nbsp;<span style="color:var(--text-faint);font-weight:400;font-size:13px">(broker-specific)</span></div>
        <div class="fx-node-sub">translate fields via _parse_from_broker()</div>
      </div>
    </div>
  </div>
  <div class="fx-pipe"><span class="fx-pipe-line"></span></div>
  <div class="fx-row">
    <div class="fx-node">
      <div class="fx-node-core">
        <div class="fx-node-eyebrow">Output</div>
        <div class="fx-node-title">Unified JSON record</div>
        <div class="fx-node-sub">same keys for every broker</div>
      </div>
    </div>
  </div>
</div>

On any failure, `fetch()` translates the low-level exception into a Fenix error:
timeouts become `RequestTimeoutError`, connection/SSL failures become `NetworkError`, and HTTP
4xx/5xx responses are routed through `handle_http_error()`, which maps the status code to the
right [error class](#/errors).

## Capabilities: the `has` registry

Not every broker supports every operation. Each broker advertises what it can do through a
`has` dictionary. The base class auto-generates order convenience methods (like
`limit_buy_order`) and each one checks `self.has[method_name]` before running, raising
`NotSupported` if the broker disabled it:

```python
class Broker:
    has = {
        "place_order": True,
        "market_buy_order": True,
        "limit_order": True,
        # …one entry per generated order method
    }
```

Subclasses only declare the capabilities they **change** — `__init_subclass__` merges a
subclass's `has` with its parent's automatically, so you never re-declare the full set. Read
more under [Orders → Capabilities](#/orders).

## Anatomy of an adapter

Putting it together, a broker subclass is organized like this:

```python
class Zerodha(Broker):
    _API = { "servers": {...}, "paths": {...} }   # endpoints  → #/api-endpoints
    STANDARD_MAPS = {...}                          # broker → fenix  → #/maps
    REQUEST_MAPS  = {...}                          # fenix → broker  → #/maps
    _REQUIRED_AUTH_HEADER_KEYS = (...)             # header validation
    ERROR_CODE_KEYS = (...); ERROR_MESSAGE_KEYS = (...)

    def describe(self): ...        # metadata           → #/describe
    def authenticate(self): ...    # login flow         → #/authentication
    def load_fno_tokens(self): ... # instrument master  → #/tokens
    def place_order(self): ...     # order entry        → #/orders
    def fetch_orderbook(self): ... # reads              → #/orders
    # …positions, holdings, margins, profile, error handling
```

Every adapter follows this same skeleton, which is also the blueprint for
[adding a new broker](#/add-broker).
