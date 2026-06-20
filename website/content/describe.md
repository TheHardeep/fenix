# The `describe()` Method

`describe()` is the single source of a broker's configuration. Every adapter **must** implement
it, returning a dictionary of metadata that the base [`Broker.__init__`](#/architecture)
consumes to set up the instance. Think of it as the broker's manifest.

```python
def describe(self) -> dict[str, Any]:
    """Child classes MUST implement this to describe their properties."""
    raise NotImplementedError(...)
```

Because `__init__` merges `describe()` with your `config` overrides, **every key below can be
set per instance** by passing `config={...}` to the constructor.

## A complete example

Here is `Zerodha.describe()` in full — a representative manifest:

```python
def describe(self) -> dict[str, Any]:
    return {
        "id": "Zerodha",
        "tokenParams": ["user_id", "password", "totpstr", "api_key", "api_secret"],
        "proxies": {},
        "sensitiveLogKeys": [
            "user_id", "password", "totp", "totpstr", "api_key",
            "api_secret", "request_token", "access_token", "Authorization",
        ],
        "enableRateLimit": True,
        "rateLimits": {
            "quote":      {"period": 1,     "capacity": 1,   "cost": 1.0},
            "historical": {"period": 1,     "capacity": 3,   "cost": 1.0},
            "order": [
                {"period": 1,     "capacity": 10,  "cost": 1.0},
                {"period": 60,    "capacity": 400, "cost": 1.0},
                {"period": 86400, "capacity": 5000,"cost": 1.0},
            ],
            "modify":     {"period": 86400, "capacity": 25,  "cost": 1.0},
            "default":    {"period": 1,     "capacity": 10,  "cost": 1.0},
        },
    }
```

## Identity & credentials

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `id` | `str` | `"Broker"` | Human-readable broker id. Appears in `repr()`, log lines, and error messages. |
| `tokenParams` | `list[str]` | `{}` | The credential keys this broker's [`authenticate()`](#/authentication) requires. Inspect with `broker.tokenParams`. |
| `proxies` | `dict` | `{}` | Optional `requests`-style proxy map applied to every call. |

## Rate limiting

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enableRateLimit` | `bool` | `True` | Master switch for [token-bucket throttling](#/rate-limiting). |
| `rateLimits` | `dict` | `{}` | Per-endpoint-group bucket definitions. Each entry is one bucket — or a **list** of buckets for multi-window limits (e.g. per-second *and* per-day). |

Each bucket declares a `period` (seconds), a `capacity` (tokens), and an optional `cost`
(tokens consumed per call, default `1.0`). The base class builds one refilling bucket per
definition. See [Rate Limiting](#/rate-limiting) for the full algorithm.

## Logging & response capture

These flags configure what the broker logs and which parts of the last response it retains.
Full detail on the [Logging & Redaction](#/logging) page.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `verbose` | `bool` | `False` | Print every request/response (redacted) through `log()`. |
| `returnResponseHeaders` | `bool` | `False` | Attach `responseHeaders` to parsed dict responses. |
| `enableLastHttpResponse` | `bool` | `True` | Keep the raw last response body on `last_http_response`. |
| `enableLastJsonResponse` | `bool` | `False` | Keep the parsed last JSON on `last_json_response`. |
| `enableLastResponseHeaders` | `bool` | `True` | Keep the last response headers on `last_response_headers`. |

## Secret redaction

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `logSensitive` | `bool` | `False` | When `True`, **disables** redaction (logs secrets verbatim). Leave off in production. |
| `sensitiveLogKeys` | `list[str] \| str` | `()` | Extra field names whose values are masked in logs, on top of the defaults. |
| `sensitiveLogKeysIncludeDefault` | `bool` | `True` | Whether to seed the redaction set with Fenix's built-in list of sensitive keys. |
| `maxLogBodyLength` | `int \| None` | `None` | Truncate logged bodies longer than this many characters. |

> [!WARNING] Keep redaction on
> `sensitiveLogKeys` is how passwords, TOTP seeds, API secrets, and access tokens stay out of
> your logs. Only set `logSensitive=True` for short-lived local debugging, never in code that
> ships.

## Paper-mode settings

Present these keys (or pass them via `config`) to construct the broker against the
[paper-trading engine](#/paper-mode) instead of the live API.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `paper_mode` | `bool` | `False` | Route order entry and reads to the embedded simulator. |
| `paper_client_id` | `str` | `"PAPER001"` | Client id reported by the simulated profile. |
| `paper_starting_margin` | `float` | `1_000_000.0` | Opening available margin for the session. |
| `paper_reject_invalid_stops` | `bool` | `True` | Reject stop orders priced through the market on submit. |
| `paper_log_history_size` | `int` | `100` | How many paper interactions to retain in the rolling log. |

## Overriding `describe()` at runtime

You rarely edit `describe()` itself — instead, override individual keys when you construct the
broker:

```python
# Verbose, with a custom proxy and a bigger paper float
broker = Zerodha(config={
    "verbose": True,
    "proxies": {"https": "http://127.0.0.1:8888"},
    "paper_mode": True,
    "paper_starting_margin": 5_000_000.0,
})
```

Keys that match an instance attribute are also applied directly after the merge, so overrides
take effect immediately — there is no separate "apply settings" step.
