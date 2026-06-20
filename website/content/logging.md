# Logging & Redaction

Fenix has a CCXT-style logging layer built into [`fetch()`](#/architecture): it can print every
request and response, it retains the last response on the instance for inspection, and it
**redacts secrets** from everything it logs. All of it is configurable through
[`describe()`](#/describe) or `config`.

## Verbose request/response logging

Set `verbose=True` to print each request and response as it happens. Output goes through the
`log()` hook (which defaults to `print`, but you can override it):

```python
broker = Zerodha(config={"verbose": True})
```

Each call emits a request line and a response line:

```text
fetch Request: Zerodha POST https://api.kite.trade/orders/regular
  RequestHeaders: {'Authorization': '***', 'X-Kite-Version': '***'}
  RequestBody: {'tradingsymbol': 'NIFTY...CE', 'transaction_type': 'BUY', ...}
  RequestParams: None

fetch Response: Zerodha POST https://api.kite.trade/orders/regular 200
  ResponseHeaders: {...}
  ResponseBody: {"status":"success","data":{"order_id":"250619000142"}}
```

Logging also honors the standard `logging` module: even without `verbose`, anything is emitted
at `DEBUG` level if your logger is configured for it.

```python
import logging
logging.basicConfig(level=logging.DEBUG)
broker = Zerodha()        # now requests/responses appear at DEBUG, still redacted
```

You can supply your own logger via `config={"logger": my_logger}` and replace the print hook by
subclassing and overriding `log()`.

## Capturing the last response

Independently of logging, the broker keeps the most recent exchange on the instance so you can
inspect it after any call. Which pieces are retained is controlled by flags:

| Attribute | Controlled by | Holds |
|-----------|---------------|-------|
| `last_http_response` | `enableLastHttpResponse` (default **on**) | Raw response body text. |
| `last_json_response` | `enableLastJsonResponse` (default off) | Parsed JSON of the last response. |
| `last_response_headers` | `enableLastResponseHeaders` (default **on**) | Response headers. |
| `last_request_headers` | always | Headers that were sent. |
| `last_request_body` | always | Body that was sent. |
| `last_request_params` | always | Query params sent. |
| `last_request_url` / `last_request_method` | always | URL and verb. |
| `last_response_url` | always | Final response URL (after redirects). |

```python
broker = Zerodha(config={"enableLastJsonResponse": True})
broker.fetch_orderbook()
print(broker.last_request_method, broker.last_request_url)
print(broker.last_json_response)          # parsed body of the last call
```

> [!TIP] returnResponseHeaders
> Set `returnResponseHeaders=True` and Fenix attaches the response headers under a
> `responseHeaders` key inside dict responses — handy when you need rate-limit headers or a
> server timestamp alongside the parsed payload.

## Secret redaction

This is the important part: **secrets are masked before anything is logged.** Passwords, TOTP
seeds, API keys/secrets, request/access tokens, cookies, and `Authorization` headers are all
replaced with `***` in verbose output and debug logs.

Redaction walks the entire payload — nested dicts, lists, and even JSON-encoded strings — and
masks any value whose key is considered sensitive. URLs are sanitized too: sensitive
query-string parameters are replaced before the URL is logged.

```text
RequestBody: {'user_id': '***', 'password': '***', 'twofa_value': '***'}
RequestURL:  https://api.kite.trade/session/token?api_key=***&request_token=***
```

### Which keys are sensitive

Fenix ships a built-in set of sensitive key names (case-insensitive, hyphen/underscore
agnostic): `authorization`, `api_key`, `api_secret`, `secret`, `password`, `pin`, `totp`,
`otp`, `cookie`, `token`, `access_token`, `refresh_token`, `request_token`, `session_token`,
`jwt_token`, and more.

Each broker also adds its own via `sensitiveLogKeys` in `describe()`. You can extend the set per
instance:

```python
broker = Zerodha(config={
    "sensitiveLogKeys": ["x_custom_secret", "checksum"],   # masked in addition to the defaults
    "sensitiveLogKeysIncludeDefault": True,                # keep the built-in list (default)
})
```

| Setting | Effect |
|---------|--------|
| `sensitiveLogKeys` | Extra field names to mask (string or list). |
| `sensitiveLogKeysIncludeDefault` | Seed the mask set with Fenix's built-in list (default `True`). |
| `maxLogBodyLength` | Truncate logged bodies longer than N characters, noting how many were dropped. |
| `logSensitive` | **Disable** redaction entirely — logs secrets verbatim. |

> [!DANGER] logSensitive turns redaction off
> `logSensitive=True` is the one switch that lets secrets reach your logs. Use it only for
> momentary local debugging, and never in shipped code or anything that writes logs to disk or
> a log aggregator.

## Truncating noisy bodies

Instrument-master downloads and bulk reads can be large. Cap what gets logged with
`maxLogBodyLength`:

```python
broker = Zerodha(config={"verbose": True, "maxLogBodyLength": 500})
# longer bodies are logged as: "…first 500 chars… (truncated 18234 chars)"
```

## Paper-mode logging

In [paper mode](#/paper-mode) there is no HTTP, but the same logging surface still works. Each
simulated operation is logged with a `paper` prefix and timing, and the last interaction is
mirrored onto `last_paper_request`, `last_paper_response`, and `last_paper_interaction` (with
the live `last_*` attributes kept in sync), so verbose debugging looks the same whether you're
live or simulated.
