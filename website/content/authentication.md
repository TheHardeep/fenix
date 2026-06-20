# Authentication

Before you can trade, you exchange your broker credentials for a set of authenticated request
headers. Fenix runs each broker's full login flow — including TOTP two-factor — and stores the
result on the instance, so you authenticate once and every subsequent call is authorized
automatically.

> [!INFO] You bring the credentials
> Fenix does not create broker accounts or API keys. Sign up with the broker, enable its API,
> and generate your keys first. Fenix uses those credentials to log in on your behalf.

## What credentials a broker needs

Each broker declares its required credential keys in `tokenParams`. Inspect them at runtime:

```python
from fenix import Zerodha
broker = Zerodha()
print(broker.tokenParams)
# ['user_id', 'password', 'totpstr', 'api_key', 'api_secret']
```

`tokenParams` differ per broker — some need an `api_secret`, some a `vendor_code`, some a
`pin`. Always read it from the broker rather than assuming.

## Logging in

Pass the credentials as `params` to `authenticate()`:

```python
creds = {
    "user_id":    "YOUR_USER_ID",
    "password":   "YOUR_PASSWORD",
    "totpstr":    "YOUR_TOTP_SECRET",   # the TOTP *seed string*, not a 6-digit code
    "api_key":    "YOUR_API_KEY",
    "api_secret": "YOUR_API_SECRET",
}

headers = broker.authenticate(params=creds)
```

`authenticate()` returns the authenticated headers and also stores them on `broker._headers`,
so you don't need to thread them through your own code — later calls pick them up
automatically.

> [!TIP] TOTP is automated
> Provide the TOTP **seed** (the base32 string from your authenticator setup) as `totpstr`, and
> Fenix generates a fresh 6-digit code at login time with `totp_creator()`. You never type a
> rotating code by hand.

### What happens under the hood

For Zerodha, `authenticate()` performs the multi-step Kite Connect login: capture the OAuth
session id, submit `user_id` + `password`, complete TOTP two-factor, capture the
`request_token` from the redirect, then exchange it (with a SHA-256 checksum of
`api_key + request_token + api_secret`) for the final `access_token`. Other brokers have their
own flows — but the **call you make is identical**.

## Reusing a session across runs

Logins are rate-limited and sometimes trigger SMS/2FA, so you don't want to log in on every
script run. After a successful `authenticate()`, save the returned headers and restore them
later with `use_headers()` (or by passing them as `headers=` to `authenticate()`):

```python
import json

# --- First run: log in and persist ---
headers = broker.authenticate(params=creds)
with open("session.json", "w") as f:
    json.dump(headers, f)

# --- Later runs: restore without logging in again ---
with open("session.json") as f:
    saved = json.load(f)

broker = Zerodha()
broker.authenticate(headers=saved)        # validates & restores, no login flow
```

`use_headers()` validates that the saved dict contains every key the broker requires
(`_REQUIRED_AUTH_HEADER_KEYS`) and raises `KeyError` if any are missing, so a corrupt or partial
session is caught immediately rather than failing mid-trade.

```python
broker.use_headers(saved, reset_session=True)   # also rebuild the HTTP session
```

| `use_headers()` argument | Purpose |
|--------------------------|---------|
| `headers` | The previously authenticated header set to restore. |
| `reset_session` | Rebuild the HTTP session so it isn't polluted by a prior user's cookies. |
| `auth_params` | Preserve non-header context (e.g. a `client_id` used in payloads). |

## Caching & forcing re-login

If headers are already set, `authenticate()` returns them without re-running the flow. Pass
`force=True` to ignore the cache and log in fresh (for example, after a token expiry):

```python
broker.authenticate(params=creds)              # logs in
broker.authenticate(params=creds)              # returns cached headers — no second login
broker.authenticate(params=creds, force=True)  # forces a fresh login
```

## Resetting the session

`reset_session()` discards the current HTTP session and creates a clean one — useful after
restoring saved headers, after a token refresh, or when recovering from a connection-pool
error:

```python
broker.reset_session()
```

## Authentication in paper mode

When the broker is constructed with `paper_mode=True`, `authenticate()` short-circuits: it sets
a placeholder header and returns immediately, with **no network call and no credentials
required**:

```python
broker = Zerodha(paper_mode=True)
broker.authenticate()          # instantly "logged in" against the simulator
```

This is what lets the exact same strategy code run live or simulated by changing one flag. See
[Paper Mode](#/paper-mode).

## Handling auth failures

A failed or expired login surfaces as [`AuthenticationError`](#/errors):

```python
from fenix import errors
try:
    broker.authenticate(params=creds)
except errors.AuthenticationError as e:
    print("Login failed:", e.message)
except KeyError as e:
    print("Missing a required credential:", e)
```
