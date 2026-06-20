# API Endpoints & `_API`

Every broker stores **all of its URLs in one place**: the `_API` class attribute. Nothing in
the adapter hard-codes a URL string inline — request methods ask for an endpoint *by name* and
`get_url()` resolves it. This keeps endpoints discoverable, overridable, and easy to audit.

## The `_API` structure

`_API` is a dictionary with three sections — `doc`, `servers`, and `paths`:

```python
_API = {
    "doc": "https://kite.trade/docs/connect/v3",   # link to the broker's API docs
    "servers": {                                    # named base URLs (hosts)
        "api":     "https://api.kite.trade",
        "auth":    "https://kite.zerodha.com",
        "connect": "https://kite.trade",
    },
    "paths": {                                      # named endpoints
        # --- Auth flow ---
        "login":  {"server": "auth", "path": "/api/login"},
        "twofa":  {"server": "auth", "path": "/api/twofa"},
        "token_url": {"server": "api", "path": "/session/token"},

        # --- Orders & portfolio ---
        "place_order": {"server": "api", "path": "/orders"},
        "tradebook":   {"server": "api", "path": "/trades"},
        "holdings":    {"server": "api", "path": "/portfolio/holdings"},
        "positions":   {"server": "api", "path": "/portfolio/positions"},
        "rms_limits":  {"server": "api", "path": "/user/margins"},
        "profile":     {"server": "api", "path": "/user/profile"},

        # --- Market data ---
        "instruments": {"server": "api", "path": "/instruments"},
    },
}
```

| Section | Purpose |
|---------|---------|
| `doc` | A link to the broker's official API reference. Documentation only. |
| `servers` | A map of **named hosts**. Brokers often span several hosts — auth on one, trading on another, market data on a third. |
| `paths` | A map of **named endpoints**. Each entry points at a server and a relative path. |

## Two kinds of path entry

A `paths` entry is one of:

- **A `{"server", "path"}` object** — the common case. `path` is joined onto the named
  `servers[server]` base URL.
- **A plain string** — a complete, absolute URL used as-is (handy for one-off external URLs).

```python
"paths": {
    "place_order": {"server": "api", "path": "/orders"},     # → joined to servers["api"]
    "status_page": "https://status.example.com/health",      # → used verbatim
}
```

## Resolving a URL with `get_url()`

Adapters never build URLs by hand. They call `get_url("<name>")`, and the base class resolves it:

```python
def get_url(self, endpoint_name: str) -> str:
    path_info = self._API["paths"].get(endpoint_name)
    if not path_info:
        raise ValueError(f"Endpoint '{endpoint_name}' not found in API definition.")
    if isinstance(path_info, str):
        return path_info                              # absolute URL → as-is
    base_url = self._API["servers"][path_info["server"]]
    return f"{base_url}{path_info['path']}"           # join host + path
```

So inside an adapter, a request reads cleanly:

```python
response = self.fetch(
    method="POST",
    url=self.get_url("place_order"),     # → https://api.kite.trade/orders
    endpoint_group="order",
    data=payload,
    headers=self._headers,
)
```

> [!TIP] Endpoint names are the contract
> Endpoint *names* (`"place_order"`, `"positions"`, `"login"`, …) are stable across brokers
> even though the underlying hosts and paths differ. That naming convention is what lets the
> unified methods look identical from broker to broker.

## Per-instance copies & runtime rewrites

Some brokers resolve a host dynamically (for example, looking up an interactive trading host at
login). If they mutated the shared class-level `_API`, they would corrupt every other instance.

To prevent that, [`__init__`](#/architecture) gives each instance a **private shallow copy** of
the `_API` shell plus its own `servers` dict, while the larger read-only `paths` map stays
shared with the class:

```python
cls_api = type(self)._API
self._API = dict(cls_api)
if "servers" in cls_api:
    self._API["servers"] = deepcopy(cls_api["servers"])
```

The practical result: an adapter can safely do `self._API["servers"]["interactive"] = resolved_host`
at runtime, and only *that* instance is affected.

## Overriding endpoints

Because `_API` is per-instance, you can repoint a host after construction — useful for sandbox
environments or a debugging proxy:

```python
broker = Zerodha()
broker._API["servers"]["api"] = "https://sandbox.kite.trade"
# every get_url("…") that targets the "api" server now points at the sandbox
```

## Special-case URLs

A few market-wide endpoints (NSE/BSE option-chain expiry feeds) are not broker-specific, so the
base class keeps them as constants rather than in any one broker's `_API`:

```python
NFO_URL = "https://www.nseindia.com/api/option-chain-indices"
BFO_URL = "https://api.bseindia.com/BseIndiaAPI/api/ddlExpiry_IV/w"
```

These power the shared [expiry-date downloads](#/tokens) used while building F&O token maps.
