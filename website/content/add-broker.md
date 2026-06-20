# Adding a Broker

Every adapter is the same shape, so adding a new broker is a matter of filling in the
broker-specific pieces against a fixed contract. This page is the blueprint — the same one
[every shipped broker](#/brokers) follows.

## The anatomy

Subclass [`Broker`](#/architecture) and provide six things: metadata, endpoints, translation
maps, a login flow, token loaders, and the request/response logic for each unified method.

```python
from fenix.base.broker import Broker
from fenix.base.constants import Side, Product, OrderType, Validity, Variety, Status, ExchangeCode

class MyBroker(Broker):
    _API = { "servers": {...}, "paths": {...} }     # 2 — endpoints
    STANDARD_MAPS = {...}                            # 3 — broker → fenix
    REQUEST_MAPS  = {...}                            # 3 — fenix → broker
    _REQUIRED_AUTH_HEADER_KEYS = (...)               # auth-header validation
    ERROR_CODE_KEYS = (...); ERROR_MESSAGE_KEYS = (...)

    def describe(self): ...                          # 1 — metadata
    def authenticate(self, params=None, headers=None, force=False): ...   # 4
    def load_equity_tokens(self, data=None): ...     # 5 — instrument masters
    def load_fno_tokens(self, data=None): ...        # 5
    def place_order(self, ...): ...                  # 6 — order entry
    def fetch_orderbook(self): ...                   # 6 — reads
    # …modify_order, cancel_order, positions, holdings, margins, profile
```

## 1 · `describe()`

Return the broker's manifest. At minimum: an `id`, the `tokenParams` your login needs, and the
`rateLimits`. See [The describe() Method](#/describe) for every key.

```python
def describe(self):
    return {
        "id": "MyBroker",
        "tokenParams": ["user_id", "password", "api_key"],
        "enableRateLimit": True,
        "rateLimits": {
            "order":   {"period": 1, "capacity": 10, "cost": 1.0},
            "default": {"period": 1, "capacity": 5,  "cost": 1.0},
        },
        "sensitiveLogKeys": ["password", "api_key", "access_token"],
    }
```

## 2 · `_API`

Put every URL in `_API` — never inline. Group hosts under `servers`, endpoints under `paths`,
and resolve them with `get_url("name")`. See [API Endpoints](#/api-endpoints).

```python
_API = {
    "doc": "https://docs.mybroker.example/api",
    "servers": {"api": "https://api.mybroker.example"},
    "paths": {
        "login":       {"server": "api", "path": "/auth/login"},
        "place_order": {"server": "api", "path": "/orders"},
        "orderbook":   {"server": "api", "path": "/orders"},
        "positions":   {"server": "api", "path": "/positions"},
        "instruments": {"server": "api", "path": "/instruments"},
    },
}
```

## 3 · Translation maps

Declare both directions so the base class can translate constants for you with
`_format_for_broker()` (outgoing) and `_parse_from_broker()` (incoming). See
[Request/Response Maps](#/maps).

```python
REQUEST_MAPS = {
    "side":       {Side.BUY: "B", Side.SELL: "S"},
    "order_type": {OrderType.MARKET: "MKT", OrderType.LIMIT: "LMT",
                   OrderType.SL: "SL", OrderType.SLM: "SL-M"},
    "product":    {Product.MIS: "I", Product.NRML: "M", Product.CNC: "C"},
    "validity":   {Validity.DAY: "DAY", Validity.IOC: "IOC"},
}
STANDARD_MAPS = {
    "side":       {"B": Side.BUY, "S": Side.SELL},
    "status":     {"open": Status.OPEN, "complete": Status.FILLED,
                   "rejected": Status.REJECTED, "cancelled": Status.CANCELLED},
}
```

## 4 · `authenticate()`

Run the broker's login flow and return request headers. Follow the standard contract: honor
`headers=` (restore via `use_headers()`), cache unless `force=True`, validate `tokenParams`, and
short-circuit in paper mode.

```python
def authenticate(self, params=None, headers=None, force=False):
    if self.paper_mode:
        self._headers = {"paper": "true"}
        return self._headers
    if headers is not None:
        return self.use_headers(headers)
    if self._headers and not force:
        return self._headers
    for key in self.tokenParams:
        if key not in (params or {}):
            raise KeyError(f"Please provide {key}")
    # …call self.get_url("login"), self.fetch(...), build and store self._headers
    return self._headers
```

Set `_REQUIRED_AUTH_HEADER_KEYS` so `use_headers()` can validate a restored session.

## 5 · Token loaders

Implement the `load_*_tokens` your broker's segments need. Download the instrument master and
shape each row into the [standard record](#/tokens), accumulating into `self.token_json` and
`self.alltoken_json`, and return `(nested_map, flat_lookup)`.

```python
def load_fno_tokens(self, data=None):
    # parse the master, build records via your format_opt_dict / format_fut_dict,
    # group options/futures by underlying, register flat "{token}_{exchange}" keys,
    # update self.token_json / self.alltoken_json, then return the tuple
    ...
```

## 6 · Unified methods

Implement order entry and the reads. The pattern is always: **format inputs → build payload →
`fetch()` with the right `endpoint_group` → parse into the unified schema.**

```python
def place_order(self, token_dict, quantity, side, product, validity,
                variety, unique_id, price=0.0, trigger=0.0, **kw):
    if self.paper_mode and self._paper is not None:        # paper short-circuit
        return self._paper.place_order(token_dict=token_dict, quantity=quantity,
                                       side=side, product=product, validity=validity,
                                       variety=variety, unique_id=unique_id,
                                       price=price, trigger=trigger)
    self._validate_order_inputs(quantity=quantity, price=price, trigger=trigger)
    data = {
        "token": token_dict["Token"],
        "side":  self._format_for_broker("side", side),
        "type":  self._format_for_broker("order_type",
                                         self._resolve_order_type(price, trigger)),
        "qty":   quantity, "price": price, "trigger": trigger,
    }
    response = self.fetch(method="POST", url=self.get_url("place_order"),
                          endpoint_group="order", json=data, headers=self._headers)
    return self._parse_place_order_response(response)
```

For reads, translate every broker field back into the [unified record](#/unified-json) with
`_parse_from_broker()`:

```python
def _parse_orderbook(self, order):
    return {
        "id":     order["order_id"],
        "symbol": order["symbol"],
        "side":   self._parse_from_broker("side", order["side"]),
        "type":   self._parse_from_broker("order_type", order["type"]),
        "status": self._parse_from_broker("status", order["status"]),
        # …the rest of the unified Order keys
    }
```

## What you get for free

By subclassing `Broker`, you inherit — without writing any of it — the HTTP session,
[throttling](#/rate-limiting), [logging and redaction](#/logging),
[error mapping](#/errors), the [order convenience methods](#/orders) (generated from your
`place_order`), the [`has`](#/orders) capability registry, and full [paper-mode](#/paper-mode)
support. You only write what is genuinely broker-specific.

> [!TIP] Capabilities
> If your broker can't do an operation, set it `False` in a `has` dict on the subclass — only
> list what you change; the base merges it with the inherited capabilities automatically.

## Checklist

- [ ] `describe()` returns `id`, `tokenParams`, `rateLimits`, `sensitiveLogKeys`.
- [ ] `_API` holds every URL; methods use `get_url()`.
- [ ] `REQUEST_MAPS` and `STANDARD_MAPS` cover side, order_type, product, validity, status, exchange.
- [ ] `authenticate()` handles params, header reuse, `force`, and paper mode.
- [ ] `load_*_tokens` populate `token_json` / `alltoken_json` and return the tuple.
- [ ] `place_order` + reads/mutations return the [unified schemas](#/unified-json).
- [ ] `_REQUIRED_AUTH_HEADER_KEYS`, `ERROR_CODE_KEYS`, `ERROR_MESSAGE_KEYS` are set.
- [ ] Export the class in `fenix/__init__.py` so it joins `fenix.brokers`.
