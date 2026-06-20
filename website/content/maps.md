# Request / Response Maps

Fenix speaks in [standardized constants](#/constants) — `Side.BUY`, `Product.MIS`,
`OrderType.SLM`. Brokers speak in their own strings — `"B"`, `"I"`, `"SL-M"`. Two lookup
tables on each adapter bridge the two directions, and two helper methods perform the
translation with built-in validation.

<div class="fx">
  <div class="fx-map">
    <div class="fx-map-row outgoing">
      <span class="fx-map-tag">Outgoing &nbsp;·&nbsp; Fenix → broker &nbsp;·&nbsp; REQUEST_MAPS</span>
      <span class="fx-chip">Side.BUY</span>
      <span class="fx-map-fn">
        <span class="fx-map-fn-name">_format_for_broker</span>
        <span class="fx-map-fn-line"></span>
      </span>
      <span class="fx-chip accent">"BUY"</span>
    </div>
    <div class="fx-map-row">
      <span class="fx-map-tag">Incoming &nbsp;·&nbsp; broker → Fenix &nbsp;·&nbsp; STANDARD_MAPS</span>
      <span class="fx-chip">"SL-M"</span>
      <span class="fx-map-fn">
        <span class="fx-map-fn-name">_parse_from_broker</span>
        <span class="fx-map-fn-line"></span>
      </span>
      <span class="fx-chip accent">OrderType.SLM</span>
    </div>
  </div>
</div>

## The two maps

| Map | Direction | Used by |
|-----|-----------|---------|
| `REQUEST_MAPS` | **Fenix → broker** | Request builders, before sending. |
| `STANDARD_MAPS` | **broker → Fenix** | Response parsers, after receiving. |

Both are keyed by a *map name* (`"side"`, `"order_type"`, `"product"`, `"validity"`,
`"variety"`, `"status"`, `"exchange"`) so one adapter holds all its translations in a tidy,
reviewable structure.

### `REQUEST_MAPS` — outgoing (Fenix → broker)

```python
REQUEST_MAPS = {
    "side": {
        Side.BUY:  "BUY",
        Side.SELL: "SELL",
    },
    "order_type": {
        OrderType.MARKET: "MARKET",
        OrderType.LIMIT:  "LIMIT",
        OrderType.SL:     "SL",
        OrderType.SLM:    "SL-M",
    },
    "product": {
        Product.MIS:  "MIS",
        Product.CNC:  "CNC",
        Product.NRML: "NRML",
    },
    "validity": { Validity.DAY: "DAY", Validity.IOC: "IOC", Validity.TTL: "TTL" },
    "variety":  { Variety.REGULAR: "regular", Variety.STOPLOSS: "regular",
                  Variety.AMO: "amo", Variety.CO: "co" },
}
```

### `STANDARD_MAPS` — incoming (broker → Fenix)

`STANDARD_MAPS` is usually the richer table, because one Fenix status can correspond to *many*
broker strings. Note how a dozen Zerodha "pending"-like states all collapse onto
`Status.PENDING`:

```python
STANDARD_MAPS = {
    "status": {
        "OPEN PENDING":        Status.PENDING,
        "MODIFY PENDING":      Status.PENDING,
        "TRIGGER PENDING":     Status.PENDING,
        "VALIDATION PENDING":  Status.PENDING,
        "OPEN":                Status.OPEN,
        "COMPLETE":            Status.FILLED,
        "REJECTED":            Status.REJECTED,
        "CANCELLED":           Status.CANCELLED,
    },
    "side":       { "BUY": Side.BUY, "SELL": Side.SELL },
    "order_type": { "MARKET": OrderType.MARKET, "LIMIT": OrderType.LIMIT,
                    "SL": OrderType.SL, "SL-M": OrderType.SLM },
    "product":    { "MIS": Product.MIS, "CNC": Product.CNC, "NRML": Product.NRML },
}
```

> [!INFO] Why the maps aren't just inverses of each other
> Translation is many-to-one on the way in (several broker statuses → one Fenix status) and
> one-to-many is impossible on the way out, so `REQUEST_MAPS` and `STANDARD_MAPS` are
> maintained independently. Keeping them as two explicit tables makes every translation
> reviewable at a glance.

## `_format_for_broker()` — outgoing with validation

Request builders call `_format_for_broker(map_name, fenix_value)` to translate a Fenix constant
into the broker's string. Crucially, it **validates** the input: if you pass a value the map
doesn't recognize, it raises an [`InputError`](#/errors) that lists the valid options.

```python
broker_side    = self._format_for_broker("side", side)          # Side.BUY → "BUY"
broker_product = self._format_for_broker("product", product)    # Product.MIS → "MIS"
```

```python
def _format_for_broker(self, map_name, fenix_value, raise_error=True):
    mapping = self.REQUEST_MAPS.get(map_name)
    if not mapping:
        raise ValueError(f"Request map '{map_name}' does not exist.")   # developer error
    broker_value = mapping.get(fenix_value)
    if broker_value is not None:
        return broker_value
    if raise_error:
        raise InputError(
            f"Invalid value for '{map_name}': '{fenix_value}'. "
            f"Possible values are: {list(mapping.keys())}"
        )
    return fenix_value
```

So a typo surfaces immediately, with a helpful message:

```python
broker.market_order(token_dict=c, side="buy", quantity=75, unique_id="x")
# InputError: Invalid value for 'side': 'buy'.
#             Possible values are: ['BUY', 'SELL']
```

Pass `raise_error=False` to translate leniently (return the original value when it isn't in the
map) — useful when a field is optional or already broker-formatted.

## `_parse_from_broker()` — incoming with a default

Response parsers call `_parse_from_broker(map_name, broker_value, default=None)` to translate a
broker string back into a Fenix constant. If the broker sends something the map doesn't cover,
it falls back to `default` (or the raw value), so an unexpected status never crashes a parse:

```python
parsed = {
    Order.SIDE:   self._parse_from_broker("side", row["transaction_type"]),
    Order.TYPE:   self._parse_from_broker("order_type", row["order_type"]),
    Order.STATUS: self._parse_from_broker("status", row["status"]),
}
```

```python
def _parse_from_broker(self, map_name, broker_value, default=None):
    return self.STANDARD_MAPS[map_name].get(broker_value, default or broker_value)
```

## How the pieces fit together

A request builder formats every constant on the way out; a response parser translates every
field on the way in. The result is that **your code only ever deals in Fenix constants** — the
broker's vocabulary never leaks into your strategy:

```python
# Outgoing — build_place_order_payload
data = {
    "transaction_type": self._format_for_broker("side", side),
    "order_type":       self._format_for_broker("order_type", order_type),
    "product":          self._format_for_broker("product", product),
    "validity":         self._format_for_broker("validity", validity),
}

# Incoming — _parse_orderbook
Order.SIDE:   self._parse_from_broker("side", order["transaction_type"]),
Order.STATUS: self._parse_from_broker("status", order["status"]),
```

See the [Constants & Standards](#/constants) page for the complete list of Fenix values that
appear on the left-hand side of every map.
