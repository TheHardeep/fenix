# Rate Limiting

Brokers enforce strict request limits — so many orders per second, per minute, per day. Fenix
throttles **automatically** using a thread-safe token-bucket limiter, so you stay within limits
without sprinkling `sleep()` calls through your strategy. Every call through
[`fetch()`](#/architecture) passes through the throttle first.

## How limits are declared

Rate limits are part of [`describe()`](#/describe) under `rateLimits`, keyed by **endpoint
group**. Each group maps to one bucket — or a **list** of buckets for multi-window limits:

```python
"rateLimits": {
    "quote":      {"period": 1,     "capacity": 1,    "cost": 1.0},
    "historical": {"period": 1,     "capacity": 3,    "cost": 1.0},
    "order": [
        {"period": 1,     "capacity": 10,   "cost": 1.0},   # 10 / second
        {"period": 60,    "capacity": 400,  "cost": 1.0},   # 400 / minute
        {"period": 86400, "capacity": 5000, "cost": 1.0},   # 5000 / day
    ],
    "modify":     {"period": 86400, "capacity": 25,   "cost": 1.0},
    "default":    {"period": 1,     "capacity": 10,   "cost": 1.0},
}
```

| Field | Meaning |
|-------|---------|
| `period` | Window length in seconds the capacity refills over. |
| `capacity` | Maximum tokens (requests) available in that window. |
| `cost` | Tokens consumed per call (default `1.0`). A heavier call can cost more. |

The Zerodha `order` group above means: **no more than 10 orders/second, 400/minute, and
5000/day** — all enforced simultaneously.

## Buckets are built at construction

When the broker initializes (and `enableRateLimit` is on), each definition becomes a refilling
token bucket. A multi-window group produces several buckets, named `"{group}_{period}s"`:

```python
for group, all_params in self.rateLimits.items():
    params_list = all_params if isinstance(all_params, list) else [all_params]
    for params in params_list:
        bucket_name = f"{group}_{int(params['period'])}s"   # e.g. order_1s, order_60s, order_86400s
        self._token_buckets[bucket_name] = {
            "tokens": float(params["capacity"]),
            "refill_rate": float(params["capacity"]) / params["period"],   # tokens per second
            "capacity": float(params["capacity"]),
            "cost": params.get("cost", 1.0),
            "last_refill_time": time.monotonic(),
        }
        self._bucket_locks[bucket_name] = threading.Lock()
```

So `order` expands into three buckets — `order_1s`, `order_60s`, `order_86400s` — each with its
own lock.

## The token-bucket algorithm

A bucket starts full. Tokens refill continuously at `capacity / period` tokens per second, up
to the cap. Each request must take `cost` tokens; if the bucket is short, the call waits just
long enough for the bucket to refill.

<div class="fx">
  <div class="fx-bucket">
    <div class="fx-bucket-core">
      <div class="fx-bucket-head">
        <b>order_1s</b>
        <span class="sep">·</span>
        <span>capacity 10</span>
        <span class="sep">·</span>
        <span>refill 10 tokens / sec</span>
      </div>
      <div class="fx-bucket-rows">
        <div class="fx-bucket-row">
          <div class="fx-bucket-meter">
            <div class="fx-bucket-fill"><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span></div>
          </div>
          <div class="fx-bucket-note"><b>Full (10)</b> — request takes 1, 9 left</div>
        </div>
        <div class="fx-bucket-row">
          <div class="fx-bucket-meter">
            <div class="fx-bucket-fill"><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span class="empty"></span></div>
          </div>
          <div class="fx-bucket-note"><b>Refilling</b> +10/s up to capacity</div>
        </div>
        <div class="fx-bucket-row">
          <div class="fx-bucket-meter">
            <div class="fx-bucket-fill"><span class="empty"></span><span class="empty"></span><span class="empty"></span><span class="empty"></span><span class="empty"></span><span class="empty"></span><span class="empty"></span><span class="empty"></span><span class="empty"></span><span class="empty"></span></div>
          </div>
          <div class="fx-bucket-note"><b>Empty</b> — wait (cost − tokens) / rate; request blocks briefly</div>
        </div>
      </div>
    </div>
  </div>
</div>

## `throttle()` — the gate every request passes

`fetch()` calls `self.throttle(endpoint_group)` *before* sending. `throttle()` gathers **all**
buckets for the group (every window), acquires their locks, refills them by elapsed time, and —
if any bucket lacks enough tokens — sleeps for the longest required wait while holding the
locks, then consumes one token from each:

```python
def throttle(self, endpoint_group):
    if not self.enableRateLimit:
        return
    relevant = [n for n in self._token_buckets if n.startswith(f"{endpoint_group}_")]
    with ExitStack() as stack:
        for name in relevant:
            stack.enter_context(self._bucket_locks[name])
        # 1. refill every bucket by elapsed time
        # 2. find the longest wait across all windows
        # 3. sleep (with padding) if needed, then refill again
        # 4. consume `cost` tokens from each bucket
```

Holding all the group's locks during the wait makes the limiter **thread-safe**: concurrent
threads placing orders share the same buckets and can't collectively exceed the limit.

> [!INFO] Padding
> Waits are multiplied by a small `rate_limit_padding` factor (`1.1`) so Fenix stays a hair
> under the broker's ceiling rather than racing the edge of it.

## Endpoint groups in practice

Each adapter method tags its request with the right group via the `endpoint_group` argument to
`fetch()`. That's how an order is throttled against the order limits and a quote against the
quote limits:

```python
# place_order → counted against the "order" buckets
self.fetch(method="POST", url=self.get_url("place_order"),
           endpoint_group="order", data=data, headers=self._headers)

# a market-data read → counted against "quote"
self.fetch(method="GET", url=self.get_url("quotes"),
           endpoint_group="quote", headers=self._headers)
```

If a method names a group that has **no** bucket defined, the request proceeds unthrottled (a
debug line notes it) — so a missing limit never blocks you. The `default` group is the
catch-all most adapters route miscellaneous calls through.

## Turning it off

Throttling is on by default. Disable it (for example, in tests or in [paper mode](#/paper-mode)
where there is no live API) with:

```python
broker = Zerodha(config={"enableRateLimit": False})
```

> [!WARNING] Leave it on against live brokers
> Disabling the limiter means you're responsible for staying within the broker's limits.
> Breaching them typically returns HTTP 429, which Fenix surfaces as
> [`RateLimitExceededError`](#/errors), and can get sessions temporarily blocked.
