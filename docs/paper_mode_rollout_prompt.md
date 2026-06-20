# Reusable Prompt: Wire `paper_mode` into a Fenix broker

Paste the block below into a fresh agent session and replace `zerodha`
with the filename stem of the target broker (e.g. `zerodha`,
`fivepaisa`, `kotak`). The prompt is self-contained — it doesn't depend
on conversation history — so it can be fired at multiple parallel
agents if you want to roll the change out across all 17 brokers at
once.

---

You are adding paper-trading support to a broker adapter in the Fenix
trading library. **The bulk of paper-mode wiring already lives in
`fenix/base/broker.py`** — every `Broker` subclass automatically gets:

- `self.paper_mode` (bool) and `self._paper` (`PaperExecutionClient | None`)
  initialised from `config={"paper_mode": True, ...}`
- A working `on_tick(token, ltp, bid, ask)` method that drives fills
- A pre-seeded `self._auth_context` populated from the broker's
  `_AUTH_CONTEXT_KEYS` (each key set to `paper_client_id`, default
  `"PAPER001"`) so methods that read it before `authenticate()` is
  called don't `KeyError`

You do NOT need to import `PaperExecutionClient`, add an `__init__`
paper block, or define `on_tick` — that's all inherited. Reference
implementations: `fenix/aliceblue.py` and `fenix/zerodha.py`.

## What paper_mode does

When a broker is constructed with `{"paper_mode": True}` in its config,
every order-entry and read method is routed to an in-process simulator
(`fenix.paper.client.PaperExecutionClient`) instead of issuing HTTP calls.
Market ticks fed in via the inherited `on_tick()` method drive fills,
position updates, and PnL inside the simulator's `MatchingEngine` (one
per token).

## Files to read first (do this before writing any code)

1. `fenix/base/broker.py` — confirm the paper-mode plumbing is already
   there. Skim **specifically**:
   - The top-level `from fenix.paper.client import PaperExecutionClient`
   - The paper-mode block at the end of `Broker.__init__`
   - The `on_tick()` method just before `describe()`

2. `fenix/aliceblue.py` — the reference broker. Read **specifically**:
   - Lines ~654–657: the paper-mode short-circuit in `authenticate()`
   - The `if self.paper_mode and self._paper is not None:` guards at
     the top of every routed method (search for `paper_mode and self._paper`)

3. `fenix/paper/client.py` — the `PaperExecutionClient` API. Look at the
   public methods (`on_tick`, `place_order`, `modify_order`, `cancel_order`,
   `square_off_position`, `fetch_orderbook`, `fetch_tradebook`,
   `fetch_order`, `fetch_order_history`, `fetch_positions`,
   `fetch_holdings`, `fetch_margin_limits`, `fetch_profile`). You only
   need to know which kwargs each one accepts.

## What to change in `fenix/zerodha.py`

### 1. `authenticate()` short-circuit

At the very top of `authenticate()`, before any other logic:

```python
if self.paper_mode:
    self._headers = {"paper": "true"}
    return self._headers
```

That's it for `__init__` / auth. **Do not** add a paper block to
`__init__`, **do not** import `PaperExecutionClient`, **do not** define
`on_tick` — the base class handles all of that.

### 2. Add paper short-circuit guards to each routed method

For **each** method below that exists on this broker, add a
short-circuit guard as the FIRST statement (before any HTTP-related
work). The method names below match the unified Fenix surface — some
brokers omit some of them, which is fine; just skip what isn't there.

| Broker method | Paper routing |
|---|---|
| `place_order` | `return self._paper.place_order(...)` — pass through every kwarg you have |
| `modify_order` | `return self._paper.modify_order(...)` |
| `cancel_order` | `return self._paper.cancel_order(...)` |
| `square_off_position` | `return self._paper.square_off_position(...)` |
| `exit_bracket_order` | `self._paper.cancel_order(order_id=order_id); return self._paper.fetch_order(order_id)` |
| `fetch_raw_orderbook` | `return self._paper.fetch_orderbook()` |
| `fetch_raw_order` | `return self._paper.fetch_order(order_id)` |
| `fetch_raw_order_history` | `return self._paper.fetch_order_history(order_id)` |
| `fetch_orderbook` | `return self._paper.fetch_orderbook()` |
| `fetch_tradebook` | `return self._paper.fetch_tradebook()` |
| `fetch_order` | `return self._paper.fetch_order(order_id)` |
| `fetch_order_history` | `return self._paper.fetch_order_history(order_id)` |
| `fetch_day_positions` | `return self._paper.fetch_positions()` |
| `fetch_net_positions` | `return self._paper.fetch_positions()` |
| `fetch_holdings` | `return self._paper.fetch_holdings()` |
| `fetch_margin_limits` | `return self._paper.fetch_margin_limits()` |
| `fetch_profile` | `return self._paper.fetch_profile()` |

Each guard is exactly this shape:

```python
if self.paper_mode and self._paper is not None:
    return self._paper.<method>(<kwargs>)
```

**Signature gotchas:**

- If this broker's method DOESN'T accept `extra_params` but the paper
  client does, just don't pass it.
- If this broker's method accepts extras the paper client doesn't (e.g.
  `raw_order_json`), pass them through — the paper client tolerates
  unknown kwargs only where the API documents them; check
  `fenix/paper/client.py` to be sure. Where it doesn't accept the kwarg,
  drop it from the paper call.
- Token-loading methods (`load_equity_tokens`, `load_fno_tokens`, etc.)
  are intentionally NOT routed — they download public contract data and
  work fine without auth.

### 3. Do NOT touch

- The token-loading methods
- The `_parse_*` helpers
- The `_build_*_payload` helpers
- The `STANDARD_MAPS` / `REQUEST_MAPS` / `_API` dictionaries
- The error-handling code paths
- The broker's `__init__` — base class handles paper-mode setup
- `on_tick` — inherited from `Broker`

### 4. `_AUTH_CONTEXT_KEYS` (only if your broker reads from `_auth_context`)

If your broker has `_AUTH_CONTEXT_KEYS = ("user_id", ...)` declared on
the class and any **non-routed** code path reads
`self._auth_context["user_id"]` before `authenticate()` runs, you get
correct defaults for free — the base `__init__` pre-seeds those keys
with `paper_client_id`. You only need to add the keys to
`_AUTH_CONTEXT_KEYS` if they aren't there already.

## Verify

After editing, copy the smoke test at `tests/test_zerodha_paper.py`
to `tests/test_<broker>_paper.py`, swap the import/class name, and run
it. All 14 scenarios should pass.

For brokers that don't expose `square_off_position`, test 13 calls
`broker._paper.square_off_position(...)` directly — copy that pattern
if needed.

If any scenario fails, the failure points to the exact guard that
wasn't wired correctly — fix that one, don't paper over it by relaxing
the assertion.

When you're done, report:

- The list of methods you added a guard to (one line per method)
- Any methods on this broker that DON'T appear in the table above (so
  the user can decide whether they also need a guard)
- The smoke-test result (X/14 passed)
- Anything you noticed that diverges from `aliceblue.py` /
  `zerodha.py` and why
