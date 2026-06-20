# Motilal Oswal

Motilal Oswal broker adapter for the Fenix trading interface.

| | |
|---|---|
| **Class** | `fenix.MotilalOswal` |
| **`id`** | `motilaloswal` |
| **Module** | `fenix/motilaloswal.py` |
| **Inherits from** | [`fenix.Symphony`](#/broker-symphony) |
| **Broker API docs** | [https://developers.symphonyfintech.in/doc/interactive](https://developers.symphonyfintech.in/doc/interactive) |
| **Auth params** | `api_key`, `api_secret` |
| **Transport** | Symphony/XTS Interactive API hosted by Motilal Oswal |

Motilal Oswal hosts the Symphony/XTS Interactive API under its own domain (`moxtsapi.motilaloswal.com`). The adapter is a thin subclass of [`Symphony`](#/broker-symphony) that overrides only the server hosts — every endpoint path, auth flow, contract-master parser, order/position/holding/funds method, rate-limit group, and unified JSON shape is inherited unchanged.

```python
class MotilalOswal(Symphony):
    id = "motilaloswal"
    _API = {**Symphony._API, "servers": { ... Motilal hosts ... }}
```

Because `get_url` builds every request URL from `servers[...] + paths[...]['path']` and the base class deep-copies `servers` per instance, the dynamic-base rewrite that `Symphony.authenticate()` applies after `HostLookup` stays isolated to each broker instance.

## What Changes vs. Symphony

| Aspect | Motilal Oswal | Source of truth |
|--------|---------------|-----------------|
| `id` | `"motilaloswal"` (re-branded in `describe()`) | This module. |
| `_API["servers"]` | Overridden to point at `moxtsapi.motilaloswal.com:3000`. | This module. |
| `_API["paths"]` | Inherited verbatim from `Symphony`. | [`broker-symphony`](#/broker-symphony). |
| Auth flow | Symphony HostLookup → API-key session. | [`broker-symphony`](#/broker-symphony). |
| Order/portfolio methods | All inherited unchanged. | [`broker-symphony`](#/broker-symphony). |
| Rate limits | Inherited from Symphony's `rateLimits`. | [`broker-symphony`](#/broker-symphony). |

## Authentication

Use the same API-key flow documented for [Symphony](#/broker-symphony); only the class name changes.

```python
from fenix import MotilalOswal

broker = MotilalOswal()
headers = broker.authenticate(params={
    "api_key": "your-app-key",
    "api_secret": "your-secret-key",
})
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `params` | Required when `headers` is not supplied | Dict containing `api_key` and `api_secret`. |
| `headers` | Optional | Reuses a previously authenticated header dict. |
| `force` | Optional | When `True`, ignores cached headers and runs the login flow again. |

Returned headers include `Content-Type` and `Authorization`; the returned dict also includes the authenticated `user_id`. After login, `Symphony.authenticate()` rewrites this instance's `interactive` and `market_data` servers to the `connectionString` returned by Motilal Oswal's HostLookup — the override here just supplies the initial bootstrap host.

## Paper Mode

```python
from fenix import MotilalOswal

broker = MotilalOswal(config={"paper_mode": True})
broker.authenticate()
```

## Instrument Tokens, Orders, Positions, Account

Identical to the parent adapter. See the corresponding sections in [Symphony](#/broker-symphony):

- **Instrument Tokens** — `load_equity_tokens`, `load_index_tokens`, `load_fno_tokens`, `load_mcx_tokens`, `load_cds_tokens`, token record fields, and exchange segment codes (`NSECM`, `NSEFO`, `MCXFO`, ...).
- **Placing Orders** — `place_order()` parameters and bracket-order routing via `target`.
- **Order Management** — `fetch_raw_orderbook`, `fetch_orderbook`, `fetch_tradebook`, `fetch_order`, `fetch_order_history`, `modify_order`, `cancel_order`.
- **Positions And Account** — `fetch_day_positions`, `fetch_net_positions`, `position_convert`, `fetch_holdings`, `fetch_margin_limits`, `fetch_profile`.

## Endpoints

**Servers** (overridden on this subclass)

| Name | Base URL |
|------|----------|
| `interactive` | `https://moxtsapi.motilaloswal.com:3000/interactive` |
| `hostlookup` | `https://moxtsapi.motilaloswal.com:3000` |
| `market_data` | `https://moxtsapi.motilaloswal.com:3000/apimarketdata` |
| `market_data_binary` | `https://moxtsapi.motilaloswal.com:3000/apibinarymarketdata` |

**Paths** — inherited from Symphony. See the [Symphony endpoints table](#/broker-symphony) for the full list (`hostlookup`, `access_token`, `place_order`, `place_order_bracket`, `modify_order`, `cancel_order`, `order_history`, `orderbook`, `tradebook`, `positions`, `position_convert`, `holdings`, `profile`, `rms_limits`, `instruments`, `instruments_binary`, `indices`).

The `interactive` and `market_data` hosts above are the *bootstrap* values written into `_API["servers"]`. After a successful `authenticate()`, Symphony's HostLookup step replaces them on this instance with the `connectionString` Motilal Oswal returns, so subsequent request URLs may point at a different host than the one shown here.

---

See [Authentication](#/authentication), [Instrument Tokens](#/tokens), [Orders](#/orders), and [Unified JSON](#/unified-json) for the shared contracts used by every Fenix broker adapter, and [Symphony](#/broker-symphony) for the full behavior this adapter inherits.
