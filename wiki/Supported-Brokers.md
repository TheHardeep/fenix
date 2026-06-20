# Supported Brokers

Fenix 2.0 currently exposes 15 broker adapters.

| Class | Broker id | Broker | Status |
| --- | --- | --- | --- |
| `AliceBlue` | `aliceblue` | AliceBlue | Supported |
| `AngelOne` | `angelone` | Angel One | Supported |
| `AnandRathi` | `anandrathi` | Anand Rathi | Supported |
| `Dhan` | `dhan` | Dhan | Supported |
| `Finvasia` | `finvasia` | Finvasia / Shoonya | Supported |
| `FivePaisa` | `fivepaisa` | 5paisa | Supported |
| `Fyers` | `fyers` | Fyers | Supported |
| `Groww` | `groww` | Groww | Supported |
| `Iifl` | `iifl` | IIFL | Supported |
| `KotakNeo` | `kotakneo` | Kotak Neo | Supported |
| `MasterTrust` | `mastertrust` | Master Trust | Supported |
| `MotilalOswal` | `motilaloswal` | Motilal Oswal | Supported |
| `Symphony` | `symphony` | Symphony / JM Financial-style deployments | Supported |
| `Upstox` | `upstox` | Upstox | Supported |
| `Zerodha` | `zerodha` | Zerodha | Supported |

## Programmatic Registry

```python
import fenix

print(fenix.brokers)
```

The registry is derived from the broker classes exported by `fenix.__init__`, so
it stays aligned with the public API.

## Shared v2 Capabilities

All broker adapters inherit the shared `Broker` base, including:

- Generated order helpers such as `market_order`, `limit_order`, `sl_order`,
  `slm_order`, and their buy/sell variants.
- `paper_mode=True` setup for adapters that route methods to the paper engine.
- Rate-limit token buckets when the adapter defines `rateLimits`.
- Redacted request/response logging.
- Last HTTP and paper-mode diagnostic snapshots.

Broker APIs still differ. A method can exist on the common surface but be
limited by the broker's live API, available exchanges, product support, or
authentication rules. Use the relevant broker adapter as the source of truth for
live behavior.

## Added In v2.0

- `AnandRathi`
- `Dhan`
- `Groww`

## Removed In v2.0

The following v1 modules are no longer part of the supported broker surface:

- `choice`
- `kotak`
- `kunjee`
- `vpc`

If your code imported any of those modules directly, update it to one of the
supported broker adapters listed above.
