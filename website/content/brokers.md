# Supported Brokers

Fenix ships adapters for **15+ Indian brokers**, each exposing the identical [unified
API](#/orders). Switching brokers is a one-word change — instantiate a different class.

## The registry

Read the live list of available broker classes at runtime:

```python
import fenix
print(fenix.brokers)
# ['AliceBlue', 'AngelOne', 'AnandRathi', 'Dhan', 'Finvasia', 'FivePaisa',
#  'Fyers', 'Groww', 'Iifl', 'KotakNeo', 'MasterTrust', 'MotilalOswal',
#  'Symphony', 'Upstox', 'Zerodha']
```

`fenix.brokers` is derived from the exported classes, so it always matches your installed
version exactly.

## Supported brokers

| Class | Broker | Reference |
|-------|--------|-----------|
| `AliceBlue` | AliceBlue | [Adapter reference ›](#/broker-aliceblue) |
| `AngelOne` | Angel One | [Adapter reference ›](#/broker-angelone) |
| `AnandRathi` | Anand Rathi | [Adapter reference ›](#/broker-anandrathi) |
| `Dhan` | Dhan | [Adapter reference ›](#/broker-dhan) |
| `Finvasia` | Finvasia (Shoonya) | [Adapter reference ›](#/broker-finvasia) |
| `FivePaisa` | 5paisa | [Adapter reference ›](#/broker-fivepaisa) |
| `Fyers` | Fyers | [Adapter reference ›](#/broker-fyers) |
| `Groww` | Groww | [Adapter reference ›](#/broker-groww) |
| `Iifl` | IIFL Securities | [Adapter reference ›](#/broker-iifl) |
| `KotakNeo` | Kotak Neo | [Adapter reference ›](#/broker-kotakneo) |
| `MasterTrust` | Master Trust | [Adapter reference ›](#/broker-mastertrust) |
| `MotilalOswal` | Motilal Oswal | [Adapter reference ›](#/broker-motilaloswal) |
| `Symphony` | Symphony | [Adapter reference ›](#/broker-symphony) |
| `Upstox` | Upstox | [Adapter reference ›](#/broker-upstox) |
| `Zerodha` | Zerodha (Kite Connect) | [Adapter reference ›](#/broker-zerodha) |

> [!INFO] More brokers over time
> The roster grows release to release. The blueprint every adapter follows is documented in
> [Adding a Broker](#/add-broker) — adapters built to that contract drop straight into the
> unified API.

## Switching brokers

Because the interface is uniform, the only broker-specific things you touch are the class name
and the credentials (`tokenParams`):

```python
from fenix import Zerodha, AngelOne, Fyers

for cls in (Zerodha, AngelOne, Fyers):
    broker = cls()
    print(broker.id, "needs:", broker.tokenParams)
```

```python
# The same strategy function works for any broker instance
def run(broker, creds):
    broker.authenticate(params=creds)
    broker.load_fno_tokens()
    c = broker.token_json["Options"]["NFO"]["NIFTY"][0]
    return broker.limit_order(token_dict=c, side="BUY", price=152.0,
                              quantity=75, unique_id="entry-1")
```

## Capabilities differ per broker

Brokers don't all support the same operations. Inspect a broker's [`has`](#/orders) registry to
see which order methods it offers, and catch [`NotSupported`](#/errors) when calling
optional ones:

```python
broker = AngelOne()
print({k: v for k, v in broker.has.items() if k.endswith("order")})
```

## Per-broker credentials

Each broker's `tokenParams` lists the exact credentials its login flow needs. A few examples of
the *shape* you'll provide (always confirm via `broker.tokenParams`):

```python
# Zerodha
{"user_id": ..., "password": ..., "totpstr": ..., "api_key": ..., "api_secret": ...}
```

See [Authentication](#/authentication) for the full login and session-reuse workflow.
