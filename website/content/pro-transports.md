# Transport Families

Indian brokers expose live data over three different transport mechanisms. Fenix-Pro implements
all three under one package, so a single `start_websocket(...)` interface hides whether the
underlying connection is a raw WebSocket, a Socket.IO client, or an async protobuf stream.

All adapters derive from a shared `Base` that provides the HTTP `fetch` bootstrap, JSON and
datetime helpers, threading primitives, and WebSocket client construction.

## 1 · `websocket-client` family

The dominant style. Adapters build a `WebSocketApp`, run `run_forever()` on a daemon thread,
serialize outgoing messages under a lock, and parse incoming **binary** frames.

> [!INFO] Adapters
> AliceBlue · Angel One · Finvasia · 5paisa · Fyers · Kotak Neo · Master Trust · Zerodha

Typical pattern: build the WebSocket URL → store callbacks → create the app via
`Base.websocket_app(...)` → start the loop in a thread → decode binary frames →
dispatch normalized ticks.

## 2 · Socket.IO family

Adapters that connect a `socketio.Client`, register event handlers for feed-specific event
names, and subscribe/unsubscribe through broker REST APIs or socket events. Several share one
implementation:

> [!INFO] Adapters
> IIFL · Kotak · Kunjee · Motilal Oswal · Symphony · VPC
>
> **Kunjee, Motilal Oswal, Symphony, and VPC** inherit directly from `iifl` and override only
> their IDs and URLs — they are deployment variants of the same XTS/Socket.IO adapter.

Typical pattern: create a broker session or bearer token via an HTTP bootstrap → connect the
Socket.IO client → register feed event handlers → subscribe.

## 3 · `asyncio` + protobuf family

The most specialized adapter, used by **Upstox**: it requests an authorized WebSocket redirect
URL over REST, opens an async connection with `websockets.connect(...)`, and decodes **protobuf**
frames (`upstox_feed_pb2`) into dictionaries. It runs the asyncio loop on a worker thread, so
the public API stays synchronous while the transport is async.

> [!INFO] Adapter
> Upstox

## At a glance

| Family | Library | Frame format | Adapters |
|--------|---------|--------------|----------|
| WebSocket | `websocket-client` | Binary | AliceBlue, Angel One, Finvasia, 5paisa, Fyers, Kotak Neo, Master Trust, Zerodha |
| Socket.IO | `python-socketio` | Events / JSON | IIFL, Kotak, Kunjee, Motilal Oswal, Symphony, VPC |
| Async + protobuf | `websockets` + `protobuf` | Protobuf | Upstox |

## Concurrency model

Every adapter exposes the same synchronous, callback-oriented public API — what varies is the
machinery underneath, tuned to each transport:

- **Threaded WebSocket adapters** keep the socket on the instance, use a `Lock` to serialize
  outbound messages, an `Event` to coordinate shutdown, and run the loop on a daemon thread.
- **Socket.IO adapters** lean on the client library's own event loop, so subscribe/unsubscribe
  calls are simple event emits.
- **Upstox** runs an asyncio loop on a worker thread — a hybrid of a synchronous public API and
  async internals, so callers never see `async`/`await`.

> [!TIP] One interface, three transports
> Whichever family the broker uses, the call site is the same: construct, `start_websocket(...)`,
> subscribe, and receive normalized [TickData / Order](#/pro-contracts) dictionaries through your
> callbacks.
