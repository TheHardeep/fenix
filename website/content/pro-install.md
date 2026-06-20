# Installing Fenix-Pro

Fenix-Pro is distributed as the `fenixpro` Python package. It targets **Python 3.10+** and runs on Windows, macOS, and Linux.

> [!INFO] Source-based install
> Fenix-Pro is a paid product and is currently installed from source rather than from a public
> index. After you receive access, clone or unpack the `fenixpro` repository and either run from
> its root or add it to your `PYTHONPATH`.

## Runtime dependencies

Install the transport libraries the adapters use. Different brokers use different transports, so
install all of them for full coverage:

```bash
pip install requests pandas websocket-client python-socketio websockets protobuf
```

If your environment needs the Socket.IO client extras explicitly:

```bash
pip install "python-socketio[client]"
```

| Package | Used by |
|---------|---------|
| `websocket-client` | The raw-WebSocket adapters (Zerodha, Angel One, Fyers, …). |
| `python-socketio` | The Socket.IO adapters (IIFL and its derivatives, Kotak). |
| `websockets` | The async Upstox adapter. |
| `protobuf` | Decoding the Upstox protobuf feed. |
| `requests` | REST bootstrap calls before a feed starts. |
| `pandas` | Datetime/feed helpers. |

## Run from source

If your Python process starts in the repository root, `fenixpro` is importable directly:

```bash
cd path/to/fenixpro
python -c "import fenixpro; print(fenixpro.__version__)"
```

```text
1.0.0
```

Or add the repository to `PYTHONPATH`:

```bash
# Windows (PowerShell)
$env:PYTHONPATH = "C:\path\to\fenixpro;$env:PYTHONPATH"

# macOS / Linux
export PYTHONPATH="/path/to/fenixpro:$PYTHONPATH"
```

## Verify

```python
import fenixpro
print(fenixpro.__version__)   # 1.0.0
print(fenixpro.brokers)       # the available adapter names
```

## Next steps

<div class="card-grid">
  <a class="doc-card" href="#/pro-quickstart"><span class="dc-icon">⚡</span><span class="dc-title">Quickstart</span><span class="dc-desc">Connect and stream your first feed.</span></a>
  <a class="doc-card" href="#/pro-pricing"><span class="dc-icon">💳</span><span class="dc-title">Pricing &amp; Plans</span><span class="dc-desc">Pick the tier for your volume.</span></a>
</div>
