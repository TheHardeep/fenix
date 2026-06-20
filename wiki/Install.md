# Install

Fenix 2.0 requires Python 3.10 or newer.

## PyPI

Install the latest published version:

```shell
pip install fenix
```

Install v2.0.0 explicitly:

```shell
pip install fenix==2.0.0
```

Package page: [fenix on PyPI](https://pypi.org/project/fenix/)

## Verify Installation

```python
import fenix

print(fenix.__version__)
print(fenix.brokers)
```

Expected version for this release:

```text
2.0.0
```

## Upgrade From 1.x

```shell
pip install --upgrade fenix
```

Important v2.0 changes:

- Python 3.8 and 3.9 are no longer supported.
- Deprecated broker modules `choice`, `kotak`, `kunjee`, and `vpc` were removed.
- New broker adapters include `AnandRathi`, `Dhan`, and `Groww`.
- Paper trading is now available through `paper_mode=True`.
- Rate-limit throttling is enabled by default where broker adapters define
  `rateLimits`.
- Debug logging now redacts sensitive values and records last request/response
  snapshots for troubleshooting.

## Optional Runtime Configuration

Most broker instances accept operational settings in the same config dictionary
as credentials:

```python
import logging
from fenix import AliceBlue

broker = AliceBlue({
    "paper_mode": False,
    "enableRateLimit": True,
    "logger": logging.getLogger("fenix"),
    "verbose": False,
})
```

For paper trading:

```python
broker = AliceBlue({
    "paper_mode": True,
    "paper_client_id": "PAPER001",
    "paper_starting_margin": 1000000,
    "paper_log_history_size": 100,
})
```

## Development Install

From a local checkout:

```shell
pip install -e .
```

Build distributions locally:

```shell
python -m build --sdist --wheel
```
