# Installation

Fenix is a pure-Python package published on PyPI. It targets **Python 3.9+** and works on
Windows, macOS, and Linux.

## Install from PyPI

```bash
pip install fenix
```

To upgrade an existing installation to the latest release:

```bash
pip install --upgrade fenix
```

> [!TIP] Use a virtual environment
> Install Fenix into a project-local virtual environment so its dependencies never collide
> with other projects.
> ```bash
> python -m venv .venv
> # Windows
> .venv\Scripts\activate
> # macOS / Linux
> source .venv/bin/activate
> pip install fenix
> ```

## Dependencies

Fenix builds on a small, well-known set of runtime libraries, installed automatically by `pip`:

| Package | Used for |
|---------|----------|
| `requests` | The HTTP session that backs every broker call. |
| `pyotp` | Generating time-based one-time passwords (TOTP) during login. |
| `python-dateutil` | Parsing and normalizing broker expiry/timestamp formats. |

No native extensions are required, so there is nothing to compile.

## Verify the installation

Import the package and print the registry of available broker classes:

```python
import fenix

print(fenix.__version__)
print(fenix.brokers)
```

```text
1.0.5
['AliceBlue', 'AngelOne', 'AnandRathi', 'Dhan', 'Finvasia', 'FivePaisa',
 'Fyers', 'Groww', 'Iifl', 'KotakNeo', 'MasterTrust', 'MotilalOswal',
 'Symphony', 'Upstox', 'Zerodha']
```

`fenix.brokers` is derived from the broker classes the package actually exports, so it always
reflects exactly what your installed version supports.

## Import styles

Every broker is exported both as a **class** (PascalCase) and is reachable through the package
namespace. Pick whichever reads best for you:

```python
# Import the class directly
from fenix import Zerodha
broker = Zerodha()

# …or reach it through the package
import fenix
broker = fenix.AngelOne()

# Constants and errors are re-exported at the top level too
from fenix import constants, errors
from fenix.base.constants import Side, Product, OrderType
```

> [!INFO] What gets exported
> `fenix.__all__` is assembled from the base `Broker` class, the broker registry, and the
> public symbols of [`constants`](#/constants) and [`errors`](#/errors). Everything you need
> for day-to-day use is importable straight from the top-level `fenix` package.

## Next steps

<div class="card-grid">
  <a class="doc-card" href="#/quickstart"><span class="dc-title">Quickstart</span><span class="dc-desc">Authenticate, load tokens, and place your first order.</span></a>
  <a class="doc-card" href="#/authentication"><span class="dc-title">Authentication</span><span class="dc-desc">Create access tokens and reuse them between runs.</span></a>
  <a class="doc-card" href="#/paper-mode"><span class="dc-title">Paper Mode</span><span class="dc-desc">Try everything safely with no live API calls.</span></a>
</div>
