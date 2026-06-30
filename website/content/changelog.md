# Changelog

Release notes for the Fenix library. Read the version you have installed with
`fenix.__version__`.

## 2.0.2 — current

*Released 2026-06-27.*

- **Fixed currency exchange-code constants** that were not being standardized correctly.
  `CDS` now maps to NSE Currency Derivatives and `BCD` to BSE Currency Derivatives in the
  [constants](#/constants) layer.

## 2.0.1.post0

*Released 2026-06-22.*

- **Added the Fenix developer documentation website** — the site you are reading now, covering
  the unified API, every broker adapter, and the Pro tier.
- **Fixed standardizations and typos in `constant.py`** so exchange and segment codes resolve
  consistently across brokers.
- **Added a PyPI release workflow** and corrected README assets so they render on the PyPI
  project page.

## 2.0.0

*Released 2026-06-20.*

The modern Fenix architecture, documented across this site:

- **Unified standard JSON** for every read — [orders](#/unified-json), positions, holdings,
  RMS, and profile share one schema across all brokers.
- **Metadata-driven brokers** via [`describe()`](#/describe), with every setting overridable
  per instance through `config`.
- **Centralized endpoints** in [`_API`](#/api-endpoints) resolved by `get_url()`.
- **Two-way translation maps** ([`REQUEST_MAPS` / `STANDARD_MAPS`](#/maps)) with validating
  helpers.
- **Token-bucket [rate limiting](#/rate-limiting)** per endpoint group, including multi-window
  limits.
- **[Logging with secret redaction](#/logging)** and last-response capture.
- **Structured [error hierarchy](#/errors)** with HTTP-status mapping and rich context.
- **Built-in [paper mode](#/paper-mode)** — a tick-driven matching engine with realistic fills
  and PnL, no live calls.
- **New AnandRathi, Dhan, and Groww broker adapters**; removed the deprecated `choice`, `kotak`,
  `kunjee`, and `vpc` modules.
- **PEP 8 naming throughout** and packaging updated for Python ≥ 3.10 with PEP 561 type data.
- **15+ [broker adapters](#/brokers)** behind one interface.

## Versioning

Fenix follows semantic versioning (`MAJOR.MINOR.PATCH`):

| Bump | Meaning |
|------|---------|
| MAJOR | Backwards-incompatible changes to the unified API. |
| MINOR | New brokers or capabilities, backwards-compatible. |
| PATCH | Fixes and adapter updates. |

```python
import fenix
print(fenix.__version__)   # e.g. "2.0.2"
```

## Staying current

```bash
pip install --upgrade fenix
```

Because instrument masters change daily and brokers revise their APIs, keep Fenix updated and
re-download [instrument tokens](#/tokens) each trading day.

> [!INFO] Source & issues
> Fenix is developed in the open. Browse the source, file issues, and read the wiki on
> [GitHub](https://github.com/TheHardeep/fenix). The library is licensed under **GPLv3**.
