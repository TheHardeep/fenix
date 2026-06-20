# Changelog

Release notes for the Fenix library. Read the version you have installed with
`fenix.__version__`.

## 2.0.0 — current

The current release. Highlights of the modern Fenix architecture documented across this site:

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
print(fenix.__version__)   # e.g. "2.0.0"
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
