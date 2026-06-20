<p align="center">
  <img src="https://github.com/TheHardeep/fenix/releases/download/2.0.0/FenixLogo.png" alt="Fenix" width="160">
</p>

# Fenix Wiki

Fenix is a Python trading library for Indian financial markets. Version 2.0
adds a first-class paper-trading engine, a refactored broker foundation, updated
broker support, Python 3.10+ packaging, rate-limit throttling, and redacted
diagnostic logging.

## Start Here

- [Install](https://github.com/TheHardeep/fenix/wiki/Install)
- [Supported Brokers](https://github.com/TheHardeep/fenix/wiki/Supported-Brokers)
- [Manual](https://github.com/TheHardeep/fenix/wiki/Manual)

## Manual Sections

- [Overview](https://github.com/TheHardeep/fenix/wiki/Manual#overview)
- [Supported Brokers](https://github.com/TheHardeep/fenix/wiki/Manual#supported-brokers)
- [Basic Usage](https://github.com/TheHardeep/fenix/wiki/Manual#basic-usage)
- [Paper Trading](https://github.com/TheHardeep/fenix/wiki/Manual#paper-trading)
- [Rate Limits](https://github.com/TheHardeep/fenix/wiki/Manual#rate-limits)
- [Authentication](https://github.com/TheHardeep/fenix/wiki/Manual#authentication)
- [Instrument Tokens](https://github.com/TheHardeep/fenix/wiki/Manual#instrument-tokens)
- [Order Methods](https://github.com/TheHardeep/fenix/wiki/Manual#order-methods)
- [Account and Order Reads](https://github.com/TheHardeep/fenix/wiki/Manual#account-and-order-reads)
- [Constants](https://github.com/TheHardeep/fenix/wiki/Manual#constants)
- [Logging and Diagnostics](https://github.com/TheHardeep/fenix/wiki/Manual#logging-and-diagnostics)
- [Migration Notes](https://github.com/TheHardeep/fenix/wiki/Manual#migration-notes)

## New In v2.0

- Paper mode through `BrokerClass({"paper_mode": True})`.
- Tick-driven fills with `on_tick()`.
- Shared token-bucket rate limiter configured per broker.
- Redacted HTTP and paper-mode debug logs.
- Last request/response snapshots for troubleshooting.
- New broker adapters: `AnandRathi`, `Dhan`, and `Groww`.

## Release Links

- [GitHub release v2.0.0](https://github.com/TheHardeep/fenix/releases/tag/2.0.0)
- [PyPI package](https://pypi.org/project/fenix/)
