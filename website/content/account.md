# Account & RMS

Read your margins, risk limits, and account profile through two unified methods.

## Margins & RMS limits

`fetch_margin_limits()` returns the account's risk-management-system (RMS) view in the unified
[RMS schema](#/unified-json): margin used and available, plus cash, span, and collateral
breakdowns where the broker provides them.

```python
rms = broker.fetch_margin_limits()
print("Available:", rms["marginAvail"])
print("Used:     ", rms["marginUsed"])
```

```json
{
  "marginUsed": 48250.0,
  "marginAvail": 951750.0,
  "cashMargin": 1000000.0,
  "spanMargin": 0.0,
  "variableMargin": 0.0,
  "collateral": 0.0,
  "info": { "broker": "Zerodha" }
}
```

A common pre-trade guard:

```python
required = price * quantity
if broker.fetch_margin_limits()["marginAvail"] < required:
    raise RuntimeError("Insufficient margin for this order")
```

When the broker itself rejects an order for funds, Fenix raises
[`InsufficientFundsError`](#/errors).

## Profile

`fetch_profile()` returns the account holder's details in the unified
[Profile schema](#/unified-json):

```python
profile = broker.fetch_profile()
print(profile["clientId"], profile["name"])
print("Enabled segments:", profile["exchangesEnabled"])
```

```json
{
  "clientId": "AB1234",
  "name": "Jane Trader",
  "emailId": "jane@example.com",
  "mobileNo": "9000000000",
  "pan": "ABCDE1234F",
  "exchangesEnabled": ["NSE", "BSE", "NFO", "BFO"],
  "enabled": true,
  "info": { "broker": "Zerodha" }
}
```

Use `exchangesEnabled` to confirm a segment is active for the account before routing orders to
it.

> [!TIP] Everything has an `info` escape hatch
> Both records carry an `info` key with the broker's raw extras. If a broker exposes a field
> Fenix doesn't standardize (a specific margin sub-bucket, a KYC flag), look for it in
> `record["info"]`.
