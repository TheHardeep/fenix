# Instrument Tokens

To trade an instrument, you need the broker's token for it. Each broker publishes an
**instrument master** — a large CSV/JSON of every tradable contract — in its own format. Fenix
downloads that master and reshapes it into a **standardized lookup** so the same indexing works
across brokers.

## The `load_*` methods

Each adapter exposes a family of loaders, one per market segment. They download the master (or
accept pre-fetched `data`) and return a tuple: a **nested unified map** and a **flat
token→record lookup**.

| Method | Segments loaded |
|--------|-----------------|
| `load_equity_tokens()` | NSE + BSE cash equity |
| `load_index_tokens()` | Index instruments (NSE, BSE, MCX) |
| `load_fno_tokens()` | NSE F&O (NFO) + BSE F&O (BFO) — futures & options |
| `load_mcx_tokens()` | MCX commodity futures & options |
| `load_cds_tokens()` | Currency derivatives (CDS) |
| `load_nco_tokens()` | NSE commodity (NCO) futures & options |

```python
fno, all_fno = broker.load_fno_tokens()
eq,  all_eq  = broker.load_equity_tokens()
idx, all_idx = broker.load_index_tokens()
```

Each loader also **populates the broker instance** as a side effect, accumulating into
`broker.token_json` (the nested view) and `broker.alltoken_json` (the flat view), so you can
load several segments and then read everything off the instance.

## The two shapes returned

### Nested map → `token_json`

The first element is organized by **segment → exchange/underlying → contract**. This is how you
look up an instrument by its human identity.

```python
broker.token_json = {
    "Equity":  { "NSE": {...}, "BSE": {...} },                # symbol → record
    "Indices": { "NSE": {...}, "BSE": {...}, "MCX": {...} },
    "Futures": { "NFO": {...}, "BFO": {...} },                # underlying → [records]
    "Options": { "NFO": {...}, "BFO": {...} },                # underlying → [records]
}
```

Equity and index entries are keyed by trading symbol; futures and options are keyed by
**underlying** (e.g. `"NIFTY"`) and hold a **list** of contracts (every strike/expiry):

```python
# equity: symbol → one record
reliance = broker.token_json["Equity"]["NSE"]["RELIANCE"]

# options: underlying → list of contracts
nifty_options = broker.token_json["Options"]["NFO"]["NIFTY"]
contract = nifty_options[0]
```

### Flat lookup → `alltoken_json`

The second element is a flat dictionary keyed by `"{exchange_token}_{exchange}"`, for reverse
lookups — e.g. resolving a token you received on an order update back to its contract:

```python
broker.alltoken_json["256265_NSE"]    # → the record for that token on NSE
```

## The record schema

Loaders normalize every broker's columns into a consistent record. The fields depend on the
instrument type.

### Equity / index record

```json
{
  "Token": "256265",
  "ExToken": "256265",
  "Exchange": "NSE",
  "Symbol": "RELIANCE",
  "ScriptName": "RELIANCE",
  "LotSize": "1",
  "TickSize": "0.05"
}
```

### Futures record

```json
{
  "Token": "...",
  "ExToken": "...",
  "Exchange": "NFO",
  "Root": "NIFTY",
  "Symbol": "NIFTY24JUNFUT",
  "LotSize": "75",
  "TickSize": "0.05",
  "Expiry": "2024-06-27",
  "ScriptName": "NIFTY 27-Jun-2024 FUT"
}
```

### Option record

Option records add the strike and option type, so you can pick a specific contract:

```json
{
  "Token": "...",
  "Exchange": "NFO",
  "Root": "NIFTY",
  "Symbol": "NIFTY2462724500CE",
  "Option": "CE",
  "StrikePrice": "24500",
  "Expiry": "2024-06-27",
  "LotSize": "75",
  "TickSize": "0.05"
}
```

The `place_order` and convenience methods take one of these records as `token_dict` — that's all
the instrument identity an order needs.

```python
contract = broker.token_json["Options"]["NFO"]["NIFTY"][0]
broker.limit_order(token_dict=contract, side="BUY", price=152.0,
                   quantity=int(contract["LotSize"]), unique_id="entry-1")
```

> [!TIP] Strikes are normalized
> Fenix cleans strike values when shaping option records — `104.0` becomes `"104"`, `104.75`
> stays `"104.75"`, and non-option sentinel strikes are dropped — so you never juggle stray
> trailing zeros when matching a strike.

## How the loaders shape the data

Internally each loader streams the instrument master, classifies each row by its segment, and
builds the normalized record. The F&O loader, for example, splits NFO/BFO and futures/options
into separate buckets and indexes each by underlying while also registering the flat token key:

```python
for row in reader:
    segment = row["segment"]
    if segment in ("NFO-OPT", "BFO-OPT"):
        record = self.format_opt_dict(row, expiry, exdp)     # → unified option record
        opt_nse[row["name"]].append(record)                  # group by underlying
        token_dict[f"{row['exchange_token']}_NFO"] = record  # flat reverse lookup
    elif segment in ("NFO-FUT", "BFO-FUT"):
        record = self.format_fut_dict(row, expiry, exdp)     # → unified future record
        fut_nse[row["name"]].append(record)
# …then merged into self.token_json / self.alltoken_json and returned
```

The helpers `format_opt_dict()` and `format_fut_dict()` are where each broker's raw columns are
mapped onto the standardized field names shown above.

## Expiry dates

F&O loaders need the list of available expiries. Fenix downloads and caches them from the
exchanges, with shared base-class helpers:

```python
Zerodha.download_expiry_dates_nfo(Root.NF)      # NSE expiries for NIFTY
Zerodha.download_expiry_dates_bfo(Root.SENSEX)  # BSE expiries for SENSEX
```

These prime NSE cookies as needed (`cookie_getter()`), fetch the expiry feed, filter and sort
the dates, and cache them on `expiry_dates[root]` so repeated lookups don't re-hit the
exchange.

## Pre-loading vs lazy loading

You can call the loaders explicitly up front (recommended — you control when the large download
happens) or let an adapter load on demand. Pre-loading once at startup and reusing the maps for
the rest of the session keeps your hot path free of network calls:

```python
broker = Zerodha()
broker.authenticate(params=creds)

# Pre-load everything you'll trade, once.
broker.load_equity_tokens()
broker.load_fno_tokens()

# …the rest of the session reads from broker.token_json / alltoken_json
```

> [!WARNING] Masters are large and change daily
> Instrument masters are big and are re-published each trading day (new expiries, new strikes).
> Download them fresh each day; don't pin a stale copy. A failed/garbled download raises
> [`TokenDownloadError`](#/errors).
