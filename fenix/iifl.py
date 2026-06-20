from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import TYPE_CHECKING
from typing import Any
from typing import NoReturn

from requests.exceptions import HTTPError

from fenix.base.broker import Broker

from fenix.base.constants import Side
from fenix.base.constants import OrderType
from fenix.base.constants import ExchangeCode
from fenix.base.constants import Product
from fenix.base.constants import Validity
from fenix.base.constants import Variety
from fenix.base.constants import Status
from fenix.base.constants import Order
from fenix.base.constants import Position
from fenix.base.constants import Profile
from fenix.base.constants import Root
from fenix.base.constants import WeeklyExpiry
from fenix.base.constants import UniqueID


from fenix.base.errors import (
    AuthenticationError,
    BrokerError,
    InsufficientFundsError,
    InsufficientHoldingsError,
    InputError,
    InvalidOrderError,
    OrderNotFoundError,
    PermissionDeniedError,
    ResponseError,
    TokenDownloadError,
)

if TYPE_CHECKING:
    from requests.models import Response


class Iifl(Broker):
    """Iifl broker adapter for the Fenix trading interface."""

    _API = {
        "doc": "https://ttblaze.iifl.com/doc/interactive/",
        "marketdata_doc": "https://ttblaze.iifl.com/doc/marketdata",
        "servers": {
            "interactive": "https://ttblaze.iifl.com/interactive",
            "market_data": "https://ttblaze.iifl.com/apimarketdata",
        },
        "paths": {
            # --- Auth Flow ---
            "access_token": {
                "server": "interactive",
                "path": "/user/session",
            },

            # --- Order & Portfolio Flow ---
            "place_order": {
                "server": "interactive",
                "path": "/orders",
            },
            "modify_order": {
                "server": "interactive",
                "path": "/orders",
            },
            "cancel_order": {
                "server": "interactive",
                "path": "/orders",
            },
            "orderbook": {
                "server": "interactive",
                "path": "/orders",
            },
            "tradebook": {
                "server": "interactive",
                "path": "/orders/trades",
            },
            "positions": {
                "server": "interactive",
                "path": "/portfolio/positions",
            },
            "holdings": {
                "server": "interactive",
                "path": "/portfolio/holdings",
            },
            "rms_limits": {
                "server": "interactive",
                "path": "/user/balance",
            },
            "profile": {
                "server": "interactive",
                "path": "/user/profile",
            },

            # --- Market Data ---
            "index_data": {
                "server": "market_data",
                "path": "/instruments/indexlist",
            },
            "instruments": {
                "server": "market_data",
                "path": "/instruments/master",
            },
        }
    }

    STANDARD_MAPS = {
        "side": {
            "BUY": Side.BUY,
            "SELL": Side.SELL,
        },
        "order_type": {
            "Market": OrderType.MARKET,
            "Limit": OrderType.LIMIT,
            "StopLimit": OrderType.SL,
            "StopMarket": OrderType.SLM,
        },
        "status": {
            "PendingNew": Status.PENDING,
            "PendingReplace": Status.PENDING,
            "Rejected": Status.REJECTED,
            "PartiallyFilled": Status.PARTIALLY_FILLED,
            "Filled": Status.FILLED,
            "Cancelled": Status.CANCELLED,
            "Open": Status.OPEN,
            "New": Status.OPEN,
            "Replaced": Status.MODIFIED,
        },
        "exchange": {
            "NSECM": ExchangeCode.NSE,
            "BSECM": ExchangeCode.BSE,
            "NSEFO": ExchangeCode.NFO,
            "BSEFO": ExchangeCode.BFO,
            "MSECM": ExchangeCode.MCX,
            "NSECO": ExchangeCode.NCO,
            "BSECO": ExchangeCode.BCO,
        },
        "product": {
            "MIS": Product.MIS,
            "NRML": Product.NRML,
            "CNC": Product.CNC,
            "CO": Product.CO,
        },
        "validity": {
            "DAY": Validity.DAY,
            "IOC": Validity.IOC,
        },
    }

    REQUEST_MAPS = {
        "side": {
            Side.BUY: "BUY",
            Side.SELL: "SELL",
        },
        "exchange": {
            ExchangeCode.NSE: "NSECM",
            ExchangeCode.BSE: "BSECM",
            ExchangeCode.NFO: "NSEFO",
            ExchangeCode.BFO: "BSEFO",
            ExchangeCode.MCX: "MSECM",
            ExchangeCode.NCO: "NSECO",
            ExchangeCode.BCO: "BSECO",
        },
        "order_type": {
            OrderType.MARKET: "Market",
            OrderType.LIMIT: "Limit",
            OrderType.SL: "StopLimit",
            OrderType.SLM: "StopMarket",
        },
        "product": {
            Product.MIS: "MIS",
            Product.NRML: "NRML",
            Product.CNC: "CNC",
            Product.CO: "CO",
        },
        "validity": {
            Validity.DAY: "DAY",
            Validity.IOC: "IOC",
        },
    }

    _REQUIRED_AUTH_HEADER_KEYS = (
        "Content-type",
        "authorization",
    )

    _AUTH_CONTEXT_KEYS = ("user_id",)

    ERROR_CODE_KEYS = (
        "code",
    )

    ERROR_MESSAGE_KEYS = (
        "description",
        "message",
    )

    _ERROR_MESSAGES = {
        "e-user-0001": "Invalid user request.",
        "e-user-0002": "Invalid user credentials or token.",
        "e-user-0003": "User is not authorized for this request.",
        "e-user-0004": "User request could not be processed.",
        "hostlookup": "Invalid host lookup access password provided.",
    }

    _DIRECT_ERROR_CLASSES = {
        "e-user-0002": AuthenticationError,
        "e-user-0003": PermissionDeniedError,
        "hostlookup": AuthenticationError,
    }

    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "Iifl",
            "tokenParams": [
                "api_key",
                "api_secret",
            ],
            "proxies": {},
            "sensitiveLogKeys": [
                "api_key",
                "api_secret",
                "secretKey",
                "appKey",
                "token",
                "userID",
                "userId",
                "user_id",
                "authorization",
                "Content-type",
            ],
            "enableRateLimit": True,
            # Iifl runs the Symphony/XTS Interactive API, so it shares the
            # same documented rate-limit table. Buckets are keyed by the
            # ``endpoint_group`` names this adapter passes to ``fetch`` — the
            # base limiter only throttles groups it has a bucket for, so every
            # group in use is declared explicitly here.
            "rateLimits": {
                # Unified Order API Throttle Limit — 10 req/sec shared across
                # place/modify/cancel (and BO/CO/spread) order APIs.
                "orders": {"period": 1, "capacity": 10, "cost": 1.0},
                # Orderbook, Order History (/orders) and Tradebook
                # (/orders/trades) — 1 req/sec.
                "post_trade": {"period": 1, "capacity": 1, "cost": 1.0},
                # Holdings & Positions (/portfolio/*) — 1 req/sec.
                "portfolio": {"period": 1, "capacity": 1, "cost": 1.0},
                # Balance (/user/balance) & Profile (/user/profile) —
                # 1 req/sec.
                "account": {"period": 1, "capacity": 1, "cost": 1.0},
                # Login (/user/session) — not in the throttle table; kept
                # conservative.
                "auth": {"period": 1, "capacity": 1, "cost": 1.0},
                # Index list — market-data API.
                "market_data": {"period": 1, "capacity": 1, "cost": 1.0},
                # Fallback for the instrument-master download.
                "default": {"period": 1, "capacity": 1, "cost": 1.0},
            },
        }

    def __init__(self, config: dict | None = None):
        """Initialize the Iifl broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
                Pass ``{"paper_mode": True}`` to route order entry and reads
                through the in-process paper-trading engine instead of the
                Iifl API.
        """
        super().__init__(config)

    def load_index_tokens(
            self,
            data: dict[str, list] | None = None,
        ) -> tuple[dict[str, Any], dict[str, Any]]:
        """
        Download index token metadata for NSE and BSE.

        Args:
            data: Optional pre-fetched index data keyed by ``"NSE"`` and
                ``"BSE"``; fetched from the broker when not supplied.

        Returns:
            A tuple of ``({"Indices": {"NSE": ..., "BSE": ...}}, token_lookup)``.
        """
        if not data:
            params = {"exchangeSegment": 1}
            response = self.fetch(
                method="GET",
                url=self.get_url("index_data"),
                endpoint_group="market_data",
                params=params,
            )
            data_nse = self._parse_json_response(response)["result"]["indexList"]

            params = {"exchangeSegment": 11}
            response = self.fetch(
                method="GET",
                url=self.get_url("index_data"),
                endpoint_group="market_data",
                params=params,
            )
            data_bse = self._parse_json_response(response)["result"]["indexList"]
        else:
            if "NSE" not in data or "BSE" not in data:
                raise KeyError(
                    "JSON data must contain 'NSE' and 'BSE' keys"
                )

            data_nse = data["NSE"]
            data_bse = data["BSE"]

        nse_dict = {}
        bse_dict = {}
        token_dict = {}

        for i in data_nse:
            symbol, token = i.split("_")
            record = {
                "Symbol": symbol,
                "Token": int(token),
                "Exchange": "NSECM",
            }
            nse_dict[symbol] = record
            tk = f"{token}_NSE"

        for i in data_bse:
            symbol, token = i.split("_")
            record = {
                "Symbol": symbol,
                "Token": int(token),
                "Exchange": "BSECM",
            }
            bse_dict[symbol] = record
            tk = f"{token}_BSE"

        token_dict[tk] = record

        nse_dict[Root.BNF] = nse_dict["NIFTY BANK"]
        nse_dict[Root.NF] = nse_dict["NIFTY 50"]
        nse_dict[Root.FNF] = nse_dict["NIFTY FIN SERVICE"]
        nse_dict[Root.MIDCPNF] = nse_dict["NIFTY MID SELECT"]

        self.token_json["Indices"].update({
            "NSE": nse_dict,
            "BSE": bse_dict,
        })

        self.alltoken_json.update(token_dict)

        return (
            {
                "Indices": {
                    "NSE": nse_dict,
                    "BSE": bse_dict,
                },
            },
            token_dict,
        )

    def load_equity_tokens(
        self,
        data: dict[str, str]
    ) -> tuple[dict, dict]:
        """Build NSE/BSE equity token dictionaries from contract-master text.

        Args:
            data: Optional pre-fetched contract-master payload; fetched from
                the broker when not supplied.

        Returns:
            ``({"Stocks": {"NSE": ..., "BSE": ...}}, token_lookup)``.
        """
        if not data:
            response = self.fetch(
                method="POST",
                url=self.get_url("instruments"),
                endpoint_group="default",
                json={
                    "exchangeSegmentList": [
                        "NSECM",
                        "BSECM",

                    ],
                },
            )
            raw_string = self._parse_json_response(response)["result"]
        else:
            if "NSE" not in data and "BSE" not in data:
                            raise KeyError("JSON data must contain 'NSE' or 'BSE' keys")

            raw_string = data.get("NSE", "BSE")

        bse_excluded_series = {"F", "FC", "G", "GC"}
        excluded_names = {"EBANKNIFTY", "BANKNIFTY1"}
        seen_descriptions: set[str] = set()

        nse_dict: dict[str, Any] = {}
        bse_dict: dict[str, Any] = {}
        alltoken_dict: dict[str, Any] = {}

        try:
            for line in raw_string.split("\n"):
                if not line:
                    continue
                f = line.split("|")

                exchange = f[0]
                series = f[5]

                if exchange == "NSECM":
                    if series != "EQ":
                        continue
                elif exchange == "BSECM":
                    if series in bse_excluded_series:
                        continue
                else:
                    continue

                token = f[1]
                name = f[3]
                symbol = f[4]
                isin = f[15]
                desc = f[18]

                if not (isin.startswith("INE") or isin.startswith("INF")):
                    continue
                if "#-A" in symbol:
                    continue
                if "NSETEST" in name:
                    continue
                if name in excluded_names:
                    continue
                if desc in seen_descriptions:
                    continue
                seen_descriptions.add(desc)

                desc_upper = desc.upper().replace("-EQ", "")
                record = {
                    "Exchange": exchange,
                    "Token": token,
                    "Symbol": name,
                    "DisplayName": name,
                    "FreezeQty": int(float(f[10])),
                    "TickSize": f[11],
                    "LotSize": f[12],
                    "ISIN": isin,
                    "DetailedDescription": desc_upper,
                    "Series": series,
                    "PriceNumerator": int(f[16]),
                    "PriceDenominator": int(f[17]),
                }

                key = f"{name}   {desc_upper}"

                if exchange == "NSECM":
                    nse_dict[key] = record
                else:
                    bse_dict[key] = record

                alltoken_dict[f"{token}_{exchange}"] = record

            self.token_json["Equity"].update({
                "NSE": nse_dict,
                "BSE": bse_dict,
            })

            self.alltoken_json.update(alltoken_dict)

            return (
                {
                    "Equity": {"NSE": nse_dict, "BSE": bse_dict},
                },
                alltoken_dict,
            )

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc

    def load_fno_tokens(
        self,
        data: dict[str, str],
    ) -> tuple[dict, dict]:
        """Build NSE/BSE F&O token dictionaries from contract-master text."""

        if not data:
            response = self.fetch(
                method="POST",
                url=self.get_url("instruments"),
                endpoint_group="default",
                json={
                    "exchangeSegmentList": [
                        "NSEFO",
                        "BSEFO",

                    ],
                },
            )
            raw_string = self._parse_json_response(response)["result"]
        else:
            if "NFO" not in data or "BFO" not in data:
                raise KeyError("JSON data must contain 'NFO' or 'BFO' keys")

            raw_string = data.get("NFO", "BFO")
        try:
            fut_series = {"SF", "FUTSTK", "IF", "FUTIDX"}
            opt_series = {"OPTSTK", "OPTIDX", "SO", "IO"}
            dt_dict: dict[str, tuple[str, str]] = {}

            fut_nse: dict[str, list] = defaultdict(list)
            fut_bse: dict[str, list] = defaultdict(list)
            opt_nse: dict[str, list] = defaultdict(list)
            opt_bse: dict[str, list] = defaultdict(list)
            token_dict: dict[str, Any] = {}

            for line in raw_string.split("\n"):
                if not line:
                    continue

                f = line.split("|")

                exchange = f[0]
                token = f[1]
                root = f[3]
                symbol = f[4]
                series = f[5]
                freeze = int(float(f[10])) - 1
                tick = f[11]
                lot = f[12]
                expiry_raw = f[16]
                strike = f[17]

                if exchange not in ("NSEFO", "BSEFO"):
                    continue
                if "NSETEST" in root:
                    continue


                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw.split(".")[0])
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    expiry, exdp = dt_dict[expiry_raw]

                record: dict[str, Any] | None = None

                if series in fut_series:
                    if strike.endswith("SPD"):
                        continue

                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": symbol,
                        "FreezeQty": freeze,
                        "TickSize": tick,
                        "LotSize": lot,
                        "Expiry": expiry,
                        "PriceNumerator": int(f[18]),
                        "PriceDenominator": int(f[19]),
                        "DisplayName": f"{root} {exdp} FUT",
                    }

                    if exchange == "NSEFO":
                        fut_nse[root].append(record)
                    else:
                        fut_bse[root].append(record)

                elif series in opt_series:
                    option = symbol[-2:]
                    strike = self._format_strike(strike)

                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Symbol": symbol,
                        "FreezeQty": freeze,
                        "TickSize": tick,
                        "LotSize": lot,
                        "Expiry": expiry,
                        "StrikePrice": strike,
                        "Option": option,
                        "PriceNumerator": int(f[20]),
                        "PriceDenominator": int(f[21]),
                        "DisplayName": f"{root} {exdp} {strike} {option}",
                    }

                    if exchange == "NSEFO":
                        opt_nse[root].append(record)
                    else:
                        opt_bse[root].append(record)

                if record is not None:
                    token_dict[f"{token}_{exchange}"] = record

            self.token_json["Futures"].update({"NFO": fut_nse, "BFO": fut_bse})
            self.token_json["Options"].update({"NFO": opt_nse, "BFO": opt_bse})

            self.alltoken_json.update(token_dict)

            return (
                {
                    "Futures": {"NSE": dict(fut_nse), "BSE": dict(fut_bse)},
                    "Options": {"NSE": dict(opt_nse), "BSE": dict(opt_bse)},
                },
                token_dict,
            )

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc

    def load_mcx_tokens(
        self,
        data: dict[str, str],
    ) -> tuple[dict, dict]:
        """Build MCX token dictionaries from contract-master text."""
        if not data:
            response = self.fetch(
                method="POST",
                url=self.get_url("instruments"),
                endpoint_group="default",
                json={
                    "exchangeSegmentList": [
                        "MCXFO",

                    ],
                },
            )
            raw_string = self._parse_json_response(response)["result"]
        else:
            if "MCX" not in data:
                raise KeyError("JSON data must contain 'MCX' keys")

            raw_string = data.get("MCX")


        fut_mcx: dict[str, list] = defaultdict(list)
        opt_mcx: dict[str, list] = defaultdict(list)
        token_dict: dict[str, Any] = {}
        dt_dict: dict[str, tuple[str, str]] = {}

        try:
            for line in raw_string.split("\n"):
                if not line:
                    continue
                f = line.split("|")

                exchange = f[0]
                series = f[5]

                if exchange != "MCXFO":
                    continue
                if series not in ("FUTCOM", "FUTIDX", "OPTFUT", "OPTIDX"):
                    continue

                token = f[1]
                root = f[3]
                symbol = f[4]
                freeze = int(float(f[10]))
                tick = f[11]
                lot = f[12]
                expiry_raw = f[16]
                strike = f[17]

                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw.split(".")[0])
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    expiry, exdp = dt_dict[expiry_raw]

                record: dict[str, Any] | None = None

                if series in ("FUTCOM", "FUTIDX"):
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": symbol,
                        "FreezeQty": freeze,
                        "TickSize": tick,
                        "LotSize": lot,
                        "Expiry": expiry,
                        "PriceNumerator": int(f[18]),
                        "PriceDenominator": int(f[19]),
                        "DisplayName": f"{root} {exdp} FUT",
                    }
                    fut_mcx[root].append(record)

                elif series in ("OPTFUT", "OPTIDX"):
                    option = symbol[-2:]
                    strike = self._format_strike(strike)
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Symbol": symbol,
                        "FreezeQty": freeze,
                        "TickSize": tick,
                        "LotSize": lot,
                        "Expiry": expiry,
                        "StrikePrice": strike,
                        "Option": option,
                        "PriceNumerator": int(f[20]),
                        "PriceDenominator": int(f[21]),
                        "DisplayName": f"{root} {exdp} {strike} {option}",
                    }
                    opt_mcx[root].append(record)

                if record is not None:
                    token_dict[f"{token}_{exchange}"] = record

            self.token_json["Futures"].update({"MCX": fut_mcx})
            self.token_json["Options"].update({"MCX": opt_mcx})

            self.alltoken_json.update(token_dict)

            return (
                {
                    "Futures": {"MCX": dict(fut_mcx)},
                    "Options": {"MCX": dict(opt_mcx)},
                },
                token_dict,
            )

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc

    def load_cds_tokens(
        self,
        data: dict[str, str],
    ) -> tuple[dict, dict]:
        """Build CDS token dictionaries from contract-master text."""
        if not data:
            response = self.fetch(
                method="POST",
                url=self.get_url("instruments"),
                endpoint_group="default",
                json={
                    "exchangeSegmentList": [
                        "NSECD",

                    ],
                },
            )
            raw_string = self._parse_json_response(response)["result"]
        else:
            if "CDS" not in data or "BCD" not in data:
                raise KeyError("JSON data must contain 'CDS' and 'BCD' keys")

            raw_string = data.get("CDS", "BCD")

        fut_cds: dict[str, list] = defaultdict(list)
        opt_cds: dict[str, list] = defaultdict(list)
        token_dict: dict[str, Any] = {}
        dt_dict: dict[str, tuple[str, str]] = {}

        try:
            for line in raw_string.split("\n"):
                if not line:
                    continue
                f = line.split("|")

                exchange = f[0]
                series = f[5]

                if exchange != "NSECD":
                    continue
                if series not in ("FUTCUR", "OPTCUR"):
                    continue

                token = f[1]
                root = f[3]
                symbol = f[4]
                freeze = int(float(f[10]))
                tick = f[11]
                lot = f[12]
                expiry_raw = f[16]
                strike = f[17]

                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw.split(".")[0])
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    expiry, exdp = dt_dict[expiry_raw]

                record: dict[str, Any] | None = None

                if series == "FUTCUR":
                    if root == "11NSETEST":
                        continue

                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": symbol,
                        "FreezeQty": freeze,
                        "TickSize": tick,
                        "LotSize": lot,
                        "Expiry": expiry,
                        "PriceNumerator": int(f[18]),
                        "PriceDenominator": int(f[19]),
                        "DisplayName": f"{root} {exdp} FUT",
                    }
                    fut_cds[root].append(record)

                elif series == "OPTCUR":
                    option = symbol[-2:]
                    strike = self._format_strike(strike)
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Symbol": symbol,
                        "FreezeQty": freeze,
                        "TickSize": tick,
                        "LotSize": lot,
                        "Expiry": expiry,
                        "StrikePrice": strike,
                        "Option": option,
                        "PriceNumerator": int(f[20]),
                        "PriceDenominator": int(f[21]),
                        "DisplayName": f"{root} {exdp} {strike} {option}",
                    }
                    opt_cds[root].append(record)

                if record is not None:
                    token_dict[f"{token}_{exchange}"] = record

            self.token_json["Futures"].update({"CDS": fut_cds})
            self.token_json["Options"].update({"CDS": opt_cds})

            self.alltoken_json.update(token_dict)

            return (
                {
                    "Futures": {"CDS": dict(fut_cds)},
                    "Options": {"CDS": dict(opt_cds)},
                },
                token_dict,
            )

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc


    # Headers & Json Parsers

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """Authenticate with Iifl and return request headers.

        Args:
            params: Login credentials and API keys required by Iifl.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and run the login flow.

        Returns:
            Headers that can authenticate subsequent Iifl API calls.

        Raises:
            KeyError: If neither credentials nor reusable headers are provided,
                or if a required credential is missing.
        """
        if self.paper_mode:
            self._headers = {"paper": "true"}
            return self._headers

        if headers is not None:
            return self.use_headers(headers)

        if self._headers and not force:
            return self._headers

        if params is None:
            raise KeyError("Please provide params or headers")

        for key in self.tokenParams:
            if key not in params:
                raise KeyError(f"Please provide {key}")

        json_data = {
            "secretKey": params["api_secret"],
            "appKey": params["api_key"],
            "source": "WebAPI",
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("access_token"),
            endpoint_group="auth",
            json=json_data,
        )
        response = self._parse_json_response(response)

        self._headers = {
            "Content-type": "application/json",
            "authorization": response["result"]["token"],
        }
        self._auth_context = {"user_id": response["result"]["userID"]}

        self.reset_session()

        return {**self._headers, **self._auth_context}

    def _json_parser(
        self,
        response: Response,
    ) -> dict[Any, Any] | list[dict[Any, Any]]:
        """
        Parse the JSON response obtained from the broker.

        Args:
            response (Response): JSON Response Obtained from Broker.

        Raises:
            ResponseError: Raised if any error received from broker.

        Returns:
            dict | list[dict]: Decoded JSON response obtained from the broker.
        """
        json_response = self.on_json_response(response)

        if not isinstance(json_response, dict):
            return json_response

        if json_response.get("type") == "success":
            return json_response

        message = (
            json_response.get("description")
            or json_response.get("message")
            or self._stringify_error_payload(json_response)
        )
        raise ResponseError(f"{self.id} {message}")

    def _orderbook_json_parser(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """
        Parse Orderbook Order Json Response.

        Args:
            order (dict): Orderbook Order Json Response from Broker.

        Returns:
            dict: Unified fenix Order Response.
        """
        order_status = self._parse_from_broker("status", order["OrderStatus"])
        parsed_order = {
            Order.ID: str(order["AppOrderID"]),
            Order.USER_ID: order["OrderUniqueIdentifier"],
            Order.TIMESTAMP: self.datetime_strp(
                order["LastUpdateDateTime"], "%d-%m-%Y %H:%M:%S"
            ),
            Order.SYMBOL: order["TradingSymbol"],
            Order.TOKEN: order["ExchangeInstrumentID"],
            Order.SIDE: self._parse_from_broker("side", order["OrderSide"]),
            Order.TYPE: self._parse_from_broker("order_type", order["OrderType"]),
            Order.AVG_PRICE: float(order["OrderAverageTradedPrice"] or 0.0),
            Order.PRICE: order["OrderPrice"],
            Order.TRIGGER_PRICE: order["OrderStopPrice"],
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: order["OrderQuantity"],
            Order.FILLED_QTY: order["LeavesQuantity"],
            Order.REMAINING_QTY: order["OrderQuantity"] - order["LeavesQuantity"],
            Order.CANCELLED_QTY: (
                order["LeavesQuantity"] if order_status == Status.CANCELLED else 0
            ),
            Order.STATUS: order_status,
            Order.REJECT_REASON: order["CancelRejectReason"],
            Order.DISCLOSED_QUANTITY: order["OrderDisclosedQuantity"],
            Order.PRODUCT: self._parse_from_broker("product", order["ProductType"]),
            Order.EXCHANGE: self._parse_from_broker(
                "exchange", order["ExchangeSegment"]
            ),
            Order.SEGMENT: self._parse_from_broker(
                "exchange", order["ExchangeSegment"]
            ),
            Order.VALIDITY: self._parse_from_broker(
                "validity", order["TimeInForce"]
            ),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _tradebook_json_parser(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """
        Parse a trade-book row into a unified order record.

        Args:
            order (dict): Trade-book row from the broker.

        Returns:
            dict: Unified fenix Order Response.
        """
        order_status = self._parse_from_broker("status", order["OrderStatus"])
        parsed_order = {
            Order.ID: str(order["AppOrderID"]),
            Order.USER_ID: order["OrderUniqueIdentifier"],
            Order.TIMESTAMP: self.datetime_strp(
                order["LastUpdateDateTime"], "%d-%m-%Y %H:%M:%S"
            ),
            Order.SYMBOL: order["TradingSymbol"],
            Order.TOKEN: order["ExchangeInstrumentID"],
            Order.SIDE: self._parse_from_broker("side", order["OrderSide"]),
            Order.TYPE: self._parse_from_broker("order_type", order["OrderType"]),
            Order.AVG_PRICE: float(order["OrderAverageTradedPrice"] or 0.0),
            Order.PRICE: order["OrderPrice"],
            Order.TRIGGER_PRICE: order["OrderStopPrice"],
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: order["OrderQuantity"],
            Order.FILLED_QTY: order["LeavesQuantity"],
            Order.REMAINING_QTY: order["OrderQuantity"] - order["LeavesQuantity"],
            Order.CANCELLED_QTY: (
                order["LeavesQuantity"] if order_status == Status.CANCELLED else 0
            ),
            Order.STATUS: order_status,
            Order.REJECT_REASON: order["CancelRejectReason"],
            Order.DISCLOSED_QUANTITY: order["OrderDisclosedQuantity"],
            Order.PRODUCT: self._parse_from_broker("product", order["ProductType"]),
            Order.EXCHANGE: self._parse_from_broker(
                "exchange", order["ExchangeSegment"]
            ),
            Order.SEGMENT: self._parse_from_broker(
                "exchange", order["ExchangeSegment"]
            ),
            Order.VALIDITY: self._parse_from_broker(
                "validity", order["TimeInForce"]
            ),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _position_json_parser(
        self,
        position: dict,
    ) -> dict[Any, Any]:
        """
        Parse Account Position Json Response.

        Args:
            position (dict): Account Position Json Response from Broker.

        Returns:
            dict: Unified fenix Position Response.
        """
        avg_price = (
            (int(position["OpenBuyQuantity"]) *
             float(position["BuyAveragePrice"]))
            + (int(position["OpenSellQuantity"]) *
               float(position["SellAveragePrice"]))
        ) / (int(position["OpenBuyQuantity"]) + int(position["OpenSellQuantity"]))

        parsed_position = {
            Position.SYMBOL: position["TradingSymbol"],
            Position.TOKEN: position["TokenID"],
            Position.NET_QTY: int(position["Quantity"]),
            Position.AVG_PRICE: avg_price,
            Position.MTM: float(position["MTM"]),
            Position.PNL: float(position["RealizedMTM"]),
            Position.BUY_QTY: int(position["OpenBuyQuantity"]),
            Position.BUY_PRICE: float(position["BuyAveragePrice"]),
            Position.SELL_QTY: int(position["OpenSellQuantity"]),
            Position.SELL_PRICE: float(position["SellAveragePrice"]),
            Position.LTP: None,
            Position.PRODUCT: self._parse_from_broker(
                "product", position["ProductType"]
            ),
            Position.EXCHANGE: self._parse_from_broker(
                "exchange", position["ExchangeSegment"]
            ),
            Position.INFO: position,
        }

        return parsed_position

    def _profile_json_parser(
        self,
        profile: dict,
    ) -> dict[Any, Any]:
        """
        Parse User Profile Json Response.

        Args:
            profile (dict): User Profile Json Response from Broker.

        Returns:
            dict: Unified fenix Profile Response.
        """
        exchanges = profile["ClientExchangeDetailsList"]
        exchanges_enabled = [
            self._parse_from_broker("exchange", i)
            for i in exchanges if exchanges[i]["Enabled"]
        ]
        parsed_profile = {
            Profile.CLIENT_ID: profile["ClientId"],
            Profile.NAME: profile["ClientName"],
            Profile.EMAIL_ID: profile["EmailId"],
            Profile.MOBILE_NO: profile["MobileNo"],
            Profile.PAN: profile["PAN"],
            Profile.ADDRESS: "",
            Profile.BANK_NAME: "",
            Profile.BANK_BRANCH_NAME: None,
            Profile.BANK_ACC_NO: "",
            Profile.EXCHANGES_ENABLED: exchanges_enabled,
            Profile.ENABLED: True,
            Profile.INFO: profile,
        }

        return parsed_profile

    def _create_order_parser(
        self,
        response: Response,
    ) -> dict[Any, Any]:
        """
        Parse Json Response Obtained from Broker After Placing Order to get order_id
        and fetching the json response for the said order_id.

        Args:
            response (Response): Json Response Obtained from broker after Placing an Order.

        Returns:
            dict: Unified fenix Order Response.
        """
        info = self._parse_json_response(response)

        order_id = info["result"]["AppOrderID"]
        order = self.fetch_order(order_id=order_id)

        return order

    def _extract_iifl_error_code(self, payload: Any) -> str | None:
        """Extract a documented Iifl error code from a payload."""
        error_code = self._extract_error_code(payload)
        if error_code:
            error_code = str(error_code).strip().lower()
            if error_code in self._ERROR_MESSAGES:
                return error_code
            if error_code.startswith("e-user-"):
                return error_code

        payload_text = self._stringify_error_payload(payload).lower()
        for documented_code in self._ERROR_MESSAGES:
            if documented_code in payload_text:
                return documented_code

        return None

    def _extract_iifl_error_message(
        self,
        payload: Any,
        error_code: str | None,
    ) -> str | None:
        """Extract the most useful Iifl error message for a payload."""
        error_message = self._extract_error_message(payload)
        documented_message = self._ERROR_MESSAGES.get(error_code or "")

        if documented_message and not error_message:
            return documented_message
        if documented_message and error_message == error_code:
            return documented_message
        if error_message:
            return error_message
        return documented_message

    def _iifl_error_class(
        self,
        error_code: str | None,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve an Iifl payload to the most specific Fenix error class."""
        if error_code in self._DIRECT_ERROR_CLASSES:
            return self._DIRECT_ERROR_CLASSES[error_code]

        message = (error_message or "").lower()
        if any(token in message for token in ("session", "token", "login", "auth")):
            return AuthenticationError
        if any(token in message for token in ("permission", "unauthor", "enabled")):
            return PermissionDeniedError
        if "insufficient fund" in message or "margin" in message:
            return InsufficientFundsError
        if "insufficient" in message and "holding" in message:
            return InsufficientHoldingsError
        if "order" in message and any(token in message for token in ("not found", "invalid")):
            return OrderNotFoundError
        if any(token in message for token in ("rejected", "price", "quantity")):
            return InvalidOrderError
        if "invalid" in message or "missing" in message:
            return InputError
        if error_code in self._ERROR_MESSAGES:
            return InputError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded Iifl payload represents an error."""
        if isinstance(payload, list):
            if not payload:
                return False
            return self._payload_indicates_error(payload[0])

        if isinstance(payload, dict):
            response_type = payload.get("type")
            if response_type is not None:
                return str(response_type).lower() != "success"

            return self._extract_iifl_error_code(payload) is not None

        return self._extract_iifl_error_code(payload) is not None

    def _raise_iifl_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for an Iifl error payload."""
        context = self._http_error_context(response, payload)
        error_code = self._extract_iifl_error_code(payload)
        error_message = self._extract_iifl_error_message(
            payload,
            error_code,
        )

        context["error_code"] = error_code
        context["error_message"] = error_message
        error_cls = self._iifl_error_class(
            error_code,
            error_message,
            context.get("status_code"),
        )

        error = error_cls(
            self._format_http_error_message(context),
            broker=self.id,
            error_code=error_code,
            status_code=context.get("status_code"),
            payload=payload,
            url=context.get("url"),
            method=context.get("method"),
            response=response,
        )
        if cause is None:
            raise error
        raise error from cause

    def handle_http_error(self, exc: HTTPError) -> NoReturn:
        """Handle HTTP errors and raise Iifl-specific exceptions."""
        payload = self._response_error_payload(exc.response)
        if self._payload_indicates_error(payload):
            self._raise_iifl_error(payload, response=exc.response, cause=exc)

        super().handle_http_error(exc)

    def _parse_json_response(self, response: Response) -> Any:
        """Decode an HTTP response and raise Iifl-specific payload errors."""
        try:
            json_response = self._json_parser(response)
        except ResponseError as exc:
            payload = self._response_error_payload(response)
            if self._payload_indicates_error(payload):
                self._raise_iifl_error(payload, response=response, cause=exc)
            raise

        if self._payload_indicates_error(json_response):
            self._raise_iifl_error(json_response, response=response)

        return json_response

    def _build_place_order_payload(
        self,
        token_dict: dict,
        quantity: int,
        side: str,
        product: str,
        validity: str,
        variety: str,
        unique_id: str,
        price: float = 0.0,
        trigger: float = 0.0,
        target: float = 0.0,
        stoploss: float = 0.0,
        trailing_sl: float = 0.0,
    ) -> dict[str, Any]:
        """Build the Iifl place-order payload."""
        if target or stoploss or trailing_sl or variety == Variety.BO:
            raise InputError(f"BO Orders Not Available in {self.id}.")

        order_type = self._resolve_order_type(price, trigger)
        return {
            "exchangeInstrumentID": token_dict["Token"],
            "exchangeSegment": self._format_for_broker(
                "exchange",
                token_dict["Exchange"],
                raise_error=False,
            ),
            "limitPrice": price,
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": self._format_for_broker("side", side),
            "orderType": self._format_for_broker("order_type", order_type),
            "productType": self._format_for_broker("product", product),
            "timeInForce": self._format_for_broker("validity", validity),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
        }

    def _parse_place_order_response(self, response: Response) -> dict[Any, Any]:
        """Extract the Iifl app order id from a place-order response."""
        info = self._parse_json_response(response)
        return {Order.ID: str(info["result"]["AppOrderID"])}

    def place_order(
        self,
        token_dict: dict,
        quantity: int,
        side: str,
        product: str,
        validity: str,
        variety: str,
        unique_id: str,
        price: float = 0.0,
        trigger: float = 0.0,
        target: float = 0.0,
        stoploss: float = 0.0,
        trailing_sl: float = 0.0,
    ) -> dict[Any, Any]:
        """Place an order through Iifl using the standard broker flow."""
        if self.paper_mode and self._paper is not None:
            return self._paper.place_order(
                token_dict=token_dict,
                quantity=quantity,
                side=side,
                product=product,
                validity=validity,
                variety=variety,
                unique_id=unique_id,
                price=price,
                trigger=trigger,
                target=target,
                stoploss=stoploss,
                trailing_sl=trailing_sl,
            )

        self._validate_order_inputs(
            quantity=quantity,
            price=price,
            trigger=trigger,
            target=target,
            stoploss=stoploss,
            trailing_sl=trailing_sl,
        )

        json_data = self._build_place_order_payload(
            token_dict=token_dict,
            quantity=quantity,
            side=side,
            product=product,
            validity=validity,
            variety=variety,
            unique_id=unique_id,
            price=price,
            trigger=trigger,
            target=target,
            stoploss=stoploss,
            trailing_sl=trailing_sl,
        )

        response = self.fetch(
            method="POST",
            url=self.get_url("place_order"),
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    # Order Details, OrderBook & TradeBook

    def fetch_raw_orderbook(self) -> list[dict]:
        """
        Fetch Raw Orderbook Details, without any Standardization.

        Returns:
            list[dict]: Raw Broker Orderbook Response. In paper mode, returns
            the unified paper order records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        response = self.fetch(
            method="GET",
            url=self.get_url("orderbook"),
            endpoint_group="post_trade",
            headers=self._headers,
        )
        return self._parse_json_response(response)

    def fetch_raw_orderhistory(
        self,
        order_id: str,
    ) -> list[dict]:
        """
        Fetch Raw History of an order.

        Parameters:
            order_id (str): id of the order.

        Returns:
            list[dict]: Raw Broker Order History Response. In paper mode,
            returns the unified paper order record wrapped in a list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        params = {"appOrderID": order_id}
        response = self.fetch(
            method="GET",
            url=self.get_url("orderbook"),
            endpoint_group="post_trade",
            params=params,
            headers=self._headers,
        )

        return self._parse_json_response(response)

    def fetch_orderbook(self) -> list[dict]:
        """
        Fetch Orderbook Details.

        Returns:
            list[dict]: List of dictionaries of orders using fenix Unified Order Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        info = self.fetch_raw_orderbook()

        orders = []
        if info["result"]:
            for order in info["result"]:
                detail = self._orderbook_json_parser(order)
                orders.append(detail)

        return orders

    def fetch_tradebook(self) -> list[dict]:
        """
        Fetch Tradebook Details.

        Returns:
            list[dict]: List of dictionaries of orders using fenix Unified Order Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_tradebook()

        response = self.fetch(
            method="GET",
            url=self.get_url("tradebook"),
            endpoint_group="post_trade",
            headers=self._headers,
        )
        info = self._parse_json_response(response)

        orders = []
        if info["result"]:
            for order in info["result"]:
                detail = self._tradebook_json_parser(order)
                orders.append(detail)

        return orders

    def fetch_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """
        Fetch Order Details.

        Parameters:
            order_id (str): id of the order.

        Raises:
            InputError: If order does not exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        info = self.fetch_raw_orderhistory(order_id=order_id)

        order = info["result"][-1]
        order = self._orderbook_json_parser(order)
        return order

    def fetch_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """
        Fetch History of an order.

        Parameters:
            order_id (str): id of the order.

        Returns:
            list: A list of dictionaries containing order history using fenix Unified Order Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        info = self.fetch_raw_orderhistory(order_id=order_id)

        order_history = []
        for order in info["result"]:
            history = self._orderbook_json_parser(order)
            order_history.append(history)

        return order_history

    # Order Modification & Sq Off

    def modify_order(
        self,
        order_id: str,
        price: float | None = None,
        trigger: float | None = None,
        quantity: int | None = None,
        order_type: str | None = None,
        validity: str | None = None,
        raw_order_json: dict | None = None,
        extra_params: dict | None = None,
    ) -> dict[Any, Any]:
        """
        Modify an open order.

        Args:
            order_id (str): id of the order to modify.
            price (float | None, optional): price of the order. Defaults to None.
            trigger (float | None, optional): trigger price of the order. Defaults to None.
            quantity (int | None, optional): order quantity. Defaults to None.
            order_type (str | None, optional): Type of Order. defaults to None
            validity (str | None, optional): Order validity Defaults to None.
            raw_order_json (dict | None, optional): Optional raw order row to
                avoid refetching history. Defaults to None.
            extra_params (dict | None, optional): Reserved for broker-specific
                extensions. Defaults to None.

        Returns:
            dict: fenix Unified Order Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.modify_order(
                order_id=order_id,
                price=price,
                trigger=trigger,
                quantity=quantity,
                order_type=order_type,
                validity=validity,
                raw_order_json=raw_order_json,
                extra_params=extra_params,
            )

        if raw_order_json:
            order_info = raw_order_json
        else:
            info = self.fetch_raw_orderhistory(order_id=order_id)
            order_info = info["result"][-1]

        json_data = {
            "appOrderID": order_id,
            "modifiedLimitPrice": price or order_info["OrderPrice"],
            "modifiedStopPrice": trigger or order_info["OrderStopPrice"],
            "modifiedOrderQuantity": quantity or order_info["OrderQuantity"],
            "modifiedOrderType": (
                self._format_for_broker("order_type", order_type)
                if order_type
                else order_info["OrderType"]
            ),
            "modifiedProductType": order_info["ProductType"],
            "modifiedTimeInForce": (
                self._format_for_broker("validity", validity)
                if validity
                else order_info["TimeInForce"]
            ),
            "orderUniqueIdentifier": order_info["OrderUniqueIdentifier"],
            "modifiedDisclosedQuantity": order_info["OrderDisclosedQuantity"],
        }

        params = {"clientID": self._auth_context["user_id"]}

        response = self.fetch(
            method="PUT",
            url=self.get_url("modify_order"),
            endpoint_group="orders",
            params=params,
            json=json_data,
            headers=self._headers,
        )

        return self._create_order_parser(response=response)

    def cancel_order(
        self,
        order_id: str,
        extra_params: dict | None = None,
    ) -> dict[Any, Any]:
        """
        Cancel an open order.

        Args:
            order_id (str): id of the order.
            extra_params (dict | None, optional): Reserved for broker-specific
                extensions. Defaults to None.

        Returns:
            dict: fenix Unified Order Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.cancel_order(
                order_id=order_id,
                extra_params=extra_params,
            )

        params = {"appOrderID": order_id}
        response = self.fetch(
            method="DELETE",
            url=self.get_url("cancel_order"),
            endpoint_group="orders",
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)

        return self.fetch_order(order_id=info["result"][0]["AppOrderID"])

    # Account Limits & Profile

    def fetch_day_positions(self) -> dict[Any, Any]:
        """
        Fetch the Day's Account Positions.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        params = {"dayOrNet": "DayWise"}
        response = self.fetch(
            method="GET",
            url=self.get_url("positions"),
            endpoint_group="portfolio",
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)

        positions = []
        if info["result"]:
            for position in info["result"]["positionList"]:
                detail = self._position_json_parser(position)
                positions.append(detail)

        return positions

    def fetch_net_positions(self) -> dict[Any, Any]:
        """
        Fetch Total Account Positions.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        params = {"dayOrNet": "NetWise"}
        response = self.fetch(
            method="GET",
            url=self.get_url("positions"),
            endpoint_group="portfolio",
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)

        positions = []
        if info["result"]:
            for position in info["result"]["positionList"]:
                detail = self._position_json_parser(position)
                positions.append(detail)

        return positions

    def fetch_positions(self) -> dict[Any, Any]:
        """
        Fetch Day & Net Account Positions.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        day_positions = self.fetch_day_positions()
        net_positions = self.fetch_net_positions()

        return day_positions + net_positions

    def fetch_holdings(self) -> dict[Any, Any]:
        """
        Fetch Account Holdings.

        Returns:
            dict[Any, Any]: fenix Unified Positions Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_holdings()

        params = {"clientID": self._auth_context["user_id"]}
        response = self.fetch(
            method="GET",
            url=self.get_url("holdings"),
            endpoint_group="portfolio",
            params=params,
            headers=self._headers,
        )
        return self._parse_json_response(response)

    def fetch_margin_limits(self) -> dict[Any, Any]:
        """
        Fetch Risk Management System Limits.

        Returns:
            dict: fenix Unified RMS Limits Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_margin_limits()

        params = {"clientID": self._auth_context["user_id"]}
        response = self.fetch(
            method="GET",
            url=self.get_url("rms_limits"),
            endpoint_group="account",
            params=params,
            headers=self._headers,
        )
        return self._parse_json_response(response)

    def fetch_profile(self) -> dict[Any, Any]:
        """
        Fetch Profile Details of the User.

        Returns:
            dict: fenix Unified Profile Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_profile()

        params = {"clientID": self._auth_context["user_id"]}
        response = self.fetch(
            method="GET",
            url=self.get_url("profile"),
            endpoint_group="account",
            params=params,
            headers=self._headers,
        )

        info = self._parse_json_response(response)
        profile = self._profile_json_parser(info["result"])

        return profile
