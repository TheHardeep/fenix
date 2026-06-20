from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from math import isnan
from typing import TYPE_CHECKING, Any, NoReturn

import pandas as pd

from requests.exceptions import HTTPError

from fenix.base.broker import Broker

from fenix.base.constants import ExchangeCode
from fenix.base.constants import Order
from fenix.base.constants import OrderType
from fenix.base.constants import Position
from fenix.base.constants import Product
from fenix.base.constants import Profile
from fenix.base.constants import RMS
from fenix.base.constants import Root
from fenix.base.constants import Side
from fenix.base.constants import Status
from fenix.base.constants import Validity

from fenix.base.errors import (
    AuthenticationError,
    BrokerError,
    InsufficientFundsError,
    InsufficientHoldingsError,
    InputError,
    InvalidOrderError,
    NetworkError,
    OrderNotFoundError,
    PermissionDeniedError,
    RateLimitExceededError,
    ResponseError,
    TokenDownloadError,
)

if TYPE_CHECKING:
    from requests.models import Response


class Symphony(Broker):
    """Symphony broker adapter for the Fenix trading interface."""

    _API = {
        "doc": "https://developers.symphonyfintech.in/doc/interactive",
        "servers": {
            # The Interactive base URL is dynamic — ``authenticate`` resolves
            # it through HostLookup and overwrites this entry. The default
            # keeps ``get_url`` working before authentication for callers that
            # only touch market-data endpoints.
            "interactive": "https://smartweb.jmfinancialservices.in/interactive",
            "hostlookup": "https://smartweb.jmfinancialservices.in",
            "market_data": "https://developers.symphonyfintech.in/apimarketdata",
            "market_data_binary": "https://developers.symphonyfintech.in/apibinarymarketdata",
        },
        "paths": {
            # --- Auth Flow ---
            "hostlookup": {
                "server": "hostlookup",
                "path": "/hostlookup",
            },
            "access_token": {
                "server": "interactive",
                "path": "/user/session",
            },

            # --- Order & Portfolio Flow ---
            "place_order": {
                "server": "interactive",
                "path": "/orders",
            },
            "place_order_bracket": {
                "server": "interactive",
                "path": "/orders/bracket",
            },
            "modify_order": {
                "server": "interactive",
                "path": "/orders",
            },
            "cancel_order": {
                "server": "interactive",
                "path": "/orders",
            },
            "order_history": {
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
            "position_convert": {
                "server": "interactive",
                "path": "/portfolio/positions/convert",
            },
            "holdings": {
                "server": "interactive",
                "path": "/portfolio/holdings",
            },
            "profile": {
                "server": "interactive",
                "path": "/user/profile",
            },
            "rms_limits": {
                "server": "interactive",
                "path": "/user/balance",
            },

            # --- Market Data ---
            "instruments": {
                "server": "market_data",
                "path": "/instruments/master",
            },
            "instruments_binary": {
                "server": "market_data_binary",
                "path": "/instruments/master",
            },
            "indices": {
                "server": "market_data",
                "path": "/instruments/indexlist",
            },
        },
    }

    STANDARD_MAPS = {
        "side": {
            "BUY": Side.BUY,
            "SELL": Side.SELL,
        },
        "order_type": {
            "Market": OrderType.MARKET,
            "Limit": OrderType.LIMIT,
            "StopMarket": OrderType.SLM,
            "StopLimit": OrderType.SL,
        },
        "status": {
            "New": Status.OPEN,
            "Open": Status.OPEN,
            "PendingNew": Status.PENDING,
            "PendingReplace": Status.PENDING,
            "PendingCancel": Status.PENDING,
            "Replaced": Status.MODIFIED,
            "Filled": Status.FILLED,
            "Cancelled": Status.CANCELLED,
            "Rejected": Status.REJECTED,
            "PartiallyFilled": Status.PARTIALLY_FILLED,
        },
        "product": {
            "MIS": Product.MIS,
            "NRML": Product.NRML,
            "CNC": Product.CNC,
            "CO": Product.CO,
        },
        "exchange": {
            "NSEFO": ExchangeCode.NFO,
            "NSECM": ExchangeCode.NSE,
            "BSEFO": ExchangeCode.BFO,
            "BSECM": ExchangeCode.BSE,
            "MCXFO": ExchangeCode.MCX,
            "NSECD": ExchangeCode.CDS,
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
        "order_type": {
            OrderType.MARKET: "Market",
            OrderType.LIMIT: "Limit",
            OrderType.SLM: "StopMarket",
            OrderType.SL: "StopLimit",
        },
        "product": {
            Product.MIS: "MIS",
            Product.NRML: "NRML",
            Product.CNC: "CNC",
            Product.CO: "CO",
            Product.BO: "MIS",
        },
        "exchange": {
            ExchangeCode.NFO: "NSEFO",
            ExchangeCode.NSE: "NSECM",
            ExchangeCode.BFO: "BSEFO",
            ExchangeCode.BSE: "BSECM",
            ExchangeCode.MCX: "MCXFO",
            ExchangeCode.CDS: "NSECD",
        },
        "validity": {
            Validity.DAY: "DAY",
            Validity.IOC: "IOC",
        },
    }

    _REQUIRED_AUTH_HEADER_KEYS = (
        "Content-Type",
        "Authorization",
    )

    _AUTH_CONTEXT_KEYS = ("user_id",)

    # Symphony error envelopes use ``{"type": "error", "code": "<code>",
    # "description": "<message>"}`` — keys mirror the documented schema.
    ERROR_CODE_KEYS = (
        "code",
    )

    ERROR_MESSAGE_KEYS = (
        "description",
    )

    # Symphony documents the four common HTTP status codes that surface in
    # error envelopes. The string keys match the ``code`` field that Symphony
    # echoes for these failures.
    _ERROR_MESSAGES: dict[str, str] = {
        "400": "Missing or bad request parameters or values.",
        "404": "Request resource was not found.",
        "429": "Too many requests to the API (rate limiting).",
        "500": "Something unexpected went wrong.",
    }

    _DIRECT_ERROR_CLASSES: dict[str, type[BrokerError]] = {
        "400": InputError,
        "404": ResponseError,
        "429": RateLimitExceededError,
        "500": NetworkError,
    }

    # Symphony reports empty order books, position lists, holdings, and trade
    # books as error envelopes whose ``description`` matches one of these
    # phrases. The post-trade readers use them to return empty lists instead
    # of re-raising.
    _NO_DATA_PHRASES = (
        "no data",
        "data not available",
        "no order",
        "no position",
        "no holding",
        "no trade",
    )

    # HostLookup credentials are fixed by the Symphony Interactive API. The
    # AccessPassword and version are the documented public constants used by
    # every Symphony deployment; subclasses only override the endpoint host.
    _HOSTLOOKUP_ACCESS_PASSWORD = "2021HostLookUpAccess"
    _HOSTLOOKUP_VERSION = "interactive_1.0.1"


    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "Symphony",
            "tokenParams": [
                "api_key",
                "api_secret",
            ],
            "proxies": {},
            "sensitiveLogKeys": [
                "appKey",
                "secretKey",
                "uniqueKey",
                "api_key",
                "api_secret",
                "token",
                "accessToken",
                "Authorization",
                "userID",
                "user_id",
                "ClientId",
                "clientID",
                "AccessPassword",
            ],
            "enableRateLimit": True,
            # Buckets follow the Symphony Interactive API rate-limits table.
            # The "orders" bucket is the *Unified Order Throttle Limit* — a
            # single 10/sec budget shared across place/modify/cancel for
            # regular, BO, CO, and spread orders.
            "rateLimits": {
                "orders": {
                    "period": 1,
                    "capacity": 10,
                    "cost": 1.0,
                },
                "margin": {
                    "period": 1,
                    "capacity": 10,
                    "cost": 1.0,
                },
                "post_trade": {
                    "period": 1,
                    "capacity": 1,
                    "cost": 1.0,
                },
                "user": {
                    "period": 1,
                    "capacity": 1,
                    "cost": 1.0,
                },
                "default": {
                    "period": 1,
                    "capacity": 1,
                    "cost": 1.0,
                },
            },
        }

    def __init__(self, config: dict | None = None):
        """Initialize the Symphony broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
        """
        super().__init__(config)

    def _resolve_interactive_base(self) -> tuple[str | None, str | None]:
        """Resolve the dynamic Interactive base URL and session ``uniqueKey``.

        Symphony requires a HostLookup round-trip before login: the client
        posts the documented access password and version, and the server
        replies with the Interactive ``connectionString`` to connect to and a
        session ``uniqueKey`` to pass to the login call.

        Returns:
            ``(connection_string, unique_key)`` from HostLookup, or
            ``(None, None)`` when the lookup is unavailable so the caller can
            fall back to the statically configured Interactive base and any
            caller-supplied ``uniqueKey``.
        """
        try:
            json_data = {
                "AccessPassword": self._HOSTLOOKUP_ACCESS_PASSWORD,
                "version": self._HOSTLOOKUP_VERSION,
            }
            response = self.fetch(
                method="POST",
                url=self.get_url("hostlookup"),
                endpoint_group="default",
                json=json_data,
            )
            result = self._parse_json_response(response)["result"]
            # The documented response is inconsistent about casing
            # (``connectionString``/``uniqueKey`` vs ``ConnectionString``/
            # ``UniqueKey``), so accept either.
            connection_string = (
                result.get("connectionString")
                or result.get("ConnectionString")
            )
            unique_key = result.get("uniqueKey") or result.get("UniqueKey")
            return connection_string, unique_key
        except Exception:  # noqa: BLE001 - fall back to static configuration
            return None, None

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """Authenticate with Symphony and return request headers.

        The login flow is a two-step exchange: a HostLookup call resolves the
        dynamic Interactive base URL and a session ``uniqueKey``, then the
        login call swaps the API keys and ``uniqueKey`` for an access token.
        When HostLookup is unavailable, the statically configured Interactive
        base is used and the ``uniqueKey`` falls back to ``params``.

        Args:
            params: Login credentials and API keys required by Symphony.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and run the login flow.

        Returns:
            Headers that can authenticate subsequent Symphony API calls.

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

        interactive_base, unique_key = self._resolve_interactive_base()
        if interactive_base:
            self._API["servers"]["interactive"] = interactive_base
        if not unique_key:
            unique_key = params.get("uniqueKey")

        data = {
            "appKey": params["api_key"],
            "secretKey": params["api_secret"],
            "uniqueKey": unique_key,
            "source": "WEBAPI",
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("access_token"),
            endpoint_group="default",
            data=data,
        )
        token_resp = self._parse_json_response(response)

        access_token = token_resp["result"]["token"]
        user_id = token_resp["result"]["userID"]

        self._headers = {
            "Content-Type": "application/json",
            "Authorization": access_token,
        }
        self._auth_context = {"user_id": user_id}

        self.reset_session()

        return {**self._headers, **self._auth_context}

    # Script Fetch

    def load_equity_tokens(
        self,
        data: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE equity token metadata.

        Args:
            data: Optional pre-fetched contract-master blob keyed by exchange.
                When omitted, the contract master is fetched from Symphony.

        Returns:
            A tuple containing the unified equity token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
            TokenDownloadError: If the contract master cannot be downloaded or
                parsed.
        """
        if not data:
            response = self.fetch(
                method="POST",
                url=self.get_url("instruments"),
                endpoint_group="default",
                json={"exchangeSegmentList": ["NSECM", "BSECM"]},
            )
            raw_string = self._parse_json_response(response)["result"]
        else:
            if "NSE" not in data and "BSE" not in data:
                raise KeyError("JSON data must contain 'NSE' or 'BSE' keys")

            raw_string = data.get("NSE", data.get("BSE", ""))

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

        except Exception as exc:  # noqa: BLE001
            raise TokenDownloadError({"Error": exc.args}) from exc

    def load_index_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE index token metadata.

        Args:
            data: Optional pre-fetched index lists keyed by ``"NSE"`` and
                ``"BSE"``. Each value is the list of ``"<symbol>_<token>"``
                strings returned by Symphony.

        Returns:
            A tuple containing the unified index token map (organised by
            exchange and including ``Root.*`` aliases) and an all-token lookup
            keyed by ``"{token}_{exchange3}"``.
        """
        if data is None:
            params = {"exchangeSegment": 1}
            response = self.fetch(
                method="GET",
                url=self.get_url("indices"),
                endpoint_group="default",
                params=params,
            )
            nse_list = self._parse_json_response(response)["result"]["indexList"]

            params = {"exchangeSegment": 11}
            response = self.fetch(
                method="GET",
                url=self.get_url("indices"),
                endpoint_group="default",
                params=params,
            )
            bse_list = self._parse_json_response(response)["result"]["indexList"]
        else:
            if "NSE" not in data or "BSE" not in data:
                raise KeyError("JSON data must contain 'NSE' and 'BSE' keys")

            nse_list = data["NSE"]
            bse_list = data["BSE"]

        nse_dict: dict[str, Any] = {}
        bse_dict: dict[str, Any] = {}
        token_dict: dict[str, Any] = {}

        for entry in nse_list:
            symbol, token = entry.split("_")
            record = {
                "Symbol": symbol,
                "Token": int(token),
                "Exchange": "NSECM",
                "ScriptName": symbol,
            }
            nse_dict[symbol] = record
            token_dict[f"{token}_NSE"] = record

        for entry in bse_list:
            symbol, token = entry.split("_")
            record = {
                "Symbol": symbol,
                "Token": int(token),
                "Exchange": "BSECM",
                "ScriptName": symbol,
            }
            bse_dict[symbol] = record
            token_dict[f"{token}_BSE"] = record

        merged: dict[str, Any] = {**nse_dict, **bse_dict}
        for alias, source_key in (
            (Root.BNF, "NIFTY BANK"),
            (Root.NF, "NIFTY 50"),
            (Root.FNF, "NIFTY FIN SERVICE"),
            (Root.MIDCPNF, "NIFTY MID SELECT"),
        ):
            if source_key in merged:
                merged[alias] = merged[source_key]

        self.indices = merged
        self.token_json["Indices"].update({
            "NSE": nse_dict,
            "BSE": bse_dict,
        })
        self.alltoken_json.update(token_dict)

        return (
            {"Indices": {"NSE": nse_dict, "BSE": bse_dict}},
            token_dict,
        )

    def load_fno_tokens(
        self,
        data: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE futures and options token metadata.

        Args:
            data: Optional pre-fetched contract-master blob keyed by exchange.
                When omitted, the contract master is fetched from Symphony.

        Returns:
            A tuple containing the unified F&O token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
            TokenDownloadError: If the contract master cannot be downloaded or
                parsed.
        """
        if not data:
            response = self.fetch(
                method="POST",
                url=self.get_url("instruments"),
                endpoint_group="default",
                json={"exchangeSegmentList": ["NSEFO", "BSEFO"]},
            )
            raw_string = self._parse_json_response(response)["result"]
        else:
            if "NFO" not in data and "BFO" not in data:
                raise KeyError("JSON data must contain 'NFO' or 'BFO' keys")

            raw_string = data.get("NFO", data.get("BFO", ""))

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

        except Exception as exc:  # noqa: BLE001
            raise TokenDownloadError({"Error": exc.args}) from exc

    def load_mcx_tokens(
        self,
        data: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load MCX futures and options token metadata.

        Args:
            data: Optional pre-fetched contract-master blob keyed by exchange.
                When omitted, the contract master is fetched from Symphony.

        Returns:
            A tuple containing the unified MCX token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
            TokenDownloadError: If the contract master cannot be downloaded or
                parsed.
        """
        if not data:
            response = self.fetch(
                method="POST",
                url=self.get_url("instruments"),
                endpoint_group="default",
                json={"exchangeSegmentList": ["MCXFO"]},
            )
            raw_string = self._parse_json_response(response)["result"]
        else:
            if "MCX" not in data:
                raise KeyError("JSON data must contain 'MCX' key")

            raw_string = data.get("MCX", "")

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

        except Exception as exc:  # noqa: BLE001
            raise TokenDownloadError({"Error": exc.args}) from exc

    def load_cds_tokens(
        self,
        data: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load currency derivatives (CDS) token metadata.

        Args:
            data: Optional pre-fetched contract-master blob keyed by exchange.
                When omitted, the contract master is fetched from Symphony.

        Returns:
            A tuple containing the unified CDS token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
            TokenDownloadError: If the contract master cannot be downloaded or
                parsed.
        """
        if not data:
            response = self.fetch(
                method="POST",
                url=self.get_url("instruments"),
                endpoint_group="default",
                json={"exchangeSegmentList": ["NSECD"]},
            )
            raw_string = self._parse_json_response(response)["result"]
        else:
            if "CDS" not in data and "BCD" not in data:
                raise KeyError("JSON data must contain 'CDS' or 'BCD' keys")

            raw_string = data.get("CDS", data.get("BCD", ""))

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

        except Exception as exc:  # noqa: BLE001
            raise TokenDownloadError({"Error": exc.args}) from exc

    # Json Parsers & Error Handling

    def _extract_symphony_error_code(self, payload: Any) -> str | None:
        """Extract a Symphony error code from a payload, when present.

        Symphony error envelopes carry the code under the documented ``code``
        key. When that key is missing — for example on raw HTML error bodies —
        the payload text is scanned for any of the documented codes in
        ``_ERROR_MESSAGES`` so callers still receive a typed code.

        Args:
            payload: Decoded broker response payload.

        Returns:
            Documented Symphony error code, or ``None`` if none was found.
        """
        error_code = self._extract_error_code(payload)
        if error_code:
            return str(error_code).strip()

        payload_text = self._stringify_error_payload(payload).upper()
        for documented_code in self._ERROR_MESSAGES:
            if documented_code in payload_text:
                return documented_code

        return None

    def _extract_symphony_error_message(
        self,
        payload: Any,
        error_code: str | None,
    ) -> str | None:
        """Extract the most useful Symphony error message for a payload.

        Prefers the broker-supplied ``description`` text. Falls back to the
        canonical message documented for ``error_code`` when the payload
        message is empty or only echoes the code itself.

        Args:
            payload: Decoded broker response payload.
            error_code: Already-extracted error code, used to look up a
                documented description.

        Returns:
            Best available human-readable error message, or ``None`` when
            neither the payload nor ``_ERROR_MESSAGES`` carry one.
        """
        error_message = self._extract_error_message(payload)
        documented_message = self._ERROR_MESSAGES.get(error_code or "")

        if documented_message and not error_message:
            return documented_message
        if documented_message and error_message == error_code:
            return documented_message
        if error_message:
            return error_message
        return documented_message

    def _symphony_error_class(
        self,
        error_code: str | None,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve a Symphony payload to the most specific Fenix error class.

        Args:
            error_code: Symphony error code already extracted from the
                payload, when available.
            error_message: Symphony error description already extracted from
                the payload, when available.
            status_code: HTTP status code associated with the response, used
                for fallback classification when the payload is unmappable.

        Returns:
            The Fenix exception class that best describes the error.
        """
        if error_code in self._DIRECT_ERROR_CLASSES:
            return self._DIRECT_ERROR_CLASSES[error_code]

        message = (error_message or "").lower()
        if any(token in message for token in ("session", "token", "login")):
            return AuthenticationError
        if "read-only" in message or "permission" in message:
            return PermissionDeniedError
        if "insufficient fund" in message or "margin" in message:
            return InsufficientFundsError
        if "insufficient" in message and (
            "quantity" in message or "holding" in message
        ):
            return InsufficientHoldingsError
        if any(phrase in message for phrase in self._NO_DATA_PHRASES):
            return ResponseError
        if "not found" in message or "not in your order book" in message:
            return OrderNotFoundError
        if any(token in message for token in ("order", "price", "quantity")):
            return InvalidOrderError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded Symphony payload represents an error.

        Symphony's documented envelope marks success or failure with a
        ``"type"`` field that is either ``"success"`` or ``"error"``. Lists
        are inspected element-wise. Payloads that lack a ``"type"`` key but
        carry a documented error code are also treated as errors.

        Args:
            payload: Decoded broker response payload.

        Returns:
            ``True`` when the payload describes a failure, ``False``
            otherwise.
        """
        if isinstance(payload, list):
            if not payload:
                return False
            return self._payload_indicates_error(payload[0])

        if isinstance(payload, dict):
            payload_type = payload.get("type")
            if isinstance(payload_type, str):
                return payload_type.lower() != "success"

            return self._extract_symphony_error_code(payload) is not None

        return self._extract_symphony_error_code(payload) is not None

    def _is_empty_response_error(self, exc: ResponseError) -> bool:
        """Return whether a response error represents an empty result set.

        Symphony reports empty order books, position lists, and similar
        result sets as errors whose ``description`` matches one of the
        ``_NO_DATA_PHRASES`` entries. Callers use this hook to convert those
        into empty lists rather than re-raising.

        Args:
            exc: ``ResponseError`` previously raised from a payload.

        Returns:
            ``True`` if the error message names an empty-result phrase.
        """
        message = str(exc).lower()
        return any(phrase in message for phrase in self._NO_DATA_PHRASES)

    def _raise_symphony_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for a Symphony error payload.

        Args:
            payload: Decoded broker response payload describing the failure.
            response: Originating HTTP response, when one is available.
            cause: Exception that triggered this raise, used to chain
                ``raise ... from`` for traceback continuity.

        Raises:
            BrokerError: Always — the concrete subclass is selected by
                ``_symphony_error_class``.
        """
        context = self._http_error_context(response, payload)
        error_code = self._extract_symphony_error_code(payload)
        error_message = self._extract_symphony_error_message(
            payload,
            error_code,
        )

        context["error_code"] = error_code
        context["error_message"] = error_message
        error_cls = self._symphony_error_class(
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
        """Handle HTTP errors and raise broker-specific exceptions.

        When the failed response carries a Symphony error envelope, the
        envelope is decoded and re-raised as the most specific Fenix
        exception. Otherwise the base-class fallback is invoked, which maps
        the HTTP status code to a generic Fenix exception.

        Args:
            exc: ``requests.HTTPError`` raised by the underlying HTTP layer.

        Raises:
            BrokerError: Always — the concrete subclass depends on the
                payload contents and HTTP status code.
        """
        payload = self._response_error_payload(exc.response)
        if self._payload_indicates_error(payload):
            self._raise_symphony_error(
                payload, response=exc.response, cause=exc,
            )

        super().handle_http_error(exc)

    def _parse_json_response(self, response: Response) -> Any:
        """Decode an HTTP response and raise broker-specific payload errors.

        Args:
            response: HTTP response returned by the Symphony API.

        Returns:
            Parsed JSON payload — typically the documented
            ``{"type": "success", "code", "description", "result"}`` envelope
            for endpoints that wrap their data, or the raw value for
            endpoints that do not.

        Raises:
            BrokerError: When the response decodes to a Symphony error
                envelope. The concrete subclass depends on the payload.
        """
        json_response = self._json_parser(response)

        if self._payload_indicates_error(json_response):
            self._raise_symphony_error(
                json_response,
                response=response,
            )

        return json_response

    def _parse_orderbook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a Symphony order-book row to a unified order record.

        Args:
            order: Raw order-book row returned by Symphony.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["AppOrderID"],
            Order.USER_ID: order["OrderUniqueIdentifier"],
            Order.TIMESTAMP: str(pd.to_datetime(order["ExchangeTransactTime"])),
            Order.SYMBOL: order["TradingSymbol"],
            Order.TOKEN: str(order["ExchangeInstrumentID"]),
            Order.SIDE: self._parse_from_broker("side", order["OrderSide"]),
            Order.TYPE: self._parse_from_broker("order_type", order["OrderType"]),
            Order.AVG_PRICE: float(order["OrderAverageTradedPrice"] or 0.0),
            Order.PRICE: order["OrderPrice"],
            Order.TRIGGER_PRICE: order["OrderStopPrice"],
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: order["OrderQuantity"],
            Order.FILLED_QTY: order["CumulativeQuantity"],
            Order.REMAINING_QTY: order["LeavesQuantity"],
            Order.CANCELLED_QTY: "",
            Order.STATUS: self._parse_from_broker("status", order["OrderStatus"]),
            Order.REJECT_REASON: order.get("CancelRejectReason", ""),
            Order.DISCLOSED_QUANTITY: order["OrderDisclosedQuantity"],
            Order.PRODUCT: order["ProductType"],
            Order.EXCHANGE: self._parse_from_broker(
                "exchange", order["ExchangeSegment"]),
            Order.SEGMENT: self._parse_from_broker(
                "exchange", order["ExchangeSegment"]),
            Order.VALIDITY: order["TimeInForce"],
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_position(
        self,
        position: dict,
    ) -> dict[Any, Any]:
        """Convert a Symphony position row to a unified position record.

        Args:
            position: Raw position row returned by Symphony.

        Returns:
            Unified Fenix position record.
        """
        buy_qty = int(position["OpenBuyQuantity"])
        sell_qty = int(position["OpenSellQuantity"])
        buy_price = float(position["BuyAveragePrice"])
        sell_price = float(position["SellAveragePrice"])

        buy_price = 0.0 if isnan(buy_price) else buy_price
        sell_price = 0.0 if isnan(sell_price) else sell_price

        mtm = (sell_price - buy_price) * min(sell_qty, buy_qty)

        total_qty = sell_qty + buy_qty
        if total_qty:
            avg_price = (
                float(position["BuyAmount"]) + float(position["SellAmount"])
            ) / total_qty
        else:
            avg_price = 0.0

        parsed_position = {
            Position.SYMBOL: position["TradingSymbol"],
            Position.TOKEN: position["ExchangeInstrumentId"],
            Position.NET_QTY: int(
                position["Quantity"]),
            Position.AVG_PRICE: avg_price,
            Position.MTM: mtm,
            Position.PNL: float(
                position["MTM"]),
            Position.BUY_QTY: buy_qty,
            Position.SELL_QTY: sell_qty,
            Position.BUY_PRICE: buy_price,
            Position.SELL_PRICE: sell_price,
            Position.LTP: 0.0,
            Position.EXCHANGE: self._parse_from_broker(
                "exchange", position["ExchangeSegment"]),
            Position.PRODUCT: self._parse_from_broker(
                "product", position["ProductType"]),
            Position.INFO: position,
        }

        return parsed_position

    def _parse_profile(
        self,
        profile: dict,
    ) -> dict[Any, Any]:
        """Convert a Symphony profile payload to a unified profile record.

        Args:
            profile: Raw profile payload returned by Symphony.

        Returns:
            Unified Fenix profile record.
        """
        exclist = profile["ClientExchangeDetailsList"]
        exchanges_enabled = [i for i in exclist if exclist[i]["Enabled"]]

        parsed_profile = {
            Profile.CLIENT_ID: profile["ClientId"],
            Profile.NAME: profile["ClientName"],
            Profile.EMAIL_ID: profile["EmailId"],
            Profile.MOBILE_NO: int(
                profile["MobileNo"]),
            Profile.PAN: profile["PAN"],
            Profile.ADDRESS: profile["ResidentialAddress"],
            Profile.BANK_NAME: profile["ClientBankInfoList"][0]["BankName"],
            Profile.BANK_BRANCH_NAME: None,
            Profile.BANK_ACC_NO: int(
                profile["ClientBankInfoList"][0]["AccountNumber"]),
            Profile.EXCHANGES_ENABLED: exchanges_enabled,
            Profile.ENABLED: None,
            Profile.INFO: profile,
        }

        return parsed_profile

    def _parse_place_order_response(
        self,
        response: Response,
    ) -> dict[Any, Any]:
        """Extract the order id from a Symphony place-order response.

        Args:
            response: HTTP response returned after placing, modifying, or
                cancelling an order.

        Returns:
            Unified order-id record.
        """
        info = self._parse_json_response(response)
        return {Order.ID: info["result"]["AppOrderID"]}

    def _parse_rms(self, rms: dict) -> dict[Any, Any]:
        """Convert a Symphony balance payload to a unified margin record.

        Symphony's ``/user/balance`` endpoint returns a nested ``BalanceList``
        whose first entry contains an ``RMSSubLimits`` block with margin
        figures. Field names vary across deployments, so common keys are tried
        in order and missing keys fall back to ``0.0`` rather than failing.

        Args:
            rms: Raw balance payload returned by Symphony.

        Returns:
            Unified Fenix RMS-limits record.
        """
        sublimits: dict[str, Any] = {}
        balance_list = rms.get("BalanceList") if isinstance(rms, dict) else None
        if isinstance(balance_list, list) and balance_list:
            first = balance_list[0] or {}
            limit_object = first.get("limitObject") or {}
            sublimits = limit_object.get("RMSSubLimits") or {}

        def _to_float(value: Any) -> float:
            try:
                return float(value)
            except (TypeError, ValueError):
                return 0.0

        margin_used = _to_float(
            sublimits.get("marginUtilized")
            or sublimits.get("MarginUtilized")
            or sublimits.get("marginused"),
        )
        margin_avail = _to_float(
            sublimits.get("netMarginAvailable")
            or sublimits.get("NetMarginAvailable")
            or sublimits.get("cashAvailable"),
        )

        return {
            RMS.MARGINUSED: margin_used,
            RMS.MARGINAVAIL: margin_avail,
            RMS.INFO: rms,
        }

    # Order Functions

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
    ) -> tuple[dict[str, Any], str]:
        """Build the Symphony API payload for a place-order request.

        Args:
            token_dict: Token metadata for the instrument being ordered.
            quantity: Number of units to order.
            side: Transaction side in Fenix format.
            product: Product code in Fenix format.
            validity: Order validity in Fenix format.
            variety: Order variety in Fenix format.
            unique_id: Client-provided order tag.
            price: Limit price, or zero for market orders.
            trigger: Stop-loss trigger price, or zero when not applicable.
            target: Bracket-order target price, or zero when not applicable.
            stoploss: Bracket-order stop-loss price.
            trailing_sl: Bracket-order trailing stop-loss amount.

        Returns:
            A tuple of the Symphony place-order payload and the endpoint name
            to post it to.
        """
        order_type = self._resolve_order_type(price, trigger)

        payload = {
            "exchangeInstrumentID": token_dict["Token"],
            "exchangeSegment": self._format_for_broker(
                "exchange", token_dict["Exchange"], raise_error=False,
            ),
            "limitPrice": price,
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": self._format_for_broker("side", side),
            "orderType": self._format_for_broker("order_type", order_type),
            "productType": self._format_for_broker("product", product),
            "timeInForce": self._format_for_broker("validity", validity),
            "orderUniqueIdentifier": unique_id,
            "clientID": self._auth_context["user_id"],
            "disclosedQuantity": 0,
        }

        if not target:
            return payload, "place_order"

        payload.update(
            {
                "squarOff": target,
                "stopLossPrice": stoploss,
                "trailingStoploss": trailing_sl,
            }
        )
        return payload, "place_order_bracket"

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
        """Place an order through Symphony.

        Args:
            token_dict: Token metadata for the instrument being ordered.
            quantity: Number of units to order.
            side: Transaction side in Fenix format.
            product: Product code in Fenix format.
            validity: Order validity in Fenix format.
            variety: Order variety in Fenix format.
            unique_id: Client-provided order tag.
            price: Limit price, or zero for market orders.
            trigger: Stop-loss trigger price, or zero when not applicable.
            target: Bracket-order target price, or zero when not applicable.
            stoploss: Bracket-order stop-loss price.
            trailing_sl: Bracket-order trailing stop-loss amount.

        Returns:
            Unified order-id record for the placed order.
        """
        self._validate_order_inputs(
            quantity=quantity,
            price=price,
            trigger=trigger,
            target=target,
            stoploss=stoploss,
            trailing_sl=trailing_sl,
        )

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

        json_data, endpoint = self._build_place_order_payload(
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
            url=self.get_url(endpoint),
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    # Order Details, OrderBook & TradeBook

    def fetch_raw_orderbook(self) -> list[dict]:
        """Fetch raw Symphony order-book rows.

        Returns:
            Raw broker order-book rows. Empty result-set responses are returned
            as an empty list. In paper mode, returns the unified paper order
            records (paper mode has no raw broker payloads to surface).
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        params = {"clientID": self._auth_context["user_id"]}
        response = self.fetch(
            method="GET",
            url=self.get_url("orderbook"),
            endpoint_group="post_trade",
            params=params,
            headers=self._headers,
        )
        try:
            info = self._parse_json_response(response)
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

        return info.get("result", []) if isinstance(info, dict) else []

    def fetch_raw_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """Fetch raw Symphony history rows for an order.

        Args:
            order_id: Broker order id to query.

        Returns:
            Raw broker order-history rows. In paper mode, returns the unified
            paper order record wrapped in a list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        params = {
            "appOrderID": order_id,
            "clientID": self._auth_context["user_id"],
        }
        response = self.fetch(
            method="GET",
            url=self.get_url("order_history"),
            endpoint_group="post_trade",
            params=params,
            headers=self._headers,
        )

        info = self._parse_json_response(response)
        return info.get("result", []) if isinstance(info, dict) else []

    def fetch_orderbook(self) -> list[dict]:
        """Fetch the order book in the unified Fenix format.

        Returns:
            Unified order records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        info = self.fetch_raw_orderbook()

        orders = []
        for order in info:
            detail = self._parse_orderbook(order)
            orders.append(detail)

        return orders

    def fetch_tradebook(self) -> list[dict]:
        """Fetch the trade book in the unified Fenix format.

        Returns:
            Unified order records. Empty result-set responses are returned as
            an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_tradebook()

        params = {"clientID": self._auth_context["user_id"]}
        response = self.fetch(
            method="GET",
            url=self.get_url("tradebook"),
            endpoint_group="post_trade",
            params=params,
            headers=self._headers,
        )

        try:
            info = self._parse_json_response(response)
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

        rows = info.get("result", []) if isinstance(info, dict) else []
        orders = []
        for order in rows:
            detail = self._parse_orderbook(order)
            orders.append(detail)

        return orders

    def fetch_orders(self) -> list[dict]:
        """Fetch unified orders from the order book.

        Returns:
            Unified Fenix order records — alias for ``fetch_orderbook``.
        """
        return self.fetch_orderbook()

    def fetch_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Fetch one order from the current order history.

        Args:
            order_id: Broker order id to find.

        Returns:
            Unified Fenix order record.

        Raises:
            OrderNotFoundError: If the order id has no history rows.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        info = self.fetch_raw_order_history(order_id=order_id)

        if not info:
            raise OrderNotFoundError("This order_id does not exist.")

        return self._parse_orderbook(info[-1])

    def fetch_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """Fetch order history in the unified Fenix format.

        Args:
            order_id: Broker order id to query.

        Returns:
            Unified order-history records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        info = self.fetch_raw_order_history(order_id=order_id)

        order_history = []
        for order in info:
            history = self._parse_orderbook(order)
            order_history.append(history)

        return order_history

    # Order Modification & Cancellation

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
        """Modify an open Symphony order.

        Args:
            order_id: Broker order id to modify.
            price: Replacement limit price. Existing price is reused when
                omitted.
            trigger: Replacement trigger price. Existing trigger is reused when
                omitted.
            quantity: Replacement quantity. Existing quantity is reused when
                omitted.
            order_type: Replacement order type in Fenix format. Existing type
                is reused when omitted.
            validity: Replacement validity. Existing validity is reused when
                omitted.
            raw_order_json: Optional raw order row to avoid refetching history.
            extra_params: Reserved for broker-specific extensions.

        Returns:
            Unified order-id record for the modified order.
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
            history = self.fetch_raw_order_history(order_id=order_id)
            order_info = history[-1]

        json_data = {
            "appOrderID": order_id,
            "modifiedOrderType": (
                self._format_for_broker("order_type", order_type)
                if order_type
                else order_info["OrderType"]
            ),
            "modifiedLimitPrice": price or order_info["OrderPrice"],
            "modifiedStopPrice": trigger or order_info["OrderStopPrice"],
            "modifiedOrderQuantity": quantity or order_info["OrderQuantity"],
            "modifiedProductType": order_info["ProductType"],
            "modifiedTimeInForce": (
                self._format_for_broker("validity", validity)
                if validity
                else order_info["TimeInForce"]
            ),
            "modifiedDisclosedQuantity": order_info["OrderDisclosedQuantity"],
            "orderUniqueIdentifier": order_info["OrderUniqueIdentifier"],
            "clientID": self._auth_context["user_id"],
        }

        if order_type:
            if order_type == OrderType.LIMIT:
                json_data["modifiedStopPrice"] = 0
            elif order_type == OrderType.MARKET:
                json_data["modifiedLimitPrice"] = 0
                json_data["modifiedStopPrice"] = 0
            elif order_type == OrderType.SLM:
                json_data["modifiedLimitPrice"] = 0

        params = {"clientID": self._auth_context["user_id"]}

        response = self.fetch(
            method="PUT",
            url=self.get_url("modify_order"),
            endpoint_group="orders",
            params=params,
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def cancel_order(
        self,
        order_id: str,
        extra_params: dict | None = None,
    ) -> dict[Any, Any]:
        """Cancel an open Symphony order.

        Args:
            order_id: Broker order id to cancel.
            extra_params: Reserved for broker-specific extensions.

        Returns:
            Unified order-id record for the cancelled order.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.cancel_order(
                order_id=order_id,
                extra_params=extra_params,
            )

        params = {
            "appOrderID": order_id,
            "clientID": self._auth_context["user_id"],
        }
        response = self.fetch(
            method="DELETE",
            url=self.get_url("cancel_order"),
            endpoint_group="orders",
            params=params,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    # Positions, Holdings, Account Limits & Profile

    def fetch_day_positions(self) -> list[Any]:
        """Fetch the day's account positions.

        Returns:
            Unified Fenix position records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        params = {
            "dayOrNet": "DayWise",
            "clientID": self._auth_context["user_id"],
        }
        response = self.fetch(
            method="GET",
            url=self.get_url("positions"),
            endpoint_group="post_trade",
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)

        positions = []
        for position in info["result"]["positionList"]:
            positions.append(self._parse_position(position))

        return positions

    def fetch_net_positions(self) -> list[Any]:
        """Fetch net account positions.

        Returns:
            Unified Fenix position records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        params = {
            "dayOrNet": "NetWise",
            "clientID": self._auth_context["user_id"],
        }
        response = self.fetch(
            method="GET",
            url=self.get_url("positions"),
            endpoint_group="post_trade",
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)

        positions = []
        for position in info["result"]["positionList"]:
            positions.append(self._parse_position(position))

        return positions

    def position_convert(
        self,
        position: dict,
        new_product: str,
    ) -> dict[Any, Any]:
        """Convert a position from one product type to another.

        Args:
            position: Unified Fenix position record describing the position
                to convert.
            new_product: Target product code in Fenix format.

        Returns:
            Decoded broker response payload.
        """
        params = {"clientID": self._auth_context["user_id"]}
        json_data = {
            "exchangeSegment": position[Position.EXCHANGE],
            "exchangeInstrumentID": int(position[Position.TOKEN]),
            "oldProductType": position[Position.PRODUCT],
            "newProductType": new_product,
            "isDayWise": new_product == Product.MIS,
            "targetQty": int(position[Position.NET_QTY]),
            "statisticsLevel": position[Position.INFO]["StatisticsLevel"],
            "isInterOpPosition": position[Position.INFO]["IsInterOpPosition"],
        }

        response = self.fetch(
            method="PUT",
            url=self.get_url("position_convert"),
            endpoint_group="orders",
            params=params,
            json=json_data,
            headers=self._headers,
        )

        return self._parse_json_response(response)

    def fetch_holdings(self) -> dict[Any, Any]:
        """Fetch account holdings.

        Returns:
            Raw Symphony holding payload. Empty result-set responses are
            returned as an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_holdings()

        params = {"clientID": self._auth_context["user_id"]}
        response = self.fetch(
            method="GET",
            url=self.get_url("holdings"),
            endpoint_group="post_trade",
            params=params,
            headers=self._headers,
        )
        try:
            return self._parse_json_response(response)
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

    def fetch_margin_limits(self) -> dict[Any, Any]:
        """Fetch account margin limits.

        Returns:
            Unified Fenix RMS-limits record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_margin_limits()

        params = {"clientID": self._auth_context["user_id"]}
        response = self.fetch(
            method="GET",
            url=self.get_url("rms_limits"),
            endpoint_group="user",
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        result = info.get("result") if isinstance(info, dict) else None
        return self._parse_rms(result if isinstance(result, dict) else {})

    def fetch_profile(self) -> dict[Any, Any]:
        """Fetch account profile details.

        Returns:
            Unified Fenix profile record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_profile()

        params = {"clientID": self._auth_context["user_id"]}
        response = self.fetch(
            method="GET",
            url=self.get_url("profile"),
            endpoint_group="user",
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return self._parse_profile(info["result"])
