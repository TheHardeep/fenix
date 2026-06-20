from __future__ import annotations

import csv
import io
import os
import re
import urllib.parse
import zipfile
from collections import defaultdict
from datetime import datetime
from typing import TYPE_CHECKING, Any

import urllib3
from requests_oauthlib import OAuth2Session

from fenix.base.broker import Broker
from fenix.base.constants import (
    RMS,
    ExchangeCode,
    Order,
    OrderType,
    Position,
    Product,
    Profile,
    Side,
    Status,
    Validity,
    Variety,
)
from fenix.base.errors import (
    AuthenticationError,
    InputError,
    InvalidOrderError,
    NetworkError,
    OrderNotFoundError,
    PermissionDeniedError,
    ResponseError,
)

if TYPE_CHECKING:
    from requests.models import Response


class MasterTrust(Broker):
    """MasterTrust broker adapter for the Fenix trading interface."""

    # Market Data Dictionaries

    _API = {
        "doc": "https://tradeapi.mastertrust.co.in",
        "marketdata_doc": "http://139.180.212.2/ray-websocket",
        "servers": {
            "api": "https://masterswift-beta.mastertrust.co.in/api/v1",
            "auth": "https://masterswift-beta.mastertrust.co.in",
            "market_data": "https://masterswift.mastertrust.co.in/api/v2",
            "compact": "https://masterswift-beta.mastertrust.co.in/api/v1",
        },
        "paths": {
            # --- Auth Flow ---
            "auth": {
                "server": "auth",
                "path": "/oauth2/auth",
            },
            "auth_token": {
                "server": "auth",
                "path": "/oauth2/token",
            },

            # --- Order & Portfolio Flow ---
            "place_order": {
                "server": "api",
                "path": "/orders",
            },
            "place_bracket_order": {
                "server": "api",
                "path": "/orders/bracket",
            },
            "modify_order": {
                "server": "api",
                "path": "/orders",
            },
            "cancel_order": {
                "server": "api",
                "path": "/orders",
            },
            "order_history": {
                "server": "api",
                "path": "/order",
            },
            "orderbook": {
                "server": "api",
                "path": "/orders",
            },
            "tradebook": {
                "server": "api",
                "path": "/trades",
            },
            "positions": {
                "server": "api",
                "path": "/positions",
            },
            "holdings": {
                "server": "api",
                "path": "/holdings",
            },
            "rms_limits": {
                "server": "api",
                "path": "/funds/view",
            },
            "profile": {
                "server": "api",
                "path": "/user/profile",
            },

            # --- Market Data ---
            "instruments": {
                "server": "market_data",
                "path": "/contracts.json",
            },
            "instruments_compact": {
                "server": "compact",
                "path": "/contract/Compact",
            },
        },
        "redirect_uri": "http://127.0.0.1/getCode",
    }

    STANDARD_MAPS = {
        "side": {
            "BUY": Side.BUY,
            "SELL": Side.SELL,
        },
        "order_type": {
            "MARKET": OrderType.MARKET,
            "LIMIT": OrderType.LIMIT,
            "SL": OrderType.SL,
            "SLM": OrderType.SLM,
        },
        "product": {
            "NRML": Product.NRML,
            "MIS": Product.MIS,
            "CNC": Product.CNC,
            "CO": Product.CO,
        },
        "exchange": {
            "NSE": ExchangeCode.NSE,
            "NFO": ExchangeCode.NFO,
            "BSE": ExchangeCode.BSE,
            "BFO": ExchangeCode.BFO,
            "MCX": ExchangeCode.MCX,
            "CDS": ExchangeCode.CDS,
        },
        "validity": {
            "DAY": Validity.DAY,
            "IOC": Validity.IOC,
        },
        "status": {
            "open pending": Status.PENDING,
            "not modified": Status.PENDING,
            "not cancelled": Status.PENDING,
            "modify pending": Status.PENDING,
            "trigger pending": Status.PENDING,
            "cancel pending": Status.PENDING,
            "validation pending": Status.PENDING,
            "put order req received": Status.PENDING,
            "modify validation pending": Status.PENDING,
            "after market order req received": Status.PENDING,
            "modify after market order req received": Status.PENDING,
            "cancelled": Status.CANCELLED,
            "cancelled after market order": Status.CANCELLED,
            "open": Status.OPEN,
            "complete": Status.FILLED,
            "rejected": Status.REJECTED,
            "modified": Status.MODIFIED,
        },
    }

    REQUEST_MAPS = {
        "side": {
            Side.BUY: "BUY",
            Side.SELL: "SELL",
        },
        "exchange": {
            ExchangeCode.NSE: "NSE",
            ExchangeCode.NFO: "NFO",
            ExchangeCode.CDS: "CDS",
            ExchangeCode.BSE: "BSE",
            ExchangeCode.BFO: "BSE",
            ExchangeCode.MCX: "MCX",
        },
        "order_type": {
            OrderType.MARKET: "MARKET",
            OrderType.LIMIT: "LIMIT",
            OrderType.SL: "SL",
            OrderType.SLM: "SLM",
        },
        "product": {
            Product.NRML: "NRML",
            Product.MIS: "MIS",
            Product.CNC: "CNC",
            Product.CO: "CO",
        },
        "validity": {
            Validity.DAY: "DAY",
            Validity.IOC: "IOC",
        },
        "variety": {
            Variety.REGULAR: "REGULAR",
            Variety.STOPLOSS: "STOPLOSS",
            Variety.AMO: "AMO",
            Variety.BO: "BO",
        },
    }

    _REQUIRED_AUTH_HEADER_KEYS = ("Authorization",)

    _AUTH_CONTEXT_KEYS = ("user_id",)

    ERROR_CODE_KEYS = (
        "code",
        "errorCode",
        "error_code",
        "status_code",
    )

    ERROR_MESSAGE_KEYS = (
        "message",
        "description",
        "error",
        "reason",
        "rejection_reason",
    )

    _ERROR_MESSAGES = {
        "200": "OK.",
        "400": "Bad request.",
        "401": "Authentication failure.",
        "403": "Forbidden.",
        "404": "Resource not found.",
        "405": "Method Not Allowed.",
        "500": "Internal Server Error.",
        "503": "Service Unavailable.",
    }

    _DIRECT_ERROR_CLASSES = {
        "400": InputError,
        "401": AuthenticationError,
        "403": PermissionDeniedError,
        "404": ResponseError,
        "405": InvalidOrderError,
    }

    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "MasterTrust",
            "tokenParams": [
                "user_id",
                "password",
                "totpstr",
                "client_id",
                "client_secret",
            ],
            "proxies": {},
            "sensitiveLogKeys": [
                "user_id",
                "password",
                "totpstr",
                "client_id",
                "client_secret",
                "login_id",
                "_csrf_token",
                "login_challenge",
                "question_ids",
                "answers",
                "code",
                "access_token",
                "refresh_token",
                "Authorization",
            ],
            "enableRateLimit": False,
            "rateLimits": {},
        }

    def __init__(self, config: dict | None = None):
        """Initialize the MasterTrust broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
                Pass ``{"paper_mode": True}`` to route order entry and reads
                through the in-process paper-trading engine instead of the
                MasterTrust API.
        """
        super().__init__(config)

    # NFO Script Fetch

    def load_equity_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE equity token metadata.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"NSE"`` and ``"BSE"``.

        Returns:
            A tuple containing the unified equity token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
        """
        if not data:

            params = {"exchanges": "NSE"}
            response = self.fetch(
                method="GET",
                endpoint_group="default",
                url=self.get_url("instruments"),
                params=params,
                verify=False,
                timeout=300
            )
            nse_data = self._parse_json_response(response)
            nse_data = nse_data["NSE"] + nse_data["NSE-OTH"]

            params = {"exchanges": "BSE"}
            response = self.fetch(
                method="GET",
                endpoint_group="default",
                url=self.get_url("instruments"),
                params=params,
                verify=False,
                timeout=120
            )
            bse_data = self._parse_json_response(response)
            bse_data = bse_data["BSE"]

        else:
            if "NSE" not in data or "BSE" not in data or "NSE-OTH" not in data:
                raise KeyError("JSON data must contain 'NSE', 'NSE-OTH' and 'BSE' keys")

            nse_data = data["NSE"] + data["NSE-OTH"]
            bse_data = data["BSE"]

        nse_dict = {}
        bse_dict = {}
        alltoken_dict = {}

        for tok_data in nse_data:

            symbol = tok_data["symbol"]
            token = tok_data["code"]
            exchange = tok_data["exchange"]

            if "NSETEST" in symbol:
                continue

            record = {
                "Token": token,
                "Exchange": exchange,
                "Symbol": tok_data["trading_symbol"],
                "ScriptName": symbol,
                "ExchangeCode": tok_data["exchange_code"],
            }

            if tok_data.get("lotSize"):
                record["LotSize"] = tok_data["lotSize"]

            nse_dict[symbol] = record

            token_key = f"{token}_{exchange}"
            alltoken_dict[token_key] = record

        for tok_data in bse_data:

            symbol = tok_data["symbol"]
            token = tok_data["code"]
            exchange = tok_data["exchange"]

            record = {
                "Token": token,
                "Exchange": exchange,
                "Symbol": tok_data["trading_symbol"],
                "ScriptName": symbol,
                "ExchangeCode": tok_data["exchange_code"],
            }

            if tok_data.get("lotSize"):
                record["LotSize"] = tok_data["lotSize"]

            bse_dict[symbol] = record

            token_key = f"{token}_{exchange}"
            alltoken_dict[token_key] = record

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

    def load_index_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE index token metadata.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"NSE-IND"`` and ``"BSE-IND"``.

        Returns:
            A tuple containing the unified index token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
        """
        if not data:

            params = {"exchanges": "NSE"}
            response = self.fetch(
                method="GET",
                endpoint_group="default",
                url=self.get_url("instruments"),
                params=params,
                verify=False,
                timeout=300
            )
            nse_data = self._parse_json_response(response)
            nse_data = nse_data["NSE-IND"]

            params = {"exchanges": "BSE"}
            response = self.fetch(
                method="GET",
                endpoint_group="default",
                url=self.get_url("instruments"),
                params=params,
                verify=False,
                timeout=300
            )
            bse_data = self._parse_json_response(response)
            bse_data = bse_data["BSE-IND"]

        else:
            if "NSE-IND" not in data or "BSE-IND" not in data:
                raise KeyError("JSON data must contain 'NSE-IND' and 'BSE-IND' keys")

            nse_data = data["NSE-IND"]
            bse_data = data["BSE-IND"]


        nse_dict = {}
        bse_dict = {}
        token_dict = {}

        for tok_data in nse_data:

            symbol = tok_data["symbol"]
            token = tok_data["code"]
            exchange = tok_data["exchange"]

            record = {
                "Token": token,
                "Exchange": exchange,
                "Symbol": tok_data["trading_symbol"],
                "ScriptName": symbol,
                "ExchangeCode": tok_data["exchange_code"],
            }

            nse_dict[symbol] = record

            token_key = f"{token}_{exchange}"
            token_dict[token_key] = record

        for tok_data in bse_data:

            symbol = tok_data["symbol"]
            token = tok_data["code"]
            exchange = tok_data["exchange"]

            record = {
                "Token": token,
                "Exchange": exchange,
                "Symbol": tok_data["trading_symbol"],
                "ScriptName": symbol,
                "ExchangeCode": tok_data["exchange_code"],
            }

            bse_dict[symbol] = record

            token_key = f"{token}_{exchange}"
            token_dict[token_key] = record

        self.token_json["Indices"].update({
            "NSE": nse_dict,
            "BSE": bse_dict,
        })

        self.alltoken_json.update(token_dict)

        return (
            {
                "Indices": {"NSE": nse_dict, "BSE": bse_dict},
            },
            token_dict,
        )

    def load_fno_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load futures and options token metadata for NFO and BFO.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"NSE-OPT"``, ``"NSE-FUT"``, and ``"BFO"``.

        Returns:
            A tuple containing unified futures/options token maps and an
            all-token lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving contract-master data.
        """
        if not data:

            params = {"exchanges": "NFO"}
            response = self.fetch(
                method="GET",
                endpoint_group="default",
                url=self.get_url("instruments"),
                params=params,
                verify=False,
                timeout=300
            )
            nse_data = self._parse_json_response(response)

            params = {
                    "info": "download",
                    "exchanges": "BFO",
                }
            response = self.fetch(
                method="GET",
                endpoint_group="default",
                url=self.get_url("instruments_compact"),
                params=params,
                verify=False,
                timeout=300
            )

            bse_buffer = io.BytesIO(response.content)

        else:
            if "NSE-OPT" not in data or "NSE-FUT" not in data or "BFO" not in data:
                raise KeyError("JSON data must contain 'NSE-OPT', 'NSE-FUT' and 'BFO' keys")

            nse_data = data["NSE-OPT"] + data["NSE-FUT"]
            bse_buffer = io.BytesIO(data["BSE"].content)


        dt_dict = {}

        fut_nse = defaultdict(list)
        fut_bse = defaultdict(list)
        opt_nse = defaultdict(list)
        opt_bse = defaultdict(list)
        token_dict = {}

        opt_series = ["SO", "IO"]
        fut_series = ["SF", "IF"]


        for tok_data in nse_data["NSE-OPT"]:

            exchange = tok_data["exchange"]

            if exchange != "NFO":
                continue

            expiry_raw = tok_data["expiry"]

            split_data = tok_data["symbol"].split(" ")
            root = split_data[0]
            strike = split_data[-2]
            option = split_data[-1]

            token = tok_data["code"]
            strike = self._format_strike(strike)

            if expiry_raw not in dt_dict:
                dt = datetime.fromtimestamp(expiry_raw).date()
                expiry = dt.strftime("%Y-%m-%d")
                exdp = dt.strftime("%d-%b").upper()
                dt_dict[expiry_raw] = (expiry, exdp)

            else:
                (expiry, exdp) = dt_dict[expiry_raw]

            record = {
                "Exchange": exchange,
                "Token": token,
                "Root": root,
                "Symbol": tok_data["trading_symbol"],
                "LotSize": tok_data["lotSize"],
                "Expiry": expiry,
                "StrikePrice": strike,
                "Option": option,
                "ExchangeCode": tok_data["exchange_code"],
                "ScriptName": f"{root} {exdp} {strike} {option}",
            }

            opt_nse[root].append(record)
            token_key = f"{token}_{exchange}"
            token_dict[token_key] = record

        for tok_data in nse_data["NSE-FUT"]:

            exchange = tok_data["exchange"]
            symbol = tok_data["symbol"]

            if exchange != "NFO":
                continue

            if "NSETEST" in symbol:
                continue

            expiry_raw = tok_data["expiry"]

            split_data = symbol.split(" ")
            root = split_data[0]
            strike = split_data[-2]
            option = split_data[-1]

            token = tok_data["code"]

            if expiry_raw not in dt_dict:
                dt = datetime.fromtimestamp(expiry_raw).date()
                expiry = dt.strftime("%Y-%m-%d")
                exdp = dt.strftime("%d-%b").upper()
                dt_dict[expiry_raw] = (expiry, exdp)

            else:
                (expiry, exdp) = dt_dict[expiry_raw]

            record = {
                "Exchange": exchange,
                "Token": token,
                "Root": root,
                "Symbol": tok_data["trading_symbol"],
                "LotSize": tok_data["lotSize"],
                "Expiry": expiry,
                "Option": option,
                "ExchangeCode": tok_data["exchange_code"],
                "ScriptName": f"{root} {exdp} FUT",
            }

            fut_nse[root].append(record)
            token_key = f"{token}_{exchange}"
            token_dict[token_key] = record

        with zipfile.ZipFile(bse_buffer) as z:
            file_name = z.namelist()[0]

            with z.open(file_name) as f:

                text_stream = io.TextIOWrapper(f, encoding="utf-8")
                csv_reader = csv.DictReader(text_stream)

                for tok_data in csv_reader:

                    expiry_raw = tok_data["expiry"]
                    root = tok_data["company_name"]
                    strike = self._format_strike(tok_data["strike"])
                    option = tok_data["option_type"]
                    exchange = tok_data["exchange"]
                    token = tok_data["exchange_token"]
                    instrument_type = tok_data["instrument_name"]

                    if exchange != "BFO":
                        continue

                    if expiry_raw not in dt_dict:
                        dt = datetime.strptime(expiry_raw, "%d-%b-%Y").date()
                        expiry = dt.strftime("%Y-%m-%d")
                        exdp = dt.strftime("%d-%b").upper()
                        dt_dict[expiry_raw] = (expiry, exdp)

                    else:
                        (expiry, exdp) = dt_dict[expiry_raw]

                    if instrument_type in fut_series:
                        record = {
                            "Exchange": exchange,
                            "Token": token,
                            "Root": root,
                            "Symbol": tok_data["trading_symbol"],
                            "TickSize": tok_data["tick_size"],
                            "LotSize": tok_data["lot_size"],
                            "Expiry": expiry,
                            "ScriptName": f"{root} {exdp} FUT",
                        }

                        fut_bse[root].append(record)

                    elif instrument_type in opt_series:
                        record = {
                            "Exchange": exchange,
                            "Token": token,
                            "Root": root,
                            "Symbol": tok_data["trading_symbol"],
                            "TickSize": tok_data["tick_size"],
                            "LotSize": tok_data["lot_size"],
                            "Expiry": expiry,
                            "StrikePrice": strike,
                            "Option": option,
                            "ScriptName": f"{root} {exdp} {strike} {option}",
                        }

                        opt_bse[root].append(record)

                    token_key = f"{token}_{exchange}"
                    token_dict[token_key] = record

        self.token_json["Futures"].update({"NFO": fut_nse, "BFO": fut_bse})
        self.token_json["Options"].update({"NFO": opt_nse, "BFO": opt_bse})

        self.alltoken_json.update(token_dict)

        return (
            {
                "Futures": {"NFO": fut_nse, "BFO": fut_bse},
                "Options": {"NFO": opt_nse, "BFO": opt_bse},
            },
            token_dict,
        )

    def load_mcx_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load MCX futures and options token metadata.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"MCX"``.

        Returns:
            A tuple containing unified MCX token maps and an all-token lookup
            keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data does not include MCX.
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving contract-master data.
        """
        if not data:

            params = {"exchanges": "MCX"}
            response = self.fetch(
                method="GET",
                endpoint_group="default",
                url=self.get_url("instruments"),
                params=params,
                verify=False,
            )
            mcx_data = self._parse_json_response(response)
            mcx_data = mcx_data["MCX"]
        else:
            if "MCX" not in data:
                raise KeyError("JSON data must contain 'MCX' key")

            mcx_data = data["MCX"]


        dt_dict = {}

        fut_mcx = defaultdict(list)
        opt_mcx = defaultdict(list)
        token_dict = {}

        for tok_data in mcx_data:

            exchange = tok_data["exchange"]
            symbol = tok_data["symbol"]

            if tok_data.get("index"):
                continue

            if symbol[-2:] == "XX":
                continue

            expiry_raw = tok_data["expiry"]

            split_data = symbol.split(" ")
            root = split_data[0]
            strike = split_data[-2]
            option = split_data[-1]

            token = tok_data["code"]

            if expiry_raw not in dt_dict:
                dt = datetime.fromtimestamp(expiry_raw).date()
                expiry = dt.strftime("%Y-%m-%d")
                exdp = dt.strftime("%d-%b").upper()
                dt_dict[expiry_raw] = (expiry, exdp)

            else:
                (expiry, exdp) = dt_dict[expiry_raw]

            if "FUT" in symbol:
                record = {
                    "Exchange": exchange,
                    "Token": token,
                    "Root": root,
                    "Symbol": tok_data["trading_symbol"],
                    "Expiry": expiry,
                    "ExchangeCode": tok_data["exchange_code"],
                    "ScriptName": f"{root} {exdp} FUT",
                }
                if tok_data.get("lotSize"):
                    record["LotSize"] = tok_data["lotSize"]

                fut_mcx[root].append(record)

            else:
                strike = self._format_strike(strike)

                record = {
                    "Exchange": exchange,
                    "Token": token,
                    "Root": root,
                    "Symbol": tok_data["trading_symbol"],
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "LotSize": tok_data["lotSize"],
                    "Option": option,
                    "ExchangeCode": tok_data["exchange_code"],
                    "ScriptName": f"{root} {exdp} {strike} {option}",
                }

                opt_mcx[root].append(record)

            token_key = f"{token}_{exchange}"
            token_dict[token_key] = record

        self.token_json["Futures"].update({"MCX": fut_mcx})
        self.token_json["Options"].update({"MCX": opt_mcx})

        self.alltoken_json.update(token_dict)

        return (
                {
                    "Futures": {"MCX": fut_mcx},
                    "Options": {"MCX": opt_mcx},
                },
                token_dict,
            )

    def load_cds_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load currency derivatives token metadata for CDS.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"NSE-OPT"`` and ``"NSE-FUT"``.

        Returns:
            A tuple containing unified currency futures/options token maps and
            an all-token lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving contract-master data.
        """
        if not data:

            params = {"exchanges": "NFO"}
            response = self.fetch(
                method="GET",
                endpoint_group="default",
                url=self.get_url("instruments"),
                params=params,
                verify=False,
            )
            nse_data = self._parse_json_response(response)

        else:
            if "NSE-OPT" not in data or "NSE-FUT" not in data:
                raise KeyError("JSON data must contain 'NSE-OPT' and 'NSE-FUT' keys")

            nse_data = data["NSE-OPT"] + data["NSE-FUT"]


        dt_dict = {}

        fut_cds = defaultdict(list)
        opt_cds = defaultdict(list)
        token_dict = {}

        for tok_data in nse_data["NSE-OPT"]:

            exchange = tok_data["exchange"]

            if exchange != "CDS":
                continue

            expiry_raw = tok_data["expiry"]

            split_data = tok_data["symbol"].split(" ")
            root = split_data[0]
            strike = split_data[-2]
            option = split_data[-1]

            token = tok_data["code"]
            strike = self._format_strike(strike)

            if expiry_raw not in dt_dict:
                dt = datetime.fromtimestamp(expiry_raw).date()
                expiry = dt.strftime("%Y-%m-%d")
                exdp = dt.strftime("%d-%b").upper()
                dt_dict[expiry_raw] = (expiry, exdp)

            else:
                (expiry, exdp) = dt_dict[expiry_raw]

            record = {
                "Exchange": exchange,
                "Token": token,
                "Root": root,
                "Symbol": tok_data["trading_symbol"],
                "Expiry": expiry,
                "StrikePrice": strike,
                "Option": option,
                "ExchangeCode": tok_data["exchange_code"],
                "ScriptName": f"{root} {exdp} {strike} {option}",
            }

            if tok_data.get("lotSize"):
                record["LotSize"] = tok_data["lotSize"]

            opt_cds[root].append(record)
            token_key = f"{token}_{exchange}"
            token_dict[token_key] = record

        for tok_data in nse_data["NSE-FUT"]:

            exchange = tok_data["exchange"]
            symbol = tok_data["symbol"]

            if exchange != "CDS":
                continue

            if "NSETEST" in symbol:
                continue

            expiry_raw = tok_data["expiry"]

            split_data = symbol.split(" ")
            root = split_data[0]
            strike = split_data[-2]
            option = split_data[-1]

            token = tok_data["code"]

            if expiry_raw not in dt_dict:
                dt = datetime.fromtimestamp(expiry_raw).date()
                expiry = dt.strftime("%Y-%m-%d")
                exdp = dt.strftime("%d-%b").upper()
                dt_dict[expiry_raw] = (expiry, exdp)

            else:
                (expiry, exdp) = dt_dict[expiry_raw]

            record = {
                "Exchange": exchange,
                "Token": token,
                "Root": root,
                "Symbol": tok_data["trading_symbol"],
                "Expiry": expiry,
                "Option": option,
                "ExchangeCode": tok_data["exchange_code"],
                "ScriptName": f"{root} {exdp} FUT",
            }

            if tok_data.get("lotSize"):
                record["LotSize"] = tok_data["lotSize"]

            fut_cds[root].append(record)
            token_key = f"{token}_{exchange}"
            token_dict[token_key] = record

        self.token_json["Futures"].update({"CDS": fut_cds})
        self.token_json["Options"].update({"CDS": opt_cds})

        self.alltoken_json.update(token_dict)

        return (
            {
                "Futures": {"CDS": fut_cds},
                "Options": {"CDS": opt_cds},
            },
            token_dict,
        )


    # Authentication & Response Parsers

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """
        Authenticate with MasterTrust and return reusable request headers.

        Args:
            params: Login credentials and API keys required by MasterTrust.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and run the login flow.

        Returns:
            Headers that can authenticate subsequent MasterTrust API calls.

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
            return {**self._headers, **self._auth_context}

        if params is None:
            raise KeyError("Please provide params or headers")

        for key in self.tokenParams:
            if key not in params:
                raise KeyError(f"Please provide {key}")

        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        scope = ["orders", "holdings"]

        oauth = OAuth2Session(
            params["client_id"],
            redirect_uri=self._API["redirect_uri"],
            scope=scope
        )
        authorization_url, _state = oauth.authorization_url(self.get_url("auth"))
        self._session.headers.update({
            "DNT": "1",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Site": "none",
            "Connection": "keep-alive",
            "Sec-Fetch-Mode": "navigate",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9,hi;q=0.8",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36",
            "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        })
        response01 = self.fetch(
            method="GET",
            endpoint_group="default",
            url=authorization_url,
            verify=False
        )

        parsed_url = urllib.parse.urlparse(response01.url)
        login_challenge = urllib.parse.parse_qs(parsed_url.query).get('login_challenge', [None])[0]

        csrf_match = re.search(r'value="([^"]+)" name="_csrf_token"', response01.text)
        csrf_token = csrf_match.group(1)

        data = {
            "login_id": params["user_id"],
            "password": params["password"],
            "login_challenge": login_challenge,
            "_csrf_token": csrf_token,
        }

        response02 = self.fetch(
            method="POST",
            endpoint_group="default",
            url=response01.url,
            data=data,
            allow_redirects=False,
            verify=False
        )

        redirected_url = response02.headers.get('Location')
        full_twofa_url = urllib.parse.urljoin(self._API["servers"]["auth"], redirected_url)

        response03 = self.fetch(
                method="GET",
                endpoint_group="default",
                url=full_twofa_url,
                verify=False,
            )

        csrf_match_2fa = re.search(r'value="([^"]+)" name="_csrf_token"', response03.text)
        csrf_token_2fa = csrf_match_2fa.group(1) if csrf_match_2fa else ""

        q_id_match = re.search(r'name="question_ids\[\]"\s+value="([^"]+)"', response03.text)
        question_id = q_id_match.group(1) if q_id_match else "51"

        totp = self.totp_creator(params["totpstr"])

        twofa_payload = {
            "answers[]": totp,
            "question_ids[]": question_id,
            "login_challenge": login_challenge,
            "_csrf_token": csrf_token_2fa
        }

        req_params = {
            'login_challenge': login_challenge,
            'login_id': params["user_id"],
            'qstate':  '[{"question_id"' + f':{question_id},' '"question":"Please enter TOTP (Use your auth app in mobile to find the 6 digit code)"}]',
            'twofa_token': re.search(r'twofa_token=([^"]+)&', response03.url).group(1),
            'twofa_type': 'totp',
        }


        try:
            response04 = self.fetch(
                method="POST",
                endpoint_group="default",
                url=response03.url,
                data=twofa_payload,
                allow_redirects=True,
                params=req_params,
                verify=False
            )

            if "/oauth/consent" in response04.url:
                consent_response = self.fetch(
                    method="GET",
                    endpoint_group="default",
                    url=response04.url,
                    verify=False
                )


                csrf_match_consent = re.search(r'value="([^"]+)" name="_csrf_token"', consent_response.text)
                csrf_token_consent = csrf_match_consent.group(1) if csrf_match_consent else ""

                consent_payload = {
                    "scopes": "orders|holdings",
                    "_csrf_token": csrf_token_consent,
                    "consent": "allow"
                }

                try:
                    self.fetch(
                        method="POST",
                        endpoint_group="default",
                        url=consent_response.url,
                        data=consent_payload,
                        allow_redirects=True,
                        verify=False,
                    )
                except NetworkError as e:
                    final_redirect_url = str(e).split(" ")[-1]

        except NetworkError as e:
            final_redirect_url = str(e).split(" ")[-1]

        token_resp = oauth.fetch_token(
                token_url=self.get_url("auth_token"),
                authorization_response=final_redirect_url,
                client_secret=params["client_secret"],
                verify=False
            )


        return self.use_headers(
            {
                "Authorization": f"Bearer {token_resp['access_token']}",
            },
            reset_session=True,
            auth_params={"user_id": params["user_id"],}
        )

    def _parse_json_response(self, response: Response) -> Any:
        """Decode an HTTP response using the shared broker JSON parser."""
        return self._json_parser(response)

    def _parse_order_history(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a MasterTrust order-history row to a unified order record.

        Args:
            order: Raw order-history row returned by MasterTrust.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["order_id"],
            Order.USER_ID: order["client_order_id"],
            Order.TIMESTAMP: (
                datetime.strptime(
                    order["exchange_time"],
                    "%d-%b-%Y %H:%M:%S",
                )
                if order["exchange_time"] != "--"
                else None
            ),
            Order.SYMBOL: order["symbol"],
            Order.TOKEN: order["token"],
            Order.SIDE: self._parse_from_broker("side", order["order_side"]),
            Order.TYPE: self._parse_from_broker(
                "order_type",
                order["order_type"],
            ),
            Order.AVG_PRICE: float(order.get("avg_price") or 0.0),
            Order.PRICE: float(order.get("price") or 0.0),
            Order.TRIGGER_PRICE: float(order.get("trigger_price") or 0.0),
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: int(order["quantity"]),
            Order.FILLED_QTY: int(order.get("fill_quantity") or 0),
            Order.REMAINING_QTY: (
                int(order["quantity"]) - int(order.get("fill_quantity") or 0)
            ),
            Order.CANCELLED_QTY: 0,
            Order.STATUS: self._parse_from_broker("status", order["status"]),
            Order.REJECT_REASON: order["reject_reason"],
            Order.DISCLOSED_QUANTITY: int(order["disclosed_quantity"] or 0),
            Order.PRODUCT: self._parse_from_broker("product", order["product"]),
            Order.EXCHANGE: "",
            Order.SEGMENT: order["segment"],
            Order.VALIDITY: self._parse_from_broker("validity", order["validity"]),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_orderbook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a MasterTrust order-book row to a unified order record.

        Args:
            order: Raw order-book row returned by MasterTrust.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["oms_order_id"],
            Order.USER_ID: order["user_order_id"],
            Order.TIMESTAMP: datetime.fromtimestamp(order["order_entry_time"]),
            Order.SYMBOL: order["trading_symbol"],
            Order.TOKEN: int(order["instrument_token"]),
            Order.SIDE: self._parse_from_broker("side", order["order_side"]),
            Order.TYPE: self._parse_from_broker(
                "order_type",
                order["order_type"],
            ),
            Order.AVG_PRICE: float(order["average_price"] or 0.0),
            Order.PRICE: float(order["price"] or 0.0),
            Order.TRIGGER_PRICE: float(order["trigger_price"] or 0.0),
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: float(order["stop_loss_value"] or 0.0),
            Order.TRAILING_STOPLOSS: float(order["trailing_stop_loss"] or 0.0),
            Order.QUANTITY: int(order["quantity"]),
            Order.FILLED_QTY: int(order["filled_quantity"] or 0),
            Order.REMAINING_QTY: int(order["remaining_quantity"] or 0),
            Order.CANCELLED_QTY: 0,
            Order.STATUS: self._parse_from_broker(
                "status",
                order["order_status"],
            ),
            Order.REJECT_REASON: order["rejection_reason"],
            Order.DISCLOSED_QUANTITY: int(order["disclosed_quantity"] or 0),
            Order.PRODUCT: self._parse_from_broker("product", order["product"]),
            Order.EXCHANGE: self._parse_from_broker("exchange", order["exchange"]),
            Order.SEGMENT: order["segment"],
            Order.VALIDITY: self._parse_from_broker("validity", order["validity"]),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_tradebook(
        self,
        trade: dict,
    ) -> dict[Any, Any]:
        """Convert a MasterTrust trade-book row to a unified order record.

        Args:
            trade: Raw trade-book row returned by MasterTrust.

        Returns:
            Unified Fenix order record.
        """
        parsed_trade = {
            Order.ID: trade["oms_order_id"],
            Order.USER_ID: "",
            Order.TIMESTAMP: datetime.fromtimestamp(trade["order_entry_time"]),
            Order.SYMBOL: trade["trading_symbol"],
            Order.TOKEN: int(trade["instrument_token"]),
            Order.SIDE: self._parse_from_broker("side", trade["order_side"]),
            Order.TYPE: self._parse_from_broker(
                "order_type",
                trade["order_type"],
            ),
            Order.AVG_PRICE: float(trade["trade_price"] or 0.0),
            Order.PRICE: float(trade["order_price"] or 0.0),
            Order.TRIGGER_PRICE: 0.0,
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: int(trade["trade_quantity"]),
            Order.FILLED_QTY: int(trade["filled_quantity"] or 0),
            Order.REMAINING_QTY: int(trade["remaining_quantity"] or 0),
            Order.CANCELLED_QTY: 0,
            Order.STATUS: "",
            Order.REJECT_REASON: "",
            Order.DISCLOSED_QUANTITY: 0,
            Order.PRODUCT: self._parse_from_broker("product", trade["product"]),
            Order.EXCHANGE: self._parse_from_broker("exchange", trade["exchange"]),
            Order.SEGMENT: "",
            Order.VALIDITY: "",
            Order.VARIETY: "",
            Order.INFO: trade,
        }

        return parsed_trade

    def _parse_position(
        self,
        position: dict,
    ) -> dict[Any, Any]:
        """Convert a MasterTrust position payload to a unified position record.

        Args:
            position: Raw position payload returned by MasterTrust.

        Returns:
            Unified Fenix position record.
        """
        parsed_position = {
            Position.SYMBOL: position["trading_symbol"],
            Position.TOKEN: position["token"],
            Position.PRODUCT: self._parse_from_broker(
                "product",
                position["product"],
            ),
            Position.NET_QTY: position["net_quantity"],
            Position.AVG_PRICE: position["average_price"],
            Position.MTM: position.get("realized_mtm"),
            Position.BUY_QTY: position["buy_quantity"],
            Position.BUY_PRICE: position["average_buy_price"],
            Position.SELL_QTY: position["sell_quantity"],
            Position.SELL_PRICE: position["average_sell_price"],
            Position.LTP: position["ltp"],
            Position.INFO: position,
        }

        return parsed_position

    def _parse_profile(
        self,
        profile: dict,
    ) -> dict[Any, Any]:
        """Convert a MasterTrust profile payload to a unified profile record.

        Args:
            profile: Raw profile payload returned by MasterTrust.

        Returns:
            Unified Fenix profile record.
        """
        parsed_profile = {
            Profile.CLIENT_ID: profile["account_id"],
            Profile.NAME: profile["name"],
            Profile.EMAIL_ID: profile["email_id"],
            Profile.MOBILE_NO: profile["phone_number"],
            Profile.PAN: profile["pan_number"],
            Profile.ADDRESS: profile["permanent_addr"],
            Profile.BANK_NAME: profile["bank_name"],
            Profile.BANK_BRANCH_NAME: profile["branch"],
            Profile.BANK_ACC_NO: profile["bank_account_number"],
            Profile.EXCHANGES_ENABLED: [],
            Profile.ENABLED: profile["status"] == "Activated",
            Profile.INFO: profile,
        }

        return parsed_profile

    def _parse_rms(self, rms: dict) -> dict[Any, Any]:
        """Convert a MasterTrust RMS payload to a unified margin record.

        Args:
            rms: Raw RMS payload returned by MasterTrust.

        Returns:
            Unified Fenix RMS limits record.
        """
        rms = rms["values"]
        parsed_rms = {
            RMS.MARGINUSED: float(rms[2][-1]),
            RMS.MARGINAVAIL: float(rms[0][-1]),
            RMS.CASHMARGIN: float(rms[5][-1]),
            RMS.VARIABLEMARGIN: float(rms[7][-1]),
            RMS.SPANMARGIN: float(rms[8][-1]),
            RMS.COLLATERAL: float(rms[6][-1]),
            RMS.INFO: rms,
        }

        return parsed_rms

    def _parse_place_order_response(self, response: Response) -> dict[Any, Any]:
        """Extract the order id from a MasterTrust place-order response.

        Args:
            response: HTTP response returned after placing, modifying, or
                cancelling an order.

        Returns:
            Unified order-id record.
        """
        info = self._parse_json_response(response)
        return {Order.ID: info["data"]["oms_order_id"]}

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
    ) -> dict[str, Any]:
        """Build the MasterTrust API payload for a place-order request.

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
            MasterTrust place-order payload as a flat dictionary suitable for
            use as the request query parameters.
        """
        order_type = self._resolve_order_type(price, trigger)
        payload = {
            "instrument_token": token_dict["Token"],
            "exchange": self._format_for_broker(
                "exchange",
                token_dict["Exchange"],
            ),
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "order_side": self._format_for_broker("side", side),
            "order_type": self._format_for_broker("order_type", order_type),
            "validity": self._format_for_broker("validity", validity),
            "product": self._format_for_broker("product", product),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": self._auth_context["user_id"],
        }

        if target:
            payload.update(
                {
                    "square_off_value": target,
                    "stop_loss_value": stoploss,
                    "trailing_stop_loss": trailing_sl,
                    "is_trailing": bool(trailing_sl),
                }
            )

        return payload

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
        """Place an order through MasterTrust.

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

        params = self._build_place_order_payload(
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

        final_url = (
            f"{self.get_url('place_bracket_order')}"
            if target
            else self.get_url("place_order")
        )

        response = self.fetch(
            method="POST",
            endpoint_group="default",
            url=final_url,
            params=params,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    # Order Details, OrderBook & TradeBook

    def fetch_raw_orderbook(self) -> list[dict]:
        """Fetch raw MasterTrust order-book rows.

        MasterTrust splits the order book into ``"completed"`` and
        ``"pending"`` views, so both are fetched and concatenated.

        Returns:
            Raw broker order-book rows.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        user_id = self._auth_context["user_id"]
        orders: list[dict] = []

        for order_type in ("completed", "pending"):
            params = {"type": order_type, "client_id": user_id}
            response = self.fetch(
                method="GET",
                endpoint_group="default",
                url=self.get_url("orderbook"),
                params=params,
                headers=self._headers,
            )
            info = self._parse_json_response(response)
            data = info.get("data") or {}
            orders.extend(data.get("orders") or [])

        return orders

    def fetch_raw_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Fetch one raw order row from the current order book.

        Args:
            order_id: Broker order id to find.

        Raises:
            OrderNotFoundError: If the order id is absent from the order book.

        Returns:
            Raw broker order-book row.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        order_id = str(order_id)
        for order in self.fetch_raw_orderbook():
            if order["oms_order_id"] == order_id:
                return order

        raise OrderNotFoundError("This order_id does not exist.")

    def fetch_raw_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """Fetch raw MasterTrust history rows for an order.

        Args:
            order_id: Broker order id to query.

        Returns:
            Raw broker order-history rows.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        params = {"client_id": self._auth_context["user_id"]}
        final_url = f"{self.get_url('order_history')}/{order_id}/history"

        response = self.fetch(
            method="GET",
            endpoint_group="default",
            url=final_url,
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return info.get("data") or []

    def fetch_orderbook(self) -> list[dict]:
        """Fetch the order book in the unified Fenix format.

        Returns:
            Unified order records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        info = self.fetch_raw_orderbook()
        return [self._parse_orderbook(order) for order in info]

    def fetch_tradebook(self) -> list[dict]:
        """Fetch the trade book in the unified Fenix format.

        Returns:
            Unified order records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_tradebook()

        params = {"client_id": self._auth_context["user_id"]}
        response = self.fetch(
            method="GET",
            endpoint_group="default",
            url=self.get_url("tradebook"),
            params=params,
            headers=self._headers,
        )

        info = self._parse_json_response(response)
        trades = (info.get("data") or {}).get("trades") or []
        return [self._parse_tradebook(trade) for trade in trades]

    def fetch_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Fetch one order from the current order book.

        Args:
            order_id: Broker order id to find.

        Raises:
            OrderNotFoundError: If the order id is absent from the order book.

        Returns:
            Unified Fenix order record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        order_id = str(order_id)
        for order in self.fetch_raw_orderbook():
            if order["oms_order_id"] == order_id:
                return self._parse_orderbook(order)

        raise OrderNotFoundError("This order_id does not exist.")

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
        return [self._parse_order_history(order) for order in info]

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
    ) -> dict[Any, Any]:
        """Modify an open MasterTrust order.

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
            raw_order_json: Pre-fetched raw order payload used as the source of
                truth. When omitted, the order is looked up via
                :meth:`fetch_raw_order`.

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
            )

        if raw_order_json:
            order_info = raw_order_json
        else:
            order_info = self.fetch_raw_order(order_id=order_id)

        params = {
            "oms_order_id": order_id,
            "instrument_token": order_info["instrument_token"],
            "exchange": order_info["exchange"],
            "price": price or order_info["price"],
            "trigger_price": trigger or order_info["trigger_price"],
            "quantity": quantity or order_info["quantity"],
            "order_type": order_type or order_info["order_type"],
            "validity": validity or order_info["validity"],
            "product": order_info["product"],
            "client_id": self._auth_context["user_id"],
        }

        response = self.fetch(
            method="PUT",
            endpoint_group="default",
            url=self.get_url("modify_order"),
            params=params,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def cancel_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Cancel an open MasterTrust order.

        Args:
            order_id: Broker order id to cancel.

        Returns:
            Unified order-id record for the cancelled order.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.cancel_order(order_id=order_id)

        params = {"client_id": self._auth_context["user_id"]}
        final_url = f"{self.get_url('cancel_order')}/{order_id}"

        response = self.fetch(
            method="DELETE",
            endpoint_group="default",
            url=final_url,
            params=params,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    # Positions, Account Limits & Profile

    def _fetch_positions_by_type(
        self,
        position_type: str,
    ) -> list[dict[str, Any]]:
        """Fetch positions of a given type and return unified records.

        Args:
            position_type: MasterTrust position view to query (``"live"`` for
                day positions, ``"historical"`` for net positions).

        Returns:
            Unified position records for the requested view.
        """
        params = {
            "type": position_type,
            "client_id": self._auth_context["user_id"],
        }

        response = self.fetch(
            method="GET",
            endpoint_group="default",
            url=self.get_url("positions"),
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return [self._parse_position(position) for position in info.get("data") or []]

    def fetch_day_positions(self) -> list[dict[str, Any]]:
        """Fetch the day's account positions in the unified Fenix format.

        Returns:
            Unified position records for the current trading day.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        return self._fetch_positions_by_type("live")

    def fetch_net_positions(self) -> list[dict[str, Any]]:
        """Fetch the net account positions in the unified Fenix format.

        Returns:
            Unified position records across the account's open history.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        return self._fetch_positions_by_type("historical")

    def fetch_holdings(self) -> list[dict[str, Any]]:
        """Fetch account holdings in the unified Fenix format.

        Returns:
            Unified holding records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_holdings()

        params = {"client_id": self._auth_context["user_id"]}

        response = self.fetch(
            method="GET",
            endpoint_group="default",
            url=self.get_url("holdings"),
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return [self._parse_position(holding) for holding in info.get("data") or []]

    def fetch_margin_limits(
        self,
    ) -> dict[Any, Any]:
        """Fetch account margin limits.

        Returns:
            Unified Fenix RMS limits record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_margin_limits()

        params = {
            "client_id": self._auth_context["user_id"],
            "type": "all",
        }

        response = self.fetch(
            method="GET",
            url=self.get_url("rms_limits"),
            endpoint_group="default",
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return self._parse_rms(info["data"])

    def fetch_profile(self) -> dict[Any, Any]:
        """Fetch the user profile in the unified Fenix format.

        Returns:
            Unified Fenix profile record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_profile()

        params = {"client_id": self._auth_context["user_id"]}

        response = self.fetch(
            method="GET",
            endpoint_group="default",
            url=self.get_url("profile"),
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return self._parse_profile(info["data"])
