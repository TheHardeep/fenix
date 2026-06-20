from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from collections import defaultdict
from datetime import datetime
from typing import TYPE_CHECKING, Any, NoReturn

from requests.exceptions import HTTPError

from fenix.base.broker import Broker

from fenix.base.constants import ExchangeCode
from fenix.base.constants import Order
from fenix.base.constants import OrderType
from fenix.base.constants import Position
from fenix.base.constants import Product
from fenix.base.constants import Profile
from fenix.base.constants import Side
from fenix.base.constants import Status
from fenix.base.constants import Validity

from fenix.base.errors import AuthenticationError
from fenix.base.errors import BrokerError
from fenix.base.errors import InputError
from fenix.base.errors import NetworkError
from fenix.base.errors import RateLimitExceededError
from fenix.base.errors import ResponseError

if TYPE_CHECKING:
    from requests.models import Response


class Finvasia(Broker):
    """Finvasia broker adapter for the Fenix trading interface."""

    _API = {
        "doc": "https://www.shoonya.com/api-documentation",
        "servers": {
            "rest": "https://api.shoonya.com",
        },
        "paths": {
            # --- Auth Flow ---
            "access_token": {
                "server": "rest",
                "path": "/NorenWClientTP/QuickAuth",
            },

            # --- Order & Portfolio Flow ---
            "place_order": {
                "server": "rest",
                "path": "/NorenWClientTP/PlaceOrder",
            },
            "modify_order": {
                "server": "rest",
                "path": "/NorenWClientTP/ModifyOrder",
            },
            "cancel_order": {
                "server": "rest",
                "path": "/NorenWClientTP/CancelOrder",
            },
            "order_history": {
                "server": "rest",
                "path": "/NorenWClientTP/SingleOrdHist",
            },
            "orderbook": {
                "server": "rest",
                "path": "/NorenWClientTP/OrderBook",
            },
            "tradebook": {
                "server": "rest",
                "path": "/NorenWClientTP/TradeBook",
            },
            "positions": {
                "server": "rest",
                "path": "/NorenWClientTP/PositionBook",
            },
            "holdings": {
                "server": "rest",
                "path": "/NorenWClientTP/Holdings",
            },
            "profile": {
                "server": "rest",
                "path": "/NorenWClientTP/ClientDetails",
            },
            "rms_limits": {
                "server": "rest",
                "path": "/NorenWClientTP/Limits",
            },

            # --- Market Data ---
            "instruments": {
                "server": "rest",
                "path": "/EXCH_symbols.txt.zip",
            },
        },
    }

    STANDARD_MAPS = {
        "side": {
            "B": Side.BUY,
            "S": Side.SELL,
        },
        "order_type": {
            "LMT": OrderType.LIMIT,
            "MKT": OrderType.MARKET,
            "SL-LMT": OrderType.SL,
            "SL-MKT": OrderType.SLM,
        },
        "product": {
            "I": Product.MIS,
            "M": Product.NRML,
            "C": Product.CNC,
            "H": Product.CO,
            "B": Product.BO,
        },
        "validity": {
            "DAY": Validity.DAY,
            "IOC": Validity.IOC,
            "EOS": "EOS",
        },
        "status": {
            "PENDING": Status.PENDING,
            "OPEN": Status.OPEN,
            "COMPLETE": Status.FILLED,
            "CANCELED": Status.CANCELLED,
            "REJECT": Status.REJECTED,
            "Replaced": Status.MODIFIED,
            "New": Status.OPEN,
        },
        "exchange": {
            "NSE": ExchangeCode.NSE,
            "NFO": ExchangeCode.NFO,
            "BSE": ExchangeCode.BSE,
            "BFO": ExchangeCode.BFO,
            "CDS": ExchangeCode.CDS,
            "NCX": ExchangeCode.NCX,
        },
    }

    REQUEST_MAPS = {
        "side": {
            Side.BUY: "B",
            Side.SELL: "S",
        },
        "order_type": {
            OrderType.MARKET: "MKT",
            OrderType.LIMIT: "LMT",
            OrderType.SL: "SL-LMT",
            OrderType.SLM: "SL-MKT",
        },
        "product": {
            Product.MIS: "I",
            Product.NRML: "M",
            Product.CNC: "C",
            Product.CO: "H",
            Product.BO: "B",
        },
        "validity": {
            Validity.DAY: "DAY",
            Validity.IOC: "IOC",
            "EOS": "EOS",
        },
        "exchange": {
            ExchangeCode.NSE: "NSE",
            ExchangeCode.NFO: "NFO",
            ExchangeCode.BSE: "BSE",
            ExchangeCode.BFO: "BFO",
            ExchangeCode.CDS: "CDS",
            ExchangeCode.MCX: "MCX",
        },
    }

    _REQUIRED_AUTH_HEADER_KEYS = (
        "uid",
        "jKey",
        "payload",
        "access_token",
    )

    ERROR_MESSAGE_KEYS = (
        "emsg",
    )

    _ERROR_MESSAGES = {

        "400": "Missing or bad request parameters or values.",
        "403": "Session expired or invalidated. Must relogin.",
        "404": "Request resource was not found.",
        "405": (
            "Request method (GET, POST etc.) is not allowed on the "
            "requested endpoint."
        ),
        "410": "The requested resource is gone permanently.",
        "429": "Too many requests to the API (rate limiting).",
        "500": "Something unexpected went wrong.",
        "502": (
            "The backend OMS is down and the API is unable to communicate "
            "with it."
        ),
        "503": "Service unavailable; the API is down.",
        "504": "Gateway timeout; the API is unreachable.",
    }

    _DIRECT_ERROR_CLASSES = {
        "400": InputError,
        "403": AuthenticationError,
        "404": ResponseError,
        "405": InputError,
        "410": ResponseError,
        "429": RateLimitExceededError,
        "500": NetworkError,
        "502": NetworkError,
        "503": NetworkError,
        "504": NetworkError,
    }

    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "Finvasia",
            "tokenParams": [
                "user_id",
                "password",
                "api_key",
                "vendor_code",
                "totpstr",
            ],
            "proxies": {},
            "sensitiveLogKeys": [
                "uid",
                "jKey",
                "payload",
                "access_token",
                "susertoken",
                "password",
                "pwd",
                "factor2",
                "api_key",
                "appkey",
                "vendor_code",
                "vc",
                "totpstr",
            ],
            "enableRateLimit": False,
            "rateLimits": {},
        }

    def __init__(self, config: dict | None = None):
        """Initialize the Finvasia broker adapter."""
        super().__init__(config)

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """Authenticate with Finvasia and return request headers.

        Args:
            params: Login credentials and API keys required by Finvasia.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and run the login flow.

        Returns:
            Headers that can authenticate subsequent Finvasia API calls.
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

        request_headers = {"Content-Type": "application/x-www-form-urlencoded"}

        sha256_password = hashlib.sha256(
            params["password"].encode("utf-8")
        ).hexdigest()
        app_key_format = f'{params["user_id"]}|{params["api_key"]}'
        sha256api_key = hashlib.sha256(
            app_key_format.encode("utf-8")
        ).hexdigest()

        jdata = {
            "source": "API",
            "apkversion": "1.0.0",
            "uid": params["user_id"],
            "pwd": sha256_password,
            "factor2": self.totp_creator(params["totpstr"]),
            "vc": params["vendor_code"],
            "appkey": sha256api_key,
            "imei": "abc1234",
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("access_token"),
            endpoint_group="rest",
            data="jData=" + json.dumps(jdata),
            headers=request_headers,
        )
        response = self._parse_json_response(response)
        access_token = response["susertoken"]

        self._headers = {
            "uid": params["user_id"],
            "jKey": f"&jKey={access_token}",
            "payload": f"jData=<data>&jKey={access_token}",
            "access_token": access_token,
        }

        self.reset_session()

        return self._headers

    # Token Loading

    def load_equity_tokens(
        self,
        data: dict[str, Response] | None = None,
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
            market_data_url = self.get_url("instruments").replace("EXCH", "NSE")

            response = self.fetch(
                method="GET",
                url=market_data_url,
                endpoint_group="default",
                verify=False,
                # headers={'User-Agent': 'Mozilla/5.0'}
            )
            nse_buffer = io.BytesIO(response.content)

            market_data_url = self.get_url("instruments").replace("EXCH", "BSE")

            response = self.fetch(
                method="GET",
                url=market_data_url,
                endpoint_group="default",
                verify=False,
                # headers={'User-Agent': 'Mozilla/5.0'}
            )
            bse_buffer = io.BytesIO(response.content)

        else:
            if "NSE" not in data or "BSE" not in data:
                raise KeyError("Response data must contain 'NSE' and 'BSE' keys")

            nse_buffer = io.BytesIO(data["NSE"].content)
            bse_buffer = io.BytesIO(data["BSE"].content)

        nse_dict = {}
        bse_dict = {}
        alltoken_dict = {}

        with zipfile.ZipFile(nse_buffer) as z:
            file_name = z.namelist()[0]

            with z.open(file_name) as f:

                text_stream = io.TextIOWrapper(f, encoding="utf-8")
                csv_reader = csv.DictReader(text_stream)

                for record in csv_reader:
                    record.pop("", None)

                    if record["Instrument"] == "INDEX":
                        continue

                    symbol = record["Symbol"]
                    record["ScriptName"] = symbol
                    record["Symbol"] = record["TradingSymbol"]

                    record.pop("TradingSymbol", None)
                    record.pop("Instrument", None)

                    nse_dict[symbol] = record
                    token_key = f"{record['Token']}_{record['Exchange']}"
                    alltoken_dict[token_key] = record
        with zipfile.ZipFile(bse_buffer) as z:
            file_name = z.namelist()[0]

            with z.open(file_name) as f:

                text_stream = io.TextIOWrapper(f, encoding="utf-8")
                csv_reader = csv.DictReader(text_stream)

                for record in csv_reader:
                    record.pop("", None)

                    if record["Instrument"] == "INDEX":
                        continue

                    symbol = record["Symbol"]
                    record["ScriptName"] = symbol
                    record["Symbol"] = record["TradingSymbol"]

                    record.pop("TradingSymbol", None)
                    record.pop("Instrument", None)

                    bse_dict[symbol] = record
                    token_key = f"{record['Token']}_{record['Exchange']}"
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
        data: dict[str, Response] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE index token metadata.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"NSE"``.

        Returns:
            A tuple containing the unified index token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
        """
        if not data:
            market_data_url = self.get_url("instruments").replace("EXCH", "NSE")

            response = self.fetch(
                method="GET",
                url=market_data_url,
                endpoint_group="default",
                verify=False,
                # headers={'User-Agent': 'Mozilla/5.0'}
            )
            nse_buffer = io.BytesIO(response.content)

        else:
            if "NSE" not in data:
                raise KeyError("Response data must contain 'NSE' and 'BSE' keys")

            nse_buffer = io.BytesIO(data["NSE"].content)

        nse_dict = {}
        token_dict = {}

        with zipfile.ZipFile(nse_buffer) as z:
            file_name = z.namelist()[0]

            with z.open(file_name) as f:

                text_stream = io.TextIOWrapper(f, encoding="utf-8")
                csv_reader = csv.DictReader(text_stream)

                for record in csv_reader:
                    record.pop("", None)

                    if record["Instrument"] == "INDEX":

                        symbol = record["Symbol"]
                        record.pop("TradingSymbol", None)
                        record.pop("Instrument", None)
                        record["ScriptName"] = record["Symbol"]

                        nse_dict[symbol] = record
                        token_key = f"{record['Token']}_{record['Exchange']}"
                        token_dict[token_key] = record

        self.token_json["Indices"].update({
            "NSE": nse_dict,
        })

        self.alltoken_json.update(token_dict)

        return (
            {
                "Indices": {"NSE": nse_dict},
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
                ``"NFO"`` and ``"BFO"``.

        Returns:
            A tuple containing unified futures/options token maps and an
            all-token lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
        """
        if not data:
            market_data_url = self.get_url("instruments").replace("EXCH", "NFO")

            response = self.fetch(
                method="GET",
                url=market_data_url,
                endpoint_group="default",
                verify=False,
                # headers={'User-Agent': 'Mozilla/5.0'}
            )
            nse_buffer = io.BytesIO(response.content)

            market_data_url = self.get_url("instruments").replace("EXCH", "BFO")

            response = self.fetch(
                method="GET",
                url=market_data_url,
                endpoint_group="default",
                verify=False,
                # headers={'User-Agent': 'Mozilla/5.0'}
            )
            bse_buffer = io.BytesIO(response.content)


        else:
            if "NFO" not in data or "BFO" not in data:
                raise KeyError("JSON data must contain 'NFO' and 'BFO' keys")

            nse_buffer = io.BytesIO(data["NSE"].content)
            bse_buffer = io.BytesIO(data["BSE"].content)

        opt_series = ["OPTIDX", "OPTSTK"]
        fut_series = ["FUTSTK", "FUTIDX"]
        dt_dict = {}

        fut_nse = defaultdict(list)
        fut_bse = defaultdict(list)
        opt_nse = defaultdict(list)
        opt_bse = defaultdict(list)
        token_dict = {}
        with zipfile.ZipFile(nse_buffer) as z:
            file_name = z.namelist()[0]

            with z.open(file_name) as f:

                text_stream = io.TextIOWrapper(f, encoding="utf-8")
                csv_reader = csv.DictReader(text_stream)

                for record in csv_reader:

                    if "NSETEST" in record["Symbol"]:
                        continue

                    record.pop("", None)
                    expiry_raw = record["Expiry"]
                    instrument_type = record["Instrument"]

                    if expiry_raw not in dt_dict:
                        dt = datetime.strptime(expiry_raw, "%d-%b-%Y").date()
                        expiry = dt.strftime("%Y-%m-%d")
                        exdp = dt.strftime("%d-%b").upper()
                        dt_dict[expiry_raw] = (expiry, exdp)

                    if instrument_type in fut_series:
                        symbol = record["Symbol"]
                        record["ScriptName"] = symbol
                        record["Symbol"] = record["TradingSymbol"]
                        record["Root"] = symbol
                        record["Expiry"] = expiry
                        record["ScriptName"] = f"{symbol} {exdp} FUT"

                        record.pop("TradingSymbol", None)
                        record.pop("Instrument", None)
                        record.pop("OptionType", None)

                        fut_nse[symbol].append(record)

                    elif instrument_type in opt_series:

                        symbol = record["Symbol"]
                        record["ScriptName"] = symbol
                        record["Symbol"] = record["TradingSymbol"]
                        record["Root"] = symbol
                        record["Expiry"] = expiry
                        record["StrikePrice"] = self._format_strike(
                            record["StrikePrice"]
                        )
                        record["ScriptName"] = (
                            f"{symbol} {exdp} "
                            f"{record['StrikePrice']} {record['OptionType']}"
                        )

                        record["Option"] = record.pop("OptionType")
                        record.pop("TradingSymbol", None)
                        record.pop("Instrument", None)

                        opt_nse[symbol].append(record)

                    else:
                        continue

                    tk = f"{record['Token']}_{record['Exchange']}"
                    token_dict[tk] = record
        with zipfile.ZipFile(bse_buffer) as z:
            file_name = z.namelist()[0]

            with z.open(file_name) as f:

                text_stream = io.TextIOWrapper(f, encoding="utf-8")
                csv_reader = csv.DictReader(text_stream)

                for record in csv_reader:

                    record.pop("", None)
                    expiry_raw = record["Expiry"]
                    instrument_type = record["Instrument"]

                    if expiry_raw not in dt_dict:
                        dt = datetime.strptime(expiry_raw, "%d-%b-%Y").date()
                        expiry = dt.strftime("%Y-%m-%d")
                        exdp = dt.strftime("%d-%b").upper()
                        dt_dict[expiry_raw] = (expiry, exdp)

                    if instrument_type in fut_series:
                        symbol = record["Symbol"]
                        record["ScriptName"] = symbol
                        record["Symbol"] = record["TradingSymbol"]
                        record["Root"] = symbol
                        record["Expiry"] = expiry
                        record["ScriptName"] = f"{symbol} {exdp} FUT"

                        record.pop("TradingSymbol", None)
                        record.pop("Instrument", None)
                        record.pop("OptionType", None)
                        record.pop("StrikePrice", None)

                        fut_bse[symbol].append(record)

                    elif instrument_type in opt_series:

                        symbol = record["Symbol"]
                        record["ScriptName"] = symbol
                        record["Symbol"] = record["TradingSymbol"]
                        record["Root"] = symbol
                        record["Expiry"] = expiry
                        record["StrikePrice"] = self._format_strike(
                            record["StrikePrice"]
                        )
                        record["ScriptName"] = (
                            f"{symbol} {exdp} "
                            f"{record['StrikePrice']} {record['OptionType']}"
                        )

                        record["Option"] = record.pop("OptionType")
                        record.pop("TradingSymbol", None)
                        record.pop("Instrument", None)

                        opt_bse[symbol].append(record)

                    else:
                        continue

                    tk = f"{record['Token']}_{record['Exchange']}"
                    token_dict[tk] = record

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
        """Load MCX futures, options, and index token metadata.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"MCX"``.

        Returns:
            A tuple containing unified MCX token maps and an all-token lookup
            keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data does not include MCX.
        """
        if not data:
            market_data_url = self.get_url("instruments").replace("EXCH", "MCX")

            response = self.fetch(
                method="GET",
                url=market_data_url,
                endpoint_group="default",
                verify=False,
                # headers={'User-Agent': 'Mozilla/5.0'}
            )
            mcx_buffer = io.BytesIO(response.content)

        else:
            if "MCX" not in data:
                raise KeyError("JSON data must contain 'MCX' key")

            mcx_buffer = io.BytesIO(data["MCX"].content)

        opt_series = ["OPTFUT"]
        fut_series = ["FUTCOM", "FUTIDX"]
        dt_dict = {}

        fut = defaultdict(list)
        opt = defaultdict(list)
        token_dict = {}
        with zipfile.ZipFile(mcx_buffer) as z:
            file_name = z.namelist()[0]

            with z.open(file_name) as f:

                text_stream = io.TextIOWrapper(f, encoding="utf-8")
                csv_reader = csv.DictReader(text_stream)

                for record in csv_reader:

                    if "NSETEST" in record["Symbol"]:
                        continue

                    record.pop("", None)
                    expiry_raw = record["Expiry"]
                    instrument_type = record["Instrument"]

                    if expiry_raw not in dt_dict:
                        dt = datetime.strptime(expiry_raw, "%d-%b-%Y").date()
                        expiry = dt.strftime("%Y-%m-%d")
                        exdp = dt.strftime("%d-%b").upper()
                        dt_dict[expiry_raw] = (expiry, exdp)

                    if instrument_type in fut_series:
                        symbol = record["Symbol"]
                        record["ScriptName"] = symbol
                        record["Symbol"] = record["TradingSymbol"]
                        record["Root"] = symbol
                        record["Expiry"] = expiry
                        record["ScriptName"] = f"{symbol} {exdp} FUT"

                        record.pop("TradingSymbol", None)
                        record.pop("Instrument", None)
                        record.pop("OptionType", None)

                        fut[symbol].append(record)

                    elif instrument_type in opt_series:

                        symbol = record["Symbol"]
                        record["ScriptName"] = symbol
                        record["Symbol"] = record["TradingSymbol"]
                        record["Root"] = symbol
                        record["Expiry"] = expiry
                        record["StrikePrice"] = self._format_strike(
                            record["StrikePrice"]
                        )
                        record["ScriptName"] = (
                            f"{symbol} {exdp} "
                            f"{record['StrikePrice']} {record['OptionType']}"
                        )

                        record["Option"] = record.pop("OptionType")
                        record.pop("TradingSymbol", None)
                        record.pop("Instrument", None)

                        opt[symbol].append(record)

                    else:
                        continue

                    tk = f"{record['Token']}_{record['Exchange']}"
                    token_dict[tk] = record

        self.token_json["Futures"].update({"MCX": fut})
        self.token_json["Options"].update({"MCX": opt})

        self.alltoken_json.update(token_dict)

        return (
            {
                "Futures": {"MCX": fut},
                "Options": {"MCX": opt},
            },
            token_dict,
        )

    def load_cds_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load currency derivatives token metadata for CDS and BCD.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"CDS"``.

        Returns:
            A tuple containing unified currency futures/options token maps and
            an all-token lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
        """
        if not data:
            market_data_url = self.get_url("instruments").replace("EXCH", "CDS")

            response = self.fetch(
                method="GET",
                url=market_data_url,
                endpoint_group="default",
                verify=False,
                # headers={'User-Agent': 'Mozilla/5.0'}
            )
            cds_buffer = io.BytesIO(response.content)

        else:
            if "CDS" not in data:
                raise KeyError("JSON data must contain 'CDS' keys")

            cds_buffer = io.BytesIO(data["CDS"].content)


        opt_series = ["OPTCUR"]
        fut_series = ["FUTCUR"]
        dt_dict = {}

        fut_cds = defaultdict(list)
        opt_cds = defaultdict(list)
        idx_cds = defaultdict(list)
        token_dict = {}

        try:
            with zipfile.ZipFile(cds_buffer) as z:
                file_name = z.namelist()[0]

                with z.open(file_name) as f:

                    text_stream = io.TextIOWrapper(f, encoding="utf-8")
                    csv_reader = csv.DictReader(text_stream)

                    for record in csv_reader:

                        record.pop("", None)
                        expiry_raw = record["Expiry"]
                        instrument_type = record["Instrument"]

                        if expiry_raw not in dt_dict and instrument_type != "UNDCUR":
                            dt = datetime.strptime(expiry_raw, "%d-%b-%Y").date()
                            expiry = dt.strftime("%Y-%m-%d")
                            exdp = dt.strftime("%d-%b").upper()
                            dt_dict[expiry_raw] = (expiry, exdp)

                        if instrument_type in fut_series:
                            symbol = record["Symbol"]
                            record["ScriptName"] = symbol
                            record["Symbol"] = record["TradingSymbol"]
                            record["Root"] = symbol
                            record["Expiry"] = expiry
                            record["ScriptName"] = f"{symbol} {exdp} FUT"

                            record.pop("TradingSymbol", None)
                            record.pop("Instrument", None)
                            record.pop("OptionType", None)

                            fut_cds[symbol].append(record)

                        elif instrument_type in opt_series:

                            symbol = record["Symbol"]
                            record["ScriptName"] = symbol
                            record["Symbol"] = record["TradingSymbol"]
                            record["Root"] = symbol
                            record["Expiry"] = expiry
                            record["StrikePrice"] = self._format_strike(
                                record["StrikePrice"]
                            )
                            record["ScriptName"] = (
                                f"{symbol} {exdp} "
                                f"{record['StrikePrice']} {record['OptionType']}"
                            )

                            record["Option"] = record.pop("OptionType")
                            record.pop("TradingSymbol", None)
                            record.pop("Instrument", None)

                            opt_cds[symbol].append(record)

                        else:
                            symbol = record["Symbol"]
                            record.pop("TradingSymbol", None)
                            record.pop("Instrument", None)
                            record["ScriptName"] = record["Symbol"]

                            idx_cds[symbol].append(record)
                            token_key = f"{record['Token']}_{record['Exchange']}"
                            token_dict[token_key] = record


                        tk = f"{record['Token']}_{record['Exchange']}"
                        token_dict[tk] = record

            self.token_json["Futures"].update({"CDS": fut_cds})
            self.token_json["Options"].update({"CDS": opt_cds})
            self.token_json["Indices"].update({"CDS": idx_cds})

            self.alltoken_json.update(token_dict)

            return (
                {
                    "Futures": {"CDS": fut_cds},
                    "Options": {"CDS": opt_cds},
                    "Indices": {"CDS": idx_cds},
                },
                token_dict,
            )
        except Exception as exc:
            raise ResponseError("Unable to parse CDS token metadata.") from exc

    def load_ncx_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load commodity derivatives token metadata for NCX.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"NCX"``.

        Returns:
            A tuple containing unified NCX futures token maps and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data does not include NCX.
        """
        if not data:
            market_data_url = self.get_url("instruments").replace("EXCH", "NCX")

            response = self.fetch(
                method="GET",
                url=market_data_url,
                endpoint_group="default",
                verify=False,
                # headers={'User-Agent': 'Mozilla/5.0'}
            )
            ncx_buffer = io.BytesIO(response.content)

        else:
            if "NCX" not in data:
                raise KeyError("JSON data must contain 'NCX' key")

            ncx_buffer = io.BytesIO(data["NCX"].content)

        fut_ncx = defaultdict(list)
        fut_series = ["OPTFUT", "FUTCOM"]
        token_dict = {}
        dt_dict = {}

        with zipfile.ZipFile(ncx_buffer) as z:
            file_name = z.namelist()[0]

            with z.open(file_name) as f:

                text_stream = io.TextIOWrapper(f, encoding="utf-8")
                csv_reader = csv.DictReader(text_stream)

                for record in csv_reader:

                    record.pop("", None)
                    expiry_raw = record["Expiry"]
                    instrument_type = record["Instrument"]

                    if expiry_raw not in dt_dict:
                        dt = datetime.strptime(expiry_raw, "%d-%b-%Y").date()
                        expiry = dt.strftime("%Y-%m-%d")
                        exdp = dt.strftime("%d-%b").upper()
                        dt_dict[expiry_raw] = (expiry, exdp)

                    if instrument_type in fut_series:
                        symbol = record["Symbol"]
                        record["ScriptName"] = symbol
                        record["Symbol"] = record["TradingSymbol"]
                        record["Root"] = symbol
                        record["Expiry"] = expiry
                        record["ScriptName"] = f"{symbol} {exdp} FUT"

                        record.pop("TradingSymbol", None)
                        record.pop("Instrument", None)
                        record.pop("OptionType", None)

                        fut_ncx[symbol].append(record)

                    else:
                        continue

                    tk = f"{record['Token']}_{record['Exchange']}"
                    token_dict[tk] = record

        self.token_json["Futures"].update({"NCX": fut_ncx})

        self.alltoken_json.update(token_dict)

        return (
            {
                "Futures": {"NCX": fut_ncx},
            },
            token_dict,
        )

    # Headers & Json Parsers

    def _extract_finvasia_error_code(self, payload: Any) -> str | None:
        """Infer a documented Finvasia/HTTP-like error code from a payload."""
        payload_text = self._stringify_error_payload(payload)
        for documented_code in self._ERROR_MESSAGES:
            if documented_code in payload_text:
                return documented_code

        return None

    def _extract_finvasia_error_message(
        self,
        payload: Any,
        error_code: str | None,
    ) -> str | None:
        """Extract the most useful Finvasia error message for a payload."""
        error_message = self._extract_error_message(payload)
        documented_message = self._ERROR_MESSAGES.get(error_code or "")

        if documented_message and not error_message:
            return documented_message
        if documented_message and error_message == error_code:
            return documented_message
        if error_message:
            return error_message
        return documented_message

    def _finvasia_error_class(
        self,
        error_code: str | None,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve a Finvasia payload to the most specific Fenix error class."""
        if error_code in self._DIRECT_ERROR_CLASSES:
            return self._DIRECT_ERROR_CLASSES[error_code]

        message = (error_message or "").lower()
        if any(token in message for token in ("session", "token", "login")):
            return AuthenticationError
        if any(token in message for token in ("rate", "too many")):
            return RateLimitExceededError
        if any(token in message for token in ("parameter", "invalid", "bad request")):
            return InputError
        if "rejected" in message or "order" in message:
            return ResponseError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded Finvasia payload represents an error."""
        if isinstance(payload, list):
            if not payload:
                return False
            return self._payload_indicates_error(payload[0])

        if isinstance(payload, dict):
            stat = payload.get("stat")
            if stat is not None:
                return str(stat).lower() != "ok"

            return self._extract_finvasia_error_code(payload) is not None

        return self._extract_finvasia_error_code(payload) is not None

    def _raise_finvasia_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for a Finvasia error payload."""
        context = self._http_error_context(response, payload)
        error_code = self._extract_finvasia_error_code(payload)
        error_message = self._extract_finvasia_error_message(
            payload,
            error_code,
        )

        context["error_code"] = error_code
        context["error_message"] = error_message
        error_cls = self._finvasia_error_class(
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
        """Handle HTTP errors and raise broker-specific exceptions."""
        payload = self._response_error_payload(exc.response)
        if self._payload_indicates_error(payload):
            self._raise_finvasia_error(payload, response=exc.response, cause=exc)

        super().handle_http_error(exc)

    def _parse_json_response(
        self,
        response: Response,
    ) -> dict[Any, Any] | list[dict[Any, Any]]:
        """Decode an HTTP response and raise Finvasia payload errors."""
        json_response = self._json_parser(response)

        if self._payload_indicates_error(json_response):
            self._raise_finvasia_error(
                json_response,
                response=response,
            )

        return json_response

    def _parse_orderbook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a Finvasia order-book row to a unified order record.

        Args:
            order: Raw order-book row returned by Finvasia.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["norenordno"],
            Order.USER_ID: order.get("remarks", ""),
            Order.TIMESTAMP: datetime.strptime(order["norentm"], "%H:%M:%S %d-%m-%Y"),
            Order.SYMBOL: order["tsym"],
            Order.TOKEN: int(order["token"]),
            Order.SIDE: self._parse_from_broker("side", order["trantype"]),
            Order.TYPE: self._parse_from_broker("order_type", order["prctyp"]),
            Order.AVG_PRICE: float(order.get("avgprc", 0.0)),
            Order.PRICE: float(order["prc"]),
            Order.TRIGGER_PRICE: float(order.get("trgprc", 0.0)),
            Order.TARGET_PRICE: float(order.get("bpprc", 0.0)),
            Order.STOPLOSS_PRICE: float(order.get("blprc", 0.0)),
            Order.TRAILING_STOPLOSS: float(order.get("trailprc", 0.0)),
            Order.QUANTITY: int(order["qty"]),
            Order.FILLED_QTY: int(order.get("fillshares", 0)),
            Order.REMAINING_QTY: int(order["qty"]) - int(order.get("fillshares", 0)),
            Order.CANCELLED_QTY: int(order.get("cancelqty", 0.0)),
            Order.STATUS: self._parse_from_broker("status", order["status"]),
            Order.REJECT_REASON: order.get("rejreason", ""),
            Order.DISCLOSED_QUANTITY: 0,  # int(order["dscqty"]),
            Order.PRODUCT: self._parse_from_broker("product", order["prd"]),
            Order.EXCHANGE: self._parse_from_broker("exchange", order["exch"]),
            Order.SEGMENT: "",
            Order.VALIDITY: self._parse_from_broker("validity", order["ret"]),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_tradebook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a Finvasia trade-book row to a unified order record.

        Args:
            order: Raw trade-book row returned by Finvasia.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["norenordno"],
            Order.USER_ID: order.get("remarks", ""),
            Order.TIMESTAMP: datetime.strptime(order["norentm"], "%H:%M:%S %d-%m-%Y"),
            Order.SYMBOL: order["tsym"],
            Order.TOKEN: int(order["token"]),
            Order.SIDE: self._parse_from_broker("side", order["trantype"]),
            Order.TYPE: self._parse_from_broker("order_type", order["prctyp"]),
            Order.AVG_PRICE: float(order.get("flprc", 0.0)),
            Order.PRICE: float(order["prc"]),
            Order.TRIGGER_PRICE: float(order.get("trgprc", 0.0)),
            Order.TARGET_PRICE: float(order.get("bpprc", 0.0)),
            Order.STOPLOSS_PRICE: float(order.get("blprc", 0.0)),
            Order.TRAILING_STOPLOSS: float(order.get("trailprc", 0.0)),
            Order.QUANTITY: int(order["qty"]),
            Order.FILLED_QTY: int(order.get("fillshares", 0)),
            Order.REMAINING_QTY: int(order["qty"]) - int(order.get("fillshares", 0)),
            Order.CANCELLED_QTY: int(order.get("cancelqty", 0.0)),
            Order.STATUS: "",
            Order.REJECT_REASON: "",
            Order.DISCLOSED_QUANTITY: 0,
            Order.PRODUCT: self._parse_from_broker("product", order["prd"]),
            Order.EXCHANGE: self._parse_from_broker("exchange", order["exch"]),
            Order.SEGMENT: "",
            Order.VALIDITY: self._parse_from_broker("validity", order["ret"]),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_position(
        self,
        position: dict,
    ) -> dict[Any, Any]:
        """Convert a Finvasia position row to a unified position record.

        Args:
            position: Raw position row returned by Finvasia.

        Returns:
            Unified Fenix position record.
        """
        parsed_position = {
            Position.SYMBOL: position["tsym"],
            Position.TOKEN: int(position["token"]),
            Position.NET_QTY: int(position["netqty"]),
            Position.AVG_PRICE: float(position["netavgprc"]),
            Position.MTM: float(position["urmtom"]),
            Position.PNL: float(position["rpnl"]),
            Position.BUY_QTY: int(position["daybuyqty"]),
            Position.BUY_PRICE: float(position["daybuyavgprc"]),
            Position.SELL_QTY: int(position["daysellqty"]),
            Position.SELL_PRICE: float(position["daysellavgprc"]),
            Position.LTP: float(position["lp"]),
            Position.PRODUCT: self._parse_from_broker("product", position["prd"]),
            Position.EXCHANGE: self._parse_from_broker("exchange", position["exch"]),
            Position.INFO: position,
        }

        return parsed_position

    def _parse_profile(
        self,
        profile: dict,
    ) -> dict[Any, Any]:
        """Convert a Finvasia profile payload to a unified profile record.

        Args:
            profile: Raw profile payload returned by Finvasia.

        Returns:
            Unified Fenix profile record.
        """
        parsed_profile = {
            Profile.CLIENT_ID: profile["actid"],
            Profile.NAME: profile["cliname"],
            Profile.EMAIL_ID: profile["email"],
            Profile.MOBILE_NO: profile["m_num"],
            Profile.PAN: profile["pan"],
            Profile.ADDRESS: "",
            Profile.BANK_NAME: profile["bankdetails"][0]["bankn"],
            Profile.BANK_BRANCH_NAME: None,
            Profile.BANK_ACC_NO: profile["bankdetails"][0]["acctnum"],
            Profile.EXCHANGES_ENABLED: profile["exarr"],
            Profile.ENABLED: profile["act_sts"] == "Activated",
            Profile.INFO: profile,
        }

        return parsed_profile

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
    ) -> dict[str, str]:
        """Build the Finvasia API payload for a place-order request.

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
            Finvasia ``jData`` payload for the place-order endpoint.
        """
        order_type = self._resolve_order_type(price=price, trigger=trigger)
        jdata = {
            "exch": token_dict["Exchange"],
            "tsym": token_dict["Symbol"],
            "prc": str(price),
            "trgprc": str(trigger),
            "qty": str(quantity),
            "trantype": self._format_for_broker("side", side),
            "prctyp": self._format_for_broker("order_type", order_type),
            "prd": self._format_for_broker("product", product),
            "ret": self._format_for_broker("validity", validity),
            "remarks": unique_id,
            "dscqty": "0",
            "uid": self._headers["uid"],
            "actid": self._headers["uid"],
            "ordersource": "API",
        }

        if target:
            jdata.update(
                {
                    "bpprc": str(target),
                    "blprc": str(stoploss),
                    "trailprc": str(trailing_sl),
                }
            )

        return jdata

    def _encode_authenticated_payload(
        self,
        payload: dict[str, Any],
    ) -> str:
        """Encode a Finvasia ``jData`` payload with the active session key."""
        return self._headers["payload"].replace(
            "<data>",
            json.dumps(payload),
        )

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
        """Place an order through Finvasia.

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
            Unified Fenix order record for the placed order.
        """
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

        jdata = self._build_place_order_payload(
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
            endpoint_group="rest",
            data=self._encode_authenticated_payload(jdata),
        )

        return self._parse_place_order_response(response=response)

    def _parse_place_order_response(
        self,
        response: Response,
    ) -> dict[Any, Any]:
        """Parse a Finvasia place-order response into a unified order record."""
        info = self._parse_json_response(response)
        order_id = info["norenordno"]

        return {Order.ID: order_id}

    # Order Details, OrderBook & TradeBook

    def fetch_raw_orderbook(
        self,
    ) -> list[dict]:
        """Fetch raw Finvasia order-book rows."""
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        jdata = {"uid": self._headers["uid"]}
        response = self.fetch(
            method="POST",
            url=self.get_url("orderbook"),
            endpoint_group="rest",
            data=self._encode_authenticated_payload(jdata),
        )

        try:
            return self._parse_json_response(response)
        except ResponseError:
            return []

    def fetch_raw_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """Fetch raw Finvasia order-history rows for an order."""
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        jdata = {
            "uid": self._headers["uid"],
            "norenordno": str(order_id),
        }
        response = self.fetch(
            method="POST",
            url=self.get_url("order_history"),
            endpoint_group="rest",
            data=self._encode_authenticated_payload(jdata),
        )

        try:
            return self._parse_json_response(response)
        except ResponseError as exc:
            raise InputError({"This order_id does not exist."}) from exc

    def fetch_raw_orderhistory(
        self,
        order_id: str,
    ) -> list[dict]:
        """Backward-compatible alias for ``fetch_raw_order_history``."""
        return self.fetch_raw_order_history(order_id=order_id)

    def fetch_orderbook(
        self,
    ) -> list[dict]:
        """Fetch the order book in unified Fenix format."""
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        return [
            self._parse_orderbook(order)
            for order in self.fetch_raw_orderbook()
        ]

    def fetch_tradebook(
        self,
    ) -> list[dict]:
        """Fetch the trade book in unified Fenix format."""
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_tradebook()

        jdata = {
            "uid": self._headers["uid"],
            "actid": self._headers["uid"],
        }
        response = self.fetch(
            method="POST",
            url=self.get_url("tradebook"),
            endpoint_group="rest",
            data=self._encode_authenticated_payload(jdata),
        )

        try:
            info = self._parse_json_response(response)
        except ResponseError:
            return []

        return [self._parse_tradebook(order) for order in info]

    def fetch_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Fetch one order in unified Fenix format."""
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        info = self.fetch_raw_order_history(order_id=order_id)
        return self._parse_orderbook(info[0])

    def fetch_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """Fetch order history in unified Fenix format."""
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        return [
            self._parse_orderbook(order)
            for order in self.fetch_raw_order_history(order_id=order_id)
        ]

    # Order Modification & Sq Off

    def modify_order(
        self,
        order_id: str,
        price: float | None = None,
        trigger: float | None = None,
        quantity: int | None = None,
        order_type: str | None = None,
        validity: str | None = None,
    ) -> dict[Any, Any]:
        """Modify an open Finvasia order.

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

        Returns:
            Unified Fenix order record after modification.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.modify_order(
                order_id=order_id,
                price=price,
                trigger=trigger,
                quantity=quantity,
                order_type=order_type,
                validity=validity,
            )

        order_info = self.fetch_raw_order_history(order_id=order_id)[0]

        jdata = {
            "norenordno": order_info["norenordno"],
            "exch": order_info["exch"],
            "tsym": order_info["tsym"],
            "prc": price or order_info["prc"],
            "trgprc": trigger or order_info["trgprc"],
            "qty": quantity or order_info["qty"],
            "prctyp": (
                self._format_for_broker("order_type", order_type)
                if order_type
                else order_info["prctyp"]
            ),
            "ret": (
                self._format_for_broker("validity", validity)
                if validity
                else order_info["ret"]
            ),
            "uid": self._headers["uid"],
            "ordersource": "API",
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("modify_order"),
            endpoint_group="rest",
            data=self._encode_authenticated_payload(jdata),
        )
        info = self._parse_json_response(response)
        modified_order_id = info["result"]

        return self.fetch_order(order_id=modified_order_id)

    def cancel_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Cancel an open Finvasia order.

        Args:
            order_id: Broker order id to cancel.

        Returns:
            Unified Fenix order record after cancellation.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.cancel_order(order_id=order_id)

        jdata = {
            "uid": self._headers["uid"],
            "norenordno": order_id,
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("cancel_order"),
            endpoint_group="rest",
            data=self._encode_authenticated_payload(jdata),
        )
        info = self._parse_json_response(response)
        cancelled_order_id = info["result"]

        return self.fetch_order(order_id=cancelled_order_id)

    # Positions, Account Limits & Profile

    def fetch_positions(
        self,
    ) -> list[dict[Any, Any]]:
        """Fetch account positions in unified Fenix format."""
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        jdata = {
            "uid": self._headers["uid"],
            "actid": self._headers["uid"],
        }
        response = self.fetch(
            method="POST",
            url=self.get_url("positions"),
            endpoint_group="rest",
            data=self._encode_authenticated_payload(jdata),
        )

        try:
            info = self._parse_json_response(response)
        except ResponseError:
            return []

        return [self._parse_position(position) for position in info]

    def fetch_day_positions(
        self,
    ) -> list[dict[Any, Any]]:
        """Fetch Finvasia position rows.

        Finvasia returns day and net quantities in the same position row, so
        this mirrors ``fetch_positions`` for naming compatibility.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        return self.fetch_positions()

    def fetch_net_positions(
        self,
    ) -> list[dict[Any, Any]]:
        """Fetch Finvasia position rows.

        Finvasia returns day and net quantities in the same position row, so
        this mirrors ``fetch_positions`` for naming compatibility.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        return self.fetch_positions()

    def fetch_holdings(
        self,
    ) -> list[dict[Any, Any]]:
        """Fetch raw account holdings."""
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_holdings()

        jdata = {
            "uid": self._headers["uid"],
            "actid": self._headers["uid"],
        }
        response = self.fetch(
            method="POST",
            url=self.get_url("holdings"),
            endpoint_group="rest",
            data=self._encode_authenticated_payload(jdata),
        )

        try:
            return self._parse_json_response(response)
        except ResponseError:
            return []

    def fetch_margin_limits(
        self,
    ) -> dict[Any, Any]:
        """Fetch risk-management limits."""
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_margin_limits()

        jdata = {
            "uid": self._headers["uid"],
            "actid": self._headers["uid"],
        }
        response = self.fetch(
            method="POST",
            url=self.get_url("rms_limits"),
            endpoint_group="rest",
            data=self._encode_authenticated_payload(jdata),
        )

        return self._parse_json_response(response)

    def fetch_profile(
        self,
    ) -> dict[Any, Any]:
        """Fetch profile details in unified Fenix format."""
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_profile()

        jdata = {
            "uid": self._headers["uid"],
            "actid": self._headers["uid"],
        }
        response = self.fetch(
            method="POST",
            url=self.get_url("profile"),
            endpoint_group="rest",
            data=self._encode_authenticated_payload(jdata),
        )
        response = self._parse_json_response(response)

        return self._parse_profile(response)
