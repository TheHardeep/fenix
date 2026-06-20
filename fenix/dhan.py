from __future__ import annotations

import csv
import io
import pyotp
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
from fenix.base.constants import RMS
from fenix.base.constants import Side
from fenix.base.constants import Status
from fenix.base.constants import UniqueID
from fenix.base.constants import Validity
from fenix.base.constants import Variety

from fenix.base.errors import (
    AuthenticationError,
    BrokerError,
    InputError,
    InsufficientFundsError,
    InsufficientHoldingsError,
    InvalidOrderError,
    NetworkError,
    OrderNotFoundError,
    PermissionDeniedError,
    RateLimitExceededError,
    ResponseError,
)

if TYPE_CHECKING:
    from requests.models import Response


class Dhan(Broker):
    """Dhan broker adapter for the Fenix trading interface."""

    # Dhan exposes a single combined instrument master (CSV). These map the
    # ``(EXCH_ID, SEGMENT)`` pair found in that file to the ``exchangeSegment``
    # enum the trading API expects (and which Fenix stores in ``Exchange``).
    _SEGMENT_TO_DHAN = {
        ("NSE", "E"): "NSE_EQ",
        ("BSE", "E"): "BSE_EQ",
        ("NSE", "D"): "NSE_FNO",
        ("BSE", "D"): "BSE_FNO",
        ("NSE", "C"): "NSE_CURRENCY",
        ("BSE", "C"): "BSE_CURRENCY",
        ("MCX", "M"): "MCX_COMM",
        ("NSE", "I"): "IDX_I",
        ("BSE", "I"): "IDX_I",
    }

    _DETAILED_CSV_URL = (
        "https://images.dhan.co/api-data/api-scrip-master-detailed.csv"
    )

    _COMPACT_CSV_URL = "https://images.dhan.co/api-data/api-scrip-master.csv"

    _API = {
        "doc": "https://dhanhq.co/docs/v2/",
        "servers": {
            "api": "https://api.dhan.co/v2",
            "auth": "https://auth.dhan.co/app"
        },
        "paths": {
            #--- Auth ---
            "token": {
                "server": "auth",
                "path": "/generateAccessToken",
            },

            # --- Orders ---
            "orders": {
                "server": "api",
                "path": "/orders",
            },
            "slice_order": {
                "server": "api",
                "path": "/orders/slicing",
            },
            "order_by_correlation": {
                "server": "api",
                "path": "/orders/external",
            },
            "trades": {
                "server": "api",
                "path": "/trades",
            },

            # --- Super Orders ---
            "super_orders": {
                "server": "api",
                "path": "/super/orders",
            },

            # --- Forever (GTT) Orders ---
            "forever_orders": {
                "server": "api",
                "path": "/forever/orders",
            },

            # --- Portfolio ---
            "positions": {
                "server": "api",
                "path": "/positions",
            },
            "holdings": {
                "server": "api",
                "path": "/holdings",
            },
            "convert_position": {
                "server": "api",
                "path": "/positions/convert",
            },

            # --- Funds, Margin & Profile ---
            "fund_limit": {
                "server": "api",
                "path": "/fundlimit",
            },
            "margin_calculator": {
                "server": "api",
                "path": "/margincalculator",
            },
            "profile": {
                "server": "api",
                "path": "/profile",
            },

            # --- Trader Control ---
            "kill_switch": {
                "server": "api",
                "path": "/killswitch",
            },

            # --- Option Chain ---
            "option_chain": {
                "server": "api",
                "path": "/optionchain",
            },
            "expiry_list": {
                "server": "api",
                "path": "/optionchain/expirylist",
            },

            # --- Instrument Master (public CDN, no auth) ---
            "instruments": _DETAILED_CSV_URL,
        },
    }

    STANDARD_MAPS = {
        "side": {
            "BUY": Side.BUY,
            "SELL": Side.SELL,
        },
        "order_type": {
            "MARKET": OrderType.MARKET,
            "LIMIT": OrderType.LIMIT,
            "STOP_LOSS": OrderType.SL,
            "STOP_LOSS_MARKET": OrderType.SLM,
        },
        "product": {
            "CNC": Product.CNC,
            "INTRADAY": Product.MIS,
            "MARGIN": Product.MARGIN,
            "MTF": Product.MTF,
            "CO": Product.CO,
            "BO": Product.BO,
        },
        "validity": {
            "DAY": Validity.DAY,
            "IOC": Validity.IOC,
        },
        "status": {
            "TRANSIT": Status.PENDING,
            "PENDING": Status.PENDING,
            "TRIGGERED": Status.PENDING,
            "CONFIRM": Status.PENDING,
            "PART_TRADED": Status.PARTIALLY_FILLED,
            "TRADED": Status.FILLED,
            "CLOSED": Status.FILLED,
            "REJECTED": Status.REJECTED,
            "CANCELLED": Status.CANCELLED,
            "EXPIRED": Status.CANCELLED,
        },
        "exchange": {
            "NSE_EQ": ExchangeCode.NSE,
            "BSE_EQ": ExchangeCode.BSE,
            "NSE_FNO": ExchangeCode.NFO,
            "BSE_FNO": ExchangeCode.BFO,
            "NSE_CURRENCY": ExchangeCode.CDS,
            "BSE_CURRENCY": ExchangeCode.BCD,
            "MCX_COMM": ExchangeCode.MCX,
            "IDX_I": "IDX_I",
        },
    }

    REQUEST_MAPS = {}

    for map_name, mapping_dict in STANDARD_MAPS.items():
        inverse_map = {v: k for k, v in mapping_dict.items()}
        REQUEST_MAPS[map_name] = inverse_map

    # Dhan has no dedicated NRML/overnight product type; carry-forward (F&O)
    # and margin positions both use the "MARGIN" product. Map the Fenix
    # ``NRML`` constant onto it so callers migrating from other brokers can
    # keep using ``Product.NRML``.
    REQUEST_MAPS["product"][Product.NRML] = "MARGIN"

    ERROR_CODE_KEYS = (
        "errorCode",
        "internalErrorCode",
        "code",
    )

    ERROR_MESSAGE_KEYS = (
        "errorMessage",
        "internalErrorMessage",
        "remarks",
        "message",
    )

    _ERROR_MESSAGES = {
        # --- Trading API error codes (DH-9xx) ---
        "DH-901": "Client ID or user generated access token is invalid or expired.",
        "DH-902": (
            "User has not subscribed to Data APIs or does not have Trading "
            "API permissions."
        ),
        "DH-903": (
            "Errors related to the user's account. Check if the required "
            "segments are activated."
        ),
        "DH-904": (
            "Too many requests on server from a single user, breaching rate "
            "limits."
        ),
        "DH-905": "Missing required fields or bad values for parameters.",
        "DH-906": "Incorrect request for order and cannot be processed.",
        "DH-907": (
            "System is unable to fetch data due to incorrect parameters or no "
            "data present."
        ),
        "DH-908": "Server was not able to process the API request.",
        "DH-909": "Network error while communicating with the exchange.",
        "DH-910": "Error originating from other reasons.",
        # --- Data API error codes ---
        "800": "Internal server error.",
        "804": "Requested number of instruments exceeds the limit.",
        "805": (
            "Too many requests or connections. Further requests may result in "
            "blocking."
        ),
        "806": "Data APIs not subscribed.",
        "807": "Access token is expired.",
        "808": "Authentication failed - incorrect credentials.",
        "809": "Access token is invalid.",
        "810": "Client ID is invalid.",
        "811": "Invalid expiry date.",
        "812": "Invalid date format.",
        "813": "Invalid security id.",
        "814": "Invalid request.",
    }

    _DIRECT_ERROR_CLASSES = {
        "DH-901": AuthenticationError,
        "DH-902": PermissionDeniedError,
        "DH-903": PermissionDeniedError,
        "DH-904": RateLimitExceededError,
        "DH-905": InputError,
        "DH-906": InvalidOrderError,
        "DH-907": ResponseError,
        "DH-908": NetworkError,
        "DH-909": NetworkError,
        "DH-910": BrokerError,
        "800": NetworkError,
        "804": InputError,
        "805": RateLimitExceededError,
        "806": PermissionDeniedError,
        "807": AuthenticationError,
        "808": AuthenticationError,
        "809": AuthenticationError,
        "810": AuthenticationError,
        "811": InputError,
        "812": InputError,
        "813": InvalidOrderError,
        "814": InputError,
    }

    _NO_DATA_PHRASES = (
        "no data",
        "not present",
        "no record",
        "no order",
        "no position",
        "no holdings available",
        "no trade",
    )

    _REQUIRED_AUTH_HEADER_KEYS = (
        "access-token",
        "Accept",
    )

    _AUTH_CONTEXT_KEYS = ("user_id",)

    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "Dhan",
            "tokenParams": [
                "client_id",
                "totpstr",
                "pin",
            ],
            "proxies": {},
            "sensitiveLogKeysIncludeDefault": True,
            "sensitiveLogKeys": [
                "client_id",
                "totpstr",
                "pin",
                "access_token",
                "access-token",
                "client-id",
                "dhanClientId",
                "correlationId",
            ],
            "enableRateLimit": True,
            "rateLimits": {
                "orders": [
                    {"period": 1, "capacity": 25, "cost": 1.0},
                    {"period": 60, "capacity": 250, "cost": 1.0},
                    {"period": 3600, "capacity": 1000, "cost": 1.0},
                ],
                "data": [
                    {"period": 1, "capacity": 5, "cost": 1.0},
                ],
                "quote": [
                    {"period": 1, "capacity": 1, "cost": 1.0},
                ],
                "default": [
                    {"period": 1, "capacity": 20, "cost": 1.0},
                ],
            },
        }

    def __init__(self, config: dict | None = None):
        """Initialize the Dhan broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
                Pass ``{"paper_mode": True}`` to route order entry and reads
                through the in-process paper-trading engine instead of the
                Dhan API.
        """
        super().__init__(config)
        # Cached instrument master rows so the (large) CSV is downloaded once
        # per instance and shared across all ``load_*_tokens`` calls.
        self._master_rows: list[dict[str, str]] | None = None

    # --------------------------------------------------------------------- #
    # Authentication
    # --------------------------------------------------------------------- #

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """Authenticate with Dhan and return request headers.

        Dhan v2 authenticates through an access token that the user generates
        from the Dhan web portal (or via the OAuth/partner consent flow). The
        token is supplied to Fenix together with the Dhan client id; this
        method assembles them into the headers required by the trading API.

        Args:
            params: Mapping containing ``client_id`` and ``access_token``.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and rebuild them.

        Returns:
            Headers that can authenticate subsequent Dhan API calls.

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

        totp = pyotp.TOTP(params["totpstr"]).now()

        json_data = {
            "dhanClientId": params["client_id"],
            "totp": totp,
            "pin": params["pin"],
        }
        response = self.fetch(
            method="POST",
            url=self.get_url("token"),
            endpoint_group="default",
            params=json_data,
            headers=headers,
        )

        info = self._parse_json_response(response)

        self._headers = {
            "access-token": info["accessToken"],
            "Accept": "application/json",
        }

        self._auth_context = {"user_id": info["dhanClientId"]}

        self.reset_session()

        return {**self._headers, **self._auth_context}


    # --------------------------------------------------------------------- #
    # Instrument master helpers
    # --------------------------------------------------------------------- #

    @staticmethod
    def _to_int(value: Any) -> int:
        """Best-effort conversion of a CSV cell to an integer."""
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _to_tick(value: Any) -> str:
        """Convert a tick-size CSV cell (quoted in paise) to rupees.

        Dhan reports ``TICK_SIZE`` in paise (e.g. ``5.0`` for ₹0.05, ``100.0``
        for ₹1.00), so the value is divided by 100 to express it in rupees.
        """
        try:
            return str(float(value) / 100)
        except (TypeError, ValueError):
            return str(value)

    def _expiry_parts(self, raw: Any) -> tuple[str, str]:
        """Return ``(iso_expiry, display_expiry)`` for a CSV expiry cell."""
        raw = (raw or "").split(" ")[0]
        try:
            dt = datetime.strptime(raw, "%Y-%m-%d")
        except (ValueError, TypeError):
            return ("", "")
        return (dt.strftime("%Y-%m-%d"), dt.strftime("%d-%b").upper())

    def _fetch_instrument_master(self) -> list[dict[str, str]]:
        """Download and cache the Dhan detailed instrument master CSV.

        The CSV is fetched without pandas: it is streamed into
        :class:`csv.DictReader` and materialised as a list of row dicts keyed
        by the header names. The parsed rows are cached on the instance so the
        (large) file is downloaded only once.

        Returns:
            Parsed instrument-master rows.

        Raises:
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving the instrument master.
        """
        if self._master_rows is not None:
            return self._master_rows

        response = self.fetch(
            method="GET",
            url=self.get_url("instruments"),
            endpoint_group="default",
            timeout=60,
        )

        reader = csv.DictReader(io.StringIO(response.text))
        self._master_rows = list(reader)

        return self._master_rows

    # --------------------------------------------------------------------- #
    # Script Fetch (token loaders)
    # --------------------------------------------------------------------- #

    def load_equity_tokens(
        self,
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE equity token metadata.

        Args:
            data: Optional pre-parsed instrument-master rows (the full Dhan
                scrip master as a list of dicts). Downloaded automatically when
                omitted.

        Returns:
            A tuple containing the unified equity token map and an all-token
            lookup keyed by ``"{security_id}_{exchange_segment}"``.
        """
        rows = data if data is not None else self._fetch_instrument_master()

        nse_dict = {}
        bse_dict = {}
        alltoken_dict = {}

        for row in rows:
            if row.get("INSTRUMENT") != "EQUITY":
                continue
            # ``ES`` is the cash equity series; ``ETF`` covers exchange traded
            # funds. Everything else under EQUITY (bonds, SDLs, T-bills, etc.)
            # is skipped.
            if row.get("INSTRUMENT_TYPE") not in ("ES", "ETF"):
                continue

            exchange = row.get("EXCH_ID")
            segment = row.get("SEGMENT")
            if segment != "E":
                continue

            dhan_segment = self._SEGMENT_TO_DHAN.get((exchange, segment))
            if not dhan_segment:
                continue

            symbol = row.get("UNDERLYING_SYMBOL")
            token = row.get("SECURITY_ID")
            if not symbol or not token:
                continue
            if "NSETEST" in symbol:
                continue

            record = {
                "Token": token,
                "Exchange": dhan_segment,
                "Symbol": symbol,
                "Segment": row["SEGMENT"],
                "ScriptName": row["SYMBOL_NAME"],
                "LotSize": self._to_int(row.get("LOT_SIZE")),
                "TickSize": self._to_tick(row.get("TICK_SIZE")),
                "ISIN": row["ISIN"]
            }

            if exchange == "NSE":
                nse_dict[symbol] = record
            else:
                bse_dict[symbol] = record

            alltoken_dict[f"{token}_{dhan_segment}"] = record

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
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load index token metadata for NSE and BSE.

        Args:
            data: Optional pre-parsed instrument-master rows. Downloaded
                automatically when omitted.

        Returns:
            A tuple containing the unified index token map and an all-token
            lookup keyed by ``"{security_id}_IDX_I"``.
        """
        rows = data if data is not None else self._fetch_instrument_master()

        nse_dict = {}
        bse_dict = {}
        token_dict = {}

        for row in rows:
            if row.get("INSTRUMENT") != "INDEX":
                continue
            if row.get("SEGMENT") != "I":
                continue

            exchange = row.get("EXCH_ID")
            symbol = row.get("SYMBOL_NAME") or row.get("UNDERLYING_SYMBOL")
            token = row.get("SECURITY_ID")
            if not symbol or not token:
                continue

            record = {
                "Token": token,
                "Exchange": exchange,
                "Symbol": symbol,
                "Segment": row["SEGMENT"],
                "ScriptName": row["DISPLAY_NAME"],
            }

            if exchange == "NSE":
                nse_dict[symbol] = record
            elif exchange == "BSE":
                bse_dict[symbol] = record
            else:
                continue

            token_dict[f"{token}_{exchange}"] = record

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
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load futures and options token metadata for NFO and BFO.

        Args:
            data: Optional pre-parsed instrument-master rows. Downloaded
                automatically when omitted.

        Returns:
            A tuple containing unified futures/options token maps and an
            all-token lookup keyed by ``"{security_id}_{exchange_segment}"``.

        Raises:
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving the instrument master.
        """
        rows = data if data is not None else self._fetch_instrument_master()

        opt_series = ("OPTIDX", "OPTSTK")
        fut_series = ("FUTIDX", "FUTSTK")
        dt_dict = {}

        fut_nse = defaultdict(list)
        fut_bse = defaultdict(list)
        opt_nse = defaultdict(list)
        opt_bse = defaultdict(list)
        token_dict = {}

        for row in rows:
            instrument = row.get("INSTRUMENT")
            if instrument not in opt_series and instrument not in fut_series:
                continue

            exchange = row.get("EXCH_ID")
            segment = row.get("SEGMENT")
            if segment != "D":
                continue

            dhan_segment = self._SEGMENT_TO_DHAN.get((exchange, segment))
            if not dhan_segment:
                continue

            root = row.get("UNDERLYING_SYMBOL")
            token = row.get("SECURITY_ID")
            if not root or not token:
                continue
            if "NSETEST" in root:
                continue

            expiry_raw = row.get("SM_EXPIRY_DATE")
            if expiry_raw not in dt_dict:
                dt_dict[expiry_raw] = self._expiry_parts(expiry_raw)
            expiry, exdp = dt_dict[expiry_raw]

            if instrument in fut_series:
                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Segment": segment,
                    "Root": root,
                    "Symbol": row.get("SYMBOL_NAME"),
                    "TickSize": self._to_tick(row.get("TICK_SIZE")),
                    "LotSize": self._to_int(row.get("LOT_SIZE")),
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                if exchange == "NSE":
                    fut_nse[root].append(record)
                else:
                    fut_bse[root].append(record)

            else:
                strike = self._format_strike(row.get("STRIKE_PRICE"))
                option = row.get("OPTION_TYPE")
                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Segment": segment,
                    "Root": root,
                    "Symbol": row.get("SYMBOL_NAME"),
                    "TickSize": self._to_tick(row.get("TICK_SIZE")),
                    "LotSize": self._to_int(row.get("LOT_SIZE")),
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": option,
                    "ScriptName": f"{root} {exdp} {strike} {option}",
                }

                if exchange == "NSE":
                    opt_nse[root].append(record)
                else:
                    opt_bse[root].append(record)

            token_dict[f"{token}_{dhan_segment}"] = record

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

    def load_cds_tokens(
        self,
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load currency derivatives token metadata for CDS and BCD.

        Args:
            data: Optional pre-parsed instrument-master rows. Downloaded
                automatically when omitted.

        Returns:
            A tuple containing unified currency futures/options token maps and
            an all-token lookup keyed by ``"{security_id}_{exchange_segment}"``.

        Raises:
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving the instrument master.
        """
        rows = data if data is not None else self._fetch_instrument_master()

        opt_series = ("OPTCUR",)
        fut_series = ("FUTCUR",)
        dt_dict = {}

        fut_nse = defaultdict(list)
        fut_bse = defaultdict(list)
        opt_nse = defaultdict(list)
        opt_bse = defaultdict(list)
        token_dict = {}

        for row in rows:
            instrument = row.get("INSTRUMENT")
            if instrument not in opt_series and instrument not in fut_series:
                continue

            exchange = row.get("EXCH_ID")
            segment = row.get("SEGMENT")
            if segment != "C":
                continue

            dhan_segment = self._SEGMENT_TO_DHAN.get((exchange, segment))
            if not dhan_segment:
                continue

            root = row.get("UNDERLYING_SYMBOL")
            token = row.get("SECURITY_ID")
            if not root or not token:
                continue

            expiry_raw = row.get("SM_EXPIRY_DATE")
            if expiry_raw not in dt_dict:
                dt_dict[expiry_raw] = self._expiry_parts(expiry_raw)
            expiry, exdp = dt_dict[expiry_raw]

            if instrument in fut_series:
                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Segment": segment,
                    "Root": root,
                    "Symbol": row.get("SYMBOL_NAME"),
                    "TickSize": self._to_tick(row.get("TICK_SIZE")),
                    "LotSize": self._to_int(row.get("LOT_SIZE")),
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                if exchange == "NSE":
                    fut_nse[root].append(record)
                else:
                    fut_bse[root].append(record)

            else:
                strike = self._format_strike(row.get("STRIKE_PRICE"))
                option = row.get("OPTION_TYPE")
                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Segment": segment,
                    "Root": root,
                    "Symbol": row.get("SYMBOL_NAME"),
                    "TickSize": self._to_tick(row.get("TICK_SIZE")),
                    "LotSize": self._to_int(row.get("LOT_SIZE")),
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": option,
                    "ScriptName": f"{root} {exdp} {strike} {option}",
                }

                if exchange == "NSE":
                    opt_nse[root].append(record)
                else:
                    opt_bse[root].append(record)

            token_dict[f"{token}_{dhan_segment}"] = record

        self.token_json["Futures"].update({"CDS": fut_nse, "BCD": fut_bse})
        self.token_json["Options"].update({"CDS": opt_nse, "BCD": opt_bse})

        self.alltoken_json.update(token_dict)

        return (
            {
                "Futures": {"CDS": fut_nse, "BCD": fut_bse},
                "Options": {"CDS": opt_nse, "BCD": opt_bse},
            },
            token_dict,
        )

    def load_mcx_tokens(
        self,
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load MCX commodity futures and options token metadata.

        Args:
            data: Optional pre-parsed instrument-master rows. Downloaded
                automatically when omitted.

        Returns:
            A tuple containing unified MCX token maps and an all-token lookup
            keyed by ``"{security_id}_MCX_COMM"``.

        Raises:
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving the instrument master.
        """
        rows = data if data is not None else self._fetch_instrument_master()

        opt_series = ("OPTFUT", "OPTIDX")
        fut_series = ("FUTCOM", "FUTIDX")
        dt_dict = {}

        fut = defaultdict(list)
        opt = defaultdict(list)
        token_dict = {}

        for row in rows:
            instrument = row.get("INSTRUMENT")
            if instrument not in opt_series and instrument not in fut_series:
                continue

            exchange = row.get("EXCH_ID")
            segment = row.get("SEGMENT")
            if exchange != "MCX" or segment != "M":
                continue

            dhan_segment = "MCX_COMM"
            root = row.get("UNDERLYING_SYMBOL")
            token = row.get("SECURITY_ID")
            if not root or not token:
                continue

            expiry_raw = row.get("SM_EXPIRY_DATE")
            if expiry_raw not in dt_dict:
                dt_dict[expiry_raw] = self._expiry_parts(expiry_raw)
            expiry, exdp = dt_dict[expiry_raw]

            if instrument in fut_series:
                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Segment": segment,
                    "Root": root,
                    "Symbol": row.get("DISPLAY_NAME"),
                    "TickSize": self._to_tick(row.get("TICK_SIZE")),
                    "LotSize": self._to_int(row.get("LOT_SIZE")),
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut[root].append(record)

            else:
                strike = self._format_strike(row.get("STRIKE_PRICE"))
                option = row.get("OPTION_TYPE")
                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Segment": segment,
                    "Root": root,
                    "Symbol": row.get("DISPLAY_NAME"),
                    "TickSize": self._to_tick(row.get("TICK_SIZE")),
                    "LotSize": self._to_int(row.get("LOT_SIZE")),
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": option,
                    "ScriptName": f"{root} {exdp} {strike} {option}",
                }

                opt[root].append(record)

            token_dict[f"{token}_{dhan_segment}"] = record

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

    # --------------------------------------------------------------------- #
    # JSON / Error handling
    # --------------------------------------------------------------------- #

    def _extract_dhan_error_code(self, payload: Any) -> str | None:
        """Extract a documented Dhan error code from a payload."""
        error_code = self._extract_error_code(payload)
        if error_code:
            code = error_code.strip().upper()
            if code in self._ERROR_MESSAGES:
                return code
            if code.startswith("DH"):
                return code
            return error_code.strip()

        payload_text = self._stringify_error_payload(payload).upper()
        for documented_code in self._ERROR_MESSAGES:
            # Only scan for the unambiguous ``DH-`` codes in free text; the
            # numeric data-API codes are too easily matched by accident.
            if documented_code.startswith("DH") and documented_code in payload_text:
                return documented_code

        return None

    def _extract_dhan_error_message(
        self,
        payload: Any,
        error_code: str | None,
    ) -> str | None:
        """Extract the most useful Dhan error message for a payload."""
        error_message = self._extract_error_message(payload)
        documented_message = self._ERROR_MESSAGES.get(error_code or "")

        if documented_message and not error_message:
            return documented_message
        if documented_message and error_message == error_code:
            return documented_message
        if error_message:
            return error_message
        return documented_message

    def _dhan_error_class(
        self,
        error_code: str | None,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve a Dhan payload to the most specific Fenix error class."""
        if error_code in self._DIRECT_ERROR_CLASSES:
            return self._DIRECT_ERROR_CLASSES[error_code]

        message = (error_message or "").lower()
        if any(token in message for token in ("session", "token", "login", "authenticat")):
            return AuthenticationError
        if (
            "permission" in message
            or "not subscribed" in message
            or "not activated" in message
        ):
            return PermissionDeniedError
        if "insufficient" in message and (
            "fund" in message or "margin" in message or "balance" in message
        ):
            return InsufficientFundsError
        if "insufficient" in message and (
            "holding" in message or "quantity" in message
        ):
            return InsufficientHoldingsError
        if "rate limit" in message or "too many" in message:
            return RateLimitExceededError
        if "order not found" in message or "not in your order book" in message:
            return OrderNotFoundError
        if any(phrase in message for phrase in self._NO_DATA_PHRASES):
            return ResponseError
        if any(token in message for token in ("order", "price", "quantity", "security")):
            return InvalidOrderError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded Dhan payload represents an error."""
        if isinstance(payload, dict):
            if any(
                payload.get(key)
                for key in ("errorCode", "errorType", "internalErrorCode")
            ):
                return True
            status = payload.get("status")
            if isinstance(status, str) and status.lower() in ["failure", "error"] :
                return True
            return False

        return False

    def _is_empty_response_error(self, exc: ResponseError) -> bool:
        """Return whether a response error represents an empty result set."""
        error_code = getattr(exc, "error_code", None)
        if error_code == "DH-907":
            return True
        message = str(exc).lower()
        return any(phrase in message for phrase in self._NO_DATA_PHRASES)

    def _raise_dhan_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for a Dhan error payload."""
        context = self._http_error_context(response, payload)
        error_code = self._extract_dhan_error_code(payload)
        error_message = self._extract_dhan_error_message(payload, error_code)

        context["error_code"] = error_code
        context["error_message"] = error_message
        error_cls = self._dhan_error_class(
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
            self._raise_dhan_error(payload, response=exc.response, cause=exc)

        super().handle_http_error(exc)

    def _parse_json_response(self, response: Response) -> Any:
        """Decode an HTTP response and raise broker-specific payload errors.

        Dhan returns the requested data directly as the response body (a list
        for collection endpoints, a dict for single-object endpoints). Error
        payloads are dicts carrying ``errorCode`` / ``errorMessage`` and an
        HTTP error status, so a successful 2xx body is returned untouched.
        """
        json_response = self._json_parser(response)
        if isinstance(json_response, dict) and self._payload_indicates_error(
            json_response
        ):
            self._raise_dhan_error(json_response, response=response)

        return json_response

    @staticmethod
    def _parse_datetime(value: Any) -> Any:
        """Parse a Dhan timestamp string into a ``datetime`` when possible."""
        if not value:
            return value
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(str(value), fmt)
            except (ValueError, TypeError):
                continue
        return value

    # --------------------------------------------------------------------- #
    # Response parsers
    # --------------------------------------------------------------------- #

    def _parse_orderbook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a Dhan order object to a unified order record.

        The parser uses ``dict.get`` throughout so that it can also normalise
        the slightly leaner super-order and forever-order payloads, which
        share most field names with the regular order book.

        Args:
            order: Raw order object returned by Dhan.

        Returns:
            Unified Fenix order record.
        """
        security_id = order.get("securityId")

        parsed_order = {
            Order.ID: order.get("orderId"),
            Order.USER_ID: order.get("correlationId", ""),
            Order.TIMESTAMP: self._parse_datetime(
                order.get("updateTime")
                or order.get("exchangeTime")
                or order.get("createTime")
            ),
            Order.SYMBOL: order.get("tradingSymbol", ""),
            Order.TOKEN: int(security_id) if security_id not in (None, "") else 0,
            Order.SIDE: self._parse_from_broker(
                "side", order.get("transactionType")
            ),
            Order.TYPE: self._parse_from_broker(
                "order_type", order.get("orderType")
            ),
            Order.AVG_PRICE: float(order.get("averageTradedPrice") or 0.0),
            Order.PRICE: float(order.get("price") or 0.0),
            Order.TRIGGER_PRICE: float(order.get("triggerPrice") or 0.0),
            Order.TARGET_PRICE: float(order.get("boProfitValue") or 0.0),
            Order.STOPLOSS_PRICE: float(order.get("boStopLossValue") or 0.0),
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: int(order.get("quantity") or 0),
            Order.FILLED_QTY: int(order.get("filledQty") or 0),
            Order.REMAINING_QTY: int(order.get("remainingQuantity") or 0),
            Order.CANCELLED_QTY: 0,
            Order.STATUS: self._parse_from_broker(
                "status", order.get("orderStatus")
            ),
            Order.REJECT_REASON: order.get("omsErrorDescription", ""),
            Order.DISCLOSED_QUANTITY: int(order.get("disclosedQuantity") or 0),
            Order.PRODUCT: self._parse_from_broker(
                "product", order.get("productType")
            ),
            Order.EXCHANGE: self._parse_from_broker(
                "exchange", order.get("exchangeSegment")
            ),
            Order.SEGMENT: self._parse_from_broker(
                "exchange", order.get("exchangeSegment")
            ),
            Order.VALIDITY: self._parse_from_broker(
                "validity", order.get("validity")
            ),
            Order.VARIETY: Variety.AMO if order.get("afterMarketOrder") else "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_tradebook(
        self,
        trade: dict,
    ) -> dict[Any, Any]:
        """Convert a Dhan trade-book row to a unified order record.

        Dhan trade-book rows describe executed fills and use
        ``tradedQuantity`` / ``tradedPrice`` in place of the order book's
        quantity/price fields.

        Args:
            trade: Raw trade-book row returned by Dhan.

        Returns:
            Unified Fenix order-like fill record.
        """
        security_id = trade.get("securityId")
        quantity = int(trade.get("tradedQuantity") or 0)

        parsed_trade = {
            Order.ID: trade.get("orderId"),
            Order.USER_ID: "",
            Order.TIMESTAMP: self._parse_datetime(
                trade.get("exchangeTime") or trade.get("updateTime")
            ),
            Order.SYMBOL: trade.get("tradingSymbol", ""),
            Order.TOKEN: int(security_id) if security_id not in (None, "") else 0,
            Order.SIDE: self._parse_from_broker(
                "side", trade.get("transactionType")
            ),
            Order.TYPE: self._parse_from_broker(
                "order_type", trade.get("orderType")
            ),
            Order.AVG_PRICE: float(trade.get("tradedPrice") or 0.0),
            Order.PRICE: float(trade.get("tradedPrice") or 0.0),
            Order.TRIGGER_PRICE: 0.0,
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: quantity,
            Order.FILLED_QTY: quantity,
            Order.REMAINING_QTY: 0,
            Order.CANCELLED_QTY: 0,
            Order.STATUS: Status.FILLED,
            Order.REJECT_REASON: "",
            Order.DISCLOSED_QUANTITY: 0,
            Order.PRODUCT: self._parse_from_broker(
                "product", trade.get("productType")
            ),
            Order.EXCHANGE: self._parse_from_broker(
                "exchange", trade.get("exchangeSegment")
            ),
            Order.SEGMENT: self._parse_from_broker(
                "exchange", trade.get("exchangeSegment")
            ),
            Order.VALIDITY: "",
            Order.VARIETY: "",
            Order.INFO: trade,
        }

        return parsed_trade

    def _parse_position(
        self,
        position: dict,
    ) -> dict[Any, Any]:
        """Convert a Dhan position row to a unified position record.

        Args:
            position: Raw position row returned by Dhan.

        Returns:
            Unified Fenix position record.
        """
        security_id = position.get("securityId")

        parsed_position = {
            Position.SYMBOL: position.get("tradingSymbol", ""),
            Position.TOKEN: int(security_id) if security_id not in (None, "") else 0,
            Position.NET_QTY: int(position.get("netQty") or 0),
            Position.AVG_PRICE: float(position.get("costPrice") or 0.0),
            Position.MTM: None,
            Position.PNL: float(position.get("unrealizedProfit") or 0.0),
            Position.REALISED_PNL: float(position.get("realizedProfit") or 0.0),
            Position.UNREALISED_PNL: float(position.get("unrealizedProfit") or 0.0),
            Position.BUY_QTY: int(position.get("buyQty") or 0),
            Position.BUY_PRICE: float(position.get("buyAvg") or 0.0),
            Position.SELL_QTY: int(position.get("sellQty") or 0),
            Position.SELL_PRICE: float(position.get("sellAvg") or 0.0),
            Position.LTP: None,
            Position.PRODUCT: self._parse_from_broker(
                "product", position.get("productType")
            ),
            Position.EXCHANGE: self._parse_from_broker(
                "exchange", position.get("exchangeSegment")
            ),
            Position.INFO: position,
        }

        return parsed_position

    def _parse_profile(
        self,
        profile: dict,
    ) -> dict[Any, Any]:
        """Convert a Dhan profile payload to a unified profile record.

        Args:
            profile: Raw profile payload returned by Dhan.

        Returns:
            Unified Fenix profile record.
        """
        active_segment = profile.get("activeSegment")
        if isinstance(active_segment, str):
            exchanges_enabled = [
                segment.strip()
                for segment in active_segment.split(",")
                if segment.strip()
            ]
        elif isinstance(active_segment, list):
            exchanges_enabled = active_segment
        else:
            exchanges_enabled = []

        parsed_profile = {
            Profile.CLIENT_ID: profile.get("dhanClientId", ""),
            Profile.NAME: "",
            Profile.EMAIL_ID: "",
            Profile.MOBILE_NO: "",
            Profile.PAN: "",
            Profile.ADDRESS: "",
            Profile.BANK_NAME: "",
            Profile.BANK_BRANCH_NAME: None,
            Profile.BANK_ACC_NO: "",
            Profile.EXCHANGES_ENABLED: exchanges_enabled,
            Profile.ENABLED: bool(profile.get("tokenValidity")),
            Profile.INFO: profile,
        }

        return parsed_profile

    def _parse_rms(self, rms: dict) -> dict[Any, Any]:
        """Convert a Dhan fund-limit payload to a unified margin record."""
        parsed_rms = {
            RMS.MARGINUSED: float(rms.get("utilizedAmount") or 0.0),
            # ``availabelBalance`` is Dhan's (misspelt) field name for the
            # available balance.
            RMS.MARGINAVAIL: float(
                rms.get("availabelBalance", rms.get("availableBalance")) or 0.0
            ),
            RMS.COLLATERAL: float(rms.get("collateralAmount") or 0.0),
            RMS.INFO: rms,
        }

        return parsed_rms

    def _parse_place_order_response(self, response: Response) -> dict[Any, Any]:
        """Extract the order id from a Dhan order response.

        Args:
            response: HTTP response returned after placing, modifying, or
                cancelling an order.

        Returns:
            Unified order-id record.
        """
        info = self._parse_json_response(response)
        return {Order.ID: info["orderId"]}

    # --------------------------------------------------------------------- #
    # Order Functions
    # --------------------------------------------------------------------- #

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
        """Build the Dhan API payload for a place-order request.

        Args:
            token_dict: Token metadata for the instrument being ordered.
            quantity: Number of units to order.
            side: Transaction side in Fenix format.
            product: Product code in Fenix format.
            validity: Order validity in Fenix format.
            variety: Order variety in Fenix format. ``Variety.AMO`` routes the
                order as an after-market order.
            unique_id: Client-provided correlation id.
            price: Limit price, or zero for market orders.
            trigger: Stop-loss trigger price, or zero when not applicable.
            target: Bracket-order target (profit) value, or zero when not
                applicable.
            stoploss: Bracket-order stop-loss value.
            trailing_sl: Bracket-order trailing stop-loss value (unused by the
                regular order endpoint; modelled through super orders).

        Returns:
            Dhan place-order payload.
        """
        order_type = self._resolve_order_type(price, trigger)

        payload = {
            "dhanClientId": self._auth_context["user_id"],
            "securityId": token_dict["Token"],
            "exchangeSegment": token_dict["Exchange"],
            "transactionType": self._format_for_broker("side", side),
            "productType": self._format_for_broker("product", product),
            "orderType": self._format_for_broker("order_type", order_type),
            "validity": self._format_for_broker("validity", validity),
            "quantity": int(quantity),
            "disclosedQuantity": 0,
            "price": float(price),
            "triggerPrice": float(trigger),
            "afterMarketOrder": variety == Variety.AMO,
        }

        if variety == Variety.AMO:
            payload["amoTime"] = "OPEN"

        if target:
            payload["productType"] = "BO"
            payload["boProfitValue"] = float(target)
            payload["boStopLossValue"] = float(stoploss)

        if unique_id:
            payload["correlationId"] = unique_id

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
        """Place an order through Dhan.

        Args:
            token_dict: Token metadata for the instrument being ordered.
            quantity: Number of units to order.
            side: Transaction side in Fenix format.
            product: Product code in Fenix format.
            validity: Order validity in Fenix format.
            variety: Order variety in Fenix format.
            unique_id: Client-provided correlation id.
            price: Limit price, or zero for market orders.
            trigger: Stop-loss trigger price, or zero when not applicable.
            target: Bracket-order target (profit) value.
            stoploss: Bracket-order stop-loss value.
            trailing_sl: Bracket-order trailing stop-loss value.

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
            url=self.get_url("orders"),
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    # --------------------------------------------------------------------- #
    # Order Details, OrderBook & TradeBook
    # --------------------------------------------------------------------- #

    def fetch_raw_orderbook(
        self,
    ) -> list[dict]:
        """Fetch raw Dhan order-book rows.

        Returns:
            Raw broker order-book rows. Empty result-set responses are returned
            as an empty list. In paper mode, returns the unified paper order
            records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        response = self.fetch(
            method="GET",
            url=self.get_url("orders"),
            endpoint_group="default",
            headers=self._headers,
        )
        try:
            return self._parse_json_response(response) or []
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

    def fetch_orderbook(
        self,
    ) -> list[dict]:
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

    def fetch_orders(
        self,
    ) -> list[dict]:
        """Fetch unified orders.

        Returns:
            Unified order records from the order book.
        """
        return self.fetch_orderbook()

    def fetch_tradebook(
        self,
    ) -> list[dict]:
        """Fetch the trade book in the unified Fenix format.

        Returns:
            Unified order-like fill records. Empty result-set responses are
            returned as an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_tradebook()

        response = self.fetch(
            method="GET",
            url=self.get_url("trades"),
            endpoint_group="default",
            headers=self._headers,
        )

        try:
            info = self._parse_json_response(response) or []
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

        orders = []
        for trade in info:
            detail = self._parse_tradebook(trade)
            orders.append(detail)

        return orders

    def fetch_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Fetch one order by its id.

        Args:
            order_id: Broker order id to find.

        Raises:
            OrderNotFoundError: If the order id does not exist.

        Returns:
            Unified Fenix order record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        response = self.fetch(
            method="GET",
            url=f"{self.get_url('orders')}/{order_id}",
            endpoint_group="default",
            headers=self._headers,
        )

        try:
            info = self._parse_json_response(response)
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                raise OrderNotFoundError("This order_id does not exist.") from exc
            raise

        if isinstance(info, list):
            if not info:
                raise OrderNotFoundError("This order_id does not exist.")
            info = info[0]

        return self._parse_orderbook(info)

    def fetch_order_by_correlation_id(
        self,
        correlation_id: str,
    ) -> dict[Any, Any]:
        """Fetch one order using the client-provided correlation id.

        Args:
            correlation_id: Correlation id supplied at order placement.

        Raises:
            OrderNotFoundError: If no order matches the correlation id.

        Returns:
            Unified Fenix order record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(correlation_id)

        response = self.fetch(
            method="GET",
            url=f"{self.get_url('order_by_correlation')}/{correlation_id}",
            endpoint_group="default",
            headers=self._headers,
        )

        try:
            info = self._parse_json_response(response)
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                raise OrderNotFoundError(
                    "This correlation_id does not exist."
                ) from exc
            raise

        if isinstance(info, list):
            if not info:
                raise OrderNotFoundError("This correlation_id does not exist.")
            info = info[0]

        return self._parse_orderbook(info)

    def fetch_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """Fetch order history in the unified Fenix format.

        Dhan does not expose a per-order status timeline; the order object
        itself carries its latest state. This method therefore returns the
        current order detail wrapped in a single-element list to keep parity
        with brokers that do expose a history endpoint.

        Args:
            order_id: Broker order id to query.

        Returns:
            Unified order records (the current state of the order).
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        return [self.fetch_order(order_id=order_id)]

    # --------------------------------------------------------------------- #
    # Order Modification & Cancellation
    # --------------------------------------------------------------------- #

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
        """Modify a pending Dhan order.

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
            raw_order_json: Optional raw order row to avoid refetching the
                order.
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
            order_info = self.fetch_order(order_id=order_id)["info"]

        new_order_type = (
            self._format_for_broker("order_type", order_type)
            if order_type
            else order_info["orderType"]
        )
        new_validity = (
            self._format_for_broker("validity", validity)
            if validity
            else order_info.get("validity", Validity.DAY)
        )

        json_data = {
            "dhanClientId": self._auth_context["user_id"],
            "orderId": str(order_id),
            "orderType": new_order_type,
            "legName": order_info.get("legName") or "",
            "quantity": int(quantity or order_info.get("quantity") or 0),
            "price": float(
                price if price is not None else order_info.get("price") or 0.0
            ),
            "disclosedQuantity": int(order_info.get("disclosedQuantity") or 0),
            "triggerPrice": float(
                trigger
                if trigger is not None
                else order_info.get("triggerPrice") or 0.0
            ),
            "validity": new_validity,
        }

        response = self.fetch(
            method="PUT",
            url=f"{self.get_url('orders')}/{order_id}",
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def cancel_order(
        self,
        order_id: str,
        extra_params: dict | None = None,
    ) -> dict[Any, Any]:
        """Cancel a pending Dhan order.

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

        response = self.fetch(
            method="DELETE",
            url=f"{self.get_url('orders')}/{order_id}",
            endpoint_group="orders",
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def exit_bracket_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Exit an open bracket order.

        Dhan exits a bracket order by cancelling the parent order, which in
        turn cancels the associated target and stop-loss legs.

        Args:
            order_id: Broker order id for the bracket order.

        Returns:
            Unified order-id record for the cancelled bracket order.
        """
        return self.cancel_order(order_id=order_id)

    def square_off_position(
        self,
        symbol: str,
        token: int,
        exchange: str,
        quantity: int,
        product: str = Product.MIS,
    ) -> dict[Any, Any]:
        """Square off an open position with an opposite market order.

        Dhan has no dedicated square-off endpoint; a position is flattened by
        placing a market order in the opposite direction. The sign of
        ``quantity`` determines the side: a positive (long) quantity is closed
        with a SELL, a negative (short) quantity with a BUY.

        Args:
            symbol: Trading symbol to square off.
            token: Security id for the instrument.
            exchange: Dhan exchange segment (e.g. ``"NSE_EQ"``).
            quantity: Signed net quantity to square off.
            product: Product code in Fenix format.

        Returns:
            Unified order-id record for the square-off order.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.square_off_position(
                symbol=symbol,
                token=token,
                exchange=exchange,
                quantity=quantity,
                product=product,
            )

        side = Side.SELL if quantity > 0 else Side.BUY
        token_dict = {
            "Token": token,
            "Exchange": exchange,
            "Symbol": symbol,
        }

        return self.place_order(
            token_dict=token_dict,
            quantity=abs(int(quantity)),
            side=side,
            product=product,
            validity=Validity.DAY,
            variety=Variety.REGULAR,
            unique_id=UniqueID.DEF_ORDER,
        )

    # --------------------------------------------------------------------- #
    # Super Orders (entry + target + stop-loss legs)
    # --------------------------------------------------------------------- #

    def place_super_order(
        self,
        token_dict: dict,
        quantity: int,
        side: str,
        product: str,
        price: float,
        target: float = 0.0,
        stoploss: float = 0.0,
        trailing_jump: float = 0.0,
        unique_id: str = UniqueID.DEF_ORDER,
        order_type: str | None = None,
    ) -> dict[Any, Any]:
        """Place a Dhan super order (entry, target and stop-loss legs).

        Args:
            token_dict: Token metadata for the instrument being ordered.
            quantity: Number of units to order.
            side: Transaction side in Fenix format.
            product: Product code in Fenix format.
            price: Entry price.
            target: Target (profit) price for the target leg.
            stoploss: Stop-loss price for the stop-loss leg.
            trailing_jump: Trailing stop-loss jump value.
            unique_id: Client-provided correlation id.
            order_type: Order type in Fenix format. Inferred from ``price``
                when omitted.

        Returns:
            Unified order-id record for the placed super order.
        """
        if order_type is None:
            order_type = self._resolve_order_type(price, 0.0)

        json_data = {
            "dhanClientId": self._auth_context["user_id"],
            "transactionType": self._format_for_broker("side", side),
            "exchangeSegment": token_dict["Exchange"],
            "productType": self._format_for_broker("product", product),
            "orderType": self._format_for_broker("order_type", order_type),
            "securityId": str(token_dict["Token"]),
            "quantity": int(quantity),
            "price": float(price),
            "targetPrice": float(target),
            "stopLossPrice": float(stoploss),
            "trailingJump": float(trailing_jump),
        }

        if unique_id:
            json_data["correlationId"] = unique_id

        response = self.fetch(
            method="POST",
            url=self.get_url("super_orders"),
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def modify_super_order(
        self,
        order_id: str,
        leg_name: str = "ENTRY_LEG",
        order_type: str | None = None,
        quantity: int | None = None,
        price: float | None = None,
        target: float | None = None,
        stoploss: float | None = None,
        trailing_jump: float | None = None,
    ) -> dict[Any, Any]:
        """Modify a leg of a pending Dhan super order.

        Args:
            order_id: Broker order id to modify.
            leg_name: Leg to modify - ``ENTRY_LEG``, ``TARGET_LEG`` or
                ``STOP_LOSS_LEG``.
            order_type: Replacement order type in Fenix format (entry leg).
            quantity: Replacement quantity (entry leg).
            price: Replacement entry price (entry leg).
            target: Replacement target price (entry or target leg).
            stoploss: Replacement stop-loss price (entry or stop-loss leg).
            trailing_jump: Replacement trailing jump (entry or stop-loss leg).

        Raises:
            InputError: If ``leg_name`` is not a valid super-order leg.

        Returns:
            Unified order-id record for the modified super order.
        """
        leg_name = str(leg_name).upper()
        if leg_name not in ("ENTRY_LEG", "TARGET_LEG", "STOP_LOSS_LEG"):
            raise InputError(
                "Invalid leg_name. Must be one of ENTRY_LEG, TARGET_LEG, "
                "STOP_LOSS_LEG."
            )

        json_data: dict[str, Any] = {
            "dhanClientId": self._auth_context["user_id"],
            "orderId": str(order_id),
            "legName": leg_name,
        }

        if leg_name == "ENTRY_LEG":
            if order_type is not None:
                json_data["orderType"] = self._format_for_broker(
                    "order_type", order_type
                )
            json_data["quantity"] = int(quantity or 0)
            json_data["price"] = float(price or 0.0)
            json_data["targetPrice"] = float(target or 0.0)
            json_data["stopLossPrice"] = float(stoploss or 0.0)
            json_data["trailingJump"] = float(trailing_jump or 0.0)
        elif leg_name == "TARGET_LEG":
            json_data["targetPrice"] = float(target or 0.0)
        else:  # STOP_LOSS_LEG
            json_data["stopLossPrice"] = float(stoploss or 0.0)
            json_data["trailingJump"] = float(trailing_jump or 0.0)

        response = self.fetch(
            method="PUT",
            url=f"{self.get_url('super_orders')}/{order_id}",
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def cancel_super_order(
        self,
        order_id: str,
        leg_name: str = "ENTRY_LEG",
    ) -> dict[Any, Any]:
        """Cancel a Dhan super order or one of its legs.

        Cancelling ``ENTRY_LEG`` cancels the entire super order; cancelling a
        target or stop-loss leg individually cannot be undone.

        Args:
            order_id: Broker order id to cancel.
            leg_name: Leg to cancel - ``ENTRY_LEG``, ``TARGET_LEG`` or
                ``STOP_LOSS_LEG``.

        Raises:
            InputError: If ``leg_name`` is not a valid super-order leg.

        Returns:
            Unified order-id record for the cancelled super order.
        """
        leg_name = str(leg_name).upper()
        if leg_name not in ("ENTRY_LEG", "TARGET_LEG", "STOP_LOSS_LEG"):
            raise InputError(
                "Invalid leg_name. Must be one of ENTRY_LEG, TARGET_LEG, "
                "STOP_LOSS_LEG."
            )

        response = self.fetch(
            method="DELETE",
            url=f"{self.get_url('super_orders')}/{order_id}/{leg_name}",
            endpoint_group="orders",
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def fetch_super_orders(
        self,
    ) -> list[dict]:
        """Fetch all super orders in the unified Fenix format.

        Returns:
            Unified order records. The raw ``legDetails`` array is preserved
            under each record's ``info`` field.
        """
        response = self.fetch(
            method="GET",
            url=self.get_url("super_orders"),
            endpoint_group="default",
            headers=self._headers,
        )

        try:
            info = self._parse_json_response(response) or []
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

        orders = []
        for order in info:
            detail = self._parse_orderbook(order)
            orders.append(detail)

        return orders

    # --------------------------------------------------------------------- #
    # Forever (GTT) Orders
    # --------------------------------------------------------------------- #

    def place_forever_order(
        self,
        token_dict: dict,
        quantity: int,
        side: str,
        product: str,
        price: float,
        trigger: float,
        validity: str = Validity.DAY,
        unique_id: str = UniqueID.DEF_ORDER,
        order_flag: str = "SINGLE",
        price1: float = 0.0,
        trigger1: float = 0.0,
        quantity1: int = 0,
        order_type: str | None = None,
    ) -> dict[Any, Any]:
        """Place a Dhan forever (GTT) order.

        Args:
            token_dict: Token metadata for the instrument being ordered.
            quantity: Number of units to order.
            side: Transaction side in Fenix format.
            product: Product code in Fenix format.
            price: Limit price for the primary leg.
            trigger: Trigger price for the primary leg.
            validity: Order validity in Fenix format.
            unique_id: Client-provided correlation id.
            order_flag: ``SINGLE`` for a single order or ``OCO`` for a
                one-cancels-other pair.
            price1: Limit price for the secondary (OCO) leg.
            trigger1: Trigger price for the secondary (OCO) leg.
            quantity1: Quantity for the secondary (OCO) leg.
            order_type: Order type in Fenix format. Inferred from
                ``price`` / ``trigger`` when omitted.

        Returns:
            Unified order-id record for the placed forever order.
        """
        if order_type is None:
            order_type = self._resolve_order_type(price, trigger)

        json_data = {
            "dhanClientId": self._auth_context["user_id"],
            "orderFlag": order_flag,
            "transactionType": self._format_for_broker("side", side),
            "exchangeSegment": token_dict["Exchange"],
            "productType": self._format_for_broker("product", product),
            "orderType": self._format_for_broker("order_type", order_type),
            "validity": self._format_for_broker("validity", validity),
            "tradingSymbol": token_dict.get("Symbol", ""),
            "securityId": str(token_dict["Token"]),
            "quantity": int(quantity),
            "disclosedQuantity": 0,
            "price": float(price),
            "triggerPrice": float(trigger),
            "price1": float(price1),
            "triggerPrice1": float(trigger1),
            "quantity1": int(quantity1),
        }

        if unique_id:
            json_data["correlationId"] = unique_id

        response = self.fetch(
            method="POST",
            url=self.get_url("forever_orders"),
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def modify_forever_order(
        self,
        order_id: str,
        leg_name: str = "ENTRY_LEG",
        order_flag: str = "SINGLE",
        price: float | None = None,
        trigger: float | None = None,
        quantity: int | None = None,
        order_type: str | None = None,
        validity: str | None = None,
        raw_order_json: dict | None = None,
    ) -> dict[Any, Any]:
        """Modify a pending Dhan forever (GTT) order.

        Args:
            order_id: Broker order id to modify.
            leg_name: Leg to modify (e.g. ``ENTRY_LEG`` or ``TARGET_LEG``).
            order_flag: ``SINGLE`` or ``OCO``.
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
            raw_order_json: Optional raw forever-order row to avoid refetching.

        Returns:
            Unified order-id record for the modified forever order.
        """
        if raw_order_json:
            order_info = raw_order_json
        else:
            order_info = {}
            for order in self.fetch_raw_forever_orders():
                if str(order.get("orderId")) == str(order_id):
                    order_info = order
                    break
            if not order_info:
                raise OrderNotFoundError("This order_id does not exist.")

        new_order_type = (
            self._format_for_broker("order_type", order_type)
            if order_type
            else order_info.get("orderType")
        )
        new_validity = (
            self._format_for_broker("validity", validity)
            if validity
            else order_info.get("validity", Validity.DAY)
        )

        json_data = {
            "dhanClientId": self._auth_context["user_id"],
            "orderId": str(order_id),
            "orderFlag": order_flag,
            "orderType": new_order_type,
            "legName": leg_name,
            "quantity": int(quantity or order_info.get("quantity") or 0),
            "disclosedQuantity": int(order_info.get("disclosedQuantity") or 0),
            "price": float(
                price if price is not None else order_info.get("price") or 0.0
            ),
            "triggerPrice": float(
                trigger
                if trigger is not None
                else order_info.get("triggerPrice") or 0.0
            ),
            "validity": new_validity,
        }

        response = self.fetch(
            method="PUT",
            url=f"{self.get_url('forever_orders')}/{order_id}",
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def cancel_forever_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Cancel a pending Dhan forever (GTT) order.

        Args:
            order_id: Broker order id to cancel.

        Returns:
            Unified order-id record for the cancelled forever order.
        """
        response = self.fetch(
            method="DELETE",
            url=f"{self.get_url('forever_orders')}/{order_id}",
            endpoint_group="orders",
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def fetch_raw_forever_orders(
        self,
    ) -> list[dict]:
        """Fetch raw Dhan forever (GTT) order rows.

        Returns:
            Raw broker forever-order rows. Empty result-set responses are
            returned as an empty list.
        """
        response = self.fetch(
            method="GET",
            url=self.get_url("forever_orders"),
            endpoint_group="default",
            headers=self._headers,
        )

        try:
            return self._parse_json_response(response) or []
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

    def fetch_forever_orders(
        self,
    ) -> list[dict]:
        """Fetch all forever (GTT) orders in the unified Fenix format.

        Returns:
            Unified order records.
        """
        info = self.fetch_raw_forever_orders()

        orders = []
        for order in info:
            detail = self._parse_orderbook(order)
            orders.append(detail)

        return orders

    # --------------------------------------------------------------------- #
    # Positions, Holdings, Margin & Profile
    # --------------------------------------------------------------------- #

    def fetch_day_positions(
        self,
    ) -> list[dict[str, Any]]:
        """Fetch intraday account positions.

        Dhan returns a single net positions snapshot, so this mirrors
        :meth:`fetch_net_positions`.

        Returns:
            Unified Fenix position records. Empty result-set responses are
            returned as an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        return self.fetch_net_positions()

    def fetch_net_positions(
        self,
    ) -> list[dict[str, Any]]:
        """Fetch net account positions.

        Returns:
            Unified Fenix position records. Empty result-set responses are
            returned as an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        response = self.fetch(
            method="GET",
            url=self.get_url("positions"),
            endpoint_group="default",
            headers=self._headers,
        )

        try:
            info = self._parse_json_response(response) or []
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

        positions = []
        for position in info:
            detail = self._parse_position(position)
            positions.append(detail)

        return positions

    def fetch_holdings(
        self,
    ) -> list[dict[str, Any]]:
        """Fetch account holdings.

        Returns:
            Raw Dhan holding rows. Empty result-set responses are returned as
            an empty list. In paper mode, returns the unified paper holdings.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_holdings()

        try:
            response = self.fetch(
                method="GET",
                url=self.get_url("holdings"),
                endpoint_group="default",
                headers=self._headers,
            )
            return self._parse_json_response(response) or []
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

    def convert_position(
        self,
        token: int,
        exchange: str,
        position_type: str,
        from_product: str,
        to_product: str,
        quantity: int,
    ) -> None:
        """Convert a position between product types (e.g. MIS to CNC).

        Args:
            token: Security id of the instrument to convert.
            exchange: Dhan exchange segment (e.g. ``"NSE_EQ"``).
            position_type: Position type - ``LONG``, ``SHORT`` or ``CLOSED``.
            from_product: Source product code in Fenix format.
            to_product: Destination product code in Fenix format.
            quantity: Quantity to convert.

        Returns:
            None. Dhan acknowledges the conversion without returning a
            normalized record.
        """
        json_data = {
            "dhanClientId": self._auth_context["user_id"],
            "fromProductType": self._format_for_broker("product", from_product),
            "exchangeSegment": exchange,
            "positionType": position_type,
            "securityId": str(token),
            "convertQty": int(quantity),
            "toProductType": self._format_for_broker("product", to_product),
        }

        self.fetch(
            method="POST",
            url=self.get_url("convert_position"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        return None

    def exit_all_positions(
        self,
    ) -> dict[Any, Any]:
        """Exit all open positions and cancel all open orders for the day.

        Dhan exposes a native ``DELETE /positions`` endpoint that flattens
        every open position and cancels every pending order in a single call.

        Returns:
            Raw Dhan response (``{"status": ..., "message": ...}``).
        """
        if self.paper_mode and self._paper is not None:
            return {
                "status": "SUCCESS",
                "message": "Paper mode: no live positions to exit.",
            }

        response = self.fetch(
            method="DELETE",
            url=self.get_url("positions"),
            endpoint_group="orders",
            headers=self._headers,
        )

        return self._parse_json_response(response)

    def fetch_margin_limits(
        self,
    ) -> dict[Any, Any]:
        """Fetch account margin limits.

        Returns:
            Unified Fenix RMS limits record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_margin_limits()

        response = self.fetch(
            method="GET",
            url=self.get_url("fund_limit"),
            endpoint_group="default",
            headers=self._headers,
        )
        response = self._parse_json_response(response)

        return self._parse_rms(response)

    def margin_calculator(
        self,
        token_dict: dict,
        quantity: int,
        side: str,
        product: str,
        price: float = 0.0,
        trigger: float = 0.0,
    ) -> dict[Any, Any]:
        """Calculate the margin required for a prospective order.

        Args:
            token_dict: Token metadata for the instrument.
            quantity: Quantity to evaluate.
            side: Transaction side in Fenix format.
            product: Product code in Fenix format.
            price: Order price.
            trigger: Trigger price.

        Returns:
            Raw Dhan margin-calculator response.
        """
        json_data = {
            "dhanClientId": self._auth_context["user_id"],
            "exchangeSegment": token_dict["Exchange"],
            "transactionType": self._format_for_broker("side", side),
            "quantity": int(quantity),
            "productType": self._format_for_broker("product", product),
            "securityId": str(token_dict["Token"]),
            "price": float(price),
            "triggerPrice": float(trigger),
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("margin_calculator"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_json_response(response)

    def fetch_profile(
        self,
    ) -> dict[Any, Any]:
        """Fetch account profile details.

        Returns:
            Unified Fenix profile record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_profile()

        response = self.fetch(
            method="GET",
            url=self.get_url("profile"),
            endpoint_group="default",
            headers=self._headers,
        )
        response = self._parse_json_response(response)

        return self._parse_profile(response)

    # --------------------------------------------------------------------- #
    # Trader Control & Option Chain
    # --------------------------------------------------------------------- #

    def kill_switch(
        self,
        activate: bool = True,
    ) -> dict[Any, Any]:
        """Activate or deactivate the trading kill switch for the day.

        Args:
            activate: ``True`` to disable trading for the day, ``False`` to
                re-enable it.

        Returns:
            Raw Dhan kill-switch response.
        """
        status = "ACTIVATE" if activate else "DEACTIVATE"
        response = self.fetch(
            method="POST",
            url=self.get_url("kill_switch"),
            endpoint_group="default",
            params={"killSwitchStatus": status},
            json={},
            headers=self._headers,
        )

        return self._parse_json_response(response)

    def fetch_expiry_list(
        self,
        under_token: int,
        under_exchange: str,
    ) -> Any:
        """Fetch the list of option expiries for an underlying.

        Args:
            under_token: Security id of the underlying instrument.
            under_exchange: Dhan exchange segment of the underlying (e.g.
                ``"IDX_I"`` or ``"NSE_FNO"``).

        Returns:
            Raw Dhan expiry-list response.
        """
        json_data = {
            "UnderlyingScrip": int(under_token),
            "UnderlyingSeg": under_exchange,
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("expiry_list"),
            endpoint_group="quote",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_json_response(response)

    def fetch_option_chain(
        self,
        under_token: int,
        under_exchange: str,
        expiry: str,
    ) -> Any:
        """Fetch the real-time option chain for an underlying and expiry.

        Args:
            under_token: Security id of the underlying instrument.
            under_exchange: Dhan exchange segment of the underlying.
            expiry: Expiry date (``YYYY-MM-DD``).

        Returns:
            Raw Dhan option-chain response.
        """
        json_data = {
            "UnderlyingScrip": int(under_token),
            "UnderlyingSeg": under_exchange,
            "Expiry": expiry,
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("option_chain"),
            endpoint_group="quote",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_json_response(response)
