from __future__ import annotations

import csv
import hashlib
import io
import json
from collections import defaultdict
from datetime import datetime
from typing import TYPE_CHECKING, Any, NoReturn
from urllib.parse import parse_qs, urlparse

from requests.exceptions import HTTPError

from fenix.base.broker import Broker
from fenix.base.constants import (
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
    BrokerError,
    InputError,
    InsufficientFundsError,
    InsufficientHoldingsError,
    InvalidOrderError,
    NetworkError,
    OrderNotFoundError,
    PermissionDeniedError,
    ResponseError,
)

if TYPE_CHECKING:
    from requests.models import Response


class Zerodha(Broker):
    """Zerodha (Kite Connect) broker adapter for the Fenix trading interface."""

    _API = {
        "doc": "https://kite.trade/docs/connect/v3",
        "servers": {
            "api": "https://api.kite.trade",
            "auth": "https://kite.zerodha.com",
            "connect": "https://kite.trade",
        },
        "paths": {
            # --- Auth Flow ---
            "api_session": {
                "server": "connect",
                "path": "/connect/login",
            },
            "session": {
                "server": "auth",
                "path": "/api/connect/session",
            },
            "login": {
                "server": "auth",
                "path": "/api/login",
            },
            "twofa": {
                "server": "auth",
                "path": "/api/twofa",
            },
            "connect_finish": {
                "server": "auth",
                "path": "/connect/finish",
            },
            "token_url": {
                "server": "api",
                "path": "/session/token",
            },

            # --- Order & Portfolio Flow ---
            "place_order": {
                "server": "api",
                "path": "/orders",
            },
            "tradebook": {
                "server": "api",
                "path": "/trades",
            },
            "holdings": {
                "server": "api",
                "path": "/portfolio/holdings",
            },
            "positions": {
                "server": "api",
                "path": "/portfolio/positions",
            },
            "rms_limits": {
                "server": "api",
                "path": "/user/margins",
            },
            "profile": {
                "server": "api",
                "path": "/user/profile",
            },

            # --- Market Data ---
            "instruments": {
                "server": "api",
                "path": "/instruments",
            },
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
            "SL": OrderType.SL,
            "SL-M": OrderType.SLM,
        },
        "status": {
            "OPEN PENDING": Status.PENDING,
            "MODIFY PENDING": Status.PENDING,
            "CANCEL PENDING": Status.PENDING,
            "TRIGGER PENDING": Status.PENDING,
            "AMO REQ RECEIVED": Status.PENDING,
            "VALIDATION PENDING": Status.PENDING,
            "PUT ORDER REQ RECEIVED": Status.PENDING,
            "MODIFY VALIDATION PENDING": Status.PENDING,
            "OPEN": Status.OPEN,
            "COMPLETE": Status.FILLED,
            "REJECTED": Status.REJECTED,
            "CANCELLED": Status.CANCELLED,
        },
        "product": {
            "MIS": Product.MIS,
            "CNC": Product.CNC,
            "NRML": Product.NRML,
        },
        "exchange": {
            "NSE": ExchangeCode.NSE,
            "NFO": ExchangeCode.NFO,
            "BSE": ExchangeCode.BSE,
            "BFO": ExchangeCode.BFO,
            "BCD": ExchangeCode.BCD,
            "MCX": ExchangeCode.MCX,
            "CDS": ExchangeCode.CDS,
        },
        "validity": {
            "DAY": Validity.DAY,
            "IOC": Validity.IOC,
            "TTL": Validity.TTL,
        },
        "variety": {
            "regular": Variety.REGULAR,
            "amo": Variety.AMO,
            "co": Variety.CO,
            "iceberg": Variety.ICEBERG,
            "auction": Variety.AUCTION,
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
            ExchangeCode.BSE: "BSE",
            ExchangeCode.BFO: "BFO",
            ExchangeCode.BCD: "BCD",
            ExchangeCode.MCX: "MCX",
            ExchangeCode.CDS: "CDS",
        },
        "order_type": {
            OrderType.MARKET: "MARKET",
            OrderType.LIMIT: "LIMIT",
            OrderType.SL: "SL",
            OrderType.SLM: "SL-M",
        },
        "product": {
            Product.MIS: "MIS",
            Product.CNC: "CNC",
            Product.NRML: "NRML",
        },
        "validity": {
            Validity.DAY: "DAY",
            Validity.IOC: "IOC",
            Validity.TTL: "TTL",
        },
        "variety": {
            Variety.REGULAR: "regular",
            Variety.STOPLOSS: "regular",
            Variety.AMO: "amo",
            Variety.CO: "co",
            Variety.ICEBERG: "iceberg",
            Variety.AUCTION: "auction",
        },
    }

    _REQUIRED_AUTH_HEADER_KEYS = (
        "X-Kite-Version",
        "User-Agent",
        "Authorization",
        "user_id",
        "api_key",
        "access_token",
    )

    ERROR_CODE_KEYS = (
        "error_type",
    )

    ERROR_MESSAGE_KEYS = (
        "message",
    )

    _ERROR_MESSAGES = {
        "TokenException": (
            "Session expired or invalidated. The user must clear the current "
            "session and re-initiate a login."
        ),
        "UserException": "Represents user account related errors.",
        "OrderException": (
            "Represents order related errors such as placement failures or a "
            "corrupt fetch."
        ),
        "InputException": (
            "Represents missing required fields or bad values for parameters."
        ),
        "MarginException": (
            "Represents insufficient funds required for the order placement."
        ),
        "HoldingException": (
            "Represents insufficient holdings available to place a sell order "
            "for the specified instrument."
        ),
        "NetworkException": (
            "Represents a network error where the API was unable to "
            "communicate with the OMS (Order Management System)."
        ),
        "DataException": (
            "Represents an internal system error where the API was unable to "
            "understand the response from the OMS."
        ),
        "GeneralException": (
            "Represents an unclassified error. This should only happen rarely."
        ),
    }

    _DIRECT_ERROR_CLASSES = {
        "TokenException": AuthenticationError,
        "UserException": PermissionDeniedError,
        "OrderException": InvalidOrderError,
        "InputException": InputError,
        "MarginException": InsufficientFundsError,
        "HoldingException": InsufficientHoldingsError,
        "NetworkException": NetworkError,
        "DataException": ResponseError,
        "GeneralException": BrokerError,
    }

    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "Zerodha",
            "tokenParams": [
                "user_id",
                "password",
                "totpstr",
                "api_key",
                "api_secret",
            ],
            "proxies": {},
            "sensitiveLogKeys": [
                "user_id",
                "password",
                "totp",
                "totpstr",
                "twofa_value",
                "api_key",
                "api_secret",
                "request_token",
                "access_token",
                "refresh_token",
                "checksum",
                "Authorization",
                "X-Kite-Version",
                "User-Agent",
            ],
            "enableRateLimit": True,
            "rateLimits": {
                "quote": {
                    "period": 1,
                    "capacity": 1,
                    "cost": 1.0,
                },
                "historical": {
                    "period": 1,
                    "capacity": 3,
                    "cost": 1.0,
                },
                "order": [
                    {
                        "period": 1,
                        "capacity": 10,
                        "cost": 1.0,
                    },
                    {
                        "period": 60,
                        "capacity": 400,
                        "cost": 1.0,
                    },
                    {
                        "period": 86400,
                        "capacity": 5000,
                        "cost": 1.0,
                    },
                ],
                "modify": {
                    "period": 86400,
                    "capacity": 25,
                    "cost": 1.0,
                },
                "default": {
                    "period": 1,
                    "capacity": 10,
                    "cost": 1.0,
                },
            },
        }

    def __init__(self, config: dict | None = None):
        """Initialize the Zerodha broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
        """
        super().__init__(config)

    # Authentication

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """Authenticate with Zerodha Kite Connect and return request headers.

        Args:
            params: Login credentials and API keys required by Kite Connect.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and re-run the login flow.

        Returns:
            Headers that authenticate subsequent Kite Connect API calls.

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

        # Step 1: capture the session id Kite issues during the OAuth redirect.
        api_session_response = self.fetch(
            method="GET",
            url=self.get_url("api_session"),
            endpoint_group="default",
            params={"api_key": params["api_key"], "v": "3"},
            timeout=10,
        )
        sess_query = urlparse(api_session_response.url).query
        sess_params = {
            key: value[0] for key, value in parse_qs(sess_query).items()
        }

        # Step 2: warm up the session endpoint with the captured id.
        self.fetch(
            method="GET",
            url=self.get_url("session"),
            endpoint_group="default",
            params=sess_params,
            timeout=10,
        )

        # Step 3: exchange user_id + password for a request_id.
        login_response = self.fetch(
            method="POST",
            url=self.get_url("login"),
            endpoint_group="default",
            data={
                "user_id": params["user_id"],
                "password": params["password"],
            },
            timeout=10,
        )
        login_payload = self._parse_json_response(login_response)
        request_id = login_payload["data"]["request_id"]

        # Step 4: complete two-factor authentication using a TOTP code.
        totp = self.totp_creator(params["totpstr"])
        self.fetch(
            method="POST",
            url=self.get_url("twofa"),
            endpoint_group="default",
            data={
                "user_id": params["user_id"],
                "request_id": request_id,
                "twofa_value": str(totp),
                "twofa_type": "totp",
                "skip_session": "false",
            },
            timeout=10,
        )

        # Step 5: capture the request_token from the connect-finish redirect.
        try:
            connect_response = self.fetch(
                method="GET",
                url=self.get_url("connect_finish"),
                endpoint_group="default",
                params=sess_params,
                timeout=10,
            )
            req_token_url = connect_response.url
        except Exception as exc:
            req_token_url = str(exc)

        request_token = (
            parse_qs(urlparse(req_token_url).query)
            .get("request_token", [""])[0]
            .split()[0]
        )

        # Step 6: exchange the request_token + checksum for an access_token.
        checksum = hashlib.sha256(
            (
                params["api_key"]
                + request_token
                + params["api_secret"]
            ).encode("utf-8")
        ).hexdigest()

        token_response = self.fetch(
            method="POST",
            url=self.get_url("token_url"),
            endpoint_group="default",
            data={
                "api_key": params["api_key"],
                "request_token": request_token,
                "checksum": checksum,
            },
            timeout=10,
        )
        token_payload = self._parse_json_response(token_response)
        access_token = token_payload["data"]["access_token"]

        self._headers = {
            "X-Kite-Version": "3",
            "User-Agent": "Kiteconnect-python/4.2.0",
            "Authorization": f'token {params["api_key"]}:{access_token}',
            "user_id": params["user_id"],
            "api_key": params["api_key"],
            "access_token": access_token,
        }

        self.reset_session()

        return self._headers

    # Script Fetch

    def _open_instruments_stream(self, data: Any | None) -> io.StringIO:
        """Return a CSV stream over the Kite Connect instruments dump.

        Args:
            data: Optional pre-fetched contract-master text. When omitted the
                instruments endpoint is downloaded.

        Returns:
            A text stream positioned at the start of the contract master.

        Raises:
            TypeError: If ``data`` is provided but is not a string.
        """
        if data is None:
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
            )
            return io.StringIO(response.text)

        if not isinstance(data, str):
            raise TypeError("The data must be string type.")
        return io.StringIO(data)

    @staticmethod
    def _parse_expiry(
        expiry_raw: str,
        cache: dict[str, tuple[str, str]],
    ) -> tuple[str, str]:
        """Parse and cache a Kite Connect expiry string.

        Args:
            expiry_raw: Raw ``YYYY-MM-DD`` expiry string from the contract
                master.
            cache: Per-call lookup that memoizes parsed expiries.

        Returns:
            A tuple of the ISO expiry and the ``DD-MON`` display form.
        """
        cached = cache.get(expiry_raw)
        if cached is not None:
            return cached

        dt = datetime.strptime(expiry_raw, "%Y-%m-%d").date()
        parsed = (dt.strftime("%Y-%m-%d"), dt.strftime("%d-%b").upper())
        cache[expiry_raw] = parsed
        return parsed

    @staticmethod
    def format_opt_dict(
        row: dict[str, Any],
        expiry: str,
        exdp: str,
    ) -> dict[str, Any]:
        """Build a unified option-instrument record from a contract-master row.

        Args:
            row: Raw contract-master row from Kite Connect.
            expiry: ISO-formatted expiry date (``YYYY-MM-DD``).
            exdp: Display-formatted expiry (``DD-MON``) used in ``ScriptName``.

        Returns:
            Unified Fenix option record.
        """
        root = row["name"]
        strike = Zerodha._format_strike(row["strike"])
        option = row["instrument_type"]

        return {
            "Token": row["instrument_token"],
            "ExToken": row["exchange_token"],
            "Exchange": row["segment"],
            "Root": root,
            "Symbol": row["tradingsymbol"],
            "LotSize": row["lot_size"],
            "TickSize": row["tick_size"],
            "Expiry": expiry,
            "StrikePrice": strike,
            "Option": option,
            "ScriptName": f"{root} {exdp} {strike} {option}",
        }

    @staticmethod
    def format_fut_dict(
        row: dict[str, Any],
        expiry: str,
        exdp: str,
    ) -> dict[str, Any]:
        """Build a unified futures-instrument record from a contract-master row.

        Args:
            row: Raw contract-master row from Kite Connect.
            expiry: ISO-formatted expiry date (``YYYY-MM-DD``).
            exdp: Display-formatted expiry (``DD-MON``) used in ``ScriptName``.

        Returns:
            Unified Fenix futures record.
        """
        root = row["name"]

        return {
            "Token": row["instrument_token"],
            "ExToken": row["exchange_token"],
            "Exchange": row["segment"],
            "Root": root,
            "Symbol": row["tradingsymbol"],
            "LotSize": row["lot_size"],
            "TickSize": row["tick_size"],
            "Expiry": expiry,
            "ScriptName": f"{root} {exdp} FUT",
        }

    def _load_single_exchange_fno(
        self,
        data: Any | None,
        opt_segment: str,
        fut_segment: str,
        suffix: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load futures and options tokens for a single-exchange segment.

        Args:
            data: Optional pre-fetched contract-master text.
            opt_segment: Kite Connect option segment string (e.g. ``"MCX-OPT"``).
            fut_segment: Kite Connect future segment string (e.g. ``"MCX-FUT"``).
            suffix: Token-key suffix appended after ``"{token}_"``.

        Returns:
            A tuple containing the unified futures/options token maps and an
            all-token lookup keyed by ``"{token}_{suffix}"``.
        """
        file_stream = self._open_instruments_stream(data)
        reader = csv.DictReader(file_stream, skipinitialspace=True)

        dt_dict: dict[str, tuple[str, str]] = {}
        fut: dict[str, list[dict[str, Any]]] = defaultdict(list)
        opt: dict[str, list[dict[str, Any]]] = defaultdict(list)
        token_dict: dict[str, Any] = {}

        for row in reader:
            segment = row["segment"]

            if segment == opt_segment:
                expiry, exdp = self._parse_expiry(row["expiry"], dt_dict)
                record = self.format_opt_dict(row, expiry, exdp)
                opt[row["name"]].append(record)
                token_dict[f"{row['exchange_token']}_{suffix}"] = record

            elif segment == fut_segment:
                expiry, exdp = self._parse_expiry(row["expiry"], dt_dict)
                record = self.format_fut_dict(row, expiry, exdp)
                fut[row["name"]].append(record)
                token_dict[f"{row['exchange_token']}_{suffix}"] = record

        self.token_json["Futures"].update({suffix: fut})
        self.token_json["Options"].update({suffix: opt})
        self.alltoken_json.update(token_dict)

        return (
            {
                "Futures": {suffix: fut},
                "Options": {suffix: opt},
            },
            token_dict,
        )

    def load_equity_tokens(
        self,
        data: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE equity token metadata.

        Args:
            data: Optional pre-fetched contract-master text. When omitted the
                contract master is downloaded from Kite Connect.

        Returns:
            A tuple containing the unified equity token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.
        """
        file_stream = self._open_instruments_stream(data)

        nse_dict: dict[str, Any] = {}
        bse_dict: dict[str, Any] = {}
        token_dict: dict[str, Any] = {}

        reader = csv.DictReader(file_stream, skipinitialspace=True)

        for row in reader:
            segment = row["segment"]

            if segment == "NSE":
                symbol = row["tradingsymbol"]
                token = row["exchange_token"]

                nse_dict[symbol] = {
                    "Token": row["instrument_token"],
                    "ExToken": token,
                    "Exchange": row["exchange"],
                    "Symbol": symbol,
                    "ScriptName": symbol,
                    "LotSize": row["lot_size"],
                    "TickSize": row["tick_size"],
                }
                token_dict[f"{token}_{segment}"] = row

            elif segment == "BSE":
                symbol = row["tradingsymbol"]
                token = row["exchange_token"]

                bse_dict[symbol] = {
                    "Token": row["instrument_token"],
                    "ExToken": token,
                    "Exchange": row["exchange"],
                    "Symbol": symbol,
                    "ScriptName": symbol,
                    "LotSize": row["lot_size"],
                    "TickSize": row["tick_size"],
                }
                token_dict[f"{token}_{segment}"] = row

        self.token_json["Equity"].update({
            "NSE": nse_dict,
            "BSE": bse_dict,
        })

        self.alltoken_json.update(token_dict)

        return (
            {
                "Equity": {"NSE": nse_dict, "BSE": bse_dict},
            },
            token_dict,
        )

    def load_index_tokens(
        self,
        data: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load index token metadata for the exchanges Kite publishes.

        Args:
            data: Optional pre-fetched contract-master text. When omitted the
                contract master is downloaded from Kite Connect.

        Returns:
            A tuple containing the unified index token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.
        """
        file_stream = self._open_instruments_stream(data)
        reader = csv.DictReader(file_stream, skipinitialspace=True)

        nse_dict: dict[str, Any] = {}
        bse_dict: dict[str, Any] = {}
        mcx_dict: dict[str, Any] = {}
        token_dict: dict[str, Any] = {}

        for row in reader:
            if row["segment"] != "INDICES":
                continue

            exchange = row["exchange"]
            symbol = row["tradingsymbol"]
            token = row["exchange_token"]

            record = {
                "Token": row["instrument_token"],
                "ExToken": token,
                "Exchange": exchange,
                "Symbol": symbol,
                "ScriptName": symbol,
            }

            if exchange == "BSE":
                bse_dict[symbol] = record
            elif exchange == "MCX":
                mcx_dict[symbol] = record
            else:
                nse_dict[symbol] = record

            token_dict[f"{token}_{exchange}"] = record

        self.token_json["Indices"].update({
            "NSE": nse_dict,
            "BSE": bse_dict,
            "MCX": mcx_dict,
        })

        self.alltoken_json.update(token_dict)

        return (
            {
                "Indices": {"NSE": nse_dict, "BSE": bse_dict, "MCX": mcx_dict},
            },
            token_dict,
        )

    def load_fno_tokens(
        self,
        data: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NFO and BFO futures and options token metadata.

        Args:
            data: Optional pre-fetched contract-master text. When omitted the
                contract master is downloaded from Kite Connect.

        Returns:
            A tuple containing the unified futures/options token maps and an
            all-token lookup keyed by ``"{token}_{exchange}"``.
        """
        file_stream = self._open_instruments_stream(data)
        reader = csv.DictReader(file_stream, skipinitialspace=True)

        dt_dict: dict[str, tuple[str, str]] = {}
        fut_nse: dict[str, list[dict[str, Any]]] = defaultdict(list)
        fut_bse: dict[str, list[dict[str, Any]]] = defaultdict(list)
        opt_nse: dict[str, list[dict[str, Any]]] = defaultdict(list)
        opt_bse: dict[str, list[dict[str, Any]]] = defaultdict(list)
        token_dict: dict[str, Any] = {}

        for row in reader:
            segment = row["segment"]

            if segment in ("NFO-OPT", "BFO-OPT"):
                expiry, exdp = self._parse_expiry(row["expiry"], dt_dict)
                record = self.format_opt_dict(row, expiry, exdp)
                root = row["name"]
                token = row["exchange_token"]
                exchange = record["Exchange"][:3]

                if exchange == "NFO":
                    opt_nse[root].append(record)
                    token_dict[f"{token}_NFO"] = record
                elif exchange == "BFO":
                    opt_bse[root].append(record)
                    token_dict[f"{token}_BFO"] = record

            elif segment in ("NFO-FUT", "BFO-FUT"):
                expiry, exdp = self._parse_expiry(row["expiry"], dt_dict)
                record = self.format_fut_dict(row, expiry, exdp)
                root = row["name"]
                token = row["exchange_token"]
                exchange = record["Exchange"][:3]

                if exchange == "NFO":
                    fut_nse[root].append(record)
                    token_dict[f"{token}_NFO"] = record
                elif exchange == "BFO":
                    fut_bse[root].append(record)
                    token_dict[f"{token}_BFO"] = record

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
        data: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load MCX futures and options token metadata.

        Args:
            data: Optional pre-fetched contract-master text. When omitted the
                contract master is downloaded from Kite Connect.

        Returns:
            A tuple containing the unified futures/options token maps and an
            all-token lookup keyed by ``"{token}_MCX"``.
        """
        return self._load_single_exchange_fno(
            data,
            opt_segment="MCX-OPT",
            fut_segment="MCX-FUT",
            suffix="MCX",
        )

    def load_cds_tokens(
        self,
        data: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load CDS futures and options token metadata.

        Args:
            data: Optional pre-fetched contract-master text. When omitted the
                contract master is downloaded from Kite Connect.

        Returns:
            A tuple containing the unified futures/options token maps and an
            all-token lookup keyed by ``"{token}_CDS"``.
        """
        return self._load_single_exchange_fno(
            data,
            opt_segment="CDS-OPT",
            fut_segment="CDS-FUT",
            suffix="CDS",
        )

    def load_nco_tokens(
        self,
        data: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NCO futures and options token metadata.

        Args:
            data: Optional pre-fetched contract-master text. When omitted the
                contract master is downloaded from Kite Connect.

        Returns:
            A tuple containing the unified futures/options token maps and an
            all-token lookup keyed by ``"{token}_NCO"``.
        """
        return self._load_single_exchange_fno(
            data,
            opt_segment="NCO-OPT",
            fut_segment="NCO-FUT",
            suffix="NCO",
        )

    # Error Handling

    def _extract_zerodha_error_code(self, payload: Any) -> str | None:
        """Extract a documented Zerodha error code from a payload."""
        error_code = self._extract_error_code(payload)
        if error_code:
            if error_code in self._ERROR_MESSAGES:
                return error_code
            if error_code.endswith("Exception"):
                return error_code

        payload_text = self._stringify_error_payload(payload)
        for documented_code in self._ERROR_MESSAGES:
            if documented_code in payload_text:
                return documented_code

        return None

    def _extract_zerodha_error_message(
        self,
        payload: Any,
        error_code: str | None,
    ) -> str | None:
        """Extract the most useful Zerodha error message for a payload."""
        error_message = self._extract_error_message(payload)
        documented_message = self._ERROR_MESSAGES.get(error_code or "")

        if documented_message and not error_message:
            return documented_message
        if documented_message and error_message == error_code:
            return documented_message
        if error_message:
            return error_message
        return documented_message

    def _zerodha_error_class(
        self,
        error_code: str | None,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve a Zerodha payload to the most specific Fenix error class."""
        if error_code in self._DIRECT_ERROR_CLASSES:
            return self._DIRECT_ERROR_CLASSES[error_code]

        message = (error_message or "").lower()
        if (
            "session" in message
            or "expired" in message
            or "invalidate" in message
        ):
            return AuthenticationError
        if "permission" in message or "not allowed" in message:
            return PermissionDeniedError
        if "insufficient fund" in message or "margin" in message:
            return InsufficientFundsError
        if "insufficient" in message and (
            "holding" in message or "quantity" in message
        ):
            return InsufficientHoldingsError
        if (
            "order not found" in message
            or "does not exist" in message
            or "not in your order book" in message
        ):
            return OrderNotFoundError
        if "invalid" in message or "bad value" in message:
            return InvalidOrderError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded Zerodha payload represents an error.

        Kite Connect responses always carry a top-level ``status`` field whose
        value is the literal string ``"success"`` or ``"error"``; anything other
        than ``"success"`` is treated as a failure.
        """
        if isinstance(payload, list):
            if not payload:
                return False
            return self._payload_indicates_error(payload[0])

        if isinstance(payload, dict):
            status = payload.get("status")
            if status is not None:
                return str(status).lower() != "success"
            return False

        return self._extract_zerodha_error_code(payload) is not None


    def _raise_zerodha_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for a Zerodha error payload."""
        context = self._http_error_context(response, payload)
        error_code = self._extract_zerodha_error_code(payload)
        error_message = self._extract_zerodha_error_message(
            payload,
            error_code,
        )

        context["error_code"] = error_code
        context["error_message"] = error_message
        error_cls = self._zerodha_error_class(
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
            self._raise_zerodha_error(payload, response=exc.response, cause=exc)

        super().handle_http_error(exc)

    @staticmethod
    def _split_concatenated_json(body: str) -> list[Any]:
        """Decode every top-level JSON document in a possibly-malformed body.

        Kite Connect occasionally returns two JSON documents glued together
        in a single response body (a documented error object followed by an
        empty success blob). Standard ``json.loads`` rejects this; here we
        walk the body with :class:`json.JSONDecoder` and yield each decoded
        object in order. The list is empty when nothing decodes.
        """
        decoder = json.JSONDecoder()
        index = 0
        length = len(body)
        decoded: list[Any] = []
        while index < length:
            # Skip whitespace between concatenated documents.
            while index < length and body[index].isspace():
                index += 1
            if index >= length:
                break
            try:
                obj, end = decoder.raw_decode(body, index)
            except ValueError:
                break
            decoded.append(obj)
            index = end
        return decoded

    def _response_error_payload(self, response: Response | None) -> Any:
        """Return the most informative payload from an error response body.

        Falls back to :meth:`_split_concatenated_json` when the body is the
        concatenated-document variant Kite Connect occasionally emits — the
        leading error object is preferred over a trailing success blob.
        """
        if response is None:
            return None

        body = (response.text or "").strip()
        if not body:
            return None

        if body.startswith(("{", "[")):
            decoded = self._split_concatenated_json(body)
            if decoded:
                for candidate in decoded:
                    if self._payload_indicates_error(candidate):
                        return candidate
                return decoded[0]

        return body

    def _parse_json_response(self, response: Response) -> Any:
        """Decode an HTTP response and raise broker-specific payload errors.

        Tolerates the concatenated-document responses Kite Connect sometimes
        emits (e.g. an ``InputException`` payload followed by an empty
        success blob); the documented error object is extracted and raised
        through the normal Zerodha error pipeline.
        """
        try:
            json_response = self._json_parser(response)
        except ResponseError as exc:
            decoded = self._split_concatenated_json(
                (response.text or "").strip()
            )
            error_object = next(
                (obj for obj in decoded if self._payload_indicates_error(obj)),
                None,
            )
            if error_object is not None:
                self._raise_zerodha_error(
                    error_object,
                    response=response,
                    cause=exc,
                )
            raise

        data_to_check = json_response[0] if isinstance(
            json_response, list) and json_response else json_response

        if self._payload_indicates_error(data_to_check):
            self._raise_zerodha_error(
                json_response,
                response=response,
            )

        return json_response

    # Order Placement

    def _build_place_order_payload(
        self,
        token_dict: dict,
        quantity: int,
        side: str,
        product: str,
        validity: str,
        unique_id: str,
        price: float = 0.0,
        trigger: float = 0.0,
    ) -> dict[str, Any]:
        """Build the Zerodha API payload for a place-order request.

        Args:
            token_dict: Token metadata for the instrument being ordered.
            quantity: Number of units to order.
            side: Transaction side in Fenix format.
            product: Product code in Fenix format.
            validity: Order validity in Fenix format.
            unique_id: Client-provided order tag.
            price: Limit price, or zero for market orders.
            trigger: Stop-loss trigger price, or zero when not applicable.

        Returns:
            Form-encoded Zerodha place-order payload.
        """
        order_type = self._resolve_order_type(price, trigger)
        return {
            "exchange": token_dict["Exchange"],
            "tradingsymbol": token_dict["Symbol"],
            "transaction_type": self._format_for_broker("side", side),
            "order_type": self._format_for_broker("order_type", order_type),
            "quantity": quantity,
            "price": price,
            "trigger_price": trigger,
            "product": self._format_for_broker("product", product),
            "validity": self._format_for_broker("validity", validity),
            "disclosed_quantity": 0,
            "tag": unique_id,
        }

    def _parse_place_order_response(
        self,
        response: Response,
    ) -> dict[Any, Any]:
        """Extract the order id from a Zerodha place-order response.

        Args:
            response: HTTP response returned after placing an order.

        Returns:
            Unified order-id record.
        """
        info = self._parse_json_response(response)
        return {Order.ID: info["data"]["order_id"]}

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
        """Place an order through Zerodha (Kite Connect).

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
            target: Bracket-order target price.
            stoploss: Bracket-order stop-loss price.
            trailing_sl: Bracket-order trailing stop-loss amount.

        Raises:
            InputError: If any bracket-order parameter is supplied; Kite
                Connect no longer supports bracket orders.

        Returns:
            Unified order-id record for the placed order.
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

        if target or stoploss or trailing_sl:
            raise InputError(
                f"Bracket orders are not available in {self.id}."
            )

        self._validate_order_inputs(
            quantity=quantity,
            price=price,
            trigger=trigger,
        )

        data = self._build_place_order_payload(
            token_dict=token_dict,
            quantity=quantity,
            side=side,
            product=product,
            validity=validity,
            unique_id=unique_id,
            price=price,
            trigger=trigger,
        )

        broker_variety = self._format_for_broker("variety", variety)
        url = f"{self.get_url('place_order')}/{broker_variety}"

        response = self.fetch(
            method="POST",
            url=url,
            endpoint_group="order",
            data=data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def _parse_orderbook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a Zerodha order-book row to a unified order record.

        Args:
            order: Raw order-book row returned by Kite Connect.

        Returns:
            Unified Fenix order record.
        """
        timestamp_raw = order.get("order_timestamp") or order.get(
            "exchange_timestamp"
        )
        parsed_order = {
            Order.ID: order["order_id"],
            Order.USER_ID: order.get("tag") or "",
            Order.TIMESTAMP: (
                datetime.strptime(timestamp_raw, "%Y-%m-%d %H:%M:%S")
                if timestamp_raw
                else None
            ),
            Order.SYMBOL: order["tradingsymbol"],
            Order.TOKEN: order["instrument_token"],
            Order.SIDE: self._parse_from_broker(
                "side", order["transaction_type"]),
            Order.TYPE: self._parse_from_broker(
                "order_type", order["order_type"]),
            Order.AVG_PRICE: float(order.get("average_price") or 0.0),
            Order.PRICE: float(order.get("price") or 0.0),
            Order.TRIGGER_PRICE: float(order.get("trigger_price") or 0.0),
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: int(order.get("quantity") or 0),
            Order.FILLED_QTY: int(order.get("filled_quantity") or 0),
            Order.REMAINING_QTY: int(order.get("pending_quantity") or 0),
            Order.CANCELLED_QTY: int(order.get("cancelled_quantity") or 0),
            Order.STATUS: self._parse_from_broker("status", order["status"]),
            Order.REJECT_REASON: order.get("status_message") or "",
            Order.DISCLOSED_QUANTITY: int(order.get("disclosed_quantity") or 0),
            Order.PRODUCT: self._parse_from_broker("product", order["product"]),
            Order.EXCHANGE: self._parse_from_broker(
                "exchange", order["exchange"]),
            Order.SEGMENT: self._parse_from_broker(
                "exchange", order["exchange"]),
            Order.VALIDITY: self._parse_from_broker(
                "validity", order["validity"]),
            Order.VARIETY: self._parse_from_broker("variety", order["variety"]),
            Order.INFO: order,
        }
        return parsed_order

    def _parse_position(
        self,
        position: dict[Any, Any],
        day_or_net: str = "",
    ) -> dict[Any, Any]:
        """Convert a Zerodha position row to a unified position record.

        Args:
            position: Raw position row returned by Kite Connect.
            day_or_net: ``"day_"`` for intraday rows, ``""`` for net rows.

        Returns:
            Unified Fenix position record.
        """
        parsed_position = {
            Position.SYMBOL: position["tradingsymbol"],
            Position.TOKEN: position["instrument_token"],
            Position.NET_QTY: position["quantity"],
            Position.AVG_PRICE: position["average_price"],
            Position.MTM: position["m2m"],
            Position.PNL: position["pnl"],
            Position.BUY_QTY: position[f"{day_or_net}buy_quantity"],
            Position.BUY_PRICE: position[f"{day_or_net}buy_price"],
            Position.SELL_QTY: position[f"{day_or_net}sell_quantity"],
            Position.SELL_PRICE: position[f"{day_or_net}sell_value"],
            Position.LTP: position["last_price"],
            Position.PRODUCT: self._parse_from_broker(
                "product", position["product"]),
            Position.EXCHANGE: self._parse_from_broker(
                "exchange", position["exchange"]),
            Position.INFO: position,
        }
        return parsed_position

    def _parse_holding(
        self,
        holding: dict[Any, Any],
    ) -> dict[Any, Any]:
        """Convert a Zerodha holding row to a unified position record.

        Args:
            holding: Raw holding row returned by Kite Connect.

        Returns:
            Unified Fenix position record.
        """
        parsed_holding = {
            Position.SYMBOL: holding["tradingsymbol"],
            Position.TOKEN: holding["instrument_token"],
            Position.NET_QTY: holding["quantity"],
            Position.AVG_PRICE: holding["average_price"],
            Position.MTM: holding["day_change"],
            Position.PNL: holding["pnl"],
            Position.LTP: holding["last_price"],
            Position.PRODUCT: self._parse_from_broker(
                "product", holding["product"]),
            Position.EXCHANGE: self._parse_from_broker(
                "exchange", holding["exchange"]),
            Position.INFO: holding,
        }
        return parsed_holding

    def _parse_profile(
        self,
        profile: dict,
    ) -> dict[Any, Any]:
        """Convert a Zerodha profile payload to a unified profile record.

        Args:
            profile: Raw profile payload returned by Kite Connect.

        Returns:
            Unified Fenix profile record.
        """
        parsed_profile = {
            Profile.CLIENT_ID: profile["user_id"],
            Profile.NAME: profile["user_name"],
            Profile.EMAIL_ID: profile["email"],
            Profile.MOBILE_NO: "",
            Profile.PAN: "",
            Profile.ADDRESS: "",
            Profile.BANK_NAME: "",
            Profile.BANK_BRANCH_NAME: None,
            Profile.BANK_ACC_NO: "",
            Profile.EXCHANGES_ENABLED: profile.get("exchanges", []),
            Profile.ENABLED: True,
            Profile.INFO: profile,
        }
        return parsed_profile

    # Order Details, OrderBook & TradeBook

    def fetch_raw_orderbook(
        self,
    ) -> list[dict]:
        """Fetch raw Zerodha order-book rows.

        Returns:
            Raw broker order-book rows. Empty result-set responses are returned
            as an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        response = self.fetch(
            method="GET",
            url=self.get_url("place_order"),
            endpoint_group="default",
            headers=self._headers,
        )
        info = self._parse_json_response(response)

        return info.get("data")

    def fetch_raw_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """Fetch raw Zerodha history rows for an order.

        Args:
            order_id: Broker order id to query.

        Returns:
            Raw broker order-history rows.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        url = f"{self.get_url('place_order')}/{order_id}"
        response = self.fetch(
            method="GET",
            url=url,
            endpoint_group="default",
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return info.get("data") or []

    def fetch_orderbook(
        self,
    ) -> list[dict]:
        """Fetch the order book in the unified Fenix format.

        Returns:
            Unified order records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        rows = self.fetch_raw_orderbook()
        return [self._parse_orderbook(row) for row in rows]

    def fetch_tradebook(
        self,
    ) -> list[dict]:
        """Fetch the trade book in the unified Fenix format.

        Returns:
            Unified order records. Empty result-set responses are returned
            as an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_tradebook()

        response = self.fetch(
            method="GET",
            url=self.get_url("tradebook"),
            endpoint_group="default",
            headers=self._headers,
        )

        info = self._parse_json_response(response)

        rows = info.get("data")
        return [self._parse_orderbook(row) for row in rows]

    def fetch_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Fetch the most recent state of one order.

        Args:
            order_id: Broker order id to look up.

        Raises:
            OrderNotFoundError: If Kite Connect has no history for the id.

        Returns:
            Unified Fenix order record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        history = self.fetch_raw_order_history(order_id=order_id)
        if not history:
            raise OrderNotFoundError(
                f"Order {order_id} was not found in the order book."
            )
        return self._parse_orderbook(history[-1])

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

        history = self.fetch_raw_order_history(order_id=order_id)
        return [self._parse_orderbook(row) for row in history]

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
    ) -> None:
        """Modify an open Zerodha order.

        Args:
            order_id: Broker order id to modify.
            price: Replacement limit price. Existing price is reused when
                omitted.
            trigger: Replacement trigger price. Existing trigger is reused
                when omitted.
            quantity: Replacement quantity. Existing quantity is reused when
                omitted.
            order_type: Replacement order type in Fenix format. Existing
                type is reused when omitted.
            validity: Replacement validity in Fenix format. Existing
                validity is reused when omitted.
            raw_order_json: Optional raw order row to avoid refetching
                history.
            extra_params: Reserved for broker-specific extensions.

        Raises:
            OrderNotFoundError: If history is unavailable for the order.

        Returns:
            None. Kite Connect acknowledges the modification without
            returning a normalized order record.
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
            if not history:
                raise OrderNotFoundError(
                    f"Order {order_id} was not found in the order book."
                )
            order_info = history[-1]

        variety = order_info["variety"]
        url = f"{self.get_url('place_order')}/{variety}/{order_id}"

        data = {
            "price": (
                price if price is not None else order_info.get("price", 0)
            ),
            "trigger_price": (
                trigger
                if trigger is not None
                else order_info.get("trigger_price", 0)
            ),
            "quantity": (
                quantity
                if quantity is not None
                else order_info["quantity"]
            ),
            "order_type": (
                self._format_for_broker("order_type", order_type)
                if order_type
                else order_info["order_type"]
            ),
            "validity": (
                self._format_for_broker("validity", validity)
                if validity
                else order_info["validity"]
            ),
        }

        response = self.fetch(
            method="PUT",
            url=url,
            endpoint_group="modify",
            data=data,
            headers=self._headers,
        )
        self._parse_json_response(response)
        return None

    def cancel_order(
        self,
        order_id: str,
        extra_params: dict | None = None,
    ) -> None:
        """Cancel an open Zerodha order.

        Args:
            order_id: Broker order id to cancel.
            extra_params: Optional broker-specific values. When it contains
                a ``"variety"`` key that value is used directly, avoiding
                the order-history lookup.

        Raises:
            OrderNotFoundError: If history is unavailable for the order.

        Returns:
            None. Kite Connect acknowledges cancellation without returning
            a normalized order record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.cancel_order(
                order_id=order_id,
                extra_params=extra_params,
            )

        extra_params = extra_params or {}

        if extra_params.get("variety"):
            variety = extra_params["variety"]
        else:
            history = self.fetch_raw_order_history(order_id=order_id)
            if not history:
                raise OrderNotFoundError(
                    f"Order {order_id} was not found in the order book."
                )
            variety = history[-1]["variety"]

        url = f"{self.get_url('place_order')}/{variety}/{order_id}"

        response = self.fetch(
            method="DELETE",
            url=url,
            endpoint_group="order",
            headers=self._headers,
        )
        self._parse_json_response(response)
        return None

    # Positions, Account Limits & Profile

    def fetch_raw_positions(
        self,
    ) -> dict[str, list]:
        """Fetch the raw Zerodha positions payload.

        Returns:
            Raw positions data keyed by ``"day"`` and ``"net"``.
        """
        response = self.fetch(
            method="GET",
            url=self.get_url("positions"),
            endpoint_group="default",
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return info.get("data") or {}

    def fetch_day_positions(
        self,
    ) -> list[dict]:
        """Fetch the day's account positions in unified format.

        Returns:
            Unified Fenix position records for intraday rows.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        info = self.fetch_raw_positions()
        rows = info.get("day")
        return [self._parse_position(row, day_or_net="day_") for row in rows]

    def fetch_net_positions(
        self,
    ) -> list[dict]:
        """Fetch net account positions in unified format.

        Returns:
            Unified Fenix position records for net rows.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        info = self.fetch_raw_positions()
        rows = info.get("net") or []
        return [self._parse_position(row) for row in rows]

    def fetch_holdings(
        self,
    ) -> list[dict]:
        """Fetch account holdings in unified format.

        Returns:
            Unified Fenix position records for the holdings bucket.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_holdings()

        response = self.fetch(
            method="GET",
            url=self.get_url("holdings"),
            endpoint_group="default",
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        rows = info.get("data") or []
        return [self._parse_holding(row) for row in rows]

    def fetch_margin_limits(
        self,
    ) -> dict[Any, Any]:
        """Fetch the authenticated user's RMS margin limits.

        Returns:
            Raw Kite Connect ``data`` payload from the user/margins endpoint.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_margin_limits()

        response = self.fetch(
            method="GET",
            url=self.get_url("rms_limits"),
            endpoint_group="default",
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return info["data"]

    def fetch_profile(
        self,
    ) -> dict[Any, Any]:
        """Fetch the authenticated user's profile.

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
        info = self._parse_json_response(response)
        return self._parse_profile(info["data"])
