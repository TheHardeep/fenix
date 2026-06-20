from __future__ import annotations

import csv
import io
import pyotp
import uuid
import time
import hashlib
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
    InsufficientFundsError,
    InsufficientHoldingsError,
    InvalidOrderError,
    NotSupported,
    OrderNotFoundError,
    PermissionDeniedError,
    RateLimitExceededError,
    ResponseError,
)

if TYPE_CHECKING:
    from requests.models import Response


class Groww(Broker):
    """Groww broker adapter for the Fenix trading interface."""

    # Groww exposes a single combined instrument master (CSV) whose ``exchange``
    # column is just ``NSE`` / ``BSE`` / ``MCX``; the cash/derivative split lives
    # in the ``segment`` column. This map collapses the ``(exchange, segment)``
    # pair into the Fenix ``ExchangeCode`` used in unified responses.
    _EXCHANGE_MAP = {
        ("NSE", "CASH"): ExchangeCode.NSE,
        ("BSE", "CASH"): ExchangeCode.BSE,
        ("NSE", "FNO"): ExchangeCode.NFO,
        ("BSE", "FNO"): ExchangeCode.BFO,
        ("MCX", "COMMODITY"): ExchangeCode.MCX,
        ("MCX", "FNO"): ExchangeCode.MCX,
        ("NSE", "CURRENCY"): ExchangeCode.CDS,
        ("BSE", "CURRENCY"): ExchangeCode.BCD,
    }

    _API = {
        "doc": "https://groww.in/trade-api/docs/python-sdk",
        "servers": {
            "api": "https://api.groww.in/v1",
            "instruments": "https://growwapi-assets.groww.in",
        },
        "paths": {
            # --- Auth ---
            "token": {
                "server": "api",
                "path": "/token/api/access",
            },

            # --- Orders ---
            "place_order": {
                "server": "api",
                "path": "/order/create",
            },
            "modify_order": {
                "server": "api",
                "path": "/order/modify",
            },
            "cancel_order": {
                "server": "api",
                "path": "/order/cancel",
            },
            "order_list": {
                "server": "api",
                "path": "/order/list",
            },
            "order_detail": {
                "server": "api",
                "path": "/order/detail",
            },
            "order_status": {
                "server": "api",
                "path": "/order/status",
            },
            "trades": {
                "server": "api",
                "path": "/order/trades",
            },

            # --- Portfolio ---
            "positions": {
                "server": "api",
                "path": "/positions/user",
            },
            "position_symbol": {
                "server": "api",
                "path": "/positions/trading-symbol",
            },
            "holdings": {
                "server": "api",
                "path": "/holdings/user",
            },

            # --- Margin & Profile ---
            "margins": {
                "server": "api",
                "path": "/margins/detail/user",
            },
            "profile": {
                "server": "api",
                "path": "/user/detail",
            },

            # --- Instrument Master (public CDN, no auth) ---
            "instruments": {
                "server": "instruments",
                "path": "/instruments/instrument.csv",
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
            "SL_M": OrderType.SLM,
        },
        "product": {
            "CNC": Product.CNC,
            "MIS": Product.MIS,
            "NRML": Product.NRML,
            "MTF": Product.MTF,
            "CO": Product.CO,
            "BO": Product.BO,
        },
        "validity": {
            "DAY": Validity.DAY,
            "IOC": Validity.IOC,
            "GTC": Validity.GTC,
            "GTD": Validity.GTD,
        },
        "status": {
            "NEW": Status.PENDING,
            "ACKED": Status.OPEN,
            "APPROVED": Status.OPEN,
            "TRIGGER_PENDING": Status.PENDING,
            "CANCELLATION_REQUESTED": Status.PENDING,
            "MODIFICATION_REQUESTED": Status.PENDING,
            "EXECUTED": Status.FILLED,
            "DELIVERY_AWAITED": Status.FILLED,
            "COMPLETED": Status.FILLED,
            "CANCELLED": Status.CANCELLED,
            "REJECTED": Status.REJECTED,
            "FAILED": Status.REJECTED,
        },
    }

    REQUEST_MAPS = {
        "side": {
            Side.BUY: "BUY",
            Side.SELL: "SELL",
        },
        "order_type": {
            OrderType.MARKET: "MARKET",
            OrderType.LIMIT: "LIMIT",
            OrderType.SL: "SL",
            OrderType.SLM: "SL_M",
        },
        "product": {
            Product.CNC: "CNC",
            Product.MIS: "MIS",
            Product.NRML: "NRML",
            Product.MTF: "MTF",
            Product.CO: "CO",
            Product.BO: "BO",
        },
        "validity": {
            Validity.DAY: "DAY",
            Validity.IOC: "IOC",
            Validity.GTC: "GTC",
            Validity.GTD: "GTD",
        },
    }

    ERROR_CODE_KEYS = (
        "code",
    )

    ERROR_MESSAGE_KEYS = (
        "message",
        "displayMessage",
    )

    # Groww surfaces most business errors as free-text messages on a
    # ``{"status": "FAILURE", "error": {...}}`` envelope rather than a
    # documented code catalogue, so the bulk of the mapping is keyword based
    # (see ``_groww_error_class``). The few stable HTTP-status codes the SDK
    # raises are kept here for direct mapping.
    _DIRECT_ERROR_CLASSES = {
        "401": AuthenticationError,
        "403": PermissionDeniedError,
        "429": RateLimitExceededError,
    }

    _REQUIRED_AUTH_HEADER_KEYS = (
        "Authorization",
        "Content-Type",
        "Accept",
        "x-client-id",
        "x-api-version",
    )

    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "Groww",
            "tokenParams": [
                ("api_key", "api_secret"),
                ("totp_token", "totpstr")
            ],
            "proxies": {},
            "sensitiveLogKeysIncludeDefault": True,
            "sensitiveLogKeys": [
                "api_key",
                "api_secret",
                "totp_token"
                "totpstr",
                "tokenRefId",
                "Authorization",
                "ucc",
                "vendor_user_id",
                "isin",
            ],
            "enableRateLimit": True,
            "rateLimits": {
                "orders": [
                    {"period": 1, "capacity": 10, "cost": 1.0},
                    {"period": 60, "capacity": 250, "cost": 1.0},
                ],
                "live_data": [
                    {"period": 1, "capacity": 10, "cost": 1.0},
                    {"period": 60, "capacity": 300, "cost": 1.0},
                ],
                # Non-trading APIs (order book, positions, holdings, margins,
                # profile, auth, instrument master).
                "default": [
                    {"period": 1, "capacity": 20, "cost": 1.0},
                    {"period": 60, "capacity": 500, "cost": 1.0},
                ],
            },
        }

    def __init__(self, config: dict | None = None):
        """Initialize the Groww broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
                Pass ``{"paper_mode": True}`` to route order entry and reads
                through the in-process paper-trading engine instead of the
                Groww API.
        """
        super().__init__(config)
        # Cached instrument master rows so the (large) CSV is downloaded once
        # per instance and shared across all ``load_*_tokens`` calls.
        self._master_rows: list[dict[str, str]] | None = None

    # --------------------------------------------------------------------- #
    # Authentication
    # --------------------------------------------------------------------- #

    @staticmethod
    def _generate_checksum(data: str, salt: str) -> str:
        """Generate a SHA-256 checksum for the given data and salt.

        Args:
            data: The payload to checksum (typically the API key).
            salt: The secret salt appended before hashing (the API secret).

        Returns:
            The hexadecimal SHA-256 digest of ``data + salt``.
        """
        input_str = data + salt
        sha256 = hashlib.sha256()
        sha256.update(input_str.encode("utf-8"))
        return sha256.hexdigest()

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """Authenticate with Groww and return request headers.

        Groww authenticates through a Bearer access token. The token can be
        supplied directly via ``params["access_token"]`` (for the long-lived
        approval flow), or generated from an ``api_key`` and a TOTP secret
        (``totpstr``) using the token-exchange endpoint.

        Args:
            params: Login credentials. Either ``access_token`` or both
                ``api_key`` and ``totpstr`` must be present.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and run the login flow.

        Returns:
            Headers that can authenticate subsequent Groww API calls.

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

        if params is None or params == {}:
            raise KeyError("Please provide params or headers")

        for keys in self.tokenParams:
            if keys[0] not in params and keys[1] not in params:
                pass
            elif keys[0] not in params or keys[1] not in params:
                raise KeyError(f"Please provide both {keys}")

        headers = {
            "x-request-id": str(uuid.uuid4()),
            "Authorization": "Bearer " + params.get("api_key", params.get("totp_token", "")),
            "Content-Type": "application/json",
            "x-client-id": "growwapi",
            "x-client-platform": "growwapi-python-client",
            "x-client-platform-version": "1.5.0",
            "x-api-version": "1.0",
        }

        if params.get("api_key"):
            timestamp = int(time.time())
            checksum = self._generate_checksum(params["api_secret"], str(timestamp))
            json_data = {
                "key_type": "approval",
                "checksum": checksum,
                "timestamp": timestamp
            }

        else:
            totp = pyotp.TOTP(params["totpstr"]).now()
            json_data = {"key_type": "totp", "totp": totp}

        response = self.fetch(
            method="POST",
            url=self.get_url("token"),
            endpoint_group="default",
            json=json_data,
            headers=headers,
        )
        info = self._parse_json_response(response)

        token = info.get("token") if isinstance(info, dict) else None
        if not token:
            raise AuthenticationError(
                "Groww did not return an access token.",
                broker=self.id,
            )

        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-client-id": "growwapi",
            "x-client-platform": "growwapi-python-client",
            "x-client-platform-version": "1.5.0",
            "x-api-version": "1.0",
        }

        self.reset_session()

        return self._headers


    # --------------------------------------------------------------------- #
    # Helpers
    # --------------------------------------------------------------------- #

    @staticmethod
    def _to_int(value: Any) -> int:
        """Best-effort conversion of a CSV cell to an integer."""
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _parse_datetime(value: Any) -> Any:
        """Parse a Groww timestamp string into a ``datetime`` when possible."""
        if not value:
            return value
        text = str(value)
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                return datetime.strptime(text, fmt)
            except (ValueError, TypeError):
                continue
        return value

    def _resolve_exchange(self, exchange: Any, segment: Any) -> Any:
        """Resolve a Groww ``(exchange, segment)`` pair to a Fenix exchange."""
        return self._EXCHANGE_MAP.get((exchange, segment), exchange)

    def _fetch_instruments(self) -> list[dict[str, str]]:
        """Download and cache the Groww instrument master CSV.

        The CSV is fetched through the rate-limited base layer and parsed with
        :class:`csv.DictReader`. Rows are cached on the instance so the (large)
        file is downloaded only once and shared across all ``load_*`` calls.

        Returns:
            Parsed instrument-master rows keyed by CSV header name.

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
            data: Optional pre-parsed instrument-master rows (the full Groww
                instrument master as a list of dicts). Downloaded automatically
                when omitted.

        Returns:
            A tuple containing the unified equity token map and an all-token
            lookup keyed by ``"{exchange_token}_{exchange}"``.
        """
        rows = data if data is not None else self._fetch_instruments()

        nse_dict = {}
        bse_dict = {}
        alltoken_dict = {}

        for row in rows:
            if row.get("instrument_type") != "EQ":
                continue

            exchange = row.get("exchange")
            symbol = row.get("trading_symbol")
            token = row.get("exchange_token")
            if not symbol or not token:
                continue
            if "NSETEST" in symbol:
                continue

            record = {
                "Token": token,
                "Exchange": exchange,
                "Segment": row.get("segment"),
                "Symbol": symbol,
                "ScriptName": row.get("name"),
                "LotSize": self._to_int(row.get("lot_size")),
                "TickSize": row.get("tick_size"),
                "ISIN": row.get("isin")
            }

            if exchange == "NSE":
                nse_dict[symbol] = record
            elif exchange == "BSE":
                bse_dict[symbol] = record
            else:
                continue

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
            lookup keyed by ``"{exchange_token}_{exchange}"``.
        """
        rows = data if data is not None else self._fetch_instruments()

        nse_dict = {}
        bse_dict = {}
        token_dict = {}

        for row in rows:
            if row.get("instrument_type") != "IDX":
                continue

            exchange = row.get("exchange")
            symbol = row.get("trading_symbol")
            token = row.get("exchange_token")
            if not symbol or not token:
                continue

            record = {
                "Exchange": exchange,
                "Segment": row.get("segment"),
                "Token": token,
                "Symbol": symbol,
                "ScriptName": row.get("name") or symbol,
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
            all-token lookup keyed by ``"{exchange_token}_{exchange}"``.

        Raises:
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving the instrument master.
        """
        rows = data if data is not None else self._fetch_instruments()

        fut_nse = defaultdict(list)
        fut_bse = defaultdict(list)
        opt_nse = defaultdict(list)
        opt_bse = defaultdict(list)
        token_dict = {}
        dt_dict = {}

        for row in rows:
            if row.get("segment") != "FNO":
                continue

            exchange = row.get("exchange")
            if exchange not in ("NSE", "BSE"):
                continue

            instrument_type = row.get("instrument_type")
            if instrument_type not in ("FUT", "CE", "PE"):
                continue

            root = row.get("underlying_symbol")
            token = row.get("exchange_token")
            if not root or not token:
                continue
            if "NSETEST" in root:
                continue

            expiry = row.get("expiry_date")
            if expiry not in dt_dict:
                dt = datetime.strptime(expiry, "%Y-%m-%d")
                exdp = dt.strftime("%d-%b").upper()
                dt_dict[expiry] = (expiry, exdp)
            else:
                (expiry, exdp) = dt_dict[expiry]

            if instrument_type == "FUT":
                record = {
                    "Exchange": exchange,
                    "Segment": row["segment"],
                    "Token": token,
                    "Root": root,
                    "Symbol": row.get("trading_symbol"),
                    "TickSize": row.get("tick_size"),
                    "LotSize": self._to_int(row.get("lot_size")),
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                if exchange == "NSE":
                    fut_nse[root].append(record)
                else:
                    fut_bse[root].append(record)

            else:
                strike = self._format_strike(row["strike_price"])
                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Segment": row["segment"],
                    "Root": root,
                    "Symbol": row.get("trading_symbol"),
                    "TickSize": row.get("tick_size"),
                    "LotSize": self._to_int(row.get("lot_size")),
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": instrument_type,
                    "ScriptName": f"{root} {exdp} {strike} {instrument_type}",
                }

                if exchange == "NSE":
                    opt_nse[root].append(record)
                else:
                    opt_bse[root].append(record)

            token_dict[f"{token}_{exchange}"] = record

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
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load MCX futures and options token metadata.

        Args:
            data: Optional pre-parsed instrument-master rows. Downloaded
                automatically when omitted.

        Returns:
            A tuple containing unified MCX token maps and an all-token lookup
            keyed by ``"{exchange_token}_MCX"``.

        Raises:
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving the instrument master.
        """
        rows = data if data is not None else self._fetch_instruments()

        fut = defaultdict(list)
        opt = defaultdict(list)
        token_dict = {}
        dt_dict = {}

        for row in rows:
            exchange = row.get("exchange")
            if exchange != "MCX":
                continue

            instrument_type = row.get("instrument_type")
            if instrument_type not in ("FUT", "CE", "PE"):
                continue

            root = row.get("underlying_symbol")
            token = row.get("exchange_token")
            if not root or not token:
                continue

            expiry = row.get("expiry_date")
            if expiry not in dt_dict:
                dt = datetime.strptime(expiry, "%Y-%m-%d")
                exdp = dt.strftime("%d-%b").upper()
                dt_dict[expiry] = (expiry, exdp)
            else:
                (expiry, exdp) = dt_dict[expiry]

            if instrument_type == "FUT":
                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Segment": row["segment"],
                    "Root": root,
                    "Symbol": row.get("trading_symbol"),
                    "TickSize": row.get("tick_size"),
                    "LotSize": self._to_int(row.get("lot_size")),
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }
                fut[root].append(record)

            else:
                strike = self._format_strike(row["strike_price"])

                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Segment": row["segment"],
                    "Root": root,
                    "Symbol": row.get("trading_symbol"),
                    "TickSize": row.get("tick_size"),
                    "LotSize": self._to_int(row.get("lot_size")),
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": instrument_type,
                    "ScriptName": f"{root} {exdp} {strike} {instrument_type}",
                }

                opt[root].append(record)

            token_dict[f"{token}_MCX"] = record

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

    def _extract_groww_error_code(self, payload: Any) -> str | None:
        """Extract a Groww error code from a payload."""
        error_code = self._extract_error_code(payload)
        if error_code:
            return str(error_code).strip()
        return None

    def _extract_groww_error_message(self, payload: Any) -> str | None:
        """Extract the most useful Groww error message for a payload."""
        return self._extract_error_message(payload)

    def _groww_error_class(
        self,
        error_code: str | None,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve a Groww payload to the most specific Fenix error class."""
        if error_code in self._DIRECT_ERROR_CLASSES:
            return self._DIRECT_ERROR_CLASSES[error_code]

        message = (error_message or "").lower()
        if any(
            token in message
            for token in ("session", "token", "login", "authenticat")
        ):
            return AuthenticationError
        if (
            "permission" in message
            or "not authorised" in message
            or "not authorized" in message
            or "not allowed" in message
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
        if any(
            token in message
            for token in ("order", "price", "quantity", "symbol", "trigger")
        ):
            return InvalidOrderError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded Groww payload represents an error."""
        if isinstance(payload, dict):
            status = payload.get("status")
            if isinstance(status, str) and status.upper() == "FAILURE":
                return True
            if isinstance(payload.get("error"), dict):
                return True
            return False

        return False

    def _raise_groww_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for a Groww error payload."""
        context = self._http_error_context(response, payload)
        error_code = self._extract_groww_error_code(payload)
        error_message = self._extract_groww_error_message(payload)

        context["error_code"] = error_code
        context["error_message"] = error_message
        error_cls = self._groww_error_class(
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
            self._raise_groww_error(payload, response=exc.response, cause=exc)

        super().handle_http_error(exc)

    def _parse_json_response(self, response: Response) -> Any:
        """Decode an HTTP response and raise broker-specific payload errors.

        Groww wraps successful responses in a ``{"status": "SUCCESS",
        "payload": {...}}`` envelope; this method validates the envelope,
        unwraps the ``payload`` when present, and returns the raw body for the
        few endpoints (e.g. token exchange) that respond without a wrapper.
        """
        json_response = self._json_parser(response)

        if isinstance(json_response, dict):
            if self._payload_indicates_error(json_response):
                self._raise_groww_error(json_response, response=response)
            if "payload" in json_response:
                return json_response["payload"]

        return json_response

    # --------------------------------------------------------------------- #
    # Response parsers
    # --------------------------------------------------------------------- #

    def _parse_orderbook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a Groww order object to a unified order record.

        Args:
            order: Raw order object returned by Groww.

        Returns:
            Unified Fenix order record.
        """
        exchange = order.get("exchange")
        segment = order.get("segment")

        parsed_order = {
            Order.ID: order.get("groww_order_id"),
            Order.USER_ID: order.get("order_reference_id", ""),
            Order.TIMESTAMP: self._parse_datetime(
                order.get("exchange_time") or order.get("created_at")
            ),
            Order.SYMBOL: order.get("trading_symbol", ""),
            Order.TOKEN: 0,
            Order.SIDE: self._parse_from_broker(
                "side", order.get("transaction_type")
            ),
            Order.TYPE: self._parse_from_broker(
                "order_type", order.get("order_type")
            ),
            Order.AVG_PRICE: float(order.get("average_fill_price") or 0.0),
            Order.PRICE: float(order.get("price") or 0.0),
            Order.TRIGGER_PRICE: float(order.get("trigger_price") or 0.0),
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: int(order.get("quantity") or 0),
            Order.FILLED_QTY: int(order.get("filled_quantity") or 0),
            Order.REMAINING_QTY: int(order.get("remaining_quantity") or 0),
            Order.CANCELLED_QTY: 0,
            Order.STATUS: self._parse_from_broker(
                "status", order.get("order_status")
            ),
            Order.REJECT_REASON: order.get("remark", ""),
            Order.DISCLOSED_QUANTITY: 0,
            Order.PRODUCT: self._parse_from_broker(
                "product", order.get("product")
            ),
            Order.EXCHANGE: self._resolve_exchange(exchange, segment),
            Order.SEGMENT: self._resolve_exchange(exchange, segment),
            Order.VALIDITY: self._parse_from_broker(
                "validity", order.get("validity")
            ),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_tradebook(
        self,
        trade: dict,
    ) -> dict[Any, Any]:
        """Convert a Groww trade row to a unified order-like fill record.

        Args:
            trade: Raw trade row returned by Groww.

        Returns:
            Unified Fenix order-like fill record.
        """
        exchange = trade.get("exchange")
        segment = trade.get("segment")
        quantity = int(trade.get("quantity") or 0)

        parsed_trade = {
            Order.ID: trade.get("groww_order_id"),
            Order.USER_ID: "",
            Order.TIMESTAMP: self._parse_datetime(
                trade.get("trade_date_time") or trade.get("created_at")
            ),
            Order.SYMBOL: trade.get("trading_symbol", ""),
            Order.TOKEN: 0,
            Order.SIDE: self._parse_from_broker(
                "side", trade.get("transaction_type")
            ),
            Order.TYPE: "",
            Order.AVG_PRICE: float(trade.get("price") or 0.0),
            Order.PRICE: float(trade.get("price") or 0.0),
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
                "product", trade.get("product")
            ),
            Order.EXCHANGE: self._resolve_exchange(exchange, segment),
            Order.SEGMENT: self._resolve_exchange(exchange, segment),
            Order.VALIDITY: "",
            Order.VARIETY: "",
            Order.INFO: trade,
        }

        return parsed_trade

    def _parse_position(
        self,
        position: dict,
    ) -> dict[Any, Any]:
        """Convert a Groww position row to a unified position record.

        Args:
            position: Raw position row returned by Groww.

        Returns:
            Unified Fenix position record.
        """
        exchange = position.get("exchange")
        segment = position.get("segment")

        parsed_position = {
            Position.SYMBOL: position.get("trading_symbol", ""),
            Position.TOKEN: 0,
            Position.NET_QTY: int(position.get("quantity") or 0),
            Position.AVG_PRICE: float(position.get("net_price") or 0.0),
            Position.MTM: None,
            Position.PNL: float(position.get("realised_pnl") or 0.0),
            Position.REALISED_PNL: float(position.get("realised_pnl") or 0.0),
            Position.UNREALISED_PNL: None,
            Position.BUY_QTY: int(position.get("credit_quantity") or 0),
            Position.BUY_PRICE: float(position.get("credit_price") or 0.0),
            Position.SELL_QTY: int(position.get("debit_quantity") or 0),
            Position.SELL_PRICE: float(position.get("debit_price") or 0.0),
            Position.LTP: None,
            Position.PRODUCT: self._parse_from_broker(
                "product", position.get("product")
            ),
            Position.EXCHANGE: self._resolve_exchange(exchange, segment),
            Position.INFO: position,
        }

        return parsed_position

    def _parse_profile(
        self,
        profile: dict,
    ) -> dict[Any, Any]:
        """Convert a Groww profile payload to a unified profile record.

        Args:
            profile: Raw profile payload returned by Groww.

        Returns:
            Unified Fenix profile record.
        """
        parsed_profile = {
            Profile.CLIENT_ID: profile.get("ucc", ""),
            Profile.NAME: "",
            Profile.EMAIL_ID: "",
            Profile.MOBILE_NO: "",
            Profile.PAN: "",
            Profile.ADDRESS: "",
            Profile.BANK_NAME: "",
            Profile.BANK_BRANCH_NAME: None,
            Profile.BANK_ACC_NO: "",
            Profile.EXCHANGES_ENABLED: profile.get("active_segments") or [],
            Profile.ENABLED: bool(
                profile.get("nse_enabled") or profile.get("bse_enabled")
            ),
            Profile.INFO: profile,
        }

        return parsed_profile

    def _parse_rms(self, rms: dict) -> dict[Any, Any]:
        """Convert a Groww margin payload to a unified margin record."""
        parsed_rms = {
            RMS.MARGINUSED: float(rms.get("net_margin_used") or 0.0),
            RMS.MARGINAVAIL: float(rms.get("clear_cash") or 0.0),
            RMS.COLLATERAL: float(rms.get("collateral_available") or 0.0),
            RMS.INFO: rms,
        }

        return parsed_rms

    def _parse_place_order_response(self, response: Response) -> dict[Any, Any]:
        """Extract the order id from a Groww order response.

        Args:
            response: HTTP response returned after placing, modifying, or
                cancelling an order.

        Returns:
            Unified order-id record.
        """
        info = self._parse_json_response(response)
        return {Order.ID: info["groww_order_id"]}

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
    ) -> dict[str, Any]:
        """Build the Groww API payload for a place-order request.

        Args:
            token_dict: Token metadata for the instrument being ordered. Must
                carry ``Symbol`` and ``Exchange``; ``Segment`` is used when
                present and otherwise derived from the exchange.
            quantity: Number of units to order.
            side: Transaction side in Fenix format.
            product: Product code in Fenix format.
            validity: Order validity in Fenix format.
            variety: Order variety in Fenix format (unused; Groww infers AMO
                from the order window).
            unique_id: Client-provided order reference id.
            price: Limit price, or zero for market orders.
            trigger: Stop-loss trigger price, or zero when not applicable.

        Returns:
            Groww place-order payload.
        """
        order_type = self._resolve_order_type(price, trigger)

        payload = {
            "exchange": token_dict["Exchange"],
            "segment": token_dict["Segment"],
            "trading_symbol": token_dict["Symbol"],
            "quantity": int(quantity),
            "price": float(price),
            "trigger_price": float(trigger) if trigger else None,
            "validity": self._format_for_broker("validity", validity),
            "product": self._format_for_broker("product", product),
            "order_type": self._format_for_broker("order_type", order_type),
            "transaction_type": self._format_for_broker("side", side),
            "order_reference_id": unique_id,
        }

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
        """Place an order through Groww.

        Args:
            token_dict: Token metadata for the instrument being ordered.
            quantity: Number of units to order.
            side: Transaction side in Fenix format.
            product: Product code in Fenix format.
            validity: Order validity in Fenix format.
            variety: Order variety in Fenix format.
            unique_id: Client-provided order reference id.
            price: Limit price, or zero for market orders.
            trigger: Stop-loss trigger price, or zero when not applicable.
            target: Bracket-order target price. Not supported by Groww's
                regular order endpoint.
            stoploss: Bracket-order stop-loss price. Not supported here.
            trailing_sl: Bracket-order trailing stop-loss. Not supported here.

        Returns:
            Unified order-id record for the placed order.

        Raises:
            NotSupported: If bracket-order parameters are supplied; Groww models
                these through its smart-order (GTT/OCO) API instead.
        """
        self._validate_order_inputs(
            quantity=quantity,
            price=price,
            trigger=trigger,
            target=target,
            stoploss=stoploss,
            trailing_sl=trailing_sl,
        )

        if target or stoploss or trailing_sl:
            raise NotSupported(
                f"{self.id} does not support bracket orders via place_order; "
                "use the Groww smart-order (GTT/OCO) API instead."
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
        )

        response = self.fetch(
            method="POST",
            url=self.get_url("place_order"),
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
        """Fetch raw Groww order-book rows.

        Returns:
            Raw broker order rows. Empty result-set responses are returned as
            an empty list. In paper mode, returns the unified paper orders.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        response = self.fetch(
            method="GET",
            url=self.get_url("order_list"),
            endpoint_group="default",
            headers=self._headers,
        )


        info = self._parse_json_response(response)
        return info.get("order_list")

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

    def _fetch_raw_trades(
        self,
        order_id: str,
        segment: str,
    ) -> list[dict]:
        """Fetch the raw trade rows for one order.

        Args:
            order_id: Groww order id to query.
            segment: Groww segment of the order (e.g. ``"CASH"``, ``"FNO"``).

        Returns:
            Raw trade rows. Empty result-set responses are returned as an empty
            list.
        """
        response = self.fetch(
            method="GET",
            url=f"{self.get_url('trades')}/{order_id}",
            endpoint_group="default",
            params={"segment": segment},
            headers=self._headers,
        )

        info = self._parse_json_response(response)
        return info.get("trade_list")

    def fetch_trades(
        self,
        order_id: str,
        segment: str,
    ) -> list[dict]:
        """Fetch the executed trades for one order in the unified format.

        Args:
            order_id: Groww order id to query.
            segment: Groww segment of the order (e.g. ``"CASH"``, ``"FNO"``).

        Returns:
            Unified order-like fill records.
        """
        info = self._fetch_raw_trades(order_id=order_id, segment=segment)
        return [self._parse_tradebook(trade) for trade in info]

    def fetch_tradebook(
        self,
    ) -> list[dict]:
        """Fetch the trade book in the unified Fenix format.

        Groww only exposes trades per order, so this walks the order book and
        aggregates the trades of every order that has been (partially) filled.

        Returns:
            Unified order-like fill records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_tradebook()

        raw_orders = self.fetch_raw_orderbook()

        trades = []
        for order in raw_orders:
            if int(order.get("filled_quantity") or 0) <= 0:
                continue

            order_id = order.get("groww_order_id")
            segment = order.get("segment")
            if not order_id or not segment:
                continue

            for trade in self._fetch_raw_trades(order_id, segment):
                trades.append(self._parse_tradebook(trade))

        return trades

    def fetch_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Fetch one order from the current order book.

        Groww's per-order endpoints require the order's segment, so this
        resolves the order from the (segment-agnostic) order book instead.

        Args:
            order_id: Broker order id to find.

        Raises:
            OrderNotFoundError: If the order id is absent from the order book.

        Returns:
            Unified Fenix order record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        info = self.fetch_raw_orderbook()
        order_id = str(order_id)
        for order in info:
            if str(order.get("groww_order_id")) == order_id:
                return self._parse_orderbook(order)

        raise OrderNotFoundError("This order_id does not exist.")

    def fetch_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """Fetch order history in the unified Fenix format.

        Groww does not expose a per-order status timeline; the order object
        itself carries its latest state. This returns the current order detail
        wrapped in a single-element list to keep parity with brokers that do
        expose a history endpoint.

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
        """Modify a pending Groww order.

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
            validity: Replacement validity. Unused by Groww's modify endpoint.
            raw_order_json: Optional raw order row to avoid refetching the
                order book.
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
            else order_info["order_type"]
        )

        json_data = {
            "groww_order_id": str(order_id),
            "segment": order_info["segment"],
            "order_type": new_order_type,
            "quantity": int(quantity or order_info.get("quantity") or 0),
            "price": float(
                price if price is not None else order_info.get("price") or 0.0
            ),
            "trigger_price": (
                float(trigger)
                if trigger is not None
                else (
                    float(order_info["trigger_price"])
                    if order_info.get("trigger_price")
                    else None
                )
            ),
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("modify_order"),
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
        """Cancel a pending Groww order.

        Args:
            order_id: Broker order id to cancel.
            extra_params: Optional broker-specific values. When it contains a
                ``"segment"`` key (or an ``"order"`` record carrying one), that
                segment is reused instead of refetching the order book.

        Returns:
            Unified order-id record for the cancelled order.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.cancel_order(
                order_id=order_id,
                extra_params=extra_params,
            )

        extra_params = extra_params or {}

        if extra_params.get("segment"):
            segment = extra_params["segment"]
        elif extra_params.get("order"):
            segment = extra_params["order"]["info"]["segment"]
        else:
            segment = self.fetch_order(order_id=order_id)["info"]["segment"]

        json_data = {
            "groww_order_id": str(order_id),
            "segment": segment,
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("cancel_order"),
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def square_off_position(
        self,
        symbol: str,
        token: int,
        exchange: str,
        quantity: int,
        product: str = Product.MIS,
    ) -> dict[Any, Any]:
        """Square off an open position with an opposite market order.

        Groww has no dedicated square-off endpoint; a position is flattened by
        placing a market order in the opposite direction. The sign of
        ``quantity`` determines the side: a positive (long) quantity is closed
        with a SELL, a negative (short) quantity with a BUY.

        Args:
            symbol: Trading symbol to square off.
            token: Exchange token for the instrument (unused by Groww order
                entry, retained for interface parity).
            exchange: Exchange in either Fenix or Groww-native form.
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

        groww_exchange, segment = self._groww_exchange_segment(exchange)
        side = Side.SELL if quantity > 0 else Side.BUY
        token_dict = {
            "Token": token,
            "Exchange": groww_exchange,
            "Segment": segment,
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
    # Positions, Account Limits & Profile
    # --------------------------------------------------------------------- #

    def fetch_day_positions(
        self,
    ) -> list[dict[str, Any]]:
        """Fetch intraday account positions.

        Groww returns a single net positions snapshot, so this mirrors
        :meth:`fetch_net_positions`.

        Returns:
            Unified Fenix position records.
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

        info = self._parse_json_response(response)
        info = info.get("positions")

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
            Raw Groww holding rows. Empty result-set responses are returned as
            an empty list. In paper mode, returns the unified paper holdings.
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
        return info.get("holdings")

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
            url=self.get_url("margins"),
            endpoint_group="default",
            headers=self._headers,
        )
        response = self._parse_json_response(response)

        return self._parse_rms(response)

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
