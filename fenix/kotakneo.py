from __future__ import annotations

import csv
import io
from collections import defaultdict
from datetime import datetime, timedelta
from json import dumps as json_dumps
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
from fenix.base.constants import Validity
from fenix.base.constants import Variety

from fenix.base.errors import (
    AuthenticationError,
    BrokerError,
    InputError,
    InsufficientFundsError,
    InvalidOrderError,
    OrderNotFoundError,
    PermissionDeniedError,
    ResponseError,
    TokenDownloadError,
)

if TYPE_CHECKING:
    from requests.models import Response


class KotakNeo(Broker):
    """KotakNeo broker adapter for the Fenix trading interface.

    Uses the KotakNeo TOTP trade-API login flow (``tradeApiLogin`` ->
    ``tradeApiValidate``). The validate response returns a per-session
    ``baseUrl`` against which every trade and report endpoint is resolved,
    plus a ``Sid``/``Auth`` header pair and an ``hsServerId`` that is sent as
    the ``sId`` query parameter on every authenticated request.
    """

    _API = {
        "doc": "https://documenter.getpostman.com/view/21534797/UzBnqmpD",
        "servers": {
            "login": "https://mis.kotaksecurities.com",
            "scrip_master": (
                "https://lapi.kotaksecurities.com/wso2-scripmaster/v1/prod"
            ),
        },
        "paths": {
            # --- Auth Flow ---
            "totp_login": {
                "server": "login",
                "path": "/login/1.0/tradeApiLogin",
            },
            "totp_validate": {
                "server": "login",
                "path": "/login/1.0/tradeApiValidate",
            },

            # --- Trade & Report Flow ---
            # These hang off the dynamic per-session ``baseUrl`` returned by
            # ``tradeApiValidate`` and are resolved through ``_trade_url``.
            "place_order": "/quick/order/rule/ms/place",
            "modify_order": "/quick/order/vr/modify",
            "cancel_order": "/quick/order/cancel",
            "orderbook": "/quick/user/orders",
            "tradebook": "/quick/user/trades",
            "order_history": "/quick/order/history",
            "positions": "/quick/user/positions",
            "holdings": "/portfolio/v1/holdings",
            "limits": "/quick/user/limits",
            "margin": "/quick/user/check-margin",
        },
    }

    STANDARD_MAPS = {
        "segment": {
            "nse_cm": ExchangeCode.NSE,
            "nse_fo": ExchangeCode.NFO,
            "bse_cm": ExchangeCode.BSE,
            "bse_fo": ExchangeCode.BFO,
            "bcs_fo": ExchangeCode.BCD,
            "mcx_fo": ExchangeCode.MCX,
            "cde_fo": ExchangeCode.CDS,
        },
        "order_type": {
            "MKT": OrderType.MARKET,
            "L": OrderType.LIMIT,
            "SL": OrderType.SL,
            "SL-M": OrderType.SLM,
        },
        "product": {
            "MIS": Product.MIS,
            "NRML": Product.NRML,
            "CNC": Product.CNC,
            "CO": Product.CO,
            "Bracket Order": Product.BO,
        },
        "side": {
            "B": Side.BUY,
            "S": Side.SELL,
        },
        "validity": {
            "DAY": Validity.DAY,
            "IOC": Validity.IOC,
            "GTC": Validity.GTC,
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
        "exchange": {
            ExchangeCode.NSE: "nse_cm",
            ExchangeCode.NFO: "nse_fo",
            ExchangeCode.BSE: "bse_cm",
            ExchangeCode.BFO: "bse_fo",
            ExchangeCode.BCD: "bcs_fo",
            ExchangeCode.MCX: "mcx_fo",
            ExchangeCode.CDS: "cde_fo",
        },
        "order_type": {
            OrderType.MARKET: "MKT",
            OrderType.LIMIT: "L",
            OrderType.SL: "SL",
            OrderType.SLM: "SL-M",
        },
        "product": {
            Product.MIS: "MIS",
            Product.NRML: "NRML",
            Product.CNC: "CNC",
            Product.CO: "CO",
            Product.BO: "Bracket Order",
        },
        "side": {
            Side.BUY: "B",
            Side.SELL: "S",
        },
        "validity": {
            Validity.DAY: "DAY",
            Validity.IOC: "IOC",
            Validity.GTC: "GTC",
        },
    }

    _REQUIRED_AUTH_HEADER_KEYS = (
        "Sid",
        "Auth",
        "neo-fin-key",
    )

    _AUTH_CONTEXT_KEYS = (
        "baseUrl",
        "serverId",
    )

    ERROR_CODE_KEYS = (
        "stCode",
    )

    ERROR_MESSAGE_KEYS = (
        "errMsg",
        "emsg",
        "Emsg",
        "Message",
        "message",
        "Error",
    )

    _ERROR_MESSAGES = {}

    _DIRECT_ERROR_CLASSES = {}

    _NO_DATA_PHRASES = (
        "no data",
        "no orders",
        "no positions",
        "no holdings",
        "no trades",
        "not found",
    )

    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "KotakNeo",
            "tokenParams": [
                "consumer_key",
                "mobile_no",
                "ucc",
                "totpstr",
                "mpin",
            ],
            "proxies": {},
            "sensitiveLogKeys": [
                "consumer_key",
                "mobileNumber",
                "mobile_no",
                "ucc",
                "totp",
                "totpstr",
                "mpin",
                "token",
                "sid",
                "Sid",
                "Auth",
                "Authorization",
                "neo-fin-key",
                "baseUrl",
                "serverId",
                "hsServerId",
                "greetingName",
                "kId",
            ],
            "enableRateLimit": True,
            "rateLimits": {
                "default": {
                    "period": 1,
                    "capacity": 10,
                    "cost": 1.0,
                },
            },
        }

    def __init__(self, config: dict | None = None):
        """Initialize the KotakNeo broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
                Pass ``{"paper_mode": True}`` to route order entry and reads
                through the in-process paper-trading engine instead of the
                KotakNeo API.
        """
        super().__init__(config)
        # Holds the ``tradeApiValidate`` ``data`` payload, which is the only
        # source of profile fields KotakNeo exposes (no profile endpoint).
        self._login_info: dict[str, Any] = {}

    # --- Helpers ---

    def _trade_url(self, endpoint_name: str) -> str:
        """Resolve a trade/report endpoint against the per-session base URL.

        Args:
            endpoint_name: Key in ``_API['paths']`` whose value is a relative
                path (e.g. ``"place_order"``).

        Returns:
            The fully-qualified URL built from the ``baseUrl`` returned by
            ``tradeApiValidate`` and stored on ``self._auth_context``.

        Raises:
            AuthenticationError: If called before a successful login.
        """
        base_url = self._auth_context.get("baseUrl")
        if not base_url:
            raise AuthenticationError(
                f"{self.id} is not authenticated. Call authenticate() first.",
                broker=self.id,
            )
        return f"{base_url}{self._API['paths'][endpoint_name]}"

    def _server_params(self) -> dict[str, str]:
        """Return the ``sId`` query parameter for authenticated requests."""
        return {"sId": self._auth_context.get("serverId", "")}

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """Authenticate with KotakNeo and return request headers.

        Runs the TOTP trade-API login flow: ``tradeApiLogin`` (view token)
        followed by ``tradeApiValidate`` (session token + per-session base
        URL and server id).

        Args:
            params: Login credentials required by KotakNeo.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and run the login flow.

        Returns:
            Headers that can authenticate subsequent KotakNeo API calls,
            merged with the stored auth context.

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

        totp = self.totp_creator(params["totpstr"])

        login_headers = {
            "Authorization": params["consumer_key"],
            "neo-fin-key": "neotradeapi",
            "Content-Type": "application/json",
            "accept": "application/json",
        }
        json_data = {
            "mobileNumber": params["mobile_no"],
            "ucc": params["ucc"],
            "totp": totp,
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("totp_login"),
            endpoint_group="default",
            json=json_data,
            headers=login_headers,
        )
        response = self._parse_json_response(response)

        view_token = response["data"]["token"]
        view_sid = response["data"]["sid"]

        validate_headers = {
            "Authorization": params["consumer_key"],
            "sid": view_sid,
            "Auth": view_token,
            "neo-fin-key": "neotradeapi",
            "Content-Type": "application/json",
            "accept": "application/json",
        }
        json_data = {"mpin": params["mpin"]}

        response = self.fetch(
            method="POST",
            url=self.get_url("totp_validate"),
            endpoint_group="default",
            json=json_data,
            headers=validate_headers,
        )
        response = self._parse_json_response(response)

        session_data = response["data"]
        session_token = session_data["token"]
        session_sid = session_data["sid"]
        server_id = session_data["hsServerId"]
        base_url = session_data["baseUrl"]
        self._login_info = session_data

        self._headers = {
            "Sid": session_sid,
            "Auth": session_token,
            "neo-fin-key": "neotradeapi",
            "Content-Type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        }
        self._auth_context = {
            "baseUrl": base_url,
            "serverId": server_id,
        }

        self.reset_session()

        return {**self._headers, **self._auth_context}

    # Script Fetch

    def _scrip_master_url(self, segment: str) -> str:
        """Build the lapi scrip-master CSV URL for a broker segment code."""
        date = str(datetime.now().date())
        base = self._API["servers"]["scrip_master"]
        return f"{base}/{date}/transformed/{segment}.csv"

    def _read_scrip_master(self, segment: str) -> list[dict[str, str]]:
        """Download and parse a KotakNeo scrip-master CSV into row dicts.

        Uses the standard-library ``csv`` module (no pandas). The CSV header
        names retain their vendor quirks (trailing spaces such as
        ``"dTickSize "``/``"lExpiryDate "`` and the ``"dStrikePrice;"``
        column), and every value is a string.

        Args:
            segment: Broker segment code, e.g. ``"nse_cm"`` or ``"nse_fo"``.

        Returns:
            One dict per instrument row keyed by the CSV column names.
        """
        response = self.fetch(
            method="GET",
            url=self._scrip_master_url(segment),
            endpoint_group="default",
        )
        reader = csv.DictReader(io.StringIO(response.text))
        return list(reader)

    @staticmethod
    def _epoch_to_date(epoch: Any, nfo: bool = False) -> Any:
        """Convert a KotakNeo expiry epoch (seconds) to a ``date``.

        KotakNeo encodes NFO expiry epochs offset by ~10 years, so the
        ``nfo`` branch adds a decade and rolls back a day to recover the true
        expiry. BFO expiries are already plain epoch seconds. Mirrors the
        original pandas ``DateOffset(years=10) - DateOffset(days=1)`` logic
        using ``datetime`` only (UTC, matching ``pd.to_datetime(unit="s")``).

        Args:
            epoch: Expiry timestamp in seconds (string or number).
            nfo: Whether to apply the NFO decade/day correction.

        Returns:
            The expiry as a ``datetime.date``.
        """
        dt = datetime.utcfromtimestamp(int(float(epoch)))
        if nfo:
            try:
                dt = dt.replace(year=dt.year + 10)
            except ValueError:
                # Feb 29 in a non-leap target year.
                dt = dt.replace(month=2, day=28, year=dt.year + 10)
            dt = dt - timedelta(days=1)
        return dt.date()

    def load_equity_tokens(
        self,
        data: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE equity token metadata.

        Args:
            data: Optional pre-fetched scrip-master rows keyed by ``"NSE"``
                and ``"BSE"`` (each a list of CSV row dicts as produced by
                ``_read_scrip_master``). When omitted, both are downloaded.

        Returns:
            A tuple containing the unified equity token map and an all-token
            lookup keyed by ``"{token}_{segment}"``.
        """
        if not data:
            nse_rows = self._read_scrip_master("nse_cm")
            bse_rows = self._read_scrip_master("bse_cm")
        else:
            nse_rows = data["NSE"]
            bse_rows = data["BSE"]

        nse_dict = {}
        bse_dict = {}
        alltoken_dict = {}

        for tok_data in nse_rows:
            if tok_data["pGroup"] != "EQ":
                continue

            script_name = tok_data["pSymbolName"]
            token = int(tok_data["pSymbol"])
            exchange = tok_data["pExchSeg"]

            if "NSETEST" in str(script_name):
                continue

            record = {
                "Token": token,
                "Exchange": exchange,
                "Symbol": tok_data["pTrdSymbol"],
                "ScriptName": script_name,
                "LotSize": int(tok_data["lLotSize"]),
                "TickSize": float(tok_data["dTickSize "]) / 100,
            }
            nse_dict[script_name] = record
            alltoken_dict[f"{token}_{exchange}"] = record

        for tok_data in bse_rows:
            if float(tok_data["dTickSize "]) == -1:
                continue

            script_name = tok_data["pSymbolName"]
            token = int(tok_data["pSymbol"])
            exchange = tok_data["pExchSeg"]

            record = {
                "Token": token,
                "Exchange": exchange,
                "Symbol": tok_data["pTrdSymbol"],
                "ScriptName": script_name,
                "LotSize": int(tok_data["lLotSize"]),
                "TickSize": float(tok_data["dTickSize "]) / 100,
            }
            bse_dict[script_name] = record
            alltoken_dict[f"{token}_{exchange}"] = record

        self.token_json["Equity"].update({"NSE": nse_dict, "BSE": bse_dict})
        self.alltoken_json.update(alltoken_dict)

        return (
            {"Equity": {"NSE": nse_dict, "BSE": bse_dict}},
            alltoken_dict,
        )

    def load_index_tokens(
        self,
        data: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load index token metadata for NSE and BSE.

        Args:
            data: Optional pre-fetched scrip-master rows keyed by ``"NSE"``
                and ``"BSE"`` (each a list of CSV row dicts). When omitted,
                both are downloaded.

        Returns:
            A tuple containing the unified index token map and an all-token
            lookup keyed by ``"{token}_{segment}"``.
        """
        if not data:
            nse_rows = self._read_scrip_master("nse_cm")
            bse_rows = self._read_scrip_master("bse_cm")
        else:
            nse_rows = data["NSE"]
            bse_rows = data["BSE"]

        nse_dict = {}
        bse_dict = {}
        token_dict = {}

        for rows, target in ((nse_rows, nse_dict), (bse_rows, bse_dict)):
            for tok_data in rows:
                # Index rows have a blank ``pGroup`` in the scrip master.
                if (tok_data.get("pGroup") or "").strip():
                    continue

                symbol = tok_data["pSymbolName"]
                token = int(tok_data["pSymbol"])
                exchange = tok_data["pExchSeg"]

                record = {
                    "Exchange": exchange,
                    "Token": token,
                    "Symbol": tok_data["pTrdSymbol"],
                    "ScriptName": symbol,
                }
                target[symbol] = record
                token_dict[f"{token}_{exchange}"] = record

        self.token_json["Indices"].update({"NSE": nse_dict, "BSE": bse_dict})
        self.alltoken_json.update(token_dict)

        return (
            {"Indices": {"NSE": nse_dict, "BSE": bse_dict}},
            token_dict,
        )

    def load_fno_tokens(
        self,
        data: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load futures and options token metadata for NFO and BFO.

        Args:
            data: Optional pre-fetched scrip-master rows keyed by ``"NFO"``
                and ``"BFO"`` (each a list of CSV row dicts). When omitted,
                both are downloaded.

        Returns:
            A tuple containing unified futures/options token maps and an
            all-token lookup keyed by ``"{token}_{segment}"``.

        Raises:
            TokenDownloadError: If reading or transforming the scrip master
                fails.
        """
        try:
            if not data:
                nfo_rows = self._read_scrip_master("nse_fo")
                bfo_rows = self._read_scrip_master("bse_fo")
            else:
                nfo_rows = data["NFO"]
                bfo_rows = data["BFO"]

            opt_series = ("OPTIDX", "OPTSTK", "IO", "SO")
            fut_series = ("FUTIDX", "FUTSTK", "IF", "SF")
            all_series = opt_series + fut_series

            bfo_rename = {"BKXOPT": "BANKEX", "BSXOPT": "SENSEX"}

            fut_nse = defaultdict(list)
            fut_bse = defaultdict(list)
            opt_nse = defaultdict(list)
            opt_bse = defaultdict(list)
            token_dict = {}

            for rows, is_nfo in ((nfo_rows, True), (bfo_rows, False)):
                for tok_data in rows:
                    instrument_type = tok_data["pInstType"]
                    if instrument_type not in all_series:
                        continue

                    # Drop calendar-spread contracts (e.g.
                    # NESTLEIND27APR2325MAY23FUT) whose ``pSymbol`` holds two
                    # leg tokens joined by a space; only single-leg
                    # instruments have a purely numeric token.
                    raw_token = tok_data["pSymbol"].strip()
                    if not raw_token.isdigit():
                        continue

                    root = tok_data["pSymbolName"]
                    if not is_nfo:
                        root = bfo_rename.get(root, root)
                    exchange = tok_data["pExchSeg"]
                    token = int(raw_token)

                    if "NSETEST" in str(root):
                        continue

                    expiry_date = self._epoch_to_date(
                        tok_data["lExpiryDate "], nfo=is_nfo
                    )
                    expiry = expiry_date.strftime("%Y-%m-%d")
                    exdp = expiry_date.strftime("%d-%b").upper()
                    tick_size = float(tok_data["dTickSize "]) / 100
                    lot_size = int(tok_data["lLotSize"])

                    if instrument_type in fut_series:
                        record = {
                            "Exchange": exchange,
                            "Token": token,
                            "Root": root,
                            "Symbol": tok_data["pTrdSymbol"],
                            "TickSize": tick_size,
                            "LotSize": lot_size,
                            "Expiry": expiry,
                            "ScriptName": f"{root} {exdp} FUT",
                        }

                        if is_nfo:
                            fut_nse[root].append(record)
                        else:
                            fut_bse[root].append(record)

                    else:
                        strike = self._format_strike(float(tok_data["dStrikePrice;"]) / 100)
                        option = tok_data["pOptionType"]
                        record = {
                            "Exchange": exchange,
                            "Token": token,
                            "Root": root,
                            "Symbol": tok_data["pTrdSymbol"],
                            "TickSize": tick_size,
                            "LotSize": lot_size,
                            "Expiry": expiry,
                            "StrikePrice": strike,
                            "Option": option,
                            "ScriptName": f"{root} {exdp} {strike} {option}",
                        }

                        if is_nfo:
                            opt_nse[root].append(record)
                        else:
                            opt_bse[root].append(record)

                    token_dict[f"{token}_{exchange}"] = record

            self.token_json["Futures"].update(
                {"NFO": fut_nse, "BFO": fut_bse}
            )
            self.token_json["Options"].update(
                {"NFO": opt_nse, "BFO": opt_bse}
            )
            self.alltoken_json.update(token_dict)

            return (
                {
                    "Futures": {"NFO": fut_nse, "BFO": fut_bse},
                    "Options": {"NFO": opt_nse, "BFO": opt_bse},
                },
                token_dict,
            )

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc

    # Json Parsers & Error Handling

    def _extract_kotakneo_error_message(self, payload: Any) -> str | None:
        """Extract the most useful KotakNeo error message for a payload."""
        return self._extract_error_message(payload)

    def _kotakneo_error_class(
        self,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve a KotakNeo payload to the most specific Fenix error class."""
        message = (error_message or "").lower()

        if any(token in message for token in ("session", "login", "token")):
            return AuthenticationError
        if "read-only" in message or "permission" in message:
            return PermissionDeniedError
        if "insufficient fund" in message or "margin" in message:
            return InsufficientFundsError
        if (
            "cancel, modify and orderhistory will only" in message
            or "order not found" in message
            or "does not exist" in message
        ):
            return OrderNotFoundError
        if any(phrase in message for phrase in self._NO_DATA_PHRASES):
            return ResponseError
        if any(token in message for token in ("order", "price", "quantity")):
            return InvalidOrderError
        if message:
            return InputError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded KotakNeo payload represents an error."""
        if isinstance(payload, list):
            if not payload:
                return False
            return self._payload_indicates_error(payload[0])

        if isinstance(payload, dict):
            stat = payload.get("stat")
            if stat is not None:
                return str(stat).lower() != "ok"
            return False

        return False

    def _is_empty_response_error(self, exc: ResponseError) -> bool:
        """Return whether a response error represents an empty result set."""
        message = str(exc).lower()
        return any(phrase in message for phrase in self._NO_DATA_PHRASES)

    def _raise_kotakneo_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for a KotakNeo error payload."""
        context = self._http_error_context(response, payload)
        error_message = self._extract_kotakneo_error_message(payload)

        context["error_message"] = error_message
        error_cls = self._kotakneo_error_class(
            error_message,
            context.get("status_code"),
        )

        error = error_cls(
            self._format_http_error_message(context),
            broker=self.id,
            error_code=context.get("error_code"),
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
            self._raise_kotakneo_error(
                payload, response=exc.response, cause=exc
            )

        super().handle_http_error(exc)

    def _parse_json_response(self, response: Response) -> Any:
        """Decode an HTTP response and raise broker-specific payload errors."""
        json_response = self._json_parser(response)
        data_to_check = (
            json_response[0]
            if isinstance(json_response, list) and json_response
            else json_response
        )

        if self._payload_indicates_error(data_to_check):
            self._raise_kotakneo_error(json_response, response=response)

        return json_response

    def _parse_orderbook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a KotakNeo order-book row to a unified order record.

        Args:
            order: Raw order-book row returned by KotakNeo.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["nOrdNo"],
            Order.USER_ID: order.get("GuiOrdId", ""),
            Order.TIMESTAMP: datetime.strptime(
                order["hsUpTm"], "%Y/%m/%d %H:%M:%S"
            ),
            Order.SYMBOL: order["trdSym"],
            Order.TOKEN: int(order["tok"]),
            Order.SIDE: self._parse_from_broker("side", order["trnsTp"]),
            Order.TYPE: self._parse_from_broker("order_type", order["prcTp"]),
            Order.AVG_PRICE: float(order["avgPrc"]),
            Order.PRICE: float(order["prc"]),
            Order.TRIGGER_PRICE: float(order["trgPrc"]),
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: order["qty"],
            Order.FILLED_QTY: order["fldQty"],
            Order.REMAINING_QTY: order["qty"] - order["fldQty"],
            Order.CANCELLED_QTY: order.get("cnlQty", 0),
            Order.STATUS: self._parse_from_broker("status", order["ordSt"]),
            Order.REJECT_REASON: order.get("rejRsn", ""),
            Order.DISCLOSED_QUANTITY: order.get("dscQty", 0),
            Order.PRODUCT: self._parse_from_broker("product", order["prod"]),
            Order.EXCHANGE: self._parse_from_broker("segment", order["exSeg"]),
            Order.SEGMENT: self._parse_from_broker("segment", order["exSeg"]),
            Order.VALIDITY: self._parse_from_broker(
                "validity", order.get("vldt", "")
            ),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_order_history(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a KotakNeo order-history row to a unified order record.

        Args:
            order: Raw order-history row returned by KotakNeo.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["nOrdNo"],
            Order.USER_ID: order.get("GuiOrdId", ""),
            Order.TIMESTAMP: datetime.strptime(
                order["flDtTm"], "%d-%b-%Y %H:%M:%S"
            ),
            Order.SYMBOL: order["trdSym"],
            Order.TOKEN: int(order["tok"]),
            Order.SIDE: self._parse_from_broker("side", order["trnsTp"]),
            Order.TYPE: self._parse_from_broker("order_type", order["prcTp"]),
            Order.AVG_PRICE: float(order["avgPrc"]),
            Order.PRICE: float(order["prc"]),
            Order.TRIGGER_PRICE: float(order["trgPrc"]),
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: order["qty"],
            Order.FILLED_QTY: order["fldQty"],
            Order.REMAINING_QTY: order["qty"] - order["fldQty"],
            Order.CANCELLED_QTY: 0,
            Order.STATUS: self._parse_from_broker("status", order["ordSt"]),
            Order.REJECT_REASON: order.get("rejRsn", ""),
            Order.DISCLOSED_QUANTITY: int(order.get("dclQty", 0)),
            Order.PRODUCT: self._parse_from_broker("product", order["prod"]),
            Order.EXCHANGE: self._parse_from_broker("segment", order["exSeg"]),
            Order.SEGMENT: self._parse_from_broker("segment", order["exSeg"]),
            Order.VALIDITY: self._parse_from_broker(
                "validity", order.get("ordDur", "")
            ),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_tradebook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a KotakNeo trade-book row to a unified fill record.

        KotakNeo trade rows describe executed fills, so order-level fields
        such as trigger price, validity, and disclosed quantity are not
        present.

        Args:
            order: Raw trade-book row returned by KotakNeo.

        Returns:
            Unified Fenix order-like fill record.
        """
        fill_quantity = int(order.get("fldQty") or 0)
        timestamp = f"{order.get('flDt', '')} {order.get('flTm', '')}".strip()

        parsed_order = {
            Order.ID: order["nOrdNo"],
            Order.USER_ID: "",
            Order.TIMESTAMP: timestamp,
            Order.SYMBOL: order["trdSym"],
            Order.TOKEN: int(order.get("tok") or 0),
            Order.SIDE: self._parse_from_broker("side", order["trnsTp"]),
            Order.TYPE: self._parse_from_broker("order_type", order["prcTp"]),
            Order.AVG_PRICE: float(order.get("avgPrc") or 0.0),
            Order.PRICE: float(order.get("avgPrc") or 0.0),
            Order.TRIGGER_PRICE: 0.0,
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: fill_quantity,
            Order.FILLED_QTY: fill_quantity,
            Order.REMAINING_QTY: 0,
            Order.CANCELLED_QTY: 0,
            Order.STATUS: Status.FILLED,
            Order.REJECT_REASON: "",
            Order.DISCLOSED_QUANTITY: 0,
            Order.PRODUCT: self._parse_from_broker("product", order["prod"]),
            Order.EXCHANGE: self._parse_from_broker("segment", order["exSeg"]),
            Order.SEGMENT: self._parse_from_broker("segment", order["exSeg"]),
            Order.VALIDITY: "",
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        """Coerce a possibly-missing/blank KotakNeo numeric field to float."""
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _parse_position(
        self,
        position: dict,
    ) -> dict[Any, Any]:
        """Convert a KotakNeo position row to a unified position record.

        Quantity and average-price fields follow the formulas documented for
        the positions endpoint. These should be re-validated against a live
        response before relying on the derived values.

        Args:
            position: Raw position row returned by KotakNeo.

        Returns:
            Unified Fenix position record.
        """
        buy_qty = int(self._safe_float(position.get("cfBuyQty"))) + int(
            self._safe_float(position.get("flBuyQty"))
        )
        sell_qty = int(self._safe_float(position.get("cfSellQty"))) + int(
            self._safe_float(position.get("flSellQty"))
        )
        net_qty = buy_qty - sell_qty

        buy_amt = self._safe_float(position.get("cfBuyAmt")) + self._safe_float(
            position.get("buyAmt")
        )
        sell_amt = self._safe_float(
            position.get("cfSellAmt")
        ) + self._safe_float(position.get("sellAmt"))

        multiplier = self._safe_float(position.get("multiplier"), 1.0) or 1.0
        gen = self._safe_float(position.get("genNum"), 1.0) / (
            self._safe_float(position.get("genDen"), 1.0) or 1.0
        )
        prc = self._safe_float(position.get("prcNum"), 1.0) / (
            self._safe_float(position.get("prcDen"), 1.0) or 1.0
        )

        buy_avg = (
            buy_amt / (buy_qty * multiplier * gen * prc) if buy_qty else 0.0
        )
        sell_avg = (
            sell_amt / (sell_qty * multiplier * gen * prc) if sell_qty else 0.0
        )
        if buy_qty > sell_qty:
            avg_price = buy_avg
        elif sell_qty > buy_qty:
            avg_price = sell_avg
        else:
            avg_price = 0.0

        parsed_position = {
            Position.SYMBOL: position.get("trdSym"),
            Position.TOKEN: int(position.get("tok") or 0),
            Position.NET_QTY: net_qty,
            Position.AVG_PRICE: avg_price,
            Position.MTM: None,
            Position.PNL: None,
            Position.BUY_QTY: buy_qty,
            Position.BUY_PRICE: buy_avg,
            Position.SELL_QTY: sell_qty,
            Position.SELL_PRICE: sell_avg,
            Position.LTP: None,
            Position.PRODUCT: self._parse_from_broker(
                "product", position.get("prod", "")
            ),
            Position.EXCHANGE: self._parse_from_broker(
                "segment", position.get("exSeg", "")
            ),
            Position.INFO: position,
        }

        return parsed_position

    def _parse_rms(self, rms: dict) -> dict[Any, Any]:
        """Convert a KotakNeo limits payload to a unified margin record."""
        parsed_rms = {
            RMS.MARGINUSED: self._safe_float(rms.get("MarginUsed")),
            RMS.MARGINAVAIL: self._safe_float(rms.get("Net")),
            RMS.INFO: rms,
        }

        return parsed_rms

    def _parse_profile(self, profile: dict) -> dict[Any, Any]:
        """Convert a KotakNeo login payload to a unified profile record.

        KotakNeo has no dedicated profile endpoint; the only profile fields it
        exposes come from the ``tradeApiValidate`` response captured during
        ``authenticate``. ``kId`` carries the account PAN.

        Args:
            profile: The stored ``tradeApiValidate`` ``data`` payload.

        Returns:
            Unified Fenix profile record.
        """
        parsed_profile = {
            Profile.CLIENT_ID: profile.get("ucc", ""),
            Profile.NAME: profile.get("greetingName", ""),
            Profile.EMAIL_ID: "",
            Profile.MOBILE_NO: "",
            Profile.PAN: profile.get("kId", ""),
            Profile.ADDRESS: "",
            Profile.BANK_NAME: "",
            Profile.BANK_BRANCH_NAME: None,
            Profile.BANK_ACC_NO: "",
            Profile.EXCHANGES_ENABLED: [],
            Profile.ENABLED: profile.get("dormancyStatus") == "A",
            Profile.INFO: profile,
        }

        return parsed_profile

    def _parse_place_order_response(self, response: Response) -> dict[Any, Any]:
        """Extract the order id from a KotakNeo order response.

        Args:
            response: HTTP response returned after placing, modifying, or
                cancelling an order.

        Returns:
            Unified order-id record.
        """
        info = self._parse_json_response(response)
        return {Order.ID: info["nOrdNo"]}

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
        """Build the KotakNeo API payload for a place-order request.

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
            KotakNeo place-order payload.

        Raises:
            InputError: If a bracket order (non-zero ``target``) is requested,
                which KotakNeo does not support through this adapter.
        """
        if target:
            raise InputError(f"BO Orders Not Available in {self.id}.")

        order_type = self._resolve_order_type(price, trigger)

        payload = {
            "es": token_dict["Exchange"],
            "ts": token_dict["Symbol"],
            "pr": price,
            "tp": trigger,
            "qt": quantity,
            "tt": self._format_for_broker("side", side),
            "pt": self._format_for_broker("order_type", order_type),
            "pc": self._format_for_broker("product", product),
            "rt": self._format_for_broker("validity", validity),
            "am": "YES" if variety == Variety.AMO else "NO",
            "ig": unique_id,
            "dq": "0",
            "mp": "0",
            "pf": "N",
            "os": "API",
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
        """Place an order through KotakNeo.

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

        payload = self._build_place_order_payload(
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
            url=self._trade_url("place_order"),
            endpoint_group="default",
            params=self._server_params(),
            data={"jData": json_dumps(payload)},
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    # Order Details, OrderBook & TradeBook

    def fetch_raw_orderbook(
        self,
    ) -> list[dict]:
        """Fetch raw KotakNeo order-book rows.

        Returns:
            Raw broker order-book rows. Empty result-set responses are returned
            as an empty list. In paper mode, returns the unified paper order
            records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        response = self.fetch(
            method="GET",
            url=self._trade_url("orderbook"),
            endpoint_group="default",
            params=self._server_params(),
            headers=self._headers,
        )

        try:
            info = self._parse_json_response(response)
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

        return info.get("data") or []

    def fetch_raw_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """Fetch raw KotakNeo history rows for an order.

        Args:
            order_id: Broker order id to query.

        Returns:
            Raw broker order-history rows. In paper mode, returns the unified
            paper order record wrapped in a list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        payload = {"nOrdNo": str(order_id)}
        response = self.fetch(
            method="POST",
            url=self._trade_url("order_history"),
            endpoint_group="default",
            params=self._server_params(),
            data={"jData": json_dumps(payload)},
            headers=self._headers,
        )

        info = self._parse_json_response(response)

        # Order history is double-nested: {"data": {"stat", "data": [...]}}.
        inner = info.get("data", info)
        if isinstance(inner, dict):
            return inner.get("data") or []
        return inner or []

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
            orders.append(self._parse_orderbook(order))

        return orders

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
            url=self._trade_url("tradebook"),
            endpoint_group="default",
            params=self._server_params(),
            headers=self._headers,
        )

        try:
            info = self._parse_json_response(response)
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

        orders = []
        for order in info.get("data") or []:
            orders.append(self._parse_tradebook(order))

        return orders

    def fetch_orders(
        self,
    ) -> list[dict]:
        """Fetch unified orders.

        Returns:
            Unified order records from the order book.
        """
        return self.fetch_orderbook()

    def fetch_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Fetch one order using its order history.

        Args:
            order_id: Broker order id to find.

        Raises:
            OrderNotFoundError: If the order id has no history.

        Returns:
            Unified Fenix order record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        info = self.fetch_raw_order_history(order_id=order_id)
        if not info:
            raise OrderNotFoundError("This order_id does not exist.")

        return self._parse_order_history(info[0])

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
            order_history.append(self._parse_order_history(order))

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
        """Modify an open KotakNeo order.

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
            if not history:
                raise OrderNotFoundError("This order_id does not exist.")
            order_info = history[0]

        payload = {
            "no": order_info["nOrdNo"],
            "tk": order_info["tok"],
            "es": order_info["exSeg"],
            "ts": order_info["trdSym"],
            "pr": str(price if price is not None else order_info["prc"]),
            "tp": str(
                trigger if trigger is not None else order_info["trgPrc"]
            ),
            "qt": str(
                quantity if quantity is not None else order_info["qty"]
            ),
            "fq": str(order_info["fldQty"]),
            "tt": order_info["trnsTp"],
            "pt": (
                self._format_for_broker("order_type", order_type)
                if order_type
                else order_info["prcTp"]
            ),
            "pc": order_info["prod"],
            "am": "YES" if order_info.get("ordGenTp") == Variety.AMO else "NO",
            "vd": (
                self._format_for_broker("validity", validity)
                if validity
                else order_info["ordDur"]
            ),
            "dq": "0",
            "mp": "0",
            "dd": "NA",
        }

        response = self.fetch(
            method="POST",
            url=self._trade_url("modify_order"),
            endpoint_group="default",
            params=self._server_params(),
            data={"jData": json_dumps(payload)},
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def cancel_order(
        self,
        order_id: str,
        extra_params: dict | None = None,
    ) -> dict[Any, Any]:
        """Cancel an open KotakNeo order.

        Args:
            order_id: Broker order id to cancel.
            extra_params: Optional broker-specific values. When it contains an
                ``"order"`` key, that raw order row is reused instead of
                refetching the order history.

        Returns:
            Unified order-id record for the cancelled order.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.cancel_order(
                order_id=order_id,
                extra_params=extra_params,
            )

        extra_params = extra_params or {}
        if extra_params.get("order"):
            order_info = extra_params["order"]
        else:
            history = self.fetch_raw_order_history(order_id=order_id)
            if not history:
                raise OrderNotFoundError("This order_id does not exist.")
            order_info = history[0]

        payload = {
            "on": str(order_id),
            "am": "YES" if order_info.get("ordGenTp") == Variety.AMO else "NO",
            "ts": order_info["trdSym"],
        }

        response = self.fetch(
            method="POST",
            url=self._trade_url("cancel_order"),
            endpoint_group="default",
            params=self._server_params(),
            data={"jData": json_dumps(payload)},
            headers=self._headers,
        )

        info = self._parse_json_response(response)

        return {Order.ID: info.get("result") or info.get("nOrdNo") or order_id}

    # Positions, Holdings & Account Limits

    def fetch_day_positions(self) -> list[Any]:
        """Fetch the day's account positions.

        Returns:
            Unified Fenix position records. Empty result-set responses are
            returned as an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        response = self.fetch(
            method="GET",
            url=self._trade_url("positions"),
            endpoint_group="default",
            params=self._server_params(),
            headers=self._headers,
        )

        try:
            info = self._parse_json_response(response)
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

        positions = []
        for position in info.get("data") or []:
            positions.append(self._parse_position(position))

        return positions

    def fetch_net_positions(self) -> list[Any]:
        """Fetch net account positions.

        Returns:
            Unified Fenix position records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        return self.fetch_day_positions()

    def fetch_holdings(self) -> list[Any]:
        """Fetch account holdings.

        Returns:
            Raw KotakNeo holding rows. Empty result-set responses are returned
            as an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_holdings()

        response = self.fetch(
            method="GET",
            url=self._trade_url("holdings"),
            endpoint_group="default",
            params={**self._server_params(), "alt": "false"},
            headers=self._headers,
        )

        try:
            info = self._parse_json_response(response)
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

        return info.get("data") or []

    def fetch_margin_limits(self) -> dict[Any, Any]:
        """Fetch account margin limits.

        Returns:
            Unified Fenix RMS limits record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_margin_limits()

        payload = {"seg": "ALL", "exch": "ALL", "prod": "ALL"}
        response = self.fetch(
            method="POST",
            url=self._trade_url("limits"),
            endpoint_group="default",
            params=self._server_params(),
            data={"jData": json_dumps(payload)},
            headers=self._headers,
        )

        info = self._parse_json_response(response)

        return self._parse_rms(info)

    def fetch_profile(self) -> dict[Any, Any]:
        """Fetch account profile details.

        KotakNeo exposes no profile endpoint, so the profile is built from the
        ``tradeApiValidate`` payload captured during ``authenticate``.

        Returns:
            Unified Fenix profile record.

        Raises:
            AuthenticationError: If called before a successful login (e.g. when
                only stored request headers were restored via ``use_headers``,
                which does not carry the login profile fields).
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_profile()

        if not self._login_info:
            raise AuthenticationError(
                f"{self.id} profile is only available after a fresh "
                "authenticate(); restored header sessions do not carry it.",
                broker=self.id,
            )

        return self._parse_profile(self._login_info)
