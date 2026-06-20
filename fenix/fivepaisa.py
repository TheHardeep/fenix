from __future__ import annotations
from typing import TYPE_CHECKING
from typing import Any
from typing import NoReturn
import base64
from collections import defaultdict
from datetime import datetime
from re import split as re_split
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

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
from fenix.base.constants import Root


from fenix.base.errors import (
    AuthenticationError,
    BrokerError,
    InputError,
    InvalidOrderError,
    OrderNotFoundError,
    ResponseError,
    TokenDownloadError,
)

if TYPE_CHECKING:
    from requests.models import Response


class EncryptionClient:

    def __init__(self, encryption_key):

        self.iv = bytes(
            [83, 71, 26, 58, 54, 35, 22, 11, 83, 71, 26, 58, 54, 35, 22, 11]
        )
        self.enc_key = encryption_key

    def _pad_and_convert_to_bytes(self, text):
        return bytes(text + chr(16 - len(text) %
                                16) * (16 - len(text) %
                                       16), encoding="utf-8")

    def encrypt(self, text):
        padded_text = self._pad_and_convert_to_bytes(text)
        cd = PBKDF2(password=self.enc_key, salt=self.iv, dkLen=48)
        aesiv = cd[:16]
        aeskey = cd[16:]

        cipher = AES.new(aeskey, AES.MODE_CBC, aesiv)

        return str(
            base64.b64encode(
                cipher.encrypt(padded_text)),
            encoding="utf-8")


class FivePaisa(Broker):
    """FivePaisa broker adapter for the Fenix trading interface."""

    _API = {
        "doc": "https://xstream.5paisa.com/dev-docs",
        "servers": {
            "api": "https://Openapi.5paisa.com/VendorsAPI/Service1.svc",
            "market_data": "https://images.5paisa.com/website/scripmaster-csv-format.csv",
        },
        "paths": {
            # --- Auth Flow ---
            "access_token": {
                "server": "api",
                "path": "/V4/LoginRequestMobileNewbyEmail",
            },

            # --- Order & Portfolio Flow ---
            "place_order": {
                "server": "api",
                "path": "/V1/PlaceOrderRequest",
            },
            "bo_order": {
                "server": "api",
                "path": "/BracketOrderRequest",
            },
            "modify_order": {
                "server": "api",
                "path": "/V1/ModifyOrderRequest",
            },
            "cancel_order": {
                "server": "api",
                "path": "/V1/CancelOrderRequest",
            },
            "orderbook": {
                "server": "api",
                "path": "/V2/OrderBook",
            },
            "tradebook": {
                "server": "api",
                "path": "/V1/TradeBook",
            },
            "positions": {
                "server": "api",
                "path": "/V4/NetPosition",
            },
            "holdings": {
                "server": "api",
                "path": "/V3/Holding",
            },

            # --- Market Data ---
            "instruments": {
                "server": "market_data",
                "path": "",
            },
        },
    }

    STANDARD_MAPS = {
        "side": {
            "B": Side.BUY,
            "S": Side.SELL,
        },
        "order_type": {
            "N": OrderType.LIMIT,
            "Y": OrderType.MARKET,
        },
        "status": {
            "Fully Executed": Status.FILLED,
            "Rejected By 5P": Status.REJECTED,
            "Rejected by Exch": Status.REJECTED,
            "Pending": Status.PENDING,
            "Cancelled": Status.CANCELLED,
            "modified": Status.MODIFIED,
            "Xmitted": Status.PENDING,
        },
        "product": {
            "I": Product.MIS,
            "D": Product.NRML,
        },
        "segment": {
            "NC": ExchangeCode.NSE,
            "ND": ExchangeCode.NFO,
            "BC": ExchangeCode.BSE,
            "BD": ExchangeCode.BFO,
            "MC": ExchangeCode.MCX,
            "MD": ExchangeCode.MCX,
        },
        "exchange": {
            "N": ExchangeCode.NSE,
            "B": ExchangeCode.BSE,
            "M": ExchangeCode.MCX,
        },
        "validity": {
            0: Validity.DAY,
            1: Validity.GTD,
            2: Validity.GTC,
            3: Validity.IOC,
            6: Validity.FOK,
        },
    }

    REQUEST_MAPS = {
        "side": {
            Side.BUY: "Buy",
            Side.SELL: "Sell",
        },
        "exchange": {
            ExchangeCode.NSE: "N",
            ExchangeCode.NFO: "N",
            ExchangeCode.BSE: "B",
            ExchangeCode.BFO: "B",
            ExchangeCode.MCX: "M",
        },
        "exchange_type": {
            ExchangeCode.NSE: "C",
            ExchangeCode.NFO: "D",
            ExchangeCode.BSE: "C",
            ExchangeCode.BFO: "D",
            ExchangeCode.MCX: "D",
        },
        "product": {
            Product.MIS: True,
            Product.NRML: False,
            Variety.BO: True,
        },
        "validity": {
            Validity.DAY: False,
            Validity.IOC: True,
        },
        "variety": {
            Variety.REGULAR: "REGULAR",
            Variety.STOPLOSS: "REGULAR",
            Variety.BO: "BO",
            Variety.AMO: "AMO",
        },
    }

    _REQUIRED_AUTH_HEADER_KEYS = (
        "Content-Type",
        "Authorization",
    )

    ERROR_CODE_KEYS = (
        "Status",
        "status",
        "ResponseCode",
    )

    ERROR_MESSAGE_KEYS = (
        "StatusDescription",
        "statusDescription",
        "Status_description",
        "Message",
        "message",
    )

    _ERROR_MESSAGES = {
        # --- Authentication ---
        "FP_INVALID_SESSION": (
            "Bearer token expired, invalid, or unauthorized session."
        ),
        "FP_TOKEN_EXPIRED": "OAuth request token expired or invalid.",

        # --- Validation ---
        "FP_INVALID_INPUTS": (
            "Missing required parameters, malformed request body, "
            "or invalid field values."
        ),
        "FP_INPUT_VALIDATION_ERROR": "Request validation failed.",

        # --- OrderBook ---
        "FP_INVALID_TIME_RANGE": (
            "'updatedInLastSeconds' should be in range from 0 to 600."
        ),
        "FP_MISSING_PARAMETERS": "Missing or invalid request parameters.",
        "FP_INVALID_CLIENT_CODE": "Invalid ClientCode.",
        "FP_NO_ORDERS_FOUND": "No order found for this client.",

        # --- Historical API ---
        "FP_PROCESSING_ERROR": (
            "Historical candle backend processing failure."
        ),

        # --- Order Status ---
        "FP_REJECTED_BY_5P": "Order rejected by 5paisa broker.",
        "FP_REJECTED_BY_EXCHANGE": "Order rejected by exchange.",
        "FP_XMITTED": "Order not accepted or did not reach the exchange.",
    }

    _DIRECT_ERROR_CLASSES = {
        "FP_INVALID_SESSION": AuthenticationError,
        "FP_TOKEN_EXPIRED": AuthenticationError,
        "FP_INVALID_INPUTS": InputError,
        "FP_INPUT_VALIDATION_ERROR": InputError,
        "FP_INVALID_TIME_RANGE": InputError,
        "FP_MISSING_PARAMETERS": InputError,
        "FP_INVALID_CLIENT_CODE": InputError,
        "FP_NO_ORDERS_FOUND": OrderNotFoundError,
        "FP_PROCESSING_ERROR": BrokerError,
        "FP_REJECTED_BY_5P": InvalidOrderError,
        "FP_REJECTED_BY_EXCHANGE": InvalidOrderError,
        "FP_XMITTED": InvalidOrderError,
    }

    _NO_DATA_PHRASES = (
        "no order found",
        "no data",
        "no positions found",
        "no holdings found",
        "no trades found",
    )

    token_params = [
        "user_id",
        "password",
        "email",
        "web_login_password",
        "dob",
        "app_name",
        "user_key",
        "encryption_key",
    ]

    base_urls = {
        "api_doc": _API["doc"],
        "access_token": (
            f"{_API['servers']['api']}"
            f"{_API['paths']['access_token']['path']}"
        ),
        "base": _API["servers"]["api"],
        "market_data": _API["servers"]["market_data"],
    }

    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "FivePaisa",
            "tokenParams": self.token_params,
            "proxies": {},
            "sensitiveLogKeys": [
                "userId",
                "password",
                "Email_id",
                "Password",
                "My2PIN",
                "ClientCode",
                "AccessToken",
                "JWTToken",
                "Authorization",
                "user_key",
                "encryption_key",
                "client_code",
                "access_token",
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
        """Initialize the FivePaisa broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
        """
        super().__init__(config)
        self._user_key = None
        self._client_code = None
        self._access_token = None
        self._auth_json_data = None

    # Script Fetch

    def _read_scripmaster(self, data: Any | None = None):
        """Return the FivePaisa scrip-master as a pandas DataFrame.

        Args:
            data: Optional pre-fetched scrip-master DataFrame. When omitted,
                the single combined CSV master is downloaded from FivePaisa.

        Returns:
            The scrip-master DataFrame with its native column layout.
        """
        if data is not None:
            return data

        return self.data_reader(self.get_url("instruments"), file_type="csv")

    @staticmethod
    def _expiry_strings(
        expiry_raw: str,
        cache: dict[str, tuple[str, str]],
    ) -> tuple[str, str]:
        """Resolve a scrip-master expiry timestamp to ``(iso, display)`` parts.

        Args:
            expiry_raw: Raw ``"%Y-%m-%d %H:%M:%S"`` expiry string from the
                scrip-master.
            cache: Per-call cache keyed by ``expiry_raw`` to avoid re-parsing
                repeated timestamps.

        Returns:
            Tuple of ``(iso_date, display_date)`` where ``iso_date`` is
            ``"YYYY-MM-DD"`` and ``display_date`` is ``"DD-MON"`` upper-cased.
        """
        if expiry_raw not in cache:
            dt = datetime.strptime(str(expiry_raw), "%Y-%m-%d %H:%M:%S").date()
            cache[expiry_raw] = (
                dt.strftime("%Y-%m-%d"),
                dt.strftime("%d-%b").upper(),
            )
        return cache[expiry_raw]

    def load_equity_tokens(
        self,
        data: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE equity token metadata.

        Args:
            data: Optional pre-fetched scrip-master DataFrame. When omitted,
                the combined CSV master is downloaded from FivePaisa.

        Returns:
            A tuple containing the unified equity token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.
        """
        df = self._read_scripmaster(data)

        equity = df[
            (df["CpType"] == "XX")
            & (df["ExchType"] == "C")
            & (df["Series"] == "EQ")
            & (df["Exch"].isin(["N", "B"]))
        ]

        nse_dict: dict[str, Any] = {}
        bse_dict: dict[str, Any] = {}
        alltoken_dict: dict[str, Any] = {}

        for row in equity.to_dict("records"):
            exchange = (
                ExchangeCode.NSE if row["Exch"] == "N" else ExchangeCode.BSE
            )
            symbol = str(row["Name"]).strip()
            token = int(float(row["Scripcode"]))

            record = {
                "Token": token,
                "Exchange": exchange,
                "Symbol": symbol,
                "ScriptName": symbol,
                "LotSize": int(float(row["LotSize"])),
                "TickSize": float(row["TickSize"]),
            }

            if exchange == ExchangeCode.NSE:
                nse_dict.setdefault(symbol, record)
            else:
                bse_dict.setdefault(symbol, record)

            alltoken_dict[f"{token}_{exchange}"] = record

        self.token_json["Equity"].update({
            "NSE": nse_dict,
            "BSE": bse_dict,
        })
        self.alltoken_json.update(alltoken_dict)

        return (
            {"Equity": {"NSE": nse_dict, "BSE": bse_dict}},
            alltoken_dict,
        )

    def load_index_tokens(
        self,
        data: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE index token metadata.

        Args:
            data: Optional pre-fetched scrip-master DataFrame. When omitted,
                the combined CSV master is downloaded from FivePaisa.

        Returns:
            A tuple containing the unified index token map (including
            ``Root.*`` aliases) and an all-token lookup keyed by
            ``"{token}_{exchange}"``.
        """
        df = self._read_scripmaster(data)

        idx = df[(df["CpType"] == "EQ") | (df["Name"] == "SENSEX")]

        nse_dict: dict[str, Any] = {}
        bse_dict: dict[str, Any] = {}
        token_dict: dict[str, Any] = {}

        for row in idx.to_dict("records"):
            exchange = (
                ExchangeCode.NSE if row["Exch"] == "N" else ExchangeCode.BSE
            )
            symbol = str(row["Name"]).strip()
            token = int(float(row["Scripcode"]))

            record = {
                "Exchange": exchange,
                "Token": token,
                "Symbol": symbol,
                "ScriptName": symbol,
            }

            if exchange == ExchangeCode.NSE:
                nse_dict[symbol] = record
            else:
                bse_dict[symbol] = record

            token_dict[f"{token}_{exchange}"] = record

        merged: dict[str, Any] = {**nse_dict, **bse_dict}
        for alias, source in (
            (Root.BNF, "BANKNIFTY"),
            (Root.NF, "NIFTY"),
            (Root.FNF, "FINNIFTY"),
            (Root.MIDCPNF, "MIDCPNifty"),
        ):
            if source in merged:
                merged[alias] = merged[source]

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

    def _load_derivative_tokens(
        self,
        rows: list[dict],
        exchange_map: dict[str, str],
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
    ]:
        """Build futures/options maps from filtered scrip-master rows.

        Args:
            rows: Scrip-master rows (``df.to_dict("records")``) already
                filtered to the desired derivative segment.
            exchange_map: Mapping of the raw ``Exch`` code to the resolved
                Fenix exchange code for this segment.

        Returns:
            Tuple of ``(futures_by_exchange, options_by_exchange,
            token_dict)``. ``futures_by_exchange``/``options_by_exchange`` are
            keyed by resolved exchange code, each value a
            ``defaultdict(list)`` keyed by root.
        """
        futures: dict[str, Any] = {
            exch: defaultdict(list) for exch in exchange_map.values()
        }
        options: dict[str, Any] = {
            exch: defaultdict(list) for exch in exchange_map.values()
        }
        token_dict: dict[str, Any] = {}
        dt_cache: dict[str, tuple[str, str]] = {}

        for row in rows:
            exchange = exchange_map.get(row["Exch"])
            if exchange is None:
                continue

            cp_type = row["CpType"]
            root = str(row["Root"]).strip()
            symbol = str(row["Name"]).strip()
            token = int(float(row["Scripcode"]))
            expiry, exdp = self._expiry_strings(row["Expiry"], dt_cache)

            if cp_type == "XX":
                record = {
                    "Exchange": exchange,
                    "Token": token,
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["TickSize"]),
                    "LotSize": int(float(row["LotSize"])),
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }
                futures[exchange][root].append(record)

            elif cp_type in ("CE", "PE"):
                strike = self._format_strike(row["StrikeRate"])
                record = {
                    "Exchange": exchange,
                    "Token": token,
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["TickSize"]),
                    "LotSize": int(float(row["LotSize"])),
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": cp_type,
                    "ScriptName": f"{root} {exdp} {strike} {cp_type}",
                }
                options[exchange][root].append(record)

            else:
                continue

            token_dict[f"{token}_{exchange}"] = record

        return futures, options, token_dict

    def load_fno_tokens(
        self,
        data: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE futures and options token metadata.

        Args:
            data: Optional pre-fetched scrip-master DataFrame. When omitted,
                the combined CSV master is downloaded from FivePaisa.

        Returns:
            A tuple containing the unified F&O token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            TokenDownloadError: If the scrip-master cannot be downloaded or
                parsed.
        """
        try:
            df = self._read_scripmaster(data)
            fno = df[(df["ExchType"] == "D") & (df["Exch"].isin(["N", "B"]))]

            futures, options, token_dict = self._load_derivative_tokens(
                rows=fno.to_dict("records"),
                exchange_map={
                    "N": ExchangeCode.NFO,
                    "B": ExchangeCode.BFO,
                },
            )

            fut_nse = futures[ExchangeCode.NFO]
            fut_bse = futures[ExchangeCode.BFO]
            opt_nse = options[ExchangeCode.NFO]
            opt_bse = options[ExchangeCode.BFO]

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

        except TokenDownloadError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise TokenDownloadError({"Error": exc.args}) from exc

    def load_mcx_tokens(
        self,
        data: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load MCX futures and options token metadata.

        Args:
            data: Optional pre-fetched scrip-master DataFrame. When omitted,
                the combined CSV master is downloaded from FivePaisa.

        Returns:
            A tuple containing the unified MCX token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            TokenDownloadError: If the scrip-master cannot be downloaded or
                parsed.
        """
        try:
            df = self._read_scripmaster(data)
            mcx = df[(df["ExchType"] == "D") & (df["Exch"] == "M")]

            futures, options, token_dict = self._load_derivative_tokens(
                rows=mcx.to_dict("records"),
                exchange_map={"M": ExchangeCode.MCX},
            )

            fut_mcx = futures[ExchangeCode.MCX]
            opt_mcx = options[ExchangeCode.MCX]

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

        except TokenDownloadError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise TokenDownloadError({"Error": exc.args}) from exc

    def load_cds_tokens(
        self,
        data: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load currency derivatives token metadata for CDS and BCD.

        Args:
            data: Optional pre-fetched scrip-master DataFrame. When omitted,
                the combined CSV master is downloaded from FivePaisa.

        Returns:
            A tuple containing the unified currency derivatives token map and
            an all-token lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            TokenDownloadError: If the scrip-master cannot be downloaded or
                parsed.
        """
        try:
            df = self._read_scripmaster(data)
            cds = df[(df["ExchType"] == "U") & (df["Exch"].isin(["N", "B"]))]

            futures, options, token_dict = self._load_derivative_tokens(
                rows=cds.to_dict("records"),
                exchange_map={
                    "N": ExchangeCode.CDS,
                    "B": ExchangeCode.BCD,
                },
            )

            fut_nse = futures[ExchangeCode.CDS]
            fut_bse = futures[ExchangeCode.BCD]
            opt_nse = options[ExchangeCode.CDS]
            opt_bse = options[ExchangeCode.BCD]

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

        except TokenDownloadError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise TokenDownloadError({"Error": exc.args}) from exc

    # Headers & Json Parsers

    def create_headers(
        self,
        params: dict,
    ) -> dict[str, Any]:
        """Generate the legacy FivePaisa auth bundle from raw credentials.

        Args:
            params: Login credentials. Must contain ``user_id``, ``password``,
                ``email``, ``web_login_password``, ``dob`` (formatted
                ``YYYYMMDD``), ``app_name``, ``user_key``, and
                ``encryption_key``.

        Returns:
            Auth bundle containing the request headers, the active client
            code, the JWT access token, and a pre-built ``json_data`` payload
            template used by subsequent FivePaisa requests.

        Raises:
            KeyError: If any required credential is missing from ``params``.
        """
        for key in self.tokenParams:
            if key not in params:
                raise KeyError(f"Please provide {key}")

        encryption_client = EncryptionClient(params["encryption_key"])

        login_payload = {
            "head": {
                "appName": params["app_name"],
                "appVer": "1.0",
                "key": params["user_key"],
                "osName": "WEB",
                "requestCode": "5PLoginV4",
                "userId": params["user_id"],
                "password": params["password"],
            },
            "body": {
                "Email_id": encryption_client.encrypt(
                    params["email"]),
                "Password": encryption_client.encrypt(
                    params["web_login_password"]),
                "LocalIP": "0.0.0.0",
                "PublicIP": "0.0.0.0",
                "HDSerailNumber": "",
                "MACAddress": "",
                "MachineID": "000000",
                "VersionNo": "1.7",
                "RequestNo": "1",
                "My2PIN": encryption_client.encrypt(
                    params["dob"]),
                "ConnectionType": "1",
            },
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("access_token"),
            endpoint_group="default",
            json=login_payload,
        )

        response = self._parse_json_response(response)

        client_code = response["body"]["ClientCode"]
        jwt_token = response["body"]["JWTToken"]
        req_headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {jwt_token}",
        }
        json_data = {
            "head": {
                "key": params["user_key"],
            },
            "body": {
                "ClientCode": client_code,
            },
        }

        headers = {
            "headers": req_headers,
            "user_key": params["user_key"],
            "client_code": client_code,
            "access_token": jwt_token,
            "json_data": json_data,
        }

        self._headers = req_headers
        self._user_key = params["user_key"]
        self._client_code = client_code
        self._access_token = jwt_token
        self._auth_json_data = json_data
        self.reset_session()
        return headers

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, Any] | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        """Authenticate with FivePaisa and store request headers."""
        if self.paper_mode:
            self._headers = {"paper": "true"}
            return self._headers

        if headers is not None:
            return self.use_headers(headers)

        if self._headers and not force:
            return self._auth_payload()

        if params is None:
            raise KeyError("Please provide params or headers")

        return self.create_headers(params)

    def use_headers(
        self,
        headers: dict[str, Any],
        reset_session: bool = False,
    ) -> dict[str, Any]:
        """Restore FivePaisa auth headers and companion request metadata."""
        if "headers" in headers:
            request_headers = headers["headers"]
            self._user_key = headers.get("user_key")
            self._client_code = headers.get("client_code")
            self._access_token = headers.get("access_token")
            self._auth_json_data = headers.get("json_data")
            self._headers = dict(request_headers)
            if reset_session:
                self.reset_session()
            return headers

        self._headers = super().use_headers(headers, reset_session)
        return self._headers

    def _auth_payload(
        self,
        headers: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return the legacy auth bundle expected by FivePaisa payloads."""
        if headers is not None:
            return headers

        if not self._headers or not self._user_key or not self._client_code:
            raise KeyError("Please authenticate before calling this method.")

        return {
            "headers": self._headers,
            "user_key": self._user_key,
            "client_code": self._client_code,
            "access_token": self._access_token,
            "json_data": self._auth_json_data,
        }

    @classmethod
    def _json_parser(
        cls,
        response: Response,
    ) -> dict[Any, Any] | list[dict[Any, Any]]:
        """Decode an HTTP response into a JSON payload."""
        return cls.on_json_response(response)

    @classmethod
    def _datetime_converter(
        cls,
        dt_str: str,
    ):
        """Convert a FivePaisa ``/Date(…)/`` timestamp string into a datetime.

        Args:
            dt_str: FivePaisa-formatted datetime string.

        Returns:
            Equivalent ``datetime`` object.
        """
        dt_str = int(re_split(r"\(|\+", dt_str)[1])
        return cls.from_timestamp(dt_str / 1000)

    @classmethod
    def _orderbook_json_parser(
        cls,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a FivePaisa order-book row to a unified order record.

        Args:
            order: Raw order-book row returned by FivePaisa.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["ExchOrderID"],
            Order.USER_ID: order["RemoteOrderID"],
            Order.TIMESTAMP: cls._datetime_converter(order["BrokerOrderTime"]),
            Order.SYMBOL: order["ScripName"],
            Order.TOKEN: order["ScripCode"],
            Order.SIDE: cls._parse_from_broker("side", order["BuySell"]),
            Order.TYPE: (
                cls._parse_from_broker("order_type", order["AtMarket"])
                if order["WithSL"] == "N"
                else OrderType.SL if order["Rate"] else OrderType.SLM
            ),
            Order.AVG_PRICE: order["Rate"],
            Order.PRICE: order["Rate"],
            Order.TRIGGER_PRICE: order["SLTriggerRate"],
            Order.QUANTITY: order["Qty"],
            Order.FILLED_QTY: order["TradedQty"],
            Order.REMAINING_QTY: order["PendingQty"],
            Order.CANCELLED_QTY: 0,
            Order.STATUS: cls._parse_from_broker("status", order["OrderStatus"]),
            Order.REJECT_REASON: order["Reason"],
            Order.DISCLOSED_QUANTITY: order["DisClosedQty"],
            Order.PRODUCT: cls._parse_from_broker("product", order["DelvIntra"]),
            Order.EXCHANGE: cls._parse_from_broker("exchange", order["Exch"]),
            Order.SEGMENT: cls._parse_from_broker(
                "segment", order["Exch"] + order["ExchType"]
            ),
            Order.VALIDITY: cls._parse_from_broker(
                "validity", order["OrderValidity"]
            ),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _tradebook_json_parser(
        cls,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert a FivePaisa trade-book row to a unified order record.

        Args:
            order: Raw trade-book row returned by FivePaisa.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["ExchOrderID"],
            Order.USER_ID: "",
            Order.TIMESTAMP: cls._datetime_converter(order["ExchangeTradeTime"]),
            Order.SYMBOL: order["ScripName"],
            Order.TOKEN: order["ScripCode"],
            Order.SIDE: cls._parse_from_broker("side", order["BuySell"]),
            Order.TYPE: "",
            Order.AVG_PRICE: float(order["Rate"] or 0.0),
            Order.PRICE: 0.0,
            Order.TRIGGER_PRICE: 0.0,
            Order.QUANTITY: order["Qty"],
            Order.FILLED_QTY: order["Qty"] - order["PendingQty"],
            Order.REMAINING_QTY: order["PendingQty"],
            Order.CANCELLED_QTY: 0,
            Order.STATUS: "",
            Order.REJECT_REASON: "",
            Order.DISCLOSED_QUANTITY: 0,
            Order.PRODUCT: cls._parse_from_broker("product", order["DelvIntra"]),
            Order.EXCHANGE: cls._parse_from_broker("exchange", order["Exch"]),
            Order.SEGMENT: cls._parse_from_broker(
                "segment", order["Exch"] + order["ExchType"]
            ),
            Order.VALIDITY: "",
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _position_json_parser(
        cls,
        position: dict,
    ) -> dict[Any, Any]:
        """Convert a FivePaisa position payload to a unified position record.

        Args:
            position: Raw position payload returned by FivePaisa.

        Returns:
            Unified Fenix position record.
        """
        parsed_position = {
            Position.SYMBOL: position["ScripName"],
            Position.TOKEN: position["ScripCode"],
            Position.NET_QTY: position["NetQty"],
            Position.AVG_PRICE: (position["BuyValue"] + position["SellValue"])
            / (position["BuyQty"] + position["SellQty"]),
            Position.MTM: position["MTOM"],
            Position.PNL: position["BookedPL"],
            Position.BUY_QTY: position["BuyQty"],
            Position.BUY_PRICE: position["BuyAvgRate"],
            Position.SELL_QTY: position["SellQty"],
            Position.SELL_PRICE: position["SellAvgRate"],
            Position.LTP: position["LTP"],
            Position.PRODUCT: cls._parse_from_broker(
                "product", position["OrderFor"]
            ),
            Position.EXCHANGE: cls._parse_from_broker(
                "segment", position["Exch"] + position["ExchType"]
            ),
            Position.INFO: position,
        }

        return parsed_position

    _ERROR_PHRASE_MAP = (
        ("invalid session", "FP_INVALID_SESSION"),
        ("token expired", "FP_TOKEN_EXPIRED"),
        ("input validation error", "FP_INPUT_VALIDATION_ERROR"),
        ("invalid inputs", "FP_INVALID_INPUTS"),
        ("updatedinlastseconds", "FP_INVALID_TIME_RANGE"),
        ("missing or invalid request parameters", "FP_MISSING_PARAMETERS"),
        ("invalid clientcode", "FP_INVALID_CLIENT_CODE"),
        ("no order found", "FP_NO_ORDERS_FOUND"),
        ("error while processing", "FP_PROCESSING_ERROR"),
        ("rejected by 5p", "FP_REJECTED_BY_5P"),
        ("rejected by exch", "FP_REJECTED_BY_EXCHANGE"),
        ("xmitted", "FP_XMITTED"),
    )

    @staticmethod
    def _coerce_status(value: Any) -> int | None:
        """Coerce a 5paisa status field to an int, or None on failure."""
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _extract_fivepaisa_error_code(self, payload: Any) -> str | None:
        """Extract a documented FivePaisa error code from a payload."""
        payload_text = self._stringify_error_payload(payload).lower()
        for phrase, code in self._ERROR_PHRASE_MAP:
            if phrase in payload_text:
                return code
        return None

    def _extract_fivepaisa_error_message(
        self,
        payload: Any,
        error_code: str | None,
    ) -> str | None:
        """Extract the most useful FivePaisa error message for a payload."""
        error_message = self._extract_error_message(payload)
        documented_message = self._ERROR_MESSAGES.get(error_code or "")

        if documented_message and not error_message:
            return documented_message
        if error_message:
            return error_message
        return documented_message

    def _fivepaisa_error_class(
        self,
        error_code: str | None,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve a FivePaisa payload to the most specific Fenix error class."""
        if error_code in self._DIRECT_ERROR_CLASSES:
            return self._DIRECT_ERROR_CLASSES[error_code]

        message = (error_message or "").lower()
        if any(token in message for token in ("session", "token", "login")):
            return AuthenticationError
        if "rejected" in message:
            return InvalidOrderError
        if any(phrase in message for phrase in self._NO_DATA_PHRASES):
            return OrderNotFoundError
        if "invalid clientcode" in message:
            return InputError
        if "missing" in message or "invalid" in message:
            return InputError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded FivePaisa payload represents an error."""
        if isinstance(payload, list):
            if not payload:
                return False
            return self._payload_indicates_error(payload[0])

        if isinstance(payload, dict):
            head = payload.get("head") if isinstance(payload.get("head"), dict) else {}
            head_status = self._coerce_status(
                head.get("Status", head.get("status"))
            )
            if head_status is not None and head_status != 0:
                return True

            body = payload.get("body") if isinstance(payload.get("body"), dict) else {}
            body_status = self._coerce_status(body.get("Status"))
            body_message = body.get("Message") or ""
            if body_status is not None and body_status != 0:
                return True
            if (
                body_status == 0
                and isinstance(body_message, str)
                and any(
                    phrase in body_message.lower()
                    for phrase in self._NO_DATA_PHRASES
                )
            ):
                return True

            ord_status_list = body.get("OrdStatusResLst") or []
            if isinstance(ord_status_list, list):
                rejection_markers = (
                    "rejected by 5p",
                    "rejected by exch",
                    "xmitted",
                )
                for entry in ord_status_list:
                    if not isinstance(entry, dict):
                        continue
                    status = (entry.get("Status") or "").lower()
                    if any(marker in status for marker in rejection_markers):
                        return True

            return False

        return self._extract_fivepaisa_error_code(payload) is not None

    def _is_empty_response_error(self, exc: ResponseError) -> bool:
        """Return whether a response error represents an empty result set."""
        message = str(exc).lower()
        return any(phrase in message for phrase in self._NO_DATA_PHRASES)

    def _raise_fivepaisa_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for a FivePaisa error payload."""
        context = self._http_error_context(response, payload)
        error_code = self._extract_fivepaisa_error_code(payload)
        error_message = self._extract_fivepaisa_error_message(
            payload,
            error_code,
        )

        context["error_code"] = error_code
        context["error_message"] = error_message
        error_cls = self._fivepaisa_error_class(
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
            self._raise_fivepaisa_error(payload, response=exc.response, cause=exc)

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
            self._raise_fivepaisa_error(
                json_response,
                response=response,
            )

        return json_response

    def _create_order_parser(
        self,
        response: Response,
        headers: dict,
    ) -> dict[Any, Any]:
        """Extract and refetch the order produced by a place-order response.

        Args:
            response: HTTP response returned after placing an order.
            headers: Auth bundle to use for the follow-up ``fetch_order`` call.

        Returns:
            Unified Fenix order record for the newly placed order.

        Raises:
            ResponseError: If FivePaisa rejected the order with a zero broker
                order id.
        """
        info = self._json_parser(response)

        broker_id = info["body"]["BrokerOrderID"]

        if broker_id == 0:
            raise ResponseError(self.id + " " + info["body"]["Message"])
        order = self.fetch_order(
            order_id=broker_id, headers=headers, key_to_check="BrokerOrderId"
        )

        return order

    def _parse_place_order_response(self, response: Response) -> dict[Any, Any]:
        """Extract the order id from a FivePaisa place-order response.

        Args:
            response: HTTP response returned after placing an order.

        Returns:
            Unified order-id record.
        """
        info = self._parse_json_response(response)
        return {Order.ID: info["body"]["BrokerOrderID"]}

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
        """Build the FivePaisa API payload for a place-order request.

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
            Tuple of (payload, path_key) where ``path_key`` selects the
            ``place_order`` or ``bo_order`` URL from the API spec.
        """
        is_sl = bool(trigger)
        at_market = not price and not trigger
        is_amo = variety == Variety.AMO

        head = {"key": self._user_key}

        if not target:
            body = {
                "ScripCode": token_dict["Token"],
                "Exchange": self._format_for_broker(
                    "exchange", token_dict["Exchange"]
                ),
                "ExchangeType": self._format_for_broker(
                    "exchange_type", token_dict["Exchange"]
                ),
                "Price": price,
                "StopLossPrice": trigger,
                "Qty": quantity,
                "OrderType": self._format_for_broker("side", side),
                "IsStopLossOrder": is_sl,
                "IsAHOrder": "Y" if is_amo else "N",
                "IsIntraday": self._format_for_broker("product", product),
                "IsIOCOrder": self._format_for_broker("validity", validity),
                "ClientCode": self._client_code,
                "RemoteOrderID": unique_id,
                "DisQty": 0,
            }
            return {"head": head, "body": body}, "place_order"

        body = {
            "ScripCode": token_dict["Token"],
            "Exch": self._format_for_broker(
                "exchange", token_dict["Exchange"]
            ),
            "ExchType": self._format_for_broker(
                "exchange_type", token_dict["Exchange"]
            ),
            "LimitPriceInitialOrder": price,
            "TriggerPriceInitialOrder": trigger,
            "LimitPriceProfitOrder": target,
            "LimitPriceForSL": stoploss,
            "TrailingSL": trailing_sl,
            "Qty": quantity,
            "BuySell": self._format_for_broker("side", side),
            "IsStopLossOrder": is_sl,
            "AtMarket": at_market,
            "IsAHOrder": "Y" if is_amo else "N",
            "IsIntraday": self._format_for_broker("product", Variety.BO),
            "IsIOCOrder": self._format_for_broker("validity", validity),
            "ClientCode": self._client_code,
            "UniqueOrderIDNormal": unique_id,
            "DisQty": 0,
        }
        return {"head": head, "body": body}, "bo_order"

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
        """Place an order through FivePaisa.

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

        json_data, path_key = self._build_place_order_payload(
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
            url=self.get_url(path_key),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    # Order Details, OrderBook & TradeBook

    def fetch_raw_orderbook(
        self,
        headers: dict | None = None,
    ) -> list[dict]:
        """Fetch raw FivePaisa order-book rows.

        Args:
            headers: Optional auth bundle to use for the request. The cached
                bundle from ``authenticate()`` is used when omitted.

        Returns:
            Raw broker order-book response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        headers = self._auth_payload(headers)
        response = self.fetch(
            method="POST",
            url=self.get_url("orderbook"),
            endpoint_group="default",
            json=headers["json_data"],
            headers=headers["headers"],
        )
        return self._parse_json_response(response)

    def fetch_raw_tradebook(
        self,
        headers: dict | None = None,
    ) -> list[dict]:
        """Fetch raw FivePaisa trade-book rows.

        Args:
            headers: Optional auth bundle to use for the request. The cached
                bundle from ``authenticate()`` is used when omitted.

        Returns:
            Raw broker trade-book response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_tradebook()

        headers = self._auth_payload(headers)
        response = self.fetch(
            method="POST",
            url=self.get_url("tradebook"),
            endpoint_group="default",
            json=headers["json_data"],
            headers=headers["headers"],
        )
        return self._parse_json_response(response)

    def fetch_orderbook(
        self,
        headers: dict | None = None,
    ) -> list[dict]:
        """Fetch the order book in the unified Fenix format.

        Args:
            headers: Optional auth bundle to use for the request. The cached
                bundle from ``authenticate()`` is used when omitted.

        Returns:
            Unified order records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        info = self.fetch_raw_orderbook(headers=headers)

        orders = []
        for order in info["body"]["OrderBookDetail"]:
            detail = self._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    def fetch_tradebook(
        self,
        headers: dict | None = None,
        default: bool = True,
    ) -> list[dict] | dict[Any, Any]:
        """Fetch the trade book in the unified Fenix format.

        Args:
            headers: Optional auth bundle to use for the request. The cached
                bundle from ``authenticate()`` is used when omitted.
            default: When ``True`` (the default), return a list of unified
                trade records. When ``False``, return a dict keyed by order
                id, used internally to enrich orderbook rows with executed
                average prices.

        Returns:
            Unified order records, either as a list or as a dict keyed by
            order id depending on ``default``.
        """
        if self.paper_mode and self._paper is not None:
            trades = self._paper.fetch_tradebook()
            if default:
                return trades
            return {trade["id"]: trade for trade in trades}

        info = self.fetch_raw_tradebook(headers=headers)

        if default:
            orders = []
            for order in info["body"]["TradeBookDetail"]:
                detail = self._tradebook_json_parser(order)
                orders.append(detail)
            return orders

        orders = {}
        for order in info["body"]["TradeBookDetail"]:
            detail = self._tradebook_json_parser(order)
            orders[detail["id"]] = detail

        return orders

    def fetch_orders(
        self,
        headers: dict | None = None,
    ) -> list[dict]:
        """Fetch the order book enriched with executed average prices.

        FivePaisa's order-book endpoint omits ``avgPrice``, so this helper
        joins each order against the trade book to populate it.

        Args:
            headers: Optional auth bundle to use for the request. The cached
                bundle from ``authenticate()`` is used when omitted.

        Returns:
            Unified order records with ``avgPrice`` populated from the trade
            book.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        info = self.fetch_raw_orderbook(headers=headers)
        tradebook_orders = self.fetch_tradebook(headers=headers, default=False)

        orders = []
        for order in info["body"]["OrderBookDetail"]:
            detail = self._orderbook_json_parser(order)

            avgprice = (
                tradebook_orders[detail["id"]]["avgPrice"]
                if tradebook_orders.get(detail["id"])
                else 0.0
            )
            detail["avgPrice"] = avgprice

            orders.append(detail)

        return orders

    def fetch_order(
        self,
        order_id: str,
        headers: dict | None = None,
        key_to_check: str = "ExchOrderID",
    ) -> dict[Any, Any]:
        """Fetch one order from the current order book.

        Args:
            order_id: Order id to find.
            headers: Optional auth bundle to use for the request. The cached
                bundle from ``authenticate()`` is used when omitted.
            key_to_check: Order-book field to match against ``order_id``.
                Defaults to ``"ExchOrderID"`` (exchange order id); set to
                ``"BrokerOrderId"`` to look up by broker order id.

        Raises:
            InputError: If the order id is absent from the order book.

        Returns:
            Unified Fenix order record, with ``avgPrice`` enriched from the
            trade book.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        orderid = str(
            order_id) if key_to_check == "ExchOrderID" else int(order_id)
        info = self.fetch_raw_orderbook(headers=headers)

        for order in info["body"]["OrderBookDetail"]:
            if order[key_to_check] == orderid:
                detail = self._orderbook_json_parser(order)
                detail["avgPrice"] = self.fetch_tradebook_order(
                    order_id=detail["id"], headers=headers, default=False
                )  # Five Paisa API is Fuddu i.e. commented.
                return detail

        raise InputError({"This orderid does not exist."})

    def fetch_tradebook_order(
        self,
        order_id: str,
        headers: dict | None = None,
        default: bool = True,
    ):
        info = self.fetch_raw_tradebook(headers=headers)

        orders = []
        for order in info["body"]["TradeBookDetail"]:
            if order["ExchOrderID"] == order_id:
                if default:
                    detail = self._tradebook_json_parser(order)
                    return detail

                return order["Rate"]

        if default:
            return orders

        return 0.0

    # Order Modification & Sq Off

    def modify_order(
        self,
        order_id: str,
        price: float | None = None,
        trigger: float | None = None,
        quantity: int | None = None,
        order_type: str | None = None,
        validity: str | None = None,
        headers: dict | None = None,
    ) -> dict[Any, Any]:
        """Modify an open FivePaisa order.

        Args:
            order_id: Exchange order id to modify.
            price: Replacement limit price. Existing price is reused when
                omitted.
            trigger: Replacement trigger price. Existing trigger is reused when
                omitted.
            quantity: Replacement quantity. Existing quantity is reused when
                omitted.
            order_type: Replacement order type in Fenix format. Existing type
                is reused when omitted. Currently unused — FivePaisa does not
                accept order-type changes via modify.
            validity: Replacement validity. Currently unused — FivePaisa does
                not accept validity changes via modify.
            headers: Optional auth bundle to use for the request. The cached
                bundle from ``authenticate()`` is used when omitted.

        Returns:
            Unified Fenix order record after modification.

        Raises:
            InputError: If ``order_id`` is absent from the order book.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.modify_order(
                order_id=order_id,
                price=price if not isinstance(price, dict) else None,
                trigger=trigger,
                quantity=quantity,
                order_type=order_type,
                validity=validity,
            )

        if isinstance(price, dict) and headers is None:
            headers = price
            price = None

        headers = self._auth_payload(headers)
        info = self.fetch_raw_orderbook(headers=headers)

        order = {}
        for order_det in info["body"]["OrderBookDetail"]:
            if order_det["ExchOrderID"] == order_id:
                order = order_det
                break

        if not order:
            raise InputError({"This orderid does not exist."})

        json_data = {
            "head": {
                "key": headers["user_key"],
            },
            "body": {
                "Price": price or order["Rate"],
                "Qty": quantity or order["Qty"],
                "ExchOrderID": order["ExchOrderID"],
                "DisQty": order["DisClosedQty"],
                "Stoplossprice": trigger or order["SLTriggerRate"],
                "RemoteOrderID": order["RemoteOrderID"],
            },
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("modify_order"),
            endpoint_group="default",
            json=json_data,
            headers=headers["headers"],
        )
        response = self._parse_json_response(response)

        return self.fetch_order(order_id=order_id, headers=headers)

    def cancel_order(
        self,
        order_id: str,
        headers: dict | None = None,
    ) -> dict[Any, Any]:
        """Cancel an open FivePaisa order.

        Args:
            order_id: Exchange order id to cancel.
            headers: Optional auth bundle to use for the request. The cached
                bundle from ``authenticate()`` is used when omitted.

        Returns:
            Unified Fenix order record after cancellation.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.cancel_order(order_id=order_id)

        headers = self._auth_payload(headers)
        json_data = {
            "head": {
                "key": headers["user_key"],
            },
            "body": {
                "ExchOrderID": order_id,
            },
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("cancel_order"),
            endpoint_group="default",
            headers=headers["headers"],
            json=json_data,
        )
        info = self._parse_json_response(response)

        order_id = info["body"]["ExchOrderID"]
        order = self.fetch_order(order_id=order_id, headers=headers)

        return order

    def fetch_positions(
        self,
        headers: dict | None = None,
    ) -> list[dict]:
        """Fetch day and net account positions in the unified Fenix format.

        Args:
            headers: Optional auth bundle to use for the request. The cached
                bundle from ``authenticate()`` is used when omitted.

        Returns:
            Unified Fenix position records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        headers = self._auth_payload(headers)
        response = self.fetch(
            method="POST",
            url=self.get_url("positions"),
            endpoint_group="default",
            json=headers["json_data"],
            headers=headers["headers"],
        )
        info = self._parse_json_response(response)

        positions = []
        for position in info["head"]["NetPositionDetail"]:
            detail = self._position_json_parser(position)
            positions.append(detail)

        return positions

    def fetch_holdings(
        self,
        headers: dict | None = None,
    ) -> list[dict]:
        """Fetch raw FivePaisa holdings.

        Args:
            headers: Optional auth bundle to use for the request. The cached
                bundle from ``authenticate()`` is used when omitted.

        Returns:
            Raw FivePaisa holdings response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_holdings()

        headers = self._auth_payload(headers)
        response = self.fetch(
            method="POST",
            url=self.get_url("holdings"),
            endpoint_group="default",
            json=headers["json_data"],
            headers=headers["headers"],
        )
        info = self._parse_json_response(response)

        return info

        # {'body': {'CacheTime': 300,
        #     'Data': [{'AvgRate': 2059.8125,
        #         'BseCode': 543396,
        #         'CurrentPrice': 624.05,
        #         'DPQty': 80,
        #         'Exch': '\x00',
        #         'ExchType': 'C',
        #         'FullName': 'ONE 97 COMMUNICATIONS LTD',
        #         'NseCode': 6705,
        #         'POASigned': 'N',
        #         'PoolQty': 0,
        #         'Quantity': 80,
        #         'ScripMultiplier': 1,
        #         'Symbol': 'PAYTM'},
        #     {'AvgRate': 22.63,
        #         'BseCode': 540787,
        #         'CurrentPrice': 58.73,
        #         'DPQty': 1,
        #         'Exch': '\x00',
        #         'ExchType': 'C',
        #         'FullName': 'ICICIPRAMC - BHARATIWIN',
        #         'NseCode': 522,
        #         'POASigned': 'N',
        #         'PoolQty': 0,
        #         'Quantity': 1,
        #         'ScripMultiplier': 1,
        #         'Symbol': 'ICICIB22'}],
        #     'Message': 'Success',
        #     'Status': 0},
        #     'head': {'responseCode': '5PHoldingV3',
        #     'status': '0',
        #     'statusDescription': 'Success'}}
