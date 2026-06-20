from __future__ import annotations
import base64
import hashlib
from collections import defaultdict
from datetime import datetime
from urllib.parse import parse_qs, urlparse

from typing import TYPE_CHECKING
from typing import Any, NoReturn

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
    RateLimitExceededError,
    ResponseError,
    TokenDownloadError,
)

if TYPE_CHECKING:
    from requests.models import Response


class Fyers(Broker):
    """Fyers broker adapter for the Fenix trading interface."""

    _API = {
        "doc": "https://myapi.fyers.in/docsv3",
        "servers": {
            "auth": "https://api-t2.fyers.in",
            "api_v2": "https://api.fyers.in/api/v2",
            "api_v3": "https://api-t1.fyers.in/api/v3",
            "market_data": "https://public.fyers.in/sym_details",
        },
        "paths": {
            # --- Auth Flow ---
            "login_otp": {
                "server": "auth",
                "path": "/vagator/v2/send_login_otp_v2",
            },
            "verify_totp": {
                "server": "auth",
                "path": "/vagator/v2/verify_otp",
            },
            "verify_pin": {
                "server": "auth",
                "path": "/vagator/v2/verify_pin_v2",
            },
            "token": {
                "server": "api_v3",
                "path": "/token",
            },
            "validate_authcode": {
                "server": "api_v3",
                "path": "/validate-authcode",
            },

            # --- Order & Portfolio Flow ---
            "place_order": {
                "server": "api_v3",
                "path": "/orders/sync",
            },
            "place_multi_order": {
                "server": "api_v3",
                "path": "/multi-order/sync",
            },
            "place_gtt_order": {
                "server": "api_v3",
                "path": "/gtt/orders/sync",
            },
            "modify_order": {
                "server": "api_v3",
                "path": "/orders",
            },
            "cancel_order": {
                "server": "api_v3",
                "path": "/orders",
            },
            "orderbook": {
                "server": "api_v3",
                "path": "/orders",
            },
            "tradebook": {
                "server": "api_v3",
                "path": "/tradebook",
            },
            "positions": {
                "server": "api_v3",
                "path": "/positions",
            },
            "holdings": {
                "server": "api_v3",
                "path": "/holdings",
            },
            "rms_limits": {
                "server": "api_v3",
                "path": "/funds",
            },
            "profile": {
                "server": "api_v3",
                "path": "/profile",
            },

            # --- Market Data ---
            "instruments": {
                "server": "market_data",
                # Path is templated by exchange/segment, e.g. "/NSE_FO.csv".
                "path": "/exch_seg_sym_master.json",
            },
        }
    }

    STANDARD_MAPS = {
        "side": {
            1: Side.BUY,
            -1: Side.SELL,
        },
        "order_type": {
            2: OrderType.MARKET,
            1: OrderType.LIMIT,
            4: OrderType.SL,
            3: OrderType.SLM,
        },
        "status": {
            6: Status.PENDING,
            5: Status.REJECTED,
            2: Status.FILLED,
            1: Status.CANCELLED,
            4: Status.OPEN,
        },
        "exchange": {
            10: ExchangeCode.NSE,
            11: ExchangeCode.MCX,
            12: ExchangeCode.BSE,
        },
        "segment": {
            "1010": ExchangeCode.NSE,
            "1011": ExchangeCode.NFO,
            "1210": ExchangeCode.BSE,
            "1211": ExchangeCode.BFO,
            "1120": ExchangeCode.MCX,
        },
        "product": {
            "INTRADAY": Product.MIS,
            "CARRYFORWARD": Product.NRML,
            "CNC": Product.CNC,
            "MARGIN": Product.MARGIN,
            "MTF": Product.MTF,
            "BO": Product.BO,
            "CO": Product.CO,
        },
        "validity": {
            "DAY": Validity.DAY,
            "IOC": Validity.IOC,
        },
    }

    REQUEST_MAPS = {
        "side": {
            Side.BUY: 1,
            Side.SELL: -1,
        },
        "exchange": {
            ExchangeCode.NSE: "NSE",
            ExchangeCode.BSE: "BSE",
            ExchangeCode.NFO: "NFO",
            ExchangeCode.BFO: "BFO",
            ExchangeCode.MCX: "MCX",
        },
        "order_type": {
            OrderType.MARKET: 2,
            OrderType.LIMIT: 1,
            OrderType.SL: 4,
            OrderType.SLM: 3,
        },
        "product": {
            Product.MIS: "INTRADAY",
            Product.NRML: "CARRYFORWARD",
            Product.CNC: "CNC",
            Product.MARGIN: "MARGIN",
            Product.MTF: "MTF",
            Product.BO: "BO",
            Product.CO: "CO",
        },
        "validity": {
            Validity.DAY: "DAY",
            Validity.IOC: "IOC",
        },
        "variety": {
            Variety.REGULAR: "NORMAL",
            Variety.STOPLOSS: "STOPLOSS",
            Variety.AMO: "AMO",
            Variety.BO: "ROBO",
        },
    }

    _REQUIRED_AUTH_HEADER_KEYS = (
        "Authorization",
    )

    ERROR_CODE_KEYS = (
        "code",
    )

    ERROR_MESSAGE_KEYS = (
        "message",
        "description",
    )

    _ERROR_MESSAGES = {
        "-8": "Token has expired.",
        "-15": "Invalid token provided.",
        "-16": "Server is unable to authenticate the user token.",
        "-17": "Token passed is either invalid or expired.",
        "-50": (
            "One or more invalid parameters were passed. Refer to the "
            "message field in the API response for details about the "
            "specific invalid inputs."
        ),
        "-51": (
            "Invalid Order ID passed while fetching orders or modifying "
            "an order."
        ),
        "-53": "Invalid position ID passed.",
        "-99": (
            "Order placement was rejected. Refer to the message field in "
            "the API response for the rejection reason."
        ),
        "-300": (
            "Invalid symbol provided. Symbols containing special characters "
            "(e.g., 'M&M') must be URL-encoded (e.g., 'M%26M') when using "
            "direct URLs."
        ),
        "-352": (
            "Invalid App ID provided, or no position available to exit "
            "in the exit position API."
        ),
        "-429": (
            "API rate limit exceeded, either per second, minute, or day."
        ),
        "400": (
            "Bad request. The request is invalid or contains invalid input "
            "for multi leg order placement."
        ),
        "401": "Authorization error. User could not be authenticated.",
        "403": (
            "Permission error. User does not have the necessary permissions."
        ),
        "429": (
            "Rate limit exceeded. User has been blocked for exceeding the "
            "rate limit."
        ),
        "500": "Internal server error.",
    }

    _DIRECT_ERROR_CLASSES = {
        "-8": AuthenticationError,
        "-15": AuthenticationError,
        "-16": AuthenticationError,
        "-17": AuthenticationError,
        "-51": OrderNotFoundError,
        "-99": InvalidOrderError,
        "-300": InputError,
        "-352": ResponseError,
        "401": AuthenticationError,
        "403": PermissionDeniedError,
        "-429": RateLimitExceededError,
        "429": RateLimitExceededError,
    }

    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "Fyers",
            "tokenParams": [
                "user_id",
                "pin",
                "totpstr",
                "api_key",
                "api_secret",
                "redirect_uri",
            ],
            "proxies": {},
            "sensitiveLogKeys": [
                "user_id",
                "pin",
                "totpstr",
                "api_key",
                "api_secret",
                "redirect_uri",
                "fy_id",
                "app_id",
                "otp",
                "identifier",
                "request_key",
                "access_token",
                "auth_code",
                "code",
                "appIdHash",
                "Authorization",
                "PAN",
                "email_id",
                "mobile_number",
            ],
            "enableRateLimit": True,
            "rateLimits": {
                "default": [
                    {
                        "period": 1,        # 1 second
                        "capacity": 10,
                        "cost": 1.0,
                    },
                    {
                        "period": 60,       # 1 minute
                        "capacity": 200,
                        "cost": 1.0,
                    },
                    {
                        "period": 86400,    # 24 hours in seconds
                        "capacity": 10000,
                        "cost": 1.0,
                    },
                ],
            }
        }

    def __init__(self, config: dict | None = None):
        """Initialize the Fyers broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
        """
        super().__init__(config)

    # NFO Script Fetch

    def _fetch_instruments(self, exc_seg: str) -> dict:
        """Download and parse the Fyers instrument master for one segment.

        Args:
            exc_seg: Fyers exchange-segment slug (e.g. ``"NSE_CM"``) substituted
                into the instruments URL.

        Returns:
            The parsed instrument master keyed by Fyers symbol id.
        """
        response = self.fetch(
            method="GET",
            url=self.get_url("instruments").replace("exc_seg", exc_seg),
            endpoint_group="default",
        )
        response.raise_for_status()

        return response.json()

    def load_equity_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE equity token metadata.

        Args:
            data: Optional pre-fetched contract-master data keyed by ``"NSE"``
                and ``"BSE"``. Downloaded automatically when omitted.

        Returns:
            A tuple containing the unified equity token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
        """
        if not data:
            nse_data = self._fetch_instruments("NSE_CM")
            bse_data = self._fetch_instruments("BSE_CM")
        else:
            if "NSE" not in data or "BSE" not in data:
                raise KeyError("JSON data must contain 'NSE' and 'BSE' keys")

            nse_data = data["NSE"]
            bse_data = data["BSE"]

        nse_dict = {}
        bse_dict = {}
        alltoken_dict = {}

        for tok_data in nse_data.values():
            token = tok_data["exToken"]
            symbol = tok_data["exSymbol"]
            exchange = tok_data["exchangeName"]
            record = {
                "Exchange": exchange,
                "Token": tok_data["fyToken"],
                "Exchange_Token": token,
                "Symbol": tok_data["symTicker"],
                "ScriptName": tok_data["exSymName"],
                "TickSize": tok_data["tickSize"],
                "LotSize": tok_data["minLotSize"],
                "FreezeQty": tok_data["qtyFreeze"],
                "Leverage": tok_data.get("leverage", 1),
                "ISIN": tok_data["isin"],
                "DetailedDescription": tok_data["symbolDesc"]
            }
            nse_dict[symbol] = record

            token_key = f"{token}_{exchange}"
            alltoken_dict[token_key] = record

        for tok_data in bse_data.values():
            token = tok_data["exToken"]
            symbol = tok_data["exSymbol"]
            exchange = tok_data["exchangeName"]
            record = {
                "Exchange": exchange,
                "Token": tok_data["fyToken"],
                "Exchange_Token": token,
                "Symbol": tok_data["symTicker"],
                "ScriptName": tok_data["exSymName"],
                "TickSize": tok_data["tickSize"],
                "LotSize": tok_data["minLotSize"],
                "FreezeQty": tok_data["qtyFreeze"],
                "Leverage": tok_data.get("leverage", 1),
                "ISIN": tok_data["isin"],
                "DetailedDescription": tok_data["symbolDesc"]
            }
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
        """Load index token metadata for NSE, BSE, and MCX.

        Args:
            data: Optional pre-fetched contract-master data keyed by ``"NSE"``
                and ``"BSE"``. Downloaded automatically when omitted.

        Returns:
            A tuple containing the unified index token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
        """
        if not data:
            nse_data = self._fetch_instruments("NSE_CM")
            bse_data = self._fetch_instruments("BSE_CM")
        else:
            if "NSE" not in data or "BSE" not in data:
                raise KeyError("JSON data must contain 'NSE' and 'BSE' keys")

            nse_data = data["NSE"]
            bse_data = data["BSE"]

        nse_dict = {}
        bse_dict = {}
        alltoken_dict = {}


        for tok_data in nse_data.values():

            description = tok_data["symbolDesc"]

            if description == "INDEX":
                token = tok_data["exToken"]
                symbol = tok_data["exSymbol"]
                exchange = tok_data["exchangeName"]
                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Symbol": tok_data["symTicker"],
                    "ScriptName": tok_data["symbolDetails"],
                }
                nse_dict[symbol] = record

                token_key = f"{token}_{exchange}"
                alltoken_dict[token_key] = record

        for tok_data in bse_data.values():

            description = tok_data["symbolDesc"]

            if description == "INDEX":
                token = tok_data["exToken"]
                symbol = tok_data["exSymbol"]
                exchange = tok_data["exchangeName"]
                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Symbol": tok_data["symTicker"],
                    "ScriptName": tok_data["symbolDetails"],
                }
                bse_dict[symbol] = record

                token_key = f"{token}_{exchange}"
                alltoken_dict[token_key] = record

        self.token_json["Indices"].update({
            "NSE": nse_dict,
            "BSE": bse_dict,
            # "MCX": mcx_dict,
        })

        self.alltoken_json.update(alltoken_dict)

        return (
            {
                "Indices": {"NSE": nse_dict, "BSE": bse_dict},  # , "MCX": mcx_dict},
            },
            alltoken_dict,
        )

    def load_fno_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load futures and options token metadata for NFO and BFO.

        Args:
            data: Optional pre-fetched contract-master data keyed by ``"NFO"``
                and ``"BFO"``. Downloaded automatically when omitted.

        Returns:
            A tuple containing the unified F&O token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
        """
        if not data:
            nse_data = self._fetch_instruments("NSE_FO")
            bse_data = self._fetch_instruments("BSE_FO")
        else:
            if "NFO" not in data or "BFO" not in data:
                raise KeyError("JSON data must contain 'NFO' and 'BFO' keys")

            nse_data = data["NFO"]
            bse_data = data["BFO"]

        opt_series = [14, 15]
        fut_series = [11, 13]
        dt_dict = {}

        fut_nse = defaultdict(list)
        fut_bse = defaultdict(list)
        opt_nse = defaultdict(list)
        opt_bse = defaultdict(list)
        token_dict = {}


        for tok_data in nse_data.values():

            instrument_type = tok_data["exInstType"]

            if instrument_type in opt_series:

                expiry_raw = tok_data["display_format_mob"]

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d %b %Y").date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    (expiry, exdp) = dt_dict[expiry_raw]



                root = tok_data["exSymbol"]
                strike = self._format_strike(tok_data["strikePrice"])
                option = tok_data["optType"]
                exchange = tok_data["exchangeName"]
                token = tok_data["exToken"]
                symbol = tok_data["exSymName"]

                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Root": root,
                    "Symbol": tok_data["symTicker"],
                    "TickSize": tok_data["tickSize"],
                    "LotSize": tok_data["minLotSize"],
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": option,
                    "ScriptName": f"{root} {exdp} {strike} {option}",
                }

                opt_nse[root].append(record)
                tk = f"{token}_NFO"
                token_dict[tk] = record


            if instrument_type in fut_series:

                expiry_raw = tok_data["display_format_mob"]

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d %b %Y").date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                root = tok_data["exSymbol"]
                exchange = tok_data["exchangeName"]
                token = tok_data["exToken"]
                symbol = tok_data["exSymName"]

                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Root": root,
                    "Symbol": tok_data["symTicker"],
                    "TickSize": tok_data["tickSize"],
                    "LotSize": tok_data["minLotSize"],
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut_nse[root].append(record)
                tk = f"{token}_NFO"
                token_dict[tk] = record

        for tok_data in bse_data.values():

            instrument_type = tok_data["exInstType"]

            if instrument_type in opt_series:

                expiry_raw = tok_data["display_format_mob"]

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d %b %Y").date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    (expiry, exdp) = dt_dict[expiry_raw]



                root = tok_data["exSymbol"]
                strike = self._format_strike(tok_data["strikePrice"])
                option = tok_data["optType"]
                exchange = tok_data["exchangeName"]
                token = tok_data["exToken"]
                symbol = tok_data["exSymName"]

                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Root": root,
                    "Symbol": tok_data["symTicker"],
                    "TickSize": tok_data["tickSize"],
                    "LotSize": tok_data["minLotSize"],
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": option,
                    "ScriptName": f"{root} {exdp} {strike} {option}",
                }

                opt_bse[root].append(record)
                tk = f"{token}_BFO"
                token_dict[tk] = record


            if instrument_type in fut_series:

                expiry_raw = tok_data["display_format_mob"]

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d %b %Y").date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                root = tok_data["exSymbol"]
                exchange = tok_data["exchangeName"]
                token = tok_data["exToken"]
                symbol = tok_data["exSymName"]

                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Root": root,
                    "Symbol": tok_data["symTicker"],
                    "TickSize": tok_data["tickSize"],
                    "LotSize": tok_data["minLotSize"],
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut_bse[root].append(record)
                tk = f"{token}_BFO"
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
        """Load MCX commodity futures and options token metadata.

        Args:
            data: Optional pre-fetched contract-master data keyed by ``"MCX"``.
                Downloaded automatically when omitted.

        Returns:
            A tuple containing the unified MCX token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing ``"MCX"``.
        """
        if not data:
            mcx_data = self._fetch_instruments("MCX_COM")
        else:
            if "MCX" not in data:
                raise KeyError("JSON data must contain 'MCX' key")

            mcx_data = data["MCX"]

        dt_dict = {}

        fut_mcx = defaultdict(list)
        opt_mcx = defaultdict(list)
        token_dict = {}


        for tok_data in mcx_data.values():

            option = tok_data["optType"]

            if option != "XX":

                expiry_raw = tok_data["display_format_mob"]

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d %b %Y").date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    (expiry, exdp) = dt_dict[expiry_raw]



                root = tok_data["exSymbol"]
                option = tok_data["optType"]
                exchange = tok_data["exchangeName"]
                token = tok_data["exToken"]
                symbol = tok_data["exSymName"]

                strike = self._format_strike(tok_data["strikePrice"])


                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Root": root,
                    "Symbol": tok_data["symTicker"],
                    "TickSize": tok_data["tickSize"],
                    "LotSize": tok_data["minLotSize"],
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": option,
                    "ScriptName": f"{root} {exdp} {strike} {option}",
                }

                opt_mcx[root].append(record)
                tk = f"{token}_{exchange}"
                token_dict[tk] = record


            else:

                expiry_raw = tok_data["display_format_mob"]

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d %b %Y").date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                root = tok_data["exSymbol"]
                exchange = tok_data["exchangeName"]
                token = tok_data["exToken"]
                symbol = tok_data["exSymName"]

                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Root": root,
                    "Symbol": tok_data["symTicker"],
                    "TickSize": tok_data["tickSize"],
                    "LotSize": tok_data["minLotSize"],
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut_mcx[root].append(record)
                tk = f"{token}_{exchange}"
                token_dict[tk] = record


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

    def load_ncx_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE commodity (NCX) futures and options token metadata.

        Args:
            data: Optional pre-fetched contract-master data keyed by ``"NCX"``.
                Downloaded automatically when omitted.

        Returns:
            A tuple containing the unified NCX token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing ``"NCX"``.
        """
        if not data:
            ncx_data = self._fetch_instruments("NSE_COM")
        else:
            if "NCX" not in data:
                raise KeyError("JSON data must contain 'NCX' key")

            ncx_data = data["NCX"]

        dt_dict = {}

        fut_ncx = defaultdict(list)
        opt_ncx = defaultdict(list)
        token_dict = {}


        for tok_data in ncx_data.values():

            option = tok_data["optType"]

            if option != "XX":

                expiry_raw = tok_data["display_format_mob"]

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d %b %Y").date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    (expiry, exdp) = dt_dict[expiry_raw]



                root = tok_data["exSymbol"]
                option = tok_data["optType"]
                exchange = tok_data["exchangeName"]
                token = tok_data["exToken"]
                symbol = tok_data["exSymName"]

                strike = self._format_strike(tok_data["strikePrice"])


                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Root": root,
                    "Symbol": tok_data["symTicker"],
                    "TickSize": tok_data["tickSize"],
                    "LotSize": tok_data["minLotSize"],
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": option,
                    "ScriptName": f"{root} {exdp} {strike} {option}",
                }

                opt_ncx[root].append(record)
                tk = f"{token}_NCX"
                token_dict[tk] = record

            else:

                expiry_raw = tok_data["display_format_mob"]

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d %b %Y").date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                root = tok_data["exSymbol"]
                exchange = tok_data["exchangeName"]
                token = tok_data["exToken"]
                symbol = tok_data["exSymName"]

                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Root": root,
                    "Symbol": tok_data["symTicker"],
                    "TickSize": tok_data["tickSize"],
                    "LotSize": tok_data["minLotSize"],
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut_ncx[root].append(record)
                tk = f"{token}_NCX"
                token_dict[tk] = record


        self.token_json["Futures"].update({"NCX": fut_ncx})
        self.token_json["Options"].update({"NCX": opt_ncx})

        self.alltoken_json.update(token_dict)

        return (
            {
                "Futures": {"NCX": fut_ncx},
                "Options": {"NCX": opt_ncx},
            },
            token_dict,
        )

    def load_cds_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load currency derivatives (CDS) futures and options token metadata.

        Args:
            data: Optional pre-fetched contract-master data keyed by ``"CDS"``.
                Downloaded automatically when omitted.

        Returns:
            A tuple containing the unified CDS token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing ``"CDS"``.
        """
        if not data:
            cds_data = self._fetch_instruments("NSE_CD")
        else:
            if "CDS" not in data:
                raise KeyError("JSON data must contain 'CDS' key")

            cds_data = data["CDS"]

        dt_dict = {}

        fut_cds = defaultdict(list)
        opt_cds = defaultdict(list)
        token_dict = {}

        for tok_data in cds_data.values():

            option = tok_data["optType"]

            if option != "XX":

                expiry_raw = tok_data["display_format_mob"]

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d %b %Y").date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    (expiry, exdp) = dt_dict[expiry_raw]



                root = tok_data["exSymbol"]
                option = tok_data["optType"]
                exchange = tok_data["exchangeName"]
                token = tok_data["exToken"]
                symbol = tok_data["exSymName"]

                strike = self._format_strike(tok_data["strikePrice"])

                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Root": root,
                    "Symbol": tok_data["symTicker"],
                    "TickSize": tok_data["tickSize"],
                    "LotSize": tok_data["minLotSize"],
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": option,
                    "ScriptName": f"{root} {exdp} {strike} {option}",
                }

                opt_cds[root].append(record)
                tk = f"{token}_{exchange}"
                token_dict[tk] = record


            else:

                expiry_raw = tok_data["display_format_mob"]

                if expiry_raw not in dt_dict:
                    if expiry_raw == "":
                        expiry_raw = "-".join(tok_data["symDetails"][:-4].split(" ")[1:])
                        dt = datetime.strptime(expiry_raw, "%d-%b-%y").date()
                    else:
                        dt = datetime.strptime(expiry_raw, "%d %b %Y").date()

                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)
                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                root = tok_data["exSymbol"]
                exchange = tok_data["exchangeName"]
                token = tok_data["exToken"]
                symbol = tok_data["exSymName"]

                record = {
                    "Exchange": exchange,
                    "Token": tok_data["fyToken"],
                    "Exchange_Token": token,
                    "Root": root,
                    "Symbol": tok_data["symTicker"],
                    "TickSize": tok_data["tickSize"],
                    "LotSize": tok_data["minLotSize"],
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut_cds[root].append(record)
                tk = f"{token}_{exchange}"
                token_dict[tk] = record

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



    # Headers & Json Parsers

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """Authenticate with Fyers and return request headers.

        Args:
            params: Login credentials and API keys required by Fyers. Must
                contain ``user_id``, ``pin``, ``totpstr``, ``api_key``,
                ``api_secret``, and ``redirect_uri``.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and run the login flow.

        Returns:
            Headers that can authenticate subsequent Fyers API calls.

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

        en_user_id = str(
            base64.b64encode(params["user_id"].encode()),
            encoding="utf-8",
        )
        json_data = {"fy_id": en_user_id, "app_id": "2"}

        response = self.fetch(
            method="POST",
            url=self.get_url("login_otp"),
            endpoint_group="default",
            json=json_data,
        )
        response = self._parse_json_response(response)

        request_key = response["request_key"]
        totp = self.totp_creator(params["totpstr"])
        json_data = {"request_key": request_key, "otp": str(totp)}

        response = self.fetch(
            method="POST",
            url=self.get_url("verify_totp"),
            endpoint_group="default",
            json=json_data,
        )
        response = self._parse_json_response(response)

        request_key = response["request_key"]
        en_pin = str(
            base64.b64encode(params["pin"].encode()),
            encoding="utf-8",
        )
        json_data = {
            "request_key": request_key,
            "identifier": en_pin,
            "identity_type": "pin",
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("verify_pin"),
            endpoint_group="default",
            json=json_data,
        )
        response = self._parse_json_response(response)

        token = response["data"]["access_token"]
        bearer_headers = {"Authorization": f"Bearer {token}"}
        json_data = {
            "fyers_id": params["user_id"],
            "app_id": params["api_key"].split("-")[0],
            "redirect_uri": params["redirect_uri"],
            "appType": params["api_key"].split("-")[-1],
            "code_challenge": "",
            "state": "sample_state",
            "scope": "",
            "nonce": "",
            "response_type": "code",
            "create_cookie": True,
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("token"),
            endpoint_group="default",
            json=json_data,
            headers=bearer_headers,
        )
        response = self._parse_json_response(response)

        parsed = urlparse(response["Url"])
        auth_code = parse_qs(parsed.query)["auth_code"][0]

        api_key_hash = hashlib.sha256(
            f"{params['api_key']}:{params['api_secret']}".encode()
        ).hexdigest()
        json_data = {
            "grant_type": "authorization_code",
            "appIdHash": api_key_hash,
            "code": auth_code,
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("validate_authcode"),
            endpoint_group="default",
            json=json_data,
        )
        response = self._parse_json_response(response)

        access_token = response["access_token"]

        self._headers = {
            "Authorization": f"{params['api_key']}:{access_token}",
        }

        self.reset_session()

        return self._headers

    def _parse_orderbook(
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
        parsed_order = {
            Order.ID: order["id"],
            Order.USER_ID: "",
            Order.TIMESTAMP: datetime.strptime(
                order["orderDateTime"], "%d-%b-%Y %H:%M:%S"
            ),
            Order.SYMBOL: order["symbol"],
            Order.TOKEN: int(order["fyToken"][10:]),
            Order.SIDE: self._parse_from_broker("side", order["side"]),
            Order.TYPE: self._parse_from_broker("order_type", order["type"]),
            Order.AVG_PRICE: order["tradedPrice"],
            Order.PRICE: order["limitPrice"],
            Order.TRIGGER_PRICE: order["stopPrice"],
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: order["qty"],
            Order.FILLED_QTY: order["filledQty"],
            Order.REMAINING_QTY: order["remainingQuantity"],
            Order.CANCELLED_QTY: 0,
            Order.STATUS: self._parse_from_broker("status", order["status"]),
            Order.REJECT_REASON: order["message"],
            Order.DISCLOSED_QUANTITY: order["disclosedQty"],
            Order.PRODUCT: self._parse_from_broker(
                "product", order["productType"]
            ),
            Order.EXCHANGE: self._parse_from_broker(
                "exchange", order["exchange"]
            ),
            Order.SEGMENT: self._parse_from_broker(
                "segment", f"{order['exchange']}{order['segment']}"
            ),
            Order.VALIDITY: self._parse_from_broker(
                "validity", order["orderValidity"]
            ),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_tradebook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """
        Parse Tradebook Order Json Response.

        Args:
            order (dict): Tradebook Order Json Response from Broker.

        Returns:
            dict: Unified fenix Order Response.
        """
        parsed_order = {
            Order.ID: order["orderNumber"],
            Order.USER_ID: "",
            Order.TIMESTAMP: datetime.strptime(
                order["orderDateTime"], "%d-%b-%Y %H:%M:%S"
            ),
            Order.SYMBOL: order["symbol"],
            Order.TOKEN: int(order["fyToken"][10:]),
            Order.SIDE: self._parse_from_broker("side", order["side"]),
            Order.TYPE: "",
            Order.AVG_PRICE: 0.0,
            Order.PRICE: 0.0,
            Order.TRIGGER_PRICE: 0.0,
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: order["tradedQty"],
            Order.FILLED_QTY: 0,
            Order.REMAINING_QTY: 0,
            Order.CANCELLED_QTY: 0,
            Order.STATUS: "",
            Order.REJECT_REASON: "",
            Order.DISCLOSED_QUANTITY: "",
            Order.PRODUCT: "",
            Order.EXCHANGE: self._parse_from_broker(
                "exchange", order["exchange"]
            ),
            Order.SEGMENT: self._parse_from_broker(
                "segment", f"{order['exchange']}{order['segment']}"
            ),
            Order.VALIDITY: "",
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_position(
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
        parsed_position = {
            Position.SYMBOL: position["symbol"],
            Position.TOKEN: int(position["fyToken"][10:]),
            Position.NET_QTY: position["netQty"],
            Position.AVG_PRICE: position["netAvg"],
            Position.MTM: position["realized_profit"],
            Position.PNL: position["pl"],
            Position.BUY_QTY: position["buyQty"],
            Position.BUY_PRICE: position["buyAvg"],
            Position.SELL_QTY: position["sellQty"],
            Position.SELL_PRICE: position["sellAvg"],
            Position.LTP: position["ltp"],
            Position.PRODUCT: self._parse_from_broker(
                "product", position["productType"]
            ),
            Position.EXCHANGE: self._parse_from_broker(
                "segment", f"{position['exchange']}{position['segment']}"
            ),
            Position.INFO: position,
        }

        return parsed_position

    def _parse_profile(
        self,
        profile: dict,
    ) -> dict[Any, Any]:
        """
        Parse User Profile Json Response.

        Args:
            profile (dict): User Profile Json Response from Broker

        Returns:
            dict: Unified fenix Profile Response
        """
        parsed_profile = {
            Profile.CLIENT_ID: profile["fy_id"],
            Profile.NAME: profile["name"],
            Profile.EMAIL_ID: profile["email_id"],
            Profile.MOBILE_NO: profile["mobile_number"],
            Profile.PAN: profile["PAN"],
            Profile.ADDRESS: "",
            Profile.BANK_NAME: "",
            Profile.BANK_BRANCH_NAME: None,
            Profile.BANK_ACC_NO: "",
            Profile.EXCHANGES_ENABLED: "",
            Profile.ENABLED: True,
            Profile.INFO: profile,
        }

        return parsed_profile

    def _extract_fyers_error_code(self, payload: Any) -> str | None:
        """Extract a documented FYERS error code from a payload."""
        error_code = self._extract_error_code(payload)
        if error_code:
            if error_code in self._ERROR_MESSAGES:
                return error_code
            if error_code.lstrip("-").isdigit():
                return error_code

        payload_text = self._stringify_error_payload(payload)
        for documented_code in self._ERROR_MESSAGES:
            if documented_code in payload_text:
                return documented_code

        return None

    def _extract_fyers_error_message(
        self,
        payload: Any,
        error_code: str | None,
    ) -> str | None:
        """Extract the most useful FYERS error message for a payload."""
        error_message = self._extract_error_message(payload)
        documented_message = self._ERROR_MESSAGES.get(error_code or "")

        if documented_message and not error_message:
            return documented_message
        if documented_message and error_message == error_code:
            return documented_message
        if error_message:
            return error_message
        return documented_message

    def _fyers_error_class(
        self,
        error_code: str | None,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve a FYERS payload to the most specific Fenix error class."""
        if error_code in self._DIRECT_ERROR_CLASSES:
            return self._DIRECT_ERROR_CLASSES[error_code]

        message = (error_message or "").lower()
        if any(token in message for token in ("token", "login", "session")):
            return AuthenticationError
        if (
            "permission" in message
            or "restricted" in message
            or "not allowed" in message
            or "read-only" in message
        ):
            return PermissionDeniedError
        if "rate limit" in message or error_code == "-429":
            return RateLimitExceededError
        if "insufficient fund" in message or "margin" in message:
            return InsufficientFundsError
        if "insufficient" in message and (
            "quantity" in message or "holding" in message
        ):
            return InsufficientHoldingsError
        if "invalid order" in message or "order not found" in message:
            return OrderNotFoundError
        if error_code in self._ERROR_MESSAGES:
            if any(
                token in message
                for token in ("order", "price", "quantity", "symbol")
            ):
                return InvalidOrderError
            return InputError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded FYERS payload represents an error."""
        if isinstance(payload, list):
            if not payload:
                return False
            return any(self._payload_indicates_error(item) for item in payload)

        if isinstance(payload, dict):
            if isinstance(payload.get("body"), dict):
                return self._payload_indicates_error(payload["body"])
            if isinstance(payload.get("data"), list):
                return self._payload_indicates_error(payload["data"])

            status = payload.get("s") or payload.get("status")
            if status is not None:
                return str(status).lower() not in {"ok", "success"}

            code = self._extract_fyers_error_code(payload)
            return code is not None and code != "200"

        return self._extract_fyers_error_code(payload) is not None

    def _raise_fyers_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for a FYERS error payload."""
        context = self._http_error_context(response, payload)
        error_code = self._extract_fyers_error_code(payload)
        error_message = self._extract_fyers_error_message(
            payload,
            error_code,
        )

        context["error_code"] = error_code
        context["error_message"] = error_message
        error_cls = self._fyers_error_class(
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
            self._raise_fyers_error(payload, response=exc.response, cause=exc)

        super().handle_http_error(exc)

    def _parse_json_response(self, response: Response) -> Any:
        """Decode an HTTP response and raise FYERS payload errors."""
        json_response = Broker._json_parser(self, response)

        if self._payload_indicates_error(json_response):
            self._raise_fyers_error(json_response, response=response)

        return json_response

    def _parse_place_order_response(self, response: Response) -> dict[Any, Any]:
        """Extract the order id from a synchronous FYERS order response."""
        info = self._parse_json_response(response)
        return {Order.ID: info["id"], Order.INFO: info}

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
        order_tag: str | None = None,
    ) -> dict[str, Any]:
        """Build a FYERS sync place-order payload."""
        order_type = self._resolve_order_type(price, trigger)
        product_type = Product.BO if target else product
        payload = {
            "symbol": token_dict["Symbol"],
            "qty": quantity,
            "type": self._format_for_broker("order_type", order_type),
            "side": self._format_for_broker("side", side),
            "productType": self._format_for_broker("product", product_type),
            "limitPrice": price,
            "stopPrice": trigger,
            "validity": self._format_for_broker("validity", validity),
            "disclosedQty": 0,
            "offlineOrder": variety == Variety.AMO,
            "stopLoss": stoploss,
            "takeProfit": target,
        }

        tag = order_tag if order_tag is not None else unique_id
        if tag and product_type not in {Product.BO, Product.CO}:
            payload["orderTag"] = tag

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
        order_tag: str | None = None,
    ) -> dict[Any, Any]:
        """Place a synchronous normal order through FYERS."""
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

        if self._headers is None:
            raise AuthenticationError("FYERS headers are not set.")

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
            order_tag=order_tag,
        )

        response = self.fetch(
            method="POST",
            url=self.get_url("place_order"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def place_multi_order(
        self,
        orders: list[dict[str, Any]],
    ) -> Any:
        """Place up to 10 synchronous FYERS orders using the multi-order API."""
        if not orders:
            raise InputError("At least one order is required.")
        if len(orders) > 10:
            raise InputError("FYERS multi-order supports at most 10 orders.")
        if self._headers is None:
            raise AuthenticationError("FYERS headers are not set.")

        response = self.fetch(
            method="POST",
            url=self.get_url("place_multi_order"),
            endpoint_group="default",
            json=orders,
            headers=self._headers,
        )

        return self._parse_json_response(response)

    def place_gtt_order(
        self,
        token_dict: dict,
        quantity: int,
        side: str,
        product: str,
        price: float,
        trigger: float,
        order_tag: str | None = None,
        leg2_price: float | None = None,
        leg2_trigger: float | None = None,
        leg2_quantity: int | None = None,
    ) -> dict[Any, Any]:
        """Place a synchronous Single or OCO GTT order through FYERS."""
        if quantity <= 0:
            raise InputError("Order quantity must be greater than 0.")
        if price <= 0 or trigger <= 0:
            raise InputError("GTT price and trigger must be greater than 0.")
        if self._headers is None:
            raise AuthenticationError("FYERS headers are not set.")

        order_info = {
            "leg1": {
                "price": price,
                "triggerPrice": trigger,
                "qty": quantity,
            }
        }

        has_leg2 = any(
            value is not None
            for value in (leg2_price, leg2_trigger, leg2_quantity)
        )
        if has_leg2:
            if (
                leg2_price is None
                or leg2_trigger is None
                or leg2_quantity is None
            ):
                raise InputError(
                    "OCO GTT requires leg2_price, leg2_trigger, "
                    "and leg2_quantity."
                )
            if leg2_price <= 0 or leg2_trigger <= 0 or leg2_quantity <= 0:
                raise InputError("OCO GTT leg2 values must be greater than 0.")
            order_info["leg2"] = {
                "price": leg2_price,
                "triggerPrice": leg2_trigger,
                "qty": leg2_quantity,
            }

        json_data = {
            "side": self._format_for_broker("side", side),
            "symbol": token_dict["Symbol"],
            "productType": self._format_for_broker("product", product),
            "orderInfo": order_info,
        }
        if order_tag:
            json_data["orderTag"] = order_tag

        response = self.fetch(
            method="POST",
            url=self.get_url("place_gtt_order"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    # Order Details, OrderBook & TradeBook

    def fetch_raw_orderbook(
        self,
    ) -> list[dict]:
        """
        Fetch Raw Orderbook Details, without any Standardization.

        Returns:
            list[dict]: Raw Broker Orderbook Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        response = self.fetch(
            method="GET",
            url=self.get_url("orderbook"),
            endpoint_group="default",
            headers=self._headers,
        )
        return self._parse_json_response(response)

    def fetch_orderbook(
        self,
    ) -> list[dict]:
        """
        Fetch Orderbook Details.

        Returns:
            list[dict]: List of dictionaries of orders using fenix Unified Order Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        info = self.fetch_raw_orderbook()

        orders = []
        for order in info["orderBook"]:
            detail = self._parse_orderbook(order)
            orders.append(detail)

        return orders

    def fetch_tradebook(
        self,
    ) -> list[dict]:
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
            endpoint_group="default",
            headers=self._headers,
        )
        info = self._parse_json_response(response)

        orders = []
        if info["tradeBook"]:
            for order in info["tradeBook"]:
                detail = self._parse_tradebook(order)
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
            OrderNotFoundError: If order does not exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        params = {"id": order_id}
        response = self.fetch(
            method="GET",
            url=self.get_url("orderbook"),
            endpoint_group="default",
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)

        order_book = info.get("orderBook") or []
        if not order_book:
            raise OrderNotFoundError("This order_id does not exist.")

        return self._parse_orderbook(order_book[0])

    # Order Modification

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
            raw_order_json (dict | None, optional): Reserved for broker-specific
                extensions. Defaults to None.
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

        json_data = {
            "id": order_id,
            "qty": quantity,
            "limitPrice": price,
            "stopPrice": trigger,
            "type": (
                self._format_for_broker("order_type", order_type)
                if order_type
                else None
            ),
        }

        for key in list(json_data):
            if not json_data[key]:
                del json_data[key]

        response = self.fetch(
            method="PATCH",
            url=self.get_url("modify_order"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        self._parse_json_response(response)

        return self.fetch_order(order_id=order_id)

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

        json_data = {"id": order_id}
        response = self.fetch(
            method="DELETE",
            url=self.get_url("cancel_order"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        info = self._parse_json_response(response)
        return self.fetch_order(order_id=info["id"])

    # Positions, Account Limits & Profile

    def fetch_day_positions(
        self,
    ) -> dict[Any, Any]:
        """
        Fetch the Day's Account Positions.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
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

        positions = []
        for position in info["netPositions"]:
            detail = self._parse_position(position)
            positions.append(detail)

        return positions

    def fetch_net_positions(
        self,
    ) -> dict[Any, Any]:
        """
        Fetch Total Account Positions.

        Returns:
            dict[Any, Any]: fenix Unified Position Response
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        return self.fetch_day_positions()

    def fetch_holdings(
        self,
    ) -> dict[Any, Any]:
        """
        Fetch Account Holdings.

        Returns:
            dict[Any, Any]: fenix Unified Positions Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_holdings()

        response = self.fetch(
            method="GET",
            url=self.get_url("holdings"),
            endpoint_group="default",
            headers=self._headers,
        )
        return self._parse_json_response(response)

    def fetch_margin_limits(
        self,
    ) -> dict[Any, Any]:
        """
        Fetch Risk Management System Limits.

        Returns:
            dict: fenix Unified RMS Limits Response.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_margin_limits()

        response = self.fetch(
            method="GET",
            url=self.get_url("rms_limits"),
            endpoint_group="default",
            headers=self._headers,
        )
        return self._parse_json_response(response)

    def fetch_profile(
        self,
    ) -> dict[Any, Any]:
        """
        Fetch Profile Details of the User.

        Returns:
            dict: fenix Unified Profile Response.
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
