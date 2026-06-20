from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import TYPE_CHECKING, Any, NoReturn

from requests.exceptions import HTTPError

from fenix.base.broker import Broker
from fenix.base.constants import (
    ExchangeCode,
    Order,
    OrderType,
    Position,
    Product,
    Profile,
    RMS,
    Side,
    Status,
    Validity,
    Variety,
)
from fenix.base.errors import (
    AuthenticationError,
    BrokerError,
    InsufficientFundsError,
    InsufficientHoldingsError,
    InputError,
    InvalidOrderError,
    PermissionDeniedError,
    OrderNotFoundError,
    ResponseError,
)

if TYPE_CHECKING:
    from requests.models import Response


class AngelOne(Broker):
    """AngelOne broker adapter for the Fenix trading interface."""

    _API = {
        'doc': "https://smartapi.angelbroking.com/docs",
        'servers': {
            'rest': 'https://apiconnect.angelbroking.com',
            'market': 'https://margincalculator.angelone.in',
        },
        'paths': {
            # Auth Flow
            'token': {
                'server': 'rest',
                'path': '/rest/auth/angelbroking/jwt/v1/generateTokens',
            },
            'session': {
                'server': 'rest',
                'path': '/rest/auth/angelbroking/user/v1/loginByPassword',
            },
            'logout': {
                'server': 'rest',
                'path': '/rest/secure/angelbroking/user/v1/logout',
            },

            # Order & Portfolio Flow
            'place_order': {
                'server': 'rest',
                'path': '/rest/secure/angelbroking/order/v1/placeOrder',
            },
            'modify_order': {
                'server': 'rest',
                'path': '/rest/secure/angelbroking/order/v1/modifyOrder',
            },
            'cancel_order': {
                'server': 'rest',
                'path': '/rest/secure/angelbroking/order/v1/cancelOrder',
            },
            'orderbook': {
                'server': 'rest',
                'path': '/rest/secure/angelbroking/order/v1/getOrderBook',
            },
            'tradebook': {
                'server': 'rest',
                'path': '/rest/secure/angelbroking/order/v1/getTradeBook',
            },
            'positions': {
                'server': 'rest',
                'path': '/rest/secure/angelbroking/order/v1/getPosition',
            },
            'holdings': {
                'server': 'rest',
                'path': (
                    '/rest/secure/angelbroking/portfolio/v1/getAllHolding'
                ),
            },
            'profile': {
                'server': 'rest',
                'path': '/rest/secure/angelbroking/user/v1/getProfile',
            },
            'funds': {
                'server': 'rest',
                'path': '/rest/secure/angelbroking/user/v1/getRMS',
            },

            # Market Data & Others
            'ltp': {
                'server': 'rest',
                'path': '/rest/secure/angelbroking/order/v1/getLtpData',
            },
            'historical': {
                'server': 'rest',
                'path': (
                    '/rest/secure/angelbroking/historical/v1/getCandleData'
                ),
            },
            'instruments': {
                'server': 'market',
                'path': '/OpenAPI_File/files/OpenAPIScripMaster.json',
            },
        }
    }

    STANDARD_MAPS = {
        'status': {
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
        'product': {
            "DELIVERY": Product.CNC,
            "CARRYFORWARD": Product.NRML,
            "MARGIN": Product.MARGIN,
            "INTRADAY": Product.MIS,
            "BO": Product.BO,
        },
        'order_type': {
            "MARKET": OrderType.MARKET,
            "LIMIT": OrderType.LIMIT,
            "STOPLOSS_LIMIT": OrderType.SL,
            "STOPLOSS_MARKET": OrderType.SLM
        },
        'variety': {
            "NORMAL": Variety.REGULAR,
            "STOPLOSS": Variety.STOPLOSS,
            "AMO": Variety.AMO,
            "ROBO": Variety.BO,
        },
        'exchange': {
            "NSE": ExchangeCode.NSE,
            "BSE": ExchangeCode.BSE,
            "NFO": ExchangeCode.NFO,
            "BFO": ExchangeCode.BFO,
            "MCX": ExchangeCode.MCX,
            "CDS": ExchangeCode.CDS,
            "NCO": ExchangeCode.NCO,
            "NCDEX": ExchangeCode.NCX,
        },
        "side": {
            "BUY": Side.BUY,
            "SELL": Side.SELL,
        },
        "validity": {
            "DAY": Validity.DAY,
            "IOC": Validity.IOC,
        }
    }

    REQUEST_MAPS = {}

    for map_name, mapping_dict in STANDARD_MAPS.items():
        inverse_map = {v: k for k, v in mapping_dict.items()}
        REQUEST_MAPS[map_name] = inverse_map

    ERROR_CODE_KEYS = (
        "errorcode",
    )

    ERROR_MESSAGE_KEYS = (
        "message",
    )

    _ERROR_MESSAGES = {
        # Auth & Token
        "AG8001": "Invalid Token",
        "AG8002": "Token Expired",
        "AG8003": "Token missing",
        "AB8050": "Invalid Refresh Token",
        "AB8051": "Refresh Token Expired",
        # Login & Account
        "AB1000": "Invalid Email Or Password",
        "AB1001": "Invalid Email",
        "AB1002": "Invalid Password Length",
        "AB1003": "Client Already Exists",
        "AB1004": "Something Went Wrong, Please Try After Sometime",
        "AB1005": "User Type Must Be USER",
        "AB1006": "Client Is Block For Trading",
        "AB1007": "AMX Error",
        "AB1008": "Invalid Order Variety",
        "AB1009": "Symbol Not Found",
        "AB1010": "AMX Session Expired",
        "AB1011": "Client not login",
        "AB1012": "Invalid Product Type",
        "AB1013": "Order not found",
        "AB1014": "Trade not found",
        "AB1015": "Holding not found",
        "AB1016": "Position not found",
        "AB1017": "Position conversion failed",
        "AB1018": "Failed to get symbol details",
        "AB1031": "Old Password Mismatch",
        "AB1032": "User Not Found",
        "AB2000": "Error not specified",
        "AB2001": "Internal Error, Please try after sometime",
        "AB2002": "ROBO order is block",
        "AB2020": "Insufficient Funds",
        "AB4008": "ordertag length should be less than 20 characters",
    }

    _DIRECT_ERROR_CLASSES = {
        "AG8001": AuthenticationError,
        "AG8002": AuthenticationError,
        "AG8003": AuthenticationError,
        "AB8050": AuthenticationError,
        "AB8051": AuthenticationError,
        "AB1000": AuthenticationError,
        "AB1001": AuthenticationError,
        "AB1002": AuthenticationError,
        "AB1010": AuthenticationError,
        "AB1011": AuthenticationError,
        "AB1031": AuthenticationError,
        "AB1032": AuthenticationError,
        "AB1006": PermissionDeniedError,
        "AB1008": InvalidOrderError,
        "AB1009": InvalidOrderError,
        "AB1012": InvalidOrderError,
        "AB1018": InvalidOrderError,
        "AB2002": InvalidOrderError,
        "AB4008": InvalidOrderError,
        "AB1013": OrderNotFoundError,
        "AB1014": OrderNotFoundError,
        "AB1015": OrderNotFoundError,
        "AB1016": OrderNotFoundError,
        "AB1017": ResponseError,
        "AB2020": InsufficientFundsError,
    }

    _REQUIRED_AUTH_HEADER_KEYS = (
        "Content-type",
        "X-ClientLocalIP",
        "X-ClientPublicIP",
        "X-MACAddress",
        "Accept",
        "X-PrivateKey",
        "X-UserType",
        "X-SourceID",
        "Authorization",
        "x-api-key",
        "x-client-code",
        "x-feed-token",
    )

    def describe(self) -> dict:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "AngelOne",
            "tokenParams": [
                "user_id",
                "pin",
                "totpstr",
                "api_key",
            ],
            "proxies": {},
            "sensitiveLogKeysIncludeDefault": True,
            "sensitiveLogKeys": [
                # Login request body
                "clientcode",
                "user_id",
                "totpstr",
                # Auth response tokens
                "jwtToken",
                "refreshToken",
                "feedToken",
                # Authenticated request headers
                "X-PrivateKey",
                "x-api-key",
                "x-client-code",
                "x-feed-token",
            ],
            "enableRateLimit": True,
            "rateLimits": {
                "auth": [
                    {
                        "period": 1,
                        "capacity": 1,
                        "cost": 1.0
                    },
                    {
                        "period": 3600,
                        "capacity": 1000,
                        "cost": 1.0
                    },
                ],
                "orders": [
                    {
                        "period": 1,
                        "capacity": 20,
                        "cost": 1.0
                    },
                    {
                        "period": 60,
                        "capacity": 500,
                        "cost": 1.0
                    },
                    {
                        "period": 3600,
                        "capacity": 1000,
                        "cost": 1.0
                    },
                ],
                "post_trade": {
                    "period": 1,
                    "capacity": 1,
                    "cost": 1.0
                },
                "user": {
                    "period": 1,
                    "capacity": 3,
                    "cost": 1.0
                },
                "funds": {
                    "period": 1,
                    "capacity": 2,
                    "cost": 1.0
                },
                "market": [
                    {
                        "period": 1,
                        "capacity": 10,
                        "cost": 1.0
                    },
                    {
                        "period": 60,
                        "capacity": 500,
                        "cost": 1.0
                    },
                    {
                        "period": 3600,
                        "capacity": 1000,
                        "cost": 1.0
                    },
                ],
                "historical": [
                    {
                        "period": 1,
                        "capacity": 3,
                        "cost": 1.0
                    },
                    {
                        "period": 60,
                        "capacity": 180,
                        "cost": 1.0
                    },
                    {
                        "period": 3600,
                        "capacity": 5000,
                        "cost": 1.0
                    },
                ],
                "default": {
                    "period": 1,
                    "capacity": 1,
                    "cost": 1.0
                },
            }
        }

    def __init__(self, config: dict | None = None):
        """Initialize the AngelOne broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
        """
        super().__init__(config)

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """Authenticate with AngelOne and return request headers.

        Args:
            params: Login credentials and API keys required by AngelOne.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and run the login flow.

        Returns:
            Headers that can authenticate subsequent AngelOne API calls.

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

        headers = {
            "Content-type": "application/json",
            "X-ClientLocalIP": "127.0.0.1",
            "X-ClientPublicIP": "106.193.147.98",
            "X-MACAddress": "00:00:00:00:00:00",
            "Accept": "application/json",
            "X-PrivateKey": params["api_key"],
            "X-UserType": "USER",
            "X-SourceID": "WEB",
        }

        json_data = {
            "clientcode": params["user_id"],
            "password": params["pin"],
            "totp": totp,
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("session"),
            endpoint_group="auth",
            json=json_data,
            headers=headers,
        )

        response = self._parse_json_response(response)

        self._headers = {
            "Content-type": "application/json",
            "X-ClientLocalIP": "127.0.0.1",
            "X-ClientPublicIP": "106.193.147.98",
            "X-MACAddress": "00:00:00:00:00:00",
            "Accept": "application/json",
            "X-PrivateKey": params["api_key"],
            "X-UserType": "USER",
            "X-SourceID": "WEB",
            "Authorization": f"Bearer {response['jwtToken']}",
            "x-api-key": "nBmFCnuK",
            "x-client-code": params["user_id"],
            "x-feed-token": response["feedToken"],
        }

        self.reset_session()

        return self._headers

    # Script Fetch

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
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
            )

            eq_data = self._parse_json_response(response)

        else:
            eq_data = data

        nse_dict = {}
        bse_dict = {}
        alltoken_dict = {}

        for tok_data in eq_data:

            if (
                tok_data['exch_seg'] == 'NSE'
                and tok_data['instrumenttype'] == ''
            ):
                name = tok_data['name']
                token = tok_data['token']
                exchange = tok_data["exch_seg"]

                if "NSETEST" in name:
                    continue

                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Symbol": tok_data["symbol"],
                    "ScriptName": name,
                    "LotSize": tok_data["lotsize"],
                    "TickSize": str(float(tok_data["tick_size"]) / 100),
                }

                nse_dict[name] = record

                token_key = f"{token}_{exchange}"
                alltoken_dict[token_key] = record

            elif (
                tok_data['exch_seg'] == 'BSE'
                and tok_data['instrumenttype'] == ''
            ):
                name = tok_data['name']
                token = tok_data['token']
                exchange = tok_data["exch_seg"]

                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Symbol": tok_data["symbol"],
                    "ScriptName": name,
                    "LotSize": tok_data["lotsize"],
                    "TickSize": str(float(tok_data["tick_size"]) / 100),
                }

                bse_dict[name] = record

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
            data: Optional pre-fetched contract-master data keyed by
                ``"NSE"``, ``"BSE"``, and ``"MCX"``.

        Returns:
            A tuple containing the unified index token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
        """
        if not data:
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
            )

            idx_data = self._parse_json_response(response)

        else:
            idx_data = data

        nse_dict = {}
        bse_dict = {}
        mcx_dict = {}
        ncd_dict = {}
        token_dict = {}

        for tok_data in idx_data:
            if tok_data['instrumenttype'] == 'AMXIDX':

                name = tok_data['name']
                token = tok_data['token']
                exchange = tok_data['exch_seg']
                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Symbol": tok_data["symbol"],
                    "ScriptName": name,
                }

                if exchange == 'NCDEX':
                    tk = f"{token}_{exchange}"
                    ncd_dict[name] = record
                elif exchange == 'NSE':
                    tk = f"{token}_{exchange}"
                    nse_dict[name] = record

                elif exchange == 'BSE':
                    tk = f"{token}_{exchange}"
                    bse_dict[name] = record

                elif exchange == 'MCX':
                    tk = f"{token}_{exchange}"
                    mcx_dict[name] = record
                else:
                    continue

                token_dict[tk] = record

        self.token_json["Indices"].update({
            "NSE": nse_dict,
            "BSE": bse_dict,
            "MCX": mcx_dict,
            "NCD": ncd_dict,
        })

        self.alltoken_json.update(token_dict)

        return (
            {
                "Indices": {"NSE": nse_dict, "BSE": bse_dict,
                            "MCX": mcx_dict, "NCD": ncd_dict,
                            },
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
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving contract-master data.
        """
        if not data:
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
            )

            fno_data = self._parse_json_response(response)

        else:
            fno_data = data

        fut_nse = defaultdict(list)
        fut_bse = defaultdict(list)
        opt_nse = defaultdict(list)
        opt_bse = defaultdict(list)
        token_dict = {}

        opt_series = ["OPTIDX", "OPTSTK"]
        fut_series = ["FUTSTK", "FUTIDX"]
        dt_dict = {}

        for tok_data in fno_data:

            expiry_raw = tok_data["expiry"]
            root = tok_data["name"]
            instrument_type = tok_data["instrumenttype"]
            exchange = tok_data["exch_seg"]
            token = tok_data["token"]

            if "NSETEST" in root:
                continue

            if exchange in ["NFO", "BFO"]:

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d%b%Y")
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                if instrument_type in fut_series:
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": tok_data["symbol"],
                        "TickSize": str(float(tok_data["tick_size"]) / 100),
                        "LotSize": tok_data["lotsize"],
                        "Expiry": expiry,
                        "ScriptName": f"{root} {exdp} FUT",
                    }

                    if exchange == "NFO":
                        fut_nse[root].append(record)
                    else:
                        fut_bse[root].append(record)

                elif instrument_type in opt_series:
                    option = tok_data["symbol"][-2:]
                    strike = self._format_strike(float(tok_data["strike"]) // 100)
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": tok_data["symbol"],
                        "TickSize": str(float(tok_data["tick_size"]) / 100),
                        "LotSize": tok_data["lotsize"],
                        "Expiry": expiry,
                        "StrikePrice": strike,
                        "Option": option,
                        "ScriptName": f"{root} {exdp} {strike} {option}",
                    }

                    if exchange == "NFO":
                        opt_nse[root].append(record)
                    else:
                        opt_bse[root].append(record)

                else:
                    continue

                tk = f"{token}_{exchange}"
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
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving contract-master data.
        """
        if not data:
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
            )

            mcx_data = self._parse_json_response(response)

        else:
            mcx_data = data

        fut_mcx = defaultdict(list)
        opt_mcx = defaultdict(list)
        token_dict = {}

        opt_series = ['OPTIDX', 'OPTFUT']
        fut_series = ['FUTIDX', 'FUTCOM']
        all_series = opt_series + fut_series
        dt_dict = {}

        for tok_data in mcx_data:

            expiry_raw = tok_data["expiry"]
            root = tok_data["name"]
            instrument_type = tok_data["instrumenttype"]
            exchange = tok_data["exch_seg"]
            token = tok_data["token"]

            if exchange == "MCX":

                if instrument_type not in all_series:
                    continue

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d%b%Y")
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                if instrument_type in fut_series:
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": tok_data["symbol"],
                        "TickSize": str(float(tok_data["tick_size"]) / 100),
                        "LotSize": tok_data["lotsize"],
                        "Expiry": expiry,
                        "ScriptName": f"{root} {exdp} FUT",
                    }

                    fut_mcx[root].append(record)

                elif instrument_type in opt_series:
                    option = tok_data["symbol"][-2:]
                    if root == "ZINC":
                        strike = self._format_strike(float(tok_data["strike"]) / 100)
                    else:
                        strike = self._format_strike(float(tok_data["strike"]) // 100)
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": tok_data["symbol"],
                        "TickSize": str(float(tok_data["tick_size"]) / 100),
                        "LotSize": tok_data["lotsize"],
                        "Expiry": expiry,
                        "StrikePrice": strike,
                        "Option": option,
                        "ScriptName": f"{root} {exdp} {strike} {option}",
                    }

                    opt_mcx[root].append(record)

                else:
                    continue

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

    def load_cds_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load currency derivatives token metadata for CDS.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"CDS"``.

        Returns:
            A tuple containing unified currency futures/options token maps and
            an all-token lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving contract-master data.
        """
        if not data:
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
            )

            cds_data = self._parse_json_response(response)

        else:
            cds_data = data

        fut_cds = defaultdict(list)
        opt_cds = defaultdict(list)
        token_dict = {}

        opt_series = ["OPTCUR", "OPTIRC"]
        fut_series = ["FUTCUR", "FUTIRC", "FUTIRT"]
        all_series = opt_series + fut_series
        dt_dict = {}

        for tok_data in cds_data:

            expiry_raw = tok_data["expiry"]
            root = tok_data["name"]
            instrument_type = tok_data["instrumenttype"]
            exchange = tok_data["exch_seg"]
            token = tok_data["token"]

            if exchange == "CDS":

                if "NSETEST" in root:
                    continue

                if instrument_type not in all_series:
                    continue

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d%b%Y")
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                if instrument_type in fut_series:
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": tok_data["symbol"],
                        "TickSize": str(float(tok_data["tick_size"]) / 100),
                        "LotSize": tok_data["lotsize"],
                        "Expiry": expiry,
                        "ScriptName": f"{root} {exdp} FUT",
                    }

                    fut_cds[root].append(record)

                elif instrument_type in opt_series:
                    option = tok_data["symbol"][-2:]
                    strike = self._format_strike(float(tok_data["strike"]) / 100)
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": tok_data["symbol"],
                        "TickSize": str(float(tok_data["tick_size"]) / 100),
                        "LotSize": tok_data["lotsize"],
                        "Expiry": expiry,
                        "StrikePrice": strike,
                        "Option": option,
                        "ScriptName": f"{root} {exdp} {strike} {option}",
                    }

                    opt_cds[root].append(record)

                else:
                    continue

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

    def load_ncx_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NCDEX commodity futures token metadata.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"NCDEX"``.

        Returns:
            A tuple containing the unified NCDEX futures token map and an
            all-token lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving contract-master data.
        """
        if not data:
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
            )

            ncd_data = self._parse_json_response(response)

        else:
            ncd_data = data

        fut_ncd = defaultdict(list)
        fut_series = ["OPTFUT", "FUTCOM"]
        token_dict = {}
        dt_dict = {}

        for tok_data in ncd_data:

            expiry_raw = tok_data["expiry"]
            root = tok_data["name"]
            instrument_type = tok_data["instrumenttype"]
            exchange = tok_data["exch_seg"]
            token = tok_data["token"]

            if exchange == "NCDEX":

                if instrument_type not in fut_series:
                    continue

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d%b%Y")
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                if instrument_type in fut_series:
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": tok_data["symbol"],
                        "TickSize": str(float(tok_data["tick_size"]) / 100),
                        "LotSize": tok_data["lotsize"],
                        "Expiry": expiry,
                        "ScriptName": f"{root} {exdp} FUT",
                    }

                    fut_ncd[root].append(record)
                    tk = f"{token}_{exchange}"
                    token_dict[tk] = record

                else:
                    continue

        self.token_json["Futures"].update({"NCX": fut_ncd})

        self.alltoken_json.update(token_dict)

        return (
            {
                "Futures": {"NCX": fut_ncd},
            },
            token_dict,
        )

    def load_nco_tokens(
        self,
        data: dict[str, list] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NCO (NSE commodity) futures and options token metadata.

        Args:
            data: Optional pre-fetched contract-master data keyed by
                ``"NCO"``.

        Returns:
            A tuple containing unified NCO futures/options token maps and
            an all-token lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving contract-master data.
        """
        if not data:
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
            )

            nco_data = self._parse_json_response(response)

        else:
            nco_data = data

        fut_nco = defaultdict(list)
        opt_nco = defaultdict(list)
        token_dict = {}

        opt_series = ['OPTBLN', 'OPTFUT']
        fut_series = ['FUTBAS', 'OPTBLN', 'FUTBLN', 'FUTENR']
        all_series = opt_series + fut_series
        dt_dict = {}

        for tok_data in nco_data:

            expiry_raw = tok_data["expiry"]
            root = tok_data["name"]
            instrument_type = tok_data["instrumenttype"]
            exchange = tok_data["exch_seg"]
            token = tok_data["token"]

            if exchange == "NCO":

                if "NSETEST" in root:
                    continue

                if instrument_type not in all_series:
                    continue

                if expiry_raw not in dt_dict:
                    dt = datetime.strptime(expiry_raw, "%d%b%Y")
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime('%d-%b').upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                if instrument_type in fut_series:
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": tok_data["symbol"],
                        "TickSize": str(float(tok_data["tick_size"]) / 100),
                        "LotSize": tok_data["lotsize"],
                        "Expiry": expiry,
                        "ScriptName": f"{root} {exdp} FUT",
                    }

                    fut_nco[root].append(record)

                elif instrument_type in opt_series:
                    option = tok_data["symbol"][-2:]
                    if root == "ZINC":
                        strike = self._format_strike(float(tok_data["strike"]) / 100)
                    else:
                        strike = self._format_strike(float(tok_data["strike"]) // 100)
                    record = {
                        "Exchange": exchange,
                        "Token": token,
                        "Root": root,
                        "Symbol": tok_data["symbol"],
                        "TickSize": str(float(tok_data["tick_size"]) / 100),
                        "LotSize": tok_data["lotsize"],
                        "Expiry": expiry,
                        "StrikePrice": strike,
                        "Option": option,
                        "ScriptName": f"{root} {exdp} {strike} {option}",
                    }

                    opt_nco[root].append(record)
                else:
                    continue

                tk = f"{token}_{exchange}"
                token_dict[tk] = record

        self.token_json["Futures"].update({"NCO": fut_nco})
        self.token_json["Options"].update({"NCO": opt_nco})

        self.alltoken_json.update(token_dict)

        return (
            {
                "Futures": {"NCO": fut_nco},
                "Options": {"NCO": opt_nco},
            },
            token_dict,
        )

    # Json Parsers

    def _extract_angelone_error_code(self, payload: Any) -> str | None:
        """Extract a documented AngelOne error code from a payload."""
        error_code = self._extract_error_code(payload)
        if error_code:
            error_code = error_code.upper()
            if error_code in self._ERROR_MESSAGES:
                return error_code
            if error_code.startswith(("AB", "AG")):
                return error_code

        payload_text = self._stringify_error_payload(payload).upper()
        for documented_code in self._ERROR_MESSAGES:
            if documented_code in payload_text:
                return documented_code

        return None

    def _extract_angelone_error_message(
        self,
        payload: Any,
        error_code: str | None,
    ) -> str | None:
        """Extract the most useful AngelOne error message for a payload."""
        error_message = self._extract_error_message(payload)
        documented_message = self._ERROR_MESSAGES.get(error_code or "")

        if documented_message and not error_message:
            return documented_message
        if documented_message and error_message == error_code:
            return documented_message
        if error_message:
            return error_message
        return documented_message

    def _angelone_error_class(
        self,
        error_code: str | None,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve an AngelOne payload to a Fenix error class."""
        if error_code in self._DIRECT_ERROR_CLASSES:
            return self._DIRECT_ERROR_CLASSES[error_code]

        message = (error_message or "").lower()
        if any(token in message for token in ("session", "token", "login")):
            return AuthenticationError
        if (
            "block" in message
            or "permission" in message
            or "read-only" in message
        ):
            return PermissionDeniedError
        if "insufficient fund" in message or "margin" in message:
            return InsufficientFundsError
        if "insufficient" in message and (
                "quantity" in message or "holding" in message):
            return InsufficientHoldingsError
        if "order not found" in message or "not in your order book" in message:
            return OrderNotFoundError
        if error_code in self._ERROR_MESSAGES:
            if any(
                token in message
                for token in (
                    "order",
                    "price",
                    "quantity",
                    "symbol")):
                return InvalidOrderError
            return InputError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded AngelOne payload represents an error."""
        if isinstance(payload, list):
            if not payload:
                return False
            return self._payload_indicates_error(payload[0])

        if isinstance(payload, dict):
            status = payload.get("success") or payload.get("status")
            if isinstance(status, bool):
                return status is False
            if isinstance(status, str):
                return status.lower() == "false"

            return self._extract_angelone_error_code(payload) is not None

        return self._extract_angelone_error_code(payload) is not None

    def _raise_angelone_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for an AngelOne error payload."""
        context = self._http_error_context(response, payload)
        error_code = self._extract_angelone_error_code(payload)
        error_message = self._extract_angelone_error_message(
            payload,
            error_code,
        )

        context["error_code"] = error_code
        context["error_message"] = error_message
        error_cls = self._angelone_error_class(
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
            self._raise_angelone_error(
                payload, response=exc.response, cause=exc)

        super().handle_http_error(exc)

    def _parse_json_response(self, response: Response) -> Any:
        """Decode an HTTP response and raise broker-specific payload errors.

        AngelOne wraps authenticated responses in a ``{success, message,
        errorcode, data}`` envelope. Public endpoints (e.g. the instrument
        master) return raw lists. This method normalises both shapes:
        wrapped envelopes are validated and unwrapped to the ``data`` payload,
        while raw payloads are returned untouched.
        """
        json_response = self._json_parser(response)

        if isinstance(
                json_response, dict) and (
                "success" in json_response or "status" in json_response):
            if self._payload_indicates_error(json_response):
                self._raise_angelone_error(
                    json_response,
                    response=response,
                )
            return json_response.get("data")

        return json_response

    def _parse_orderbook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert an AngelOne order-book row to a unified order record.

        Args:
            order: Raw order-book row returned by AngelOne.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["orderid"],
            Order.USER_ID: order["ordertag"],
            Order.TIMESTAMP: datetime.strptime(
                order["updatetime"], "%d-%b-%Y %H:%M:%S"
            ),
            Order.SYMBOL: order["tradingsymbol"],
            Order.TOKEN: int(order["symboltoken"]),
            Order.SIDE: self._parse_from_broker(
                "side", order["transactiontype"]
            ),
            Order.TYPE: self._parse_from_broker(
                "order_type", order["ordertype"]
            ),
            Order.AVG_PRICE: order["averageprice"],
            Order.PRICE: order["price"],
            Order.TRIGGER_PRICE: order["triggerprice"],
            Order.TARGET_PRICE: order["squareoff"],
            Order.STOPLOSS_PRICE: order["stoploss"],
            Order.TRAILING_STOPLOSS: order["trailingstoploss"],
            Order.QUANTITY: int(order["quantity"]),
            Order.FILLED_QTY: int(order["filledshares"]),
            Order.REMAINING_QTY: int(order["unfilledshares"]),
            Order.CANCELLED_QTY: int(order["cancelsize"]),
            Order.STATUS: self._parse_from_broker("status", order["status"]),
            Order.REJECT_REASON: order["text"],
            Order.DISCLOSED_QUANTITY: int(order["disclosedquantity"]),
            Order.PRODUCT: self._parse_from_broker(
                "product", order["producttype"]
            ),
            Order.EXCHANGE: self._parse_from_broker(
                "exchange", order["exchange"]
            ),
            Order.SEGMENT: self._parse_from_broker(
                "exchange", order["exchange"]
            ),
            Order.VALIDITY: self._parse_from_broker(
                "validity", order["duration"]
            ),
            Order.VARIETY: self._parse_from_broker("variety", order["variety"]),
            Order.INFO: order,
        }

        return parsed_order

    def _parse_tradebook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert an AngelOne trade-book row to a unified order record.

        AngelOne tradebook rows describe executed fills, not orders. The
        response shape is intentionally narrower than the orderbook (e.g. no
        ``ordertype``, ``variety``, ``status``, ``triggerprice``, etc.) and
        uses ``fillprice``/``fillsize``/``fillid``/``filltime`` in place of
        the orderbook's price/quantity fields.

        Args:
            order: Raw trade-book row returned by AngelOne.

        Returns:
            Unified Fenix order-like fill record.
        """
        fill_quantity = int(order.get("fillsize") or 0)

        parsed_order = {
            Order.ID: order["orderid"],
            Order.USER_ID: "",
            Order.TIMESTAMP: order.get("filltime", ""),
            Order.SYMBOL: order["tradingsymbol"],
            Order.TOKEN: int(order.get("symboltoken") or 0),
            Order.SIDE: self._parse_from_broker(
                "side", order["transactiontype"]
            ),
            Order.TYPE: "",
            Order.AVG_PRICE: float(order.get("fillprice") or 0.0),
            Order.PRICE: float(order.get("fillprice") or 0.0),
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
            Order.PRODUCT: self._parse_from_broker(
                "product", order["producttype"]
            ),
            Order.EXCHANGE: self._parse_from_broker(
                "exchange", order["exchange"]
            ),
            Order.SEGMENT: self._parse_from_broker(
                "exchange", order["exchange"]
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
        """Convert an AngelOne position row to a unified position record.

        Args:
            position: Raw position row returned by AngelOne.

        Returns:
            Unified Fenix position record.
        """
        parsed_position = {
            Position.SYMBOL: position["tradingsymbol"],
            Position.TOKEN: int(position["symboltoken"]),
            Position.NET_QTY: int(position["netqty"]),
            Position.AVG_PRICE: float(position["netprice"]),
            Position.MTM: None,
            Position.PNL: None,
            Position.BUY_QTY: int(position["buyqty"]),
            Position.BUY_PRICE: float(position["totalbuyavgprice"]),
            Position.SELL_QTY: int(position["sellqty"]),
            Position.SELL_PRICE: float(position["totalsellavgprice"]),
            Position.LTP: None,
            Order.PRODUCT: self._parse_from_broker(
                "product", position["producttype"]
            ),
            Position.EXCHANGE: self._parse_from_broker(
                "exchange", position["exchange"]
            ),
            Position.INFO: position,
        }

        return parsed_position

    def _parse_profile(
        self,
        profile: dict,
    ) -> dict[Any, Any]:
        """Convert an AngelOne profile payload to a unified profile record.

        Args:
            profile: Raw profile payload returned by AngelOne.

        Returns:
            Unified Fenix profile record.
        """
        parsed_profile = {
            Profile.CLIENT_ID: profile["clientcode"],
            Profile.NAME: profile["name"],
            Profile.EMAIL_ID: profile["email"],
            Profile.MOBILE_NO: profile["mobileno"],
            Profile.PAN: "",
            Profile.ADDRESS: "",
            Profile.BANK_NAME: "",
            Profile.BANK_BRANCH_NAME: None,
            Profile.BANK_ACC_NO: "",
            Profile.EXCHANGES_ENABLED: profile["exchanges"],
            Profile.ENABLED: True,
            Profile.INFO: profile,
        }

        return parsed_profile

    def _parse_rms(self, rms: dict) -> dict[Any, Any]:
        """Convert an AngelOne RMS payload to a unified margin record."""
        parsed_rms = {
            RMS.MARGINUSED: float(rms.get("utiliseddebits", 0.0)),
            RMS.MARGINAVAIL: float(rms["net"]),
            RMS.INFO: rms
        }

        return parsed_rms

    def _parse_place_order_response(
        self,
        response: Response,
    ) -> dict[Any, Any]:
        """Extract the order id from an AngelOne order response.

        Args:
            response: HTTP response returned after placing, modifying, or
                cancelling an order.

        Returns:
            Unified order-id record.
        """
        info = self._parse_json_response(response)

        return {Order.ID: info["orderid"]}

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
        """Build the AngelOne API payload for a place-order request.

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
            AngelOne place-order payload.
        """
        order_type = self._resolve_order_type(price, trigger)

        # AngelOne requires STOPLOSS variety for SL/SLM orders when the caller
        # leaves the variety as REGULAR.
        if (
            order_type in (OrderType.SL, OrderType.SLM)
            and variety == Variety.REGULAR
        ):
            variety = Variety.STOPLOSS

        payload = {
            "symboltoken": token_dict["Token"],
            "exchange": token_dict["Exchange"],
            "tradingsymbol": token_dict["Symbol"],
            "price": price,
            "triggerprice": trigger,
            "quantity": quantity,
            "transactiontype": self._format_for_broker("side", side),
            "ordertype": self._format_for_broker("order_type", order_type),
            "producttype": self._format_for_broker("product", product),
            "duration": self._format_for_broker("validity", validity),
            "ordertag": unique_id,
            "disclosedquantity": "0",
        }

        if not target:
            payload["variety"] = self._format_for_broker("variety", variety)
        else:
            payload.update(
                {
                    "squareoff": target,
                    "stoploss": stoploss,
                    "trailingStopLoss": trailing_sl,
                }
            )
            payload["variety"] = self._format_for_broker("variety", Variety.BO)

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
        """Place an order through AngelOne.

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

    def fetch_raw_orderbook(
        self,
    ) -> list[dict]:
        """Fetch raw AngelOne order-book rows.

        Returns:
            Raw broker order-book rows. Empty result-set responses are returned
            as an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        response = self.fetch(
            method="GET",
            url=self.get_url("orderbook"),
            endpoint_group="post_trade",
            headers=self._headers,
        )

        return self._parse_json_response(response) or []

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
            url=self.get_url("tradebook"),
            endpoint_group="post_trade",
            headers=self._headers,
        )
        info = self._parse_json_response(response) or []

        orders = []
        for order in info:
            detail = self._parse_tradebook(order)
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

        info = self.fetch_raw_orderbook()

        if info:
            for order in info:
                if order["orderid"] == order_id:
                    detail = self._parse_orderbook(order)
                    return detail

        raise OrderNotFoundError("This order_id does not exist.")

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
        extra_params: dict = {},
    ) -> dict[Any, Any]:
        """Modify an open AngelOne order.

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
            order_info = self.fetch_order(order_id=order_id)
            order_info = order_info["info"]

        json_data = {
            "orderid": order_id,
            "symboltoken": order_info["symboltoken"],
            "exchange": order_info["exchange"],
            "tradingsymbol": order_info["tradingsymbol"],
            # "price": price or order_info["price"],
            "quantity": quantity or order_info["quantity"],
            "ordertype": (
                self._format_for_broker('order_type', order_type)
                if order_type
                else order_info["ordertype"]
            ),
            "producttype": order_info["producttype"],
            "duration": (
                self._format_for_broker('validity', validity)
                if validity
                else order_info["duration"]
            ),
            "variety": order_info["variety"],
        }

        if json_data["ordertype"] == self._format_for_broker(
                'order_type', OrderType.LIMIT):
            json_data["price"] = price or order_info["price"]
            json_data["triggerprice"] = 0

        elif json_data["ordertype"] == self._format_for_broker(
            'order_type',
            OrderType.SL,
        ):
            json_data["price"] = price or order_info["price"]
            json_data["triggerprice"] = trigger or order_info["triggerprice"]

        elif json_data["ordertype"] == self._format_for_broker(
            'order_type',
            OrderType.MARKET,
        ):
            json_data["price"] = 0
            json_data["triggerprice"] = 0

        elif json_data["ordertype"] == self._format_for_broker(
            'order_type',
            OrderType.SLM,
        ):
            json_data["price"] = 0
            json_data["triggerprice"] = trigger or order_info["triggerprice"]

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
        extra_params: dict = {}
    ) -> dict[Any, Any]:
        """Cancel an open AngelOne order.

        Args:
            order_id: Broker order id to cancel.
            extra_params: Optional broker-specific values. When it contains an
                ``"order"`` key, that normalized order record is reused.

        Returns:
            None. AngelOne acknowledges cancellation without returning a
            normalized order record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.cancel_order(
                order_id=order_id,
                extra_params=extra_params,
            )

        if extra_params.get("order"):
            variety = extra_params["order"]["info"]["variety"]
        else:
            curr_order = self.fetch_order(order_id=order_id)
            variety = curr_order["info"]["variety"]

        json_data = {
            "orderid": order_id,
            "variety": variety,
        }

        self.fetch(
            method="POST",
            url=self.get_url("cancel_order"),
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )

        # return self.fetch_order(order_id=info["data"]["orderid"])
        return None

    # Positions, Account Limits & Profile

    def fetch_day_positions(self) -> list[Any]:
        """Fetch intraday account positions.

        Returns:
            Unified Fenix position records. Empty result-set responses are
            returned as an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        response = self.fetch(
            method="GET",
            url=self.get_url("positions"),
            endpoint_group="post_trade",
            headers=self._headers,
        )
        info = self._parse_json_response(response) or []

        positions = []
        for position in info:
            detail = self._parse_position(position)
            positions.append(detail)

        return positions

    def fetch_net_positions(self) -> dict[Any, Any]:
        """Fetch net account positions.

        Returns:
            Unified Fenix position records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        return self.fetch_day_positions()

    def fetch_holdings(self) -> dict[Any, Any]:
        """Fetch account holdings.

        Returns:
            Raw AngelOne holding rows. Empty result-set responses are returned
            as an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_holdings()

        response = self.fetch(
            method="GET",
            url=self.get_url("holdings"),
            endpoint_group="post_trade",
            headers=self._headers,
        )
        data = self._parse_json_response(response) or {}

        return data.get("holdings") or []

    def fetch_margin_limits(self) -> dict[Any, Any]:
        """Fetch account margin limits.

        Returns:
            Unified Fenix RMS limits record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_margin_limits()

        response = self.fetch(
            method="GET",
            url=self.get_url("funds"),
            endpoint_group="funds",
            headers=self._headers,
        )
        response = self._parse_json_response(response)

        return self._parse_rms(response)

    def fetch_profile(self) -> dict[Any, Any]:
        """Fetch account profile details.

        Returns:
            Unified Fenix profile record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_profile()

        response = self.fetch(
            method="GET",
            url=self.get_url("profile"),
            endpoint_group="user",
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        profile = self._parse_profile(info)

        return profile
