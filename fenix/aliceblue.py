from __future__ import annotations

import base64
import hashlib
from collections import defaultdict
from datetime import datetime
from os import urandom
from typing import TYPE_CHECKING, Any, NoReturn

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from requests.exceptions import HTTPError

from fenix.base.broker import Broker

from fenix.base.constants import ExchangeCode
from fenix.base.constants import Order
from fenix.base.constants import OrderType
from fenix.base.constants import Product
from fenix.base.constants import Profile
from fenix.base.constants import RMS
from fenix.base.constants import Root
from fenix.base.constants import Side
from fenix.base.constants import Status
from fenix.base.constants import Validity
from fenix.base.constants import Variety

from fenix.base.errors import (
    AuthenticationError,
    BrokerError,
    InsufficientFundsError,
    InsufficientHoldingsError,
    InputError,
    InvalidOrderError,
    OrderNotFoundError,
    PermissionDeniedError,
    ResponseError,
    TokenDownloadError,
)

if TYPE_CHECKING:
    from requests.models import Response


class CryptoJsAES:
    """Provide CryptoJS-compatible AES encryption and decryption helpers."""

    @staticmethod
    def __pad(data):
        """Pad bytes to an AES block boundary using PKCS#7-style padding."""
        block_size = 16
        length = block_size - (len(data) % block_size)
        return data + (chr(length) * length).encode()

    @staticmethod
    def __unpad(data):
        """Remove PKCS#7-style padding from decrypted bytes."""
        return data[: -(data[-1] if isinstance(data[-1], int)
                        else ord(data[-1]))]

    @staticmethod
    def __bytes_to_key(data, salt, output=48):
        """Derive AES key and initialization-vector bytes from a passphrase."""
        assert len(salt) == 8, len(salt)
        data += salt
        key = hashlib.md5(data).digest()
        final_key = key
        while len(final_key) < output:
            key = hashlib.md5(key + data).digest()
            final_key += key
        return final_key[:output]

    @staticmethod
    def encrypt(message, passphrase):
        """Encrypt bytes with a CryptoJS-compatible AES-CBC payload format."""
        salt = urandom(8)
        key_iv = CryptoJsAES.__bytes_to_key(passphrase, salt, 32 + 16)
        key = key_iv[:32]
        iv = key_iv[32:]
        aes = Cipher(algorithms.AES(key), modes.CBC(iv))
        return base64.b64encode(
            b"Salted__"
            + salt
            + aes.encryptor().update(CryptoJsAES.__pad(message))
            + aes.encryptor().finalize()
        )

    @staticmethod
    def decrypt(encrypted, passphrase):
        """Decrypt a CryptoJS-compatible AES-CBC payload."""
        encrypted = base64.b64decode(encrypted)
        assert encrypted[0:8] == b"Salted__"
        salt = encrypted[8:16]
        key_iv = CryptoJsAES.__bytes_to_key(passphrase, salt, 32 + 16)
        key = key_iv[:32]
        iv = key_iv[32:]
        aes = Cipher(algorithms.AES(key), modes.CBC(iv))
        return CryptoJsAES.__unpad(
            aes.decryptor().update(encrypted[16:]) + aes.decryptor().finalize()
        )


class AliceBlue(Broker):
    """AliceBlue broker adapter for the Fenix trading interface."""

    _API = {
        "doc": "https://ant.aliceblueonline.com/productdocumentation",
        "servers": {
            "api": "https://ant.aliceblueonline.com/rest/AliceBlueAPIService",
            "auth": "https://ant.aliceblueonline.com",
            "market_data": "https://v2api.aliceblueonline.com/restpy",
            "order_api": "https://a3.aliceblueonline.com/",
        },
        "paths": {
            # --- Auth Flow ---
            "get_user_details": {
                "server": "api",
                "path": "/sso/getUserDetails",
            },
            "verify_user": {
                "server": "auth",
                "path": "/omk/auth/access/client/verify",
            },
            "get_enc_key": {
                "server": "auth",
                "path": "/omk/auth/access/client/enckey",
            },
            "validate": {
                "server": "auth",
                "path": "/omk/auth/access/v1/pwd/validate",
            },
            "verify_totp": {
                "server": "auth",
                "path": "/omk/auth/access/topt/verify",
            },

            # --- Order & Portfolio Flow ---
            "place_order": {
                "server": "order_api",
                "path": "open-api/od/v1/orders/placeorder",
            },
            "modify_order": {
                "server": "order_api",
                "path": "open-api/od/v1/orders/modify",
            },
            "cancel_order": {
                "server": "order_api",
                "path": "open-api/od/v1/orders/cancel",
            },
            "exit_bo": {
                "server": "api",
                "path": "/api/placeOrder/exitBracketOrder",
            },
            "orderbook": {
                "server": "api",
                "path": "/api/placeOrder/fetchOrderBook",
            },
            "tradebook": {
                "server": "api",
                "path": "/api/placeOrder/fetchTradeBook",
            },
            "order_history": {
                "server": "order_api",
                "path": "open-api/od/v1/orders/history",
            },
            "positions": {
                "server": "api",
                "path": "/api/positionAndHoldings/positionBook",
            },
            "holdings": {
                "server": "api",
                "path": "/api/positionAndHoldings/holdings",
            },
            "sqoff_position": {
                "server": "api",
                "path": "/api/positionAndHoldings/sqrOofPosition",
            },
            "rms_limits": {
                "server": "api",
                "path": "/api/limits/getRmsLimits",
            },
            "profile": {
                "server": "api",
                "path": "/api/customer/accountDetails",
            },

            # --- Market Data ---
            "instruments": {
                "server": "market_data",
                "path": "/contract_master",
            },
        }
    }

    STANDARD_MAPS = {
        'side': {
            'B': Side.BUY,
            'S': Side.SELL
        },
        "order_type": {
            "MKT": OrderType.MARKET,
            "L": OrderType.LIMIT,
            "SL": OrderType.SL,
            "SL-M": OrderType.SLM
        },
        'status': {
            'open pending': Status.PENDING,
            'not modified': Status.PENDING,
            'not cancelled': Status.PENDING,
            'modify pending': Status.PENDING,
            'trigger pending': Status.PENDING,
            'cancel pending': Status.PENDING,
            'validation pending': Status.PENDING,
            'put order req received': Status.PENDING,
            'modify validation pending': Status.PENDING,
            'after market order req received': Status.PENDING,
            'modify after market order req received': Status.PENDING,
            'cancelled': Status.CANCELLED,
            'cancelled after market order': Status.CANCELLED,
            'open': Status.OPEN,
            'complete': Status.FILLED,
            'rejected': Status.REJECTED,
            'modified': Status.MODIFIED,
        },
        "product": {
            Product.MIS: "INTRADAY",
            Product.NRML: "LONGTERM",
            Product.CNC: "MTF",
            Product.CO: "CO",
            Product.BO: "BO",
        },
        'segment': {
            "nse_cm": ExchangeCode.NSE,
            "bse_cm": ExchangeCode.BSE,
            "nse_fo": ExchangeCode.NFO,
            "bse_fo": ExchangeCode.BFO,
            "mcx_fo": ExchangeCode.MCX,
            "cde_fo": ExchangeCode.CDS,
            "mcx_sx": ExchangeCode.BFO,
            "bcs_fo": ExchangeCode.BCD,
            "nse_com": ExchangeCode.NCO,
            "bse_com": ExchangeCode.BCO,
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
            Validity.DAY: "DAY",
            Validity.IOC: "IOC"
        },
    }

    REQUEST_MAPS = {
        "side": {
            Side.BUY: "BUY",
            Side.SELL: "SELL"
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
            OrderType.SLM: "SLM",
        },
        "product": {
            Product.MIS: "INTRADAY",
            Product.NRML: "LONGTERM",
            Product.CNC: "MTF",
            Product.CO: "CO",
            Product.BO: "BO",
        },
        "validity": {
            Validity.DAY: "DAY",
            Validity.IOC: "IOC"
        },
        "variety": {
            Variety.REGULAR: "REGULAR",
            Variety.STOPLOSS: "REGULAR",
            Variety.BO: "BO",
            Variety.AMO: "AMO",
        }
    }

    _REQUIRED_AUTH_HEADER_KEYS = (
        "ID",
        "AccessToken",
        "Authorization",
        "X-SAS-Version",
        "User-Agent",
        "Content-Type",
        "susertoken",
    )

    ERROR_CODE_KEYS = (
        "errorCode",
    )

    ERROR_MESSAGE_KEYS = (
        "emsg",
        "Emsg",
        "message",
    )

    _ERROR_MESSAGES = {
        "EC003": "An error occurred. Please try again later.",
        "EC900": "'exchange' cannot be empty or null.",
        "EC901": (
            "'exchange' should be one of the following values: "
            "{ 'NSE', 'BSE', 'MCX', 'NFO', 'BFO', 'CDS', 'BCD'}."
        ),
        "EC902": "'tradingSymbol' cannot be empty or null.",
        "EC903": "'quantity' cannot be empty or null.",
        "EC904": "'quantity' should be a positive number.",
        "EC906": "'product' cannot be empty or null.",
        "EC907": "'transactionType' cannot be empty or null.",
        "EC908": "'token' cannot be empty or null.",
        "EC909": "'disclosedQty' cannot be empty or null.",
        "EC910": "'price' cannot be empty or null.",
        "EC911": "'triggerPrice' cannot be empty or null.",
        "EC912": "Failed to place the order.",
        "EC913": "Failed to retrieve user details.",
        "EC914": "'Request parameter' cannot be empty or null.",
        "EC915": "Failed to retrieve the order book.",
        "EC916": "No orders found for this user.",
        "EC917": "Failed to retrieve order history.",
        "EC918": "No order history found for the given order ID.",
        "EC919": "Failed to retrieve the position book.",
        "EC920": "No positions found for this user.",
        "EC921": "Failed to retrieve holdings.",
        "EC922": "No holdings found for this user.",
        "EC923": "Failed to retrieve profile details.",
        "EC924": "Failed to retrieve RMS limits.",
        "EC925": "'nestOrderNo' cannot be empty or null.",
        "EC926": "No trades found for this user.",
        "EC927": "Failed to retrieve the trade book.",
        "EC929": (
            "'transactionType' should be one of the following values: "
            "{'BUY', 'SELL'}."
        ),
        "EC930": (
            "'orderType' should be one of the following values: "
            "{'LIMIT', 'MARKET', 'SL', 'SLM'}."
        ),
        "EC932": (
            "'validity' should be one of the following values: "
            "{'DAY', 'IOC'}."
        ),
        "EC933": "'priceType' cannot be empty or null.",
        "EC934": "'orderType' cannot be empty or null.",
        "EC935": "Failed to retrieve the single order margin.",
        "EC936": "'product' cannot be empty or null.",
        "EC937": "Failed to cancel all orders.",
        "EC938": "No open orders to cancel from the order book.",
        "EC939": "Failed to retrieve the span margin.",
        "EC941": "'instrumentId' cannot be empty or null.",
        "EC942": "'orderComplexity' cannot be empty or null.",
        "EC944": "'validity' cannot be empty or null.",
        "EC945": "'brokerOrderId' cannot be empty or null.",
        "EC946": "Invalid 'instrumentId'. It must contain only numeric characters.",
        "EC947": "'instrumentId' does not exist.",
        "EC948": "'quantity' cannot exceed 50,000,000.",
        "EC949": "'quantity' should be a positive number.",
        "EC950": "'price' is required and cannot be empty or null.",
        "EC951": "'slTriggerPrice' is required and cannot be empty or null.",
        "EC953": "'targetPrice' is required and cannot be empty or null.",
        "EC954": "'quantity' should be a multiple of the lot size.",
        "EC957": "Invalid 'price'.",
        "EC958": "'price' cannot be zero or negative.",
        "EC959": "Invalid 'slTriggerPrice'.",
        "EC960": "'slTriggerPrice' cannot be zero or negative.",
        "EC962": "'stopLossPrice' cannot be zero or negative.",
        "EC963": "Invalid 'targetPrice'.",
        "EC964": "'targetPrice' cannot be zero or negative.",
        "EC966": "'trailingSlAmount' cannot be empty or null for SL order type.",
        "EC967": "'trailingSlAmount' should be a positive number.",
        "EC968": "'trailingSlAmount' cannot be zero or negative.",
        "EC969": "'Product' should be either 'NORMAL' or 'INTRADAY'.",
        "EC970": "'disclosedQuantity' is not applicable for this segment.",
        "EC971": "'orderTag' should not exceed 50 characters",
        "EC972": "'algoId' should not exceed 12 characters.",
        "EC973": "For a buy order, 'slTriggerPrice' should be less than the 'price'.",
        "EC974": (
            "For a sell order, 'slTriggerPrice' should be greater than "
            "the 'price'."
        ),
        "EC975": "'disclosedQuantity' cannot exceed the total order 'quantity'.",
        "EC979": "Invalid 'brokerOrderId'.",
        "EC980": "Invalid 'instrumentId'.",
        "EC981": "Invalid 'disclosedQty'.",
        "EC982": "For 'AMO', 'disclosedQuantity' should be zero.",
        "EC983": "Invalid 'algoId'.",
        "EC984": "Invalid 'orderTag'.",
        "EC986": "SpanMargin is not allowed for 'NSEEQ' and 'BSEEQ'.",
        "EC988": "'marketProtection' should be a positive number.",
        "EC990": "'quantity' should be a multiple of the lot size.",
        "EC991": "'disclosedQuantity' should be a multiple of the lot size.",
        "EC992": "Unable to modify the given order. 'brokerOrderId' is invalid.",
        "EC993": (
            "Provided 'brokerOrderId' is not in a valid state to modify "
            "the order."
        ),
        "EC994": "The given 'brokerOrderId' is not in your order book.",
        "EC996": "'validity' of IOC is not allowed for AMO orders.",
        "EC997": (
            "The specified order is not available in the order book and "
            "cannot be canceled. Please verify the order details and try again."
        ),
        "EC998": (
            "The specified order is not available in the order book, and "
            "order history cannot be retrieved. Please verify the order ID "
            "and try again."
        ),
        "EC999": (
            "The specified order is not available in the order book and "
            "cannot be modified. Please verify the order details and try again."
        ),
        "EC801": (
            "Orders with exchange 'BSEEQ/BSEFO/BSECURR' cannot be modified "
            "to order type 'SL' (Stop Loss)."
        ),
        "EC806": "'exchange' accepts only {'NSEEQ', 'BSEEQ'}.",
        "EC807": "'product' - 'NORMAL' is not allowed in cash segment.",
        "EC813": "'deviceId' cannot exceed 98 characters.",
        "EC814": "'brokerOrderId' cannot be empty or null.",
        "EC815": "Invalid 'brokerOrderId'.",
        "EC819": "Only the trigger price field can be modified.",
        "EC822": "SL trigger price should be lower than price.",
        "EC823": "SL trigger price should be higher than price.",
        "EC824": "SL trigger price should be %.2f%% below price.",
        "EC825": "SL trigger price should be %.2f%% above price.",
        "EC826": "Please enter a price.",
        "EC827": "Please enter a target price.",
        "EC828": "Please enter an SL trigger price.",
        "EC829": "AMO is not allowed for this product.",
        "EC830": "AMO is not allowed for this order type.",
        "EC831": "AMO is not allowed for this validity.",
        "EC832": "AMO is not allowed for this segment.",
        "EC834": "Market protection cannot be modified.",
        "EC837": "This product is not allowed for this segment.",
        "EC838": "This order type is not allowed.",
        "EC842": (
            "'disclosedQuantity' should be at least %.2f%% of the total "
            "order quantity."
        ),
        "EC843": "Only price and quantity fields can be modified.",
        "EC844": "Only price and order type fields can be modified.",
        "EC846": "SL trigger price should be %.2f%% or %.2f paise below price.",
        "EC847": "SL trigger price should be %.2f%% or %.2f paise above price.",
        "EC848": "Price should be higher than the SL trigger price.",
        "EC849": "Price should be lower than the SL trigger price.",
        "EC850": "Price should be %.2f%% or %.2f paise above the SL trigger price.",
        "EC851": "Price should be %.2f%% or %.2f paise below the SL trigger price.",
        "EC852": "This product is not allowed.",
        "EC855": "Modification is not allowed.",
        "EC856": "SL trigger price should be less than main leg price.",
        "EC857": "SL trigger price should be more than main leg price.",
        "EC858": "Order placement not allowed for this exchange.",
        "EC865": "'product' - 'Delivery' is not allowed in FnO segment.",
        "EC868": "Position not found for the specified instrument.",
        "EC869": "Insufficient buy quantity available for conversion.",
        "EC870": "Insufficient sell quantity available for conversion.",
        "EC871": "Conversion of overnight BUY positions in options is not allowed.",
        "EC873": "Failed to convert positions.",
        "EC082": "Invalid parameter: 'deviceId' cannot be empty or null.",
        "EC086": (
            "You are a read-only user and are not allowed to place, modify, "
            "or cancel orders."
        ),
        "EC087": "Session Expired",
        "EC088": "Single order slicing limit exceeded",
        "EC089": "'disclosedQuantity' cannot be same the total order 'quantity'.",
        "EC090": (
            "'exchange' should be one of the following values: "
            "{ 'NSE', 'BSE', 'MCX', 'NFO', 'BFO'}."
        ),
        "EC091": (
            "'orderComplexity' should be one of the following values: "
            "{'REGULAR', 'AMO'}."
        ),
        "EC092": (
            "'product' should be one of the following values: "
            "{'INTRADAY', 'LONGTERM', 'MTF'}."
        ),
    }

    _DIRECT_ERROR_CLASSES = {
        "EC086": PermissionDeniedError,
        "EC087": AuthenticationError,
        "EC869": InsufficientHoldingsError,
        "EC870": InsufficientHoldingsError,
        "EC918": OrderNotFoundError,
        "EC938": OrderNotFoundError,
        "EC994": OrderNotFoundError,
        "EC997": OrderNotFoundError,
        "EC998": OrderNotFoundError,
        "EC999": OrderNotFoundError,
    }

    _NO_DATA_PHRASES = (
        "no data",
        "no orders found",
        "no positions found",
        "no holdings found",
        "no trades found",
    )

    # Request maps are now created in __init__

    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "AliceBlue",
            "tokenParams": [
                "user_id",
                "password",
                "totpstr",
                "api_key",
                "api_secret",
            ],
            "proxies": {},
            "sensitiveLogKeys": [
                "userId",
                "userData",
                "encKey",
                "token",
                "totp",
                "vendor",
                "accessToken",
                "redirectUrl",
                "authCode",
                "checkSum",
                "userSession",
                "clientId",
                "ucc",
                "mobileNo",
                "email",
                "name",
                "ID",
                "AccessToken",
                "Authorization",
                "X-SAS-Version",
                "User-Agent",
                "Content-Type",
                "susertoken",
            ],
            "enableRateLimit": True,
            "rateLimits": {
                "default": {
                    "period": 900,   # 15 minutes in seconds (15 * 60)
                    "capacity": 1800,
                    "cost": 1.0,
                },

            }
        }

    def __init__(self, config: dict | None = None):
        """Initialize the AliceBlue broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
                Pass ``{"paper_mode": True}`` to route order entry and reads
                through the in-process paper-trading engine instead of the
                AliceBlue API.
        """
        super().__init__(config)

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """Authenticate with AliceBlue and return request headers.

        Args:
            params: Login credentials and API keys required by AliceBlue.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and run the login flow.

        Returns:
            Headers that can authenticate subsequent AliceBlue API calls.

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

        json_data = {"userId": params["user_id"]}

        response = self.fetch(
            method="POST",
            url=self.get_url("verify_user"),
            endpoint_group="default",
            json=json_data,
        )
        response = self._parse_json_response(response)

        response = self.fetch(
            method="POST",
            url=self.get_url("get_enc_key"),
            endpoint_group="default",
            json=json_data,

        )
        response = self._parse_json_response(response)

        encryption_key = response["result"][0]["encKey"]
        checksum = CryptoJsAES.encrypt(
            params["password"].encode(), encryption_key.encode()
        )
        checksum = checksum.decode("utf-8")
        json_data = {
            "userId": params["user_id"],
            "userData": checksum,
            "source": "WEB",
        }

        login_req = self.fetch(
            method="POST",
            url=self.get_url("validate"),
            endpoint_group="default",
            json=json_data,
        )

        _ = self._parse_json_response(login_req)

        for _ in range(1):
            totp = self.totp_creator(params["totpstr"])

            json_data = {
                "userId": params["user_id"],
                "totp": totp,
                "source": "WEB",
                "vendor": params["api_key"],
            }
            response = self.fetch(
                method="POST",
                url=self.get_url("verify_totp"),
                endpoint_group="default",
                json=json_data,
            )  # totp_req
            response = self._parse_json_response(response)

        auth_code = response["result"][0]["redirectUrl"].split("&userId")[
            0].split("authCode=")[-1]

        checksum_input = (
            f'{params["user_id"]}{auth_code}{params["api_secret"]}'
        )
        checksum = hashlib.sha256(checksum_input.encode("utf-8")).hexdigest()
        json_data = {"checkSum": checksum}

        response = self.fetch(
            method="POST",
            url=self.get_url("get_user_details"),
            endpoint_group="default",
            json=json_data,
        )

        response = self._parse_json_response(response)

        access_token = response["userSession"]
        sha256_encryption = hashlib.sha256(
            access_token.encode("utf-8")
        ).hexdigest()
        susertoken = hashlib.sha256(
            sha256_encryption.encode("utf-8")).hexdigest()

        self._headers = {
            "ID": params["user_id"],
            "AccessToken": access_token,
            "Authorization": f'Bearer {params["user_id"]} {access_token}',
            "X-SAS-Version": "2.0",
            "User-Agent": "AliceBlue_V21.0.1",
            "Content-Type": "application/json",
            "susertoken": susertoken,
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

            params = {"exch": "NSE"}
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
                params=params,
            )
            nse_data = self._parse_json_response(response)
            nse_data = nse_data["NSE"]

            params = {"exch": "BSE"}
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
                params=params,
            )
            bse_data = self._parse_json_response(response)
            bse_data = bse_data["BSE"]

        else:
            if "NSE" not in data or "BSE" not in data:
                raise KeyError("JSON data must contain 'NSE' and 'BSE' keys")

            nse_data = data["NSE"]
            bse_data = data["BSE"]

        nse_dict = {}
        bse_dict = {}
        alltoken_dict = {}

        for tok_data in nse_data:
            if tok_data["instrument_type"] == "0":

                symbol = tok_data["symbol"]
                token = tok_data["token"]
                exchange = tok_data["exch"]

                if "NSETEST" in symbol:
                    continue

                record = {
                    "Token": token,
                    "Exchange": exchange,
                    "Symbol": tok_data["trading_symbol"],
                    "ScriptName": symbol,
                    "LotSize": tok_data["lot_size"],
                    "TickSize": tok_data["tick_size"],
                }
                nse_dict[symbol] = record

                token_key = f"{token}_{exchange}"
                alltoken_dict[token_key] = record

        for tok_data in bse_data:
            if tok_data["instrument_type"] == "E":
                symbol = tok_data["symbol"]
                token = tok_data["token"]

                record = {
                    "Token": token,
                    "Exchange": tok_data["exch"],
                    "Symbol": tok_data["trading_symbol"],
                    "ScriptName": symbol,
                    "LotSize": tok_data["lot_size"],
                    "TickSize": tok_data["tick_size"],
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
            data: Optional pre-fetched contract-master data keyed by
                ``"NSE"``, ``"BSE"``, and ``"MCX"``.

        Returns:
            A tuple containing the unified index token map and an all-token
            lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
        """
        if not data:
            params = {"exch": "INDICES"}
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
                params=params,
            )
            idx_data = self._parse_json_response(response)
            nse_idx = idx_data["NSE"]
            bse_idx = idx_data["BSE"]

            params = {"exch": "MCX"}
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
                params=params,
            )
            mcx_data = self._parse_json_response(response)
            mcx_data = mcx_data["MCX"]

        else:
            if (
                "NSE" not in data
                or "BSE" not in data
                or "MCX" not in data
            ):
                raise KeyError(
                    "JSON data must contain 'NSE', 'BSE' and 'MCX' keys"
                )

            nse_idx = data["NSE"]
            bse_idx = data["BSE"]
            mcx_data = data["MCX"]

        nse_dict = {}
        bse_dict = {}
        mcx_dict = {}
        token_dict = {}

        for tok_data in nse_idx:
            symbol = tok_data["symbol"]
            token = tok_data["token"]

            record = {
                "Exchange": "NSE",
                "Token": token,
                "Symbol": symbol,
                "ScriptName": symbol,
            }
            nse_dict[symbol] = record

            tk = f"{token}_NSE"
            token_dict[tk] = record

        for tok_data in bse_idx:
            symbol = tok_data["symbol"]
            token = tok_data["token"]
            record = {
                "Exchange": "BSE",
                "Token": token,
                "Symbol": symbol,
                "ScriptName": symbol,
            }
            bse_dict[symbol] = record

            tk = f"{token}_BSE"
            token_dict[tk] = record

        for tok_data in mcx_data:
            if tok_data["instrument_type"] == "INDEX":
                symbol = tok_data["symbol"]
                token = tok_data["token"]
                record = {
                    "Exchange": "MCX",
                    "Token": token,
                    "Symbol": symbol,
                    "ScriptName": symbol,
                }

                mcx_dict[symbol] = record

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
            params = {"exch": "NFO"}
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
                params=params,
            )

            nfo_data = self._parse_json_response(response)

            params = {"exch": "BFO"}
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
                params=params,
            )

            bfo_data = self._parse_json_response(response)

            all_data = nfo_data["NFO"] + bfo_data["BFO"]

        else:
            if "NFO" not in data or "BFO" not in data:
                raise KeyError("JSON data must contain 'NFO' and 'BFO' keys")

            all_data = data["NFO"] + data["BFO"]

        opt_series = ["OPTIDX", "OPTSTK", "SO", "IO"]
        fut_series = ["FUTSTK", "FUTIDX", "SF", "IF"]
        dt_dict = {}

        fut_nse = defaultdict(list)
        fut_bse = defaultdict(list)
        opt_nse = defaultdict(list)
        opt_bse = defaultdict(list)
        token_dict = {}

        for tok_data in all_data:

            expiry_raw = tok_data["expiry_date"]
            root = tok_data["symbol"]
            strike = self._format_strike(tok_data["strike_price"])
            option = tok_data["option_type"]
            instrument_type = tok_data["instrument_type"]
            exchange = tok_data["exch"]
            token = tok_data["token"]

            if "NSETEST" in root:
                continue

            if expiry_raw not in dt_dict:
                dt = datetime.fromtimestamp(expiry_raw/1000).date()
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
                    "Symbol": tok_data["trading_symbol"],
                    "TickSize": tok_data["tick_size"],
                    "LotSize": tok_data["lot_size"],
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                if exchange == "NFO":
                    fut_nse[root].append(record)
                else:
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
            params = {"exch": "MCX"}
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
                params=params,
            )

            mcx_data = self._parse_json_response(response)
            mcx_data = mcx_data["MCX"]
        else:
            if "MCX" not in data:
                raise KeyError("JSON data must contain 'MCX' key")

            mcx_data = data["MCX"]

        opt_series = ["OPTFUT"]
        fut_series = ["FUTCOM", "FUTIDX"]
        dt_dict = {}

        fut = defaultdict(list)
        opt = defaultdict(list)
        index = defaultdict(list)
        token_dict = {}

        for tok_data in mcx_data:

            expiry_raw = tok_data["expiry_date"]
            root = tok_data["symbol"]
            strike = self._format_strike(tok_data["strike_price"])
            option = tok_data["option_type"]
            instrument_type = tok_data["instrument_type"]
            exchange = tok_data["exch"]
            token = tok_data["token"]

            if instrument_type == "INDEX":

                record = {
                    "Exchange": exchange,
                    "Token": token,
                    "Root": root,
                    "Symbol": root,
                    "ScriptName": root,
                }

                index[root].append(record)

            else:

                if expiry_raw not in dt_dict:
                    dt = datetime.fromtimestamp(expiry_raw/1000).date()
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
                        "Symbol": tok_data["trading_symbol"],
                        "TickSize": tok_data["tick_size"],
                        "LotSize": tok_data["lot_size"],
                        "Expiry": expiry,
                        "ScriptName": f"{root} {exdp} FUT",
                    }

                    fut[root].append(record)

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

                    opt[root].append(record)

                else:
                    continue

            tk = f"{token}_{exchange}"
            token_dict[tk] = record

        self.token_json["Futures"].update({"MCX": fut})
        self.token_json["Options"].update({"MCX": opt})
        self.token_json["Indices"].update({"MCX": index})

        self.alltoken_json.update(token_dict)

        return (
            {
                "Futures": {"MCX": fut},
                "Options": {"MCX": opt},
                "Indices": {"MCX": index},
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
                ``"CDS"`` and ``"BCD"``.

        Returns:
            A tuple containing unified currency futures/options token maps and
            an all-token lookup keyed by ``"{token}_{exchange}"``.

        Raises:
            KeyError: If supplied contract-master data is missing an exchange.
            TokenDownloadError: If the base fetch layer raises a token download
                failure while retrieving contract-master data.
        """
        if not data:
            params = {"exch": "CDS"}
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
                params=params,
            )
            cds_data = self._parse_json_response(response)

            params = {"exch": "BCD"}
            response = self.fetch(
                method="GET",
                url=self.get_url("instruments"),
                endpoint_group="default",
                params=params,
            )

            bcd_data = self._parse_json_response(response)

            all_data = cds_data["CDS"] + bcd_data["BCD"]

        else:
            if "CDS" not in data or "BCD" not in data:
                raise KeyError("JSON data must contain 'CDS' and 'BCD' keys")

            all_data = data["CDS"] + data["BCD"]

        opt_series = ["OPTCUR"]
        fut_series = ["FUTCUR"]
        dt_dict = {}

        fut_nse = defaultdict(list)
        fut_bse = defaultdict(list)
        opt_nse = defaultdict(list)
        opt_bse = defaultdict(list)
        token_dict = {}
        for tok_data in all_data:

            expiry_raw = tok_data["expiry_date"]
            root = tok_data["symbol"]
            strike = self._format_strike(tok_data["strike_price"])
            option = tok_data["option_type"]
            instrument_type = tok_data["instrument_type"]
            exchange = tok_data["exch"]
            token = tok_data["token"]

            if expiry_raw not in dt_dict:
                dt = datetime.fromtimestamp(expiry_raw/1000).date()
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
                    "Symbol": tok_data["trading_symbol"],
                    "TickSize": tok_data["tick_size"],
                    "LotSize": tok_data["lot_size"],
                    "Expiry": expiry,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                if exchange == "CDS":
                    fut_nse[root].append(record)
                else:
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

                if exchange == "CDS":
                    opt_nse[root].append(record)
                else:
                    opt_bse[root].append(record)
            else:
                continue

            tk = f"{token}_{exchange}"
            token_dict[tk] = record

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


    def _extract_aliceblue_error_code(self, payload: Any) -> str | None:
        """Extract a documented AliceBlue error code from a payload."""
        error_code = self._extract_error_code(payload)
        if error_code:
            error_code = error_code.upper()
            if error_code in self._ERROR_MESSAGES:
                return error_code
            if error_code.startswith("EC"):
                return error_code

        payload_text = self._stringify_error_payload(payload).upper()
        for documented_code in self._ERROR_MESSAGES:
            if documented_code in payload_text:
                return documented_code

        return None

    def _extract_aliceblue_error_message(
        self,
        payload: Any,
        error_code: str | None,
    ) -> str | None:
        """Extract the most useful AliceBlue error message for a payload."""
        error_message = self._extract_error_message(payload)
        documented_message = self._ERROR_MESSAGES.get(error_code or "")

        if documented_message and not error_message:
            return documented_message
        if documented_message and error_message == error_code:
            return documented_message
        if error_message:
            return error_message
        return documented_message

    def _aliceblue_error_class(
        self,
        error_code: str | None,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve an AliceBlue payload to the most specific Fenix error class."""
        if error_code in self._DIRECT_ERROR_CLASSES:
            return self._DIRECT_ERROR_CLASSES[error_code]

        message = (error_message or "").lower()
        if any(token in message for token in ("session", "token", "login")):
            return AuthenticationError
        if "read-only" in message or "permission" in message:
            return PermissionDeniedError
        if "insufficient fund" in message or "margin" in message:
            return InsufficientFundsError
        if "insufficient" in message and "quantity" in message:
            return InsufficientHoldingsError
        if any(phrase in message for phrase in self._NO_DATA_PHRASES):
            return ResponseError
        if "failed to retrieve" in message or "not found" in message:
            return ResponseError
        if (
            "not in your order book" in message
            or "not available in the order book" in message
        ):
            return OrderNotFoundError
        if error_code in self._ERROR_MESSAGES:
            if any(token in message for token in ("order", "price", "quantity")):
                return InvalidOrderError
            return InputError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded AliceBlue payload represents an error."""
        if isinstance(payload, list):
            if not payload:
                return False
            return self._payload_indicates_error(payload[0])

        if isinstance(payload, dict):
            stat = payload.get("stat") or payload.get("status")
            if stat is not None:
                return str(stat).lower() != "ok"

            return False

        return self._extract_aliceblue_error_code(payload) is not None

    def _is_empty_response_error(self, exc: ResponseError) -> bool:
        """Return whether a response error represents an empty result set."""
        message = str(exc).lower()
        return any(
            phrase in message
            for phrase in self._NO_DATA_PHRASES
        )

    def _raise_aliceblue_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for an AliceBlue error payload."""
        context = self._http_error_context(response, payload)
        error_code = self._extract_aliceblue_error_code(payload)
        error_message = self._extract_aliceblue_error_message(
            payload,
            error_code,
        )

        context["error_code"] = error_code
        context["error_message"] = error_message
        error_cls = self._aliceblue_error_class(
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
            self._raise_aliceblue_error(payload, response=exc.response, cause=exc)

        super().handle_http_error(exc)

    def _parse_json_response(self, response: Response) -> Any:
        """Decode an HTTP response and raise broker-specific payload errors."""
        json_response = self._json_parser(response)
        data_to_check = json_response[0] if isinstance(
            json_response, list) and json_response else json_response

        if self._payload_indicates_error(data_to_check):
            self._raise_aliceblue_error(
                json_response,
                response=response,
            )

        return json_response


    def _parse_order_history(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert an AliceBlue order-history row to a unified order record.

        Args:
            order: Raw order-history row returned by AliceBlue.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["nestordernumber"],
            Order.USER_ID: "",
            Order.TIMESTAMP: (
                datetime.strptime(order["ExchTimeStamp"], "%d/%m/%Y %H:%M:%S")
                if order["ExchTimeStamp"]
                else order["ExchTimeStamp"]
            ),
            Order.SYMBOL: order["Trsym"],
            Order.TOKEN: "",
            Order.SIDE: self._parse_from_broker("side", order["Action"]),
            Order.TYPE: self._parse_from_broker("order_type", order["Ordtype"]),
            Order.AVG_PRICE: float(order.get("averageprice") or 0.0),
            Order.PRICE: float(order.get("Prc") or 0.0),
            Order.TRIGGER_PRICE: float(order.get("triggerprice") or 0.0),
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: int(order["Qty"]),
            Order.FILLED_QTY: int(order.get("filledShares") or 0),
            Order.REMAINING_QTY: (
                int(order["Qty"]) - int(order.get("filledShares") or 0)
            ),
            Order.CANCELLED_QTY: 0,
            Order.STATUS: self._parse_from_broker("status", order["Status"]),
            Order.REJECT_REASON: order["rejectionreason"],
            Order.DISCLOSED_QUANTITY: int(order["disclosedqty"]),
            Order.PRODUCT: self._parse_from_broker("product", order["productcode"]),
            Order.EXCHANGE: self._parse_from_broker("exchange", order["exchange"]),
            Order.SEGMENT: self._parse_from_broker("exchange", order["exchange"]),
            Order.VALIDITY: self._parse_from_broker("validity", order["duration"]),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_orderbook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert an AliceBlue order-book row to a unified order record.

        Args:
            order: Raw order-book row returned by AliceBlue.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["Nstordno"],
            Order.USER_ID: order["remarks"],
            Order.TIMESTAMP: (
                datetime.strptime(order["ExchConfrmtime"], "%d-%b-%Y %H:%M:%S")
                if order["ExchConfrmtime"] != "--"
                else datetime.strptime(order["OrderedTime"], "%d/%m/%Y %H:%M:%S")
            ),
            Order.SYMBOL: order["Trsym"],
            Order.TOKEN: int(order["token"]),
            Order.SIDE: self._parse_from_broker("side", order["Trantype"]),
            Order.TYPE: self._parse_from_broker("order_type", order["Prctype"]),
            Order.AVG_PRICE: float(order["Avgprc"]),
            Order.PRICE: float(order["Prc"]),
            Order.TRIGGER_PRICE: float(order["Trgprc"]),
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: order["Qty"],
            Order.FILLED_QTY: order["Fillshares"],
            Order.REMAINING_QTY: order["Unfilledsize"],
            Order.CANCELLED_QTY: order["Cancelqty"],
            Order.STATUS: self._parse_from_broker("status", order["Status"]),
            Order.REJECT_REASON: order["RejReason"],
            Order.DISCLOSED_QUANTITY: order["Dscqty"],
            Order.PRODUCT: self._parse_from_broker("product", order["Pcode"]),
            Order.EXCHANGE: self._parse_from_broker("exchange", order["Exchange"]),
            Order.SEGMENT: self._parse_from_broker("segment", order["Exseg"]),
            Order.VALIDITY: self._parse_from_broker("validity", order["Validity"]),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    def _parse_profile(
        self,
        profile: dict,
    ) -> dict[Any, Any]:
        """Convert an AliceBlue profile payload to a unified profile record.

        Args:
            profile: Raw profile payload returned by AliceBlue.

        Returns:
            Unified Fenix profile record.
        """
        exchanges_enabled = [
            self._parse_from_broker("segment", i)
            # cls.resp_segment.get(i, None)
            for i in profile["exchEnabled"].split("|")
            if i
        ]

        parsed_profile = {
            Profile.CLIENT_ID: profile["accountId"],
            Profile.NAME: profile["accountName"],
            Profile.EMAIL_ID: profile["emailAddr"],
            Profile.MOBILE_NO: profile["cellAddr"],
            Profile.PAN: "",
            Profile.ADDRESS: "",
            Profile.BANK_NAME: "",
            Profile.BANK_BRANCH_NAME: None,
            Profile.BANK_ACC_NO: "",
            Profile.EXCHANGES_ENABLED: exchanges_enabled,
            Profile.ENABLED: profile["accountStatus"] == "Activated",
            Profile.INFO: profile,
        }

        return parsed_profile

    def _parse_place_order_response(self, response: Response) -> dict[Any, Any]:
        """Extract the order id from an AliceBlue place-order response.

        Args:
            response: HTTP response returned after placing an order.

        Returns:
            Unified order-id record.
        """
        info = self._parse_json_response(response)
        return {Order.ID: info['result'][0]['brokerOrderId']}

    def _parse_rms(self, rms: dict) -> dict[Any, Any]:
        """Convert an AliceBlue RMS payload to a unified margin record."""
        parsed_rms = {
            RMS.MARGINUSED: float(rms["cncMarginUsed"]),
            RMS.MARGINAVAIL: float(rms["net"]),
            RMS.INFO: rms
        }

        return parsed_rms

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
    ) -> list[dict[str, Any]]:
        """Build the AliceBlue API payload for a place-order request.

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
            AliceBlue place-order payload wrapped in the list format expected
            by the endpoint.
        """
        order_type = self._resolve_order_type(price, trigger)
        payload = {
            "instrumentId": token_dict["Token"],
            "exchange": token_dict["Exchange"],
            "trading_symbol": token_dict["Symbol"],
            "price": price,
            "slTriggerPrice": trigger,
            "quantity": quantity,
            "transactionType": self._format_for_broker('side', side),
            "orderType": self._format_for_broker("order_type", order_type),
            "product": self._format_for_broker('product', product),
            "validity": self._format_for_broker('validity', validity),
            "orderTag": unique_id,
            "disclosedQuantity": 0,
            "apiOrderSource": unique_id,
        }

        if not target:
            payload["orderComplexity"] = self._format_for_broker(
                'variety',
                variety,
            )
        else:
            payload.update(
                {
                    "targetLegPrice": target,
                    "slLegPrice": stoploss,
                    "trailingSlAmount": trailing_sl,
                }
            )
            payload["orderComplexity"] = self._format_for_broker(
                "variety",
                Variety.BO,
            )

        return [payload]

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
        """Place an order through AliceBlue.

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
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    # Order Details, OrderBook & TradeBook

    def fetch_raw_orderbook(
        self,
    ) -> list[dict]:
        """Fetch raw AliceBlue order-book rows.

        Returns:
            Raw broker order-book rows. Empty result-set responses are returned
            as an empty list. In paper mode, returns the unified paper order
            records (paper mode has no raw broker payloads to surface).
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        response = self.fetch(
            method="GET",
            url=self.get_url("orderbook"),
            endpoint_group="default",
            headers=self._headers,
        )
        try:
            return self._parse_json_response(response)

        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

    def fetch_raw_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """Fetch raw AliceBlue history rows for an order.

        Args:
            order_id: Broker order id to query.

        Returns:
            Raw broker order-history rows. In paper mode, returns the unified
            paper order record wrapped in a list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        json_data = {"brokerOrderId": order_id}
        response = self.fetch(
            method="POST",
            url=self.get_url("order_history"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_json_response(response)

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
            Unified order records. Empty result-set responses are returned as
            an empty list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_tradebook()

        response = self.fetch(
            method="GET",
            url=self.get_url("tradebook"),
            endpoint_group="default",
            headers=self._headers,
        )

        try:
            info = self._parse_json_response(response)
        except ResponseError as exc:
            if self._is_empty_response_error(exc):
                return []
            raise

        orders = []
        for order in info:
            detail = self._parse_orderbook(order)
            orders.append(detail)

        return orders

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
        order_id = str(order_id)
        for order in info:
            if order["brokerOrderId"] == order_id:
                detail = self._parse_orderbook(order)
                return detail

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

        order_history = []
        for order in info:
            history = self._parse_order_history(order)
            order_history.append(history)

        return order_history

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
        """Modify an open AliceBlue order.

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
            None. AliceBlue acknowledges the modification without returning a
            normalized order record.
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
            order_history = self.fetch_raw_order_history(order_id=order_id)
            order_info = order_history[0]

        json_data = {
            "brokerOrderId": order_info["Nstordno"],
            "quantity": quantity or order_info["Qty"],
            "orderType": (
                self._format_for_broker('order_type', order_type)
                if order_type
                else order_info["Prctype"]
            ),
            "disclosedQuantity": "0",
            "slLegPrice": "",
            "trailingSLAmount": "",
            "targetLegPrice": "",
            "validity": validity or order_info["Validity"],
            "marketProtection": ""
        }

        if json_data["orderType"] in ["L", OrderType.LIMIT]:
            json_data["price"] = price or order_info["Prc"]
            json_data["slTriggerPrice"] = 0
            json_data["orderType"] = "LIMIT"

        elif json_data["orderType"] == OrderType.SL:
            json_data["price"] = price or order_info["Prc"]
            json_data["slTriggerPrice"] = trigger or order_info["Trgprc"]
            json_data["orderType"] = "SL"

        elif json_data["orderType"] in [OrderType.MARKET, "MKT"]:
            json_data["price"] = 0
            json_data["slTriggerPrice"] = 0
            json_data["orderType"] = "MARKET"

        elif json_data["orderType"] in ["SL-M", OrderType.SLM]:
            json_data["price"] = 0
            json_data["slTriggerPrice"] = trigger or order_info["Trgprc"]
            json_data["orderType"] = "SLM"

        response = self.fetch(
            method="POST",
            url=self.get_url("modify_order"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )
        _ = self._parse_json_response(response)

        return None  # self.fetch_order(order_id=order_id)

    def cancel_order(
        self,
        order_id: str,
        extra_params: dict | None = None
    ) -> None:
        """Cancel an open AliceBlue order.

        Args:
            order_id: Broker order id to cancel.
            extra_params: Optional broker-specific values. When it contains an
                ``"order"`` key, that normalized order record is reused.

        Returns:
            None. AliceBlue acknowledges cancellation without returning a
            normalized order record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.cancel_order(
                order_id=order_id,
                extra_params=extra_params,
            )

        extra_params = extra_params or {}

        if extra_params.get("order"):
            order = extra_params["order"]
        else:
            order = self.fetch_order(order_id=order_id)

        json_data = {
            # "exch": order["info"]["Exchange"],
            "brokerOrderId": order["id"],
            # "trading_symbol": order["symbol"],
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("cancel_order"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )
        self._parse_json_response(response)

        return None  # self._parse_place_order_response(response=response)

    def square_off_position(
        self,
        symbol: str,
        token: int,
        exchange: str,
        quantity: int,
        product: str = Product.MIS,
    ) -> dict[Any, Any]:
        """Square off an open position.

        Args:
            symbol: Trading symbol to square off.
            token: Exchange token for the instrument.
            exchange: Exchange code in Fenix format.
            quantity: Quantity to square off.
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

        json_data = {
            "exchSeg": self._format_for_broker('exchange', exchange),
            "pCode": self._format_for_broker('product', product),
            "netQty": quantity,
            "tockenNo": token,
            "symbol": symbol,
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("sqoff_position"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    def exit_bracket_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Exit an open bracket order.

        Args:
            order_id: Broker order id for the bracket order.

        Returns:
            Unified order record after the bracket-order exit request.
        """
        if self.paper_mode and self._paper is not None:
            self._paper.cancel_order(order_id=order_id)
            return self._paper.fetch_order(order_id)

        json_data = {"nestOrderNumber": order_id}

        response = self.fetch(
            method="POST",
            url=self.get_url("order_history"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )
        order_history = self._parse_json_response(response)

        order = order_history[0]

        json_data = {
            "nestOrderNumber": order["nestordernumber"],
            "symbolOrderId": order["Trsym"],
            "status": order["Status"],
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("exit_bracket_order"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )
        response = self._parse_json_response(response)

        return self.fetch_order(order_id=order_id)

    # Positions, Account Limits & Profile

    def fetch_day_positions(
        self,
    ) -> list[dict[str, Any]]:
        """Fetch intraday account positions.

        Returns:
            Raw AliceBlue day-position rows. Empty result-set responses are
            returned as an empty list. In paper mode, returns the unified
            paper position records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        json_data = {"ret": Validity.DAY}
        response = self.fetch(
            method="POST",
            url=self.get_url("positions"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        try:
            return self._parse_json_response(response)
        except ResponseError as e:
            if self._is_empty_response_error(e):
                return []
            raise

    def fetch_net_positions(
        self,
    ) -> list[dict[str, Any]]:
        """Fetch net account positions.

        Returns:
            Raw AliceBlue net-position rows. Empty result-set responses are
            returned as an empty list. In paper mode, returns the unified
            paper position records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        json_data = {"ret": "NET"}
        response = self.fetch(
            method="POST",
            url=self.get_url("positions"),
            endpoint_group="default",
            json=json_data,
            headers=self._headers,
        )

        try:
            return self._parse_json_response(response)
        except ResponseError as e:
            if self._is_empty_response_error(e):
                return []
            raise

    def fetch_holdings(
        self,
    ) -> list[dict[str, Any]]:
        """Fetch account holdings.

        Returns:
            Raw AliceBlue holding rows. Empty result-set responses are returned
            as an empty list. In paper mode, returns the unified paper
            position records (no T+1 settlement modelling).
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_holdings()

        response = self.fetch(
            method="GET",
            url=self.get_url("holdings"),
            endpoint_group="default",
            headers=self._headers,
        )
        try:
            return self._parse_json_response(response)
        except ResponseError as e:
            if self._is_empty_response_error(e):
                return []
            raise

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
            url=self.get_url("rms_limits"),
            endpoint_group="default",
            headers=self._headers,
        )
        response = self._parse_json_response(response)
        return self._parse_rms(response[0])

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

        profile = self._parse_profile(response)

        return profile
