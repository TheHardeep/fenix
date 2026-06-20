from __future__ import annotations

import csv
import gzip
import io
import time
import math
from collections import defaultdict
from datetime import datetime
from typing import TYPE_CHECKING, Any, NoReturn

from requests.exceptions import HTTPError

from selenium import webdriver
from selenium.common.exceptions import NoSuchDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.ui import WebDriverWait

from fenix.base.broker import Broker

from fenix.base.constants import ExchangeCode
from fenix.base.constants import Order
from fenix.base.constants import OrderType
from fenix.base.constants import Product
from fenix.base.constants import Position
from fenix.base.constants import Profile
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
    RateLimitExceededError,
    ResponseError,
)

if TYPE_CHECKING:
    from requests.models import Response


class Upstox(Broker):
    """Upstox broker adapter for the Fenix trading interface."""

    _API = {
        "doc": "https://upstox.com/developer/api-documentation/open-api",
        "servers": {
            "auth": "https://api.upstox.com",
            "api": "https://api.upstox.com/v2",
            "api_v3": "https://api.upstox.com/v3",
            "market_data": "https://assets.upstox.com",
        },
        "paths": {
            # --- Auth Flow ---
            "token_dialog": {
                "server": "auth",
                "path": "/v2/login/authorization/dialog",
            },
            "token_exchange": {
                "server": "auth",
                "path": "/v2/login/authorization/token",
            },

            # --- Order & Portfolio Flow ---
            "place_order": {
                "server": "api",
                "path": "/order/place",
            },
            "modify_order": {
                "server": "api",
                "path": "/order/modify",
            },
            "cancel_order": {
                "server": "api",
                "path": "/order/cancel",
            },
            "order_history": {
                "server": "api",
                "path": "/order/history",
            },
            "single_order": {
                "server": "api",
                "path": "/order/details",
            },
            "orderbook": {
                "server": "api",
                "path": "/order/retrieve-all",
            },
            "tradebook": {
                "server": "api",
                "path": "/order/trades/get-trades-for-day",
            },
            "positions": {
                "server": "api",
                "path": "/portfolio/short-term-positions",
            },
            "holdings": {
                "server": "api",
                "path": "/portfolio/long-term-holdings",
            },
            "rms_limits": {
                "server": "api_v3",
                "path": "/user/get-funds-and-margin",
            },
            "profile": {
                "server": "api",
                "path": "/user/profile",
            },

            # --- Market Data ---
            "instruments": {
                "server": "market_data",
                "path": "/market-quote/instruments/exchange/complete.csv.gz",
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
        "product": {
            "I": Product.MIS,
            "D": Product.NRML,
            "CNC": Product.CNC,
            "OCO": Product.CO,
        },
        "validity": {
            "DAY": Validity.DAY,
            "IOC": Validity.IOC,
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
        "variety": {
            "SIMPLE": Variety.REGULAR,
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
            Product.MIS: "I",
            Product.NRML: "D",
            Product.CNC: "CNC",
            Product.CO: "OCO",
            Product.BO: "I",
        },
        "validity": {
            Validity.DAY: "DAY",
            Validity.IOC: "IOC",
        },
        "variety": {
            Variety.REGULAR: "REGULAR",
            Variety.STOPLOSS: "REGULAR",
            Variety.BO: "BO",
            Variety.AMO: "AMO",
        },
    }

    _REQUIRED_AUTH_HEADER_KEYS = (
        "Authorization",
        "Accept",
    )

    ERROR_CODE_KEYS = (
        "error_code",
        "errorCode",
    )

    ERROR_MESSAGE_KEYS = (
        "message",
    )

    _ERROR_MESSAGES = {
        "UDAPI10000": (
            "This request is not supported by Upstox API. The API call is "
            "not recognized or valid, possibly due to incorrect URL "
            "formatting or unexpected characters in the URL."
        ),
        "UDAPI10005": (
            "Too many requests sent. Rate limit for the API has been "
            "exceeded."
        ),
        "UDAPI100015": (
            "API Version does not exist. API version is not part of the "
            "header attributes."
        ),
        "UDAPI100016": (
            "Invalid credentials. One of the credentials passed to this "
            "API is invalid."
        ),
        "UDAPI100036": "Invalid input passed to the API.",
        "UDAPI100038": "Invalid input passed to the API.",
        "UDAPI100050": "Invalid token used to access API.",
        "UDAPI100067": (
            "The API you are trying to access is not permitted with an "
            "extended_token."
        ),
        "UDAPI100073": (
            "Your 'client_id' is inactive. Please contact the support team "
            "for further assistance."
        ),
        "UDAPI100500": (
            "Something went wrong. An unexpected error occurred. Please "
            "contact support."
        ),
    }

    _DIRECT_ERROR_CLASSES = {
        "UDAPI10000": InputError,
        "UDAPI10005": RateLimitExceededError,
        "UDAPI100015": InputError,
        "UDAPI100016": AuthenticationError,
        "UDAPI100036": InputError,
        "UDAPI100038": InputError,
        "UDAPI100050": AuthenticationError,
        "UDAPI100067": PermissionDeniedError,
        "UDAPI100073": PermissionDeniedError,
        "UDAPI100500": BrokerError,
    }


    def describe(self) -> dict[str, Any]:
        """Return broker metadata consumed by the base broker class."""
        return {
            "id": "Upstox",
            "tokenParams": [
                "api_key",
                "api_secret",
                "redirect_uri",
                "totpstr",
                "mobile_no",
                "pin",
            ],
            "proxies": {},
            "sensitiveLogKeys": [
                "code",
                "client_id",
                "client_secret",
                "redirect_uri",
                "access_token",
                "refresh_token",
                "Authorization",
                "extended_token"
            ],
            "enableRateLimit": True,
            "rateLimits": {
                # Combined limit for Order Placement APIs (Place, Modify,
                # Cancel, Multi Order and GTT Order) — Regular Algos.
                "orders": [
                    {
                        "period": 1,
                        "capacity": 10,
                        "cost": 1.0,
                    },
                    {
                        "period": 60,
                        "capacity": 500,
                        "cost": 1.0,
                    },
                    {
                        "period": 1800,
                        "capacity": 2000,
                        "cost": 1.0,
                    },
                ],
                # Standard APIs (holdings, positions, funds, historical
                # candles, profile, orderbook, tradebook, etc.).
                "default": [
                    {
                        "period": 1,
                        "capacity": 50,
                        "cost": 1.0,
                    },
                    {
                        "period": 60,
                        "capacity": 500,
                        "cost": 1.0,
                    },
                    {
                        "period": 1800,
                        "capacity": 2000,
                        "cost": 1.0,
                    },
                ],
            },
        }

    def __init__(self, config: dict | None = None):
        """Initialize the Upstox broker adapter.

        Args:
            config: Optional broker configuration passed to the base class.
                Pass ``{"paper_mode": True}`` to route order entry and reads
                through the in-process paper-trading engine instead of the
                Upstox API.
        """
        super().__init__(config)

    def authenticate(
        self,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, str]:
        """Authenticate with Upstox and return request headers.

        Args:
            params: Login credentials and API keys required by Upstox.
            headers: Previously authenticated headers to reuse.
            force: Whether to ignore cached headers and run the login flow.

        Returns:
            Headers that can authenticate subsequent Upstox API calls.

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

        dialog_url = (
            f"{self.get_url('token_dialog')}"
            f"?response_type=code"
            f"&client_id={params['api_key']}"
            f"&redirect_uri={params['redirect_uri']}"
        )

        user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/79.0.3945.79 Safari/537.36"
        )

        driver = None
        try:
            options = webdriver.EdgeOptions()
            options.add_argument("--headless")
            options.add_argument(f"user-agent={user_agent}")
            driver = webdriver.Edge(options=options)
        except NoSuchDriverException:
            try:
                options = webdriver.ChromeOptions()
                options.add_argument("--headless")
                options.add_argument(f"user-agent={user_agent}")
                driver = webdriver.Chrome(options=options)
            except NoSuchDriverException:
                options = webdriver.FirefoxOptions()
                options.add_argument("--headless")
                options.add_argument(f"user-agent={user_agent}")
                driver = webdriver.Firefox(options=options)

        driver.get(dialog_url)

        elem = driver.find_element(By.ID, "mobileNum")
        elem.clear()
        elem.send_keys(params["mobile_no"])

        c1 = driver.find_element(By.ID, "getOtp")
        driver.execute_script("arguments[0].removeAttribute('disabled');", c1)
        c1.click()

        totp = self.totp_creator(params["totpstr"])
        elem = WebDriverWait(driver, 5).until(
            ec.presence_of_element_located((By.ID, "otpNum"))
        )
        elem.clear()
        elem.send_keys(totp)

        c1 = driver.find_element(By.ID, "continueBtn")
        c1.click()

        elem = WebDriverWait(driver, 5).until(
            ec.presence_of_element_located((By.ID, "pinCode"))
        )
        elem.clear()
        elem.send_keys(params["pin"])

        c1 = driver.find_element(By.ID, "pinContinueBtn")
        c1.click()

        time.sleep(1)
        code = ""
        for _ in range(5):
            split_code = driver.current_url.split("code=")
            if len(split_code) > 1:
                code = split_code[-1]
                break
            time.sleep(2)

        driver.quit()

        request_headers = {
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "code": code,
            "client_id": params["api_key"],
            "client_secret": params["api_secret"],
            "redirect_uri": params["redirect_uri"],
            "grant_type": "authorization_code",
        }

        response = self.fetch(
            method="POST",
            url=self.get_url("token_exchange"),
            endpoint_group="default",
            data=data,
            headers=request_headers,
        )
        info = self._json_parser(response)
        access_token = info["access_token"]

        self._headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        self.reset_session()

        return self._headers


    def _read_master(self, data: list[dict] | None = None) -> list[dict]:
        """Return the Upstox instrument master as a list of row dicts.

        Args:
            data: Optional pre-parsed instrument-master rows (the full Upstox
                master as a list of dicts). When omitted the single gzipped CSV
                master is downloaded and parsed.

        Returns:
            The instrument-master rows with their native column layout.
        """
        if data is not None:
            return data

        response = self.fetch(
            method="GET",
            url=self.get_url("instruments"),
            endpoint_group="default",
        )
        response.raise_for_status()

        csv_text = gzip.decompress(response.content).decode("utf-8")
        return list(csv.DictReader(io.StringIO(csv_text)))

    def load_equity_tokens(
        self,
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE equity token metadata.

        Args:
            data: Optional pre-parsed instrument-master rows (the full Upstox
                master as a list of dicts). Downloaded automatically when
                omitted.

        Returns:
            A tuple containing the unified equity token map and an all-token
            lookup keyed by ``"{exchange}_{exchange_token}"``.
        """
        rows = self._read_master(data)

        nse_tokens: dict[str, dict] = {}
        bse_tokens: dict[str, dict] = {}
        all_tokens: dict[str, dict] = {}

        for row in rows:
            exchange = row["exchange"]
            symbol = row["tradingsymbol"]
            token = row["exchange_token"]
            token_key = f"{exchange.split('_')[0]}_{token}"

            if exchange == "NSE_EQ":
                record = {
                        "Token": row["instrument_key"],
                        "ExchangeToken": int(row["exchange_token"]),
                        "Exchange": exchange,
                        "Symbol": symbol,
                        "TickSize": float(row["tick_size"]),
                        "LotSize": int(float(row["lot_size"])),
                    }
                nse_tokens[symbol] = record
                all_tokens[token_key] = record
            elif exchange == "BSE_EQ":
                record = {
                    "Token": row["instrument_key"],
                    "ExchangeToken": int(row["exchange_token"]),
                    "Exchange": exchange,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(float(row["lot_size"])),
                }
                bse_tokens[symbol] = record
                all_tokens[token_key] = record
            else:
                continue

        self.token_json["Equity"].update({
            "NSE": nse_tokens,
            "BSE": bse_tokens,
        })

        self.alltoken_json.update(all_tokens)

        return (
            {
                "Equity": {"NSE": nse_tokens, "BSE": bse_tokens},
            },
            all_tokens,
        )

    def load_index_tokens(
        self,
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE and BSE index token metadata.

        Args:
            data: Optional pre-parsed instrument-master rows (the full Upstox
                master as a list of dicts). Downloaded automatically when
                omitted.

        Returns:
            A tuple containing the unified index token map and an all-token
            lookup keyed by ``"{exchange}_{exchange_token}"``.
        """
        rows = self._read_master(data)

        nse_dict = {}
        bse_dict = {}
        token_dict = {}

        for row in rows:
            exchange = row["exchange"]
            symbol = row["tradingsymbol"]
            exchange_token = row["exchange_token"]
            token_key = f"{exchange.split('_')[0]}_{exchange_token}"

            if exchange == "NSE_INDEX":

                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Symbol": symbol,
                    "ExchangeCode": exchange_token,
                    "ScriptName": symbol,
                }

                nse_dict[symbol] = record
                token_dict[token_key] = record

            elif exchange == "BSE_INDEX":

                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Symbol": symbol,
                    "ExchangeCode": exchange_token,
                    "ScriptName": symbol,
                }

                bse_dict[symbol]= record
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
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NFO and BFO futures and options token metadata.

        Args:
            data: Optional pre-parsed instrument-master rows (the full Upstox
                master as a list of dicts). Downloaded automatically when
                omitted.

        Returns:
            A tuple containing the unified futures/options token maps and an
            all-token lookup keyed by ``"{exchange}_{exchange_token}"``.
        """
        rows = self._read_master(data)

        fut_nse = defaultdict(list)
        fut_bse = defaultdict(list)
        opt_nse = defaultdict(list)
        opt_bse = defaultdict(list)
        token_dict = {}


        opt_series = ["OPTIDX", "OPTSTK"]
        fut_series = ["FUTIDX", "FUTSTK"]

        name_dict = {}
        dt_dict = {}

        for row in rows:
            name = row["name"]
            instrument_type = row["instrument_type"]
            exchange = row["exchange"]
            symbol = row["tradingsymbol"]
            expiry_raw = row["expiry"]


            if exchange == "NSE_EQ" and name not in name_dict:
                name_dict[name] = symbol
            elif exchange == "BSE_EQ" and name not in name_dict:
                name_dict[name] = symbol
            else:
                continue

        for row in rows:
            name = row["name"]
            instrument_type = row["instrument_type"]
            exchange = row["exchange"]
            symbol = row["tradingsymbol"]
            expiry_raw = row["expiry"]

            if exchange == "NSE_FO" and instrument_type in opt_series:
                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw).date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                root = name_dict.get(name, name)
                token_key = f'NFO_{row["exchange_token"]}'
                strike = self._format_strike(row["strike"])

                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(row["lot_size"]),
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": row["option_type"],
                    "ExchangeCode": row["exchange_token"],
                    "ScriptName": f"{root} {exdp} {strike} {row['option_type']}",
                }

                opt_nse[root].append(record)
                token_dict[token_key] = record

            elif exchange == "BSE_FO" and instrument_type in opt_series:
                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw).date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                root = name_dict.get(name, name)
                token_key = f'BFO_{row["exchange_token"]}'
                strike = self._format_strike(row["strike"])

                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(row["lot_size"]),
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": row["option_type"],
                    "ExchangeCode": row["exchange_token"],
                    "ScriptName": f"{root} {exdp} {strike} {row['option_type']}",
                }

                opt_bse[root].append(record)
                token_dict[token_key] = record

            elif exchange == "NSE_FO" and instrument_type in fut_series:
                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw).date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                root = name_dict.get(name, name)
                token_key = f'NFO_{row["exchange_token"]}'

                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(row["lot_size"]),
                    "Expiry": expiry,
                    "ExchangeCode": row["exchange_token"],
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut_nse[root].append(record)
                token_dict[token_key] = record

            elif exchange == "BSE_FO" and instrument_type in fut_series:
                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw).date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                root = name_dict.get(name, name)
                token_key = f'BFO_{row["exchange_token"]}'

                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(row["lot_size"]),
                    "Expiry": expiry,
                    "ExchangeCode": row["exchange_token"],
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut_bse[root].append(record)
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

    def load_cds_tokens(
        self,
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NCD and BCD currency derivatives token metadata.

        Args:
            data: Optional pre-parsed instrument-master rows (the full Upstox
                master as a list of dicts). Downloaded automatically when
                omitted.

        Returns:
            A tuple containing the unified currency futures/options token maps
            and an all-token lookup keyed by ``"{exchange}_{exchange_token}"``.
        """
        rows = self._read_master(data)

        fut_ncd = defaultdict(list)
        opt_ncd = defaultdict(list)
        fut_bcd = defaultdict(list)
        opt_bcd = defaultdict(list)
        token_dict = {}


        opt_series = ["OPTCUR", "OPTIRD", "OPTCUR"]
        fut_series = ["FUTCUR"]

        dt_dict = {}


        for row in rows:
            root = row["name"]
            instrument_type = row["instrument_type"]
            exchange = row["exchange"]
            symbol = row["tradingsymbol"]
            expiry_raw = row["expiry"]
            exchange_token = row["exchange_token"]
            token_key = f"{exchange.split('_')[0]}_{exchange_token}"

            if exchange == "NCD_FO" and instrument_type in opt_series:
                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw).date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]


                strike = self._format_strike(row["strike"])

                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(row["lot_size"]),
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": row["option_type"],
                    "ExchangeCode": exchange_token,
                    "ScriptName": f"{root} {exdp} {strike} {row['option_type']}",
                }

                opt_ncd[root].append(record)
                token_dict[token_key] = record

            elif exchange == "NCD_FO" and instrument_type in fut_series:
                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw).date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]


                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(row["lot_size"]),
                    "Expiry": expiry,
                    "ExchangeCode": exchange_token,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut_ncd[root].append(record)
                token_dict[token_key] = record

            elif exchange == "BCD_FO" and instrument_type in opt_series:
                    if expiry_raw not in dt_dict:
                        dt = datetime.fromisoformat(expiry_raw).date()
                        expiry = dt.strftime("%Y-%m-%d")
                        exdp = dt.strftime("%d-%b").upper()
                        dt_dict[expiry_raw] = (expiry, exdp)

                    else:
                        (expiry, exdp) = dt_dict[expiry_raw]


                    strike = self._format_strike(row["strike"])

                    record = {
                        "Exchange": exchange,
                        "Token": row["instrument_key"],
                        "Root": root,
                        "Symbol": symbol,
                        "TickSize": float(row["tick_size"]),
                        "LotSize": int(row["lot_size"]),
                        "Expiry": expiry,
                        "StrikePrice": strike,
                        "Option": row["option_type"],
                        "ExchangeCode": exchange_token,
                        "ScriptName": f"{root} {exdp} {strike} {row['option_type']}",
                    }

                    opt_bcd[root].append(record)
                    token_dict[token_key] = record

            elif exchange == "BCD_FO" and instrument_type in fut_series:
                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw).date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]

                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(row["lot_size"]),
                    "Expiry": expiry,
                    "ExchangeCode": exchange_token,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut_bcd[root].append(record)
                token_dict[token_key] = record

        self.token_json["Futures"].update({"NCD": fut_ncd, "BCD": fut_bcd})
        self.token_json["Options"].update({"NCD": opt_ncd, "BCD": opt_bcd})

        self.alltoken_json.update(token_dict)

        return (
            {
                "Futures": {"NCD": fut_ncd, "BCD": fut_bcd},
                "Options": {"NCD": opt_ncd, "BCD": opt_bcd},
            },
            token_dict,
        )

    def load_ncx_tokens(
        self,
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load NSE commodity (NCX) futures and options token metadata.

        Args:
            data: Optional pre-parsed instrument-master rows (the full Upstox
                master as a list of dicts). Downloaded automatically when
                omitted.

        Returns:
            A tuple containing the unified NCX futures/options token maps and
            an all-token lookup keyed by ``"NCX_{exchange_token}"``.
        """
        rows = self._read_master(data)

        fut_ncx = defaultdict(list)
        opt_ncx = defaultdict(list)
        token_dict = {}

        opt_series = ["OPTFUT"]
        fut_series = ["FUTCOM"]

        dt_dict = {}

        for row in rows:
            root = row["name"]
            instrument_type = row["instrument_type"]
            exchange = row["exchange"]
            symbol = row["tradingsymbol"]
            expiry_raw = row["expiry"]
            exchange_token = row["exchange_token"]
            token_key = f"NCX_{exchange_token}"

            if exchange == "NSE_COM" and instrument_type in opt_series:
                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw).date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]


                strike = self._format_strike(row["strike"])


                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(row["lot_size"]),
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": row["option_type"],
                    "ExchangeCode": exchange_token,
                    "ScriptName": f"{root} {exdp} {strike} {row['option_type']}",
                }

                opt_ncx[root].append(record)
                token_dict[token_key] = record

            elif exchange == "NSE_FO" and instrument_type in fut_series:
                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw).date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]


                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(row["lot_size"]),
                    "Expiry": expiry,
                    "ExchangeCode": exchange_token,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut_ncx[root].append(record)
                token_dict[token_key] = record

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

    def load_mcx_tokens(
        self,
        data: list[dict] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load MCX futures and options token metadata.

        Args:
            data: Optional pre-parsed instrument-master rows (the full Upstox
                master as a list of dicts). Downloaded automatically when
                omitted.

        Returns:
            A tuple containing the unified MCX futures/options token maps and
            an all-token lookup keyed by ``"MCX_{exchange_token}"``.
        """
        rows = self._read_master(data)

        fut_mcx = defaultdict(list)
        opt_mcx = defaultdict(list)
        token_dict = {}


        opt_series = ["OPTFUT", 'OPTIDX']
        fut_series = ["FUTCOM", 'FUTIDX']

        dt_dict = {}


        for row in rows:
            root = row["name"]
            instrument_type = row["instrument_type"]
            exchange = row["exchange"]
            symbol = row["tradingsymbol"]
            expiry_raw = row["expiry"]
            exchange_token = row["exchange_token"]
            token_key = f"MCX_{exchange_token}"

            if exchange == "MCX_FO" and instrument_type in opt_series:
                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw).date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]


                strike = self._format_strike(row["strike"])


                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(row["lot_size"]),
                    "Expiry": expiry,
                    "StrikePrice": strike,
                    "Option": row["option_type"],
                    "ExchangeCode": exchange_token,
                    "ScriptName": f"{root} {exdp} {strike} {row['option_type']}",
                }

                opt_mcx[root].append(record)
                token_dict[token_key] = record

            elif exchange == "MCX_FO" and instrument_type in fut_series:
                if expiry_raw not in dt_dict:
                    dt = datetime.fromisoformat(expiry_raw).date()
                    expiry = dt.strftime("%Y-%m-%d")
                    exdp = dt.strftime("%d-%b").upper()
                    dt_dict[expiry_raw] = (expiry, exdp)

                else:
                    (expiry, exdp) = dt_dict[expiry_raw]


                record = {
                    "Exchange": exchange,
                    "Token": row["instrument_key"],
                    "Root": root,
                    "Symbol": symbol,
                    "TickSize": float(row["tick_size"]),
                    "LotSize": int(row["lot_size"]),
                    "Expiry": expiry,
                    "ExchangeCode": exchange_token,
                    "ScriptName": f"{root} {exdp} FUT",
                }

                fut_mcx[root].append(record)
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

    # Error Handling

    def _extract_upstox_error_code(self, payload: Any) -> str | None:
        """Extract a documented Upstox error code from a payload."""
        error_code = self._extract_error_code(payload)
        if error_code:
            error_code = error_code.upper()
            if error_code in self._ERROR_MESSAGES:
                return error_code
            if error_code.startswith("UDAPI"):
                return error_code

        payload_text = self._stringify_error_payload(payload).upper()
        for documented_code in self._ERROR_MESSAGES:
            if documented_code in payload_text:
                return documented_code

        return None

    def _extract_upstox_error_message(
        self,
        payload: Any,
        error_code: str | None,
    ) -> str | None:
        """Extract the most useful Upstox error message for a payload."""
        error_message = self._extract_error_message(payload)
        documented_message = self._ERROR_MESSAGES.get(error_code or "")

        if documented_message and not error_message:
            return documented_message
        if documented_message and error_message == error_code:
            return documented_message
        if error_message:
            return error_message
        return documented_message

    def _upstox_error_class(
        self,
        error_code: str | None,
        error_message: str | None,
        status_code: int | None = None,
    ) -> type[BrokerError]:
        """Resolve an Upstox payload to the most specific Fenix error class."""
        if error_code in self._DIRECT_ERROR_CLASSES:
            return self._DIRECT_ERROR_CLASSES[error_code]

        message = (error_message or "").lower()
        if any(
            token in message
            for token in ("session", "token", "login", "expired")
        ):
            return AuthenticationError
        if "permission" in message or "unauthorized" in message:
            return PermissionDeniedError
        if "insufficient fund" in message or "margin" in message:
            return InsufficientFundsError
        if "insufficient" in message and (
            "quantity" in message or "holding" in message
        ):
            return InsufficientHoldingsError
        if "order not found" in message or "not in your order book" in message:
            return OrderNotFoundError
        if error_code in self._ERROR_MESSAGES:
            if any(
                token in message for token in ("order", "price", "quantity")
            ):
                return InvalidOrderError
            return InputError

        return self._http_error_class(status_code)

    def _payload_indicates_error(self, payload: Any) -> bool:
        """Return whether a decoded Upstox payload represents an error."""
        if isinstance(payload, list):
            if not payload:
                return False
            return self._payload_indicates_error(payload[0])

        if isinstance(payload, dict):
            status = payload.get("status")
            if isinstance(status, str):
                return status.lower() != "success"
            if payload.get("errors"):
                return True
            return self._extract_upstox_error_code(payload) is not None

        return self._extract_upstox_error_code(payload) is not None

    def _raise_upstox_error(
        self,
        payload: Any,
        response: Response | None = None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise the mapped Fenix exception for an Upstox error payload."""
        error_payload = payload
        if (
            isinstance(payload, dict)
            and isinstance(payload.get("errors"), list)
            and payload["errors"]
        ):
            error_payload = payload["errors"][0]

        context = self._http_error_context(response, payload)
        error_code = self._extract_upstox_error_code(error_payload)
        error_message = self._extract_upstox_error_message(
            error_payload,
            error_code,
        )

        context["error_code"] = error_code
        context["error_message"] = error_message
        error_cls = self._upstox_error_class(
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
            self._raise_upstox_error(
                payload, response=exc.response, cause=exc,
            )

        super().handle_http_error(exc)

    def _parse_json_response(self, response: Response) -> Any:
        """Decode an HTTP response and raise broker-specific payload errors."""
        json_response = self._json_parser(response)

        if self._payload_indicates_error(json_response):
            self._raise_upstox_error(
                json_response,
                response=response,
            )

        return json_response["data"]

    # Json Parsers

    def _parse_orderbook(
        self,
        order: dict,
    ) -> dict[Any, Any]:
        """Convert an Upstox order-book row to a unified order record.

        Args:
            order: Raw order-book row returned by Upstox.

        Returns:
            Unified Fenix order record.
        """
        parsed_order = {
            Order.ID: order["order_id"],
            Order.USER_ID: order.get("tag", ""),
            Order.TIMESTAMP: (
                datetime.strptime(
                    order["order_timestamp"], "%Y-%m-%d %H:%M:%S",
                )
                if order.get("order_timestamp")
                else order.get("order_timestamp")
            ),
            Order.SYMBOL: order["trading_symbol"],
            Order.TOKEN: order["instrument_token"],
            Order.EXCHANGE_TOKEN: order["instrument_token"].split("|")[-1],
            Order.SIDE: self._parse_from_broker(
                "side", order["transaction_type"],
            ),
            Order.TYPE: self._parse_from_broker(
                "order_type", order["order_type"],
            ),
            Order.AVG_PRICE: float(order.get("average_price") or 0.0),
            Order.PRICE: float(order.get("price") or 0.0),
            Order.TRIGGER_PRICE: float(order.get("trigger_price") or 0.0),
            Order.TARGET_PRICE: 0.0,
            Order.STOPLOSS_PRICE: 0.0,
            Order.TRAILING_STOPLOSS: 0.0,
            Order.QUANTITY: int(order.get("quantity") or 0),
            Order.FILLED_QTY: int(order.get("filled_quantity") or 0),
            Order.REMAINING_QTY: int(order.get("pending_quantity") or 0),
            Order.CANCELLED_QTY: 0,
            Order.STATUS: self._parse_from_broker("status", order["status"]),
            Order.REJECT_REASON: order.get("status_message_raw", ""),
            Order.DISCLOSED_QUANTITY: int(order.get("disclosed_quantity") or 0),
            Order.PRODUCT: self._parse_from_broker(
                "product", order["product"],
            ),
            Order.EXCHANGE: self._parse_from_broker(
                "exchange", order["exchange"],
            ),
            Order.SEGMENT: self._parse_from_broker(
                "exchange", order["exchange"],
            ),
            Order.VALIDITY: self._parse_from_broker(
                "validity", order["validity"],
            ),
            Order.VARIETY: self._parse_from_broker(
                "variety", order.get("variety", ""),
            ),
            Order.INFO: order,
        }

        return parsed_order

    def _parse_net_position(
        self,
        position: dict,
    ) -> dict[Any, Any]:
        """Convert an Upstox net-position row to a unified position record.

        Args:
            position: Raw position row returned by Upstox.

        Returns:
            Unified Fenix position record.
        """
        if position["buy_price"]:
            buy_qty = position["buy_value"] // position["buy_price"]
        else:
            buy_qty = 0

        if position["sell_price"]:
            sell_qty = position["sell_value"] // position["sell_price"]
        else:
            sell_qty = 0

        average_price = position["average_price"]
        if not average_price:
            average_price = (position["buy_value"] + position["sell_value"]) / (buy_qty + sell_qty)
            average_price = math.trunc(average_price * 100) / 100

        parsed_position = {
            Position.SYMBOL: position["tradingsymbol"],
            Position.TOKEN: position["instrument_token"],
            Position.NET_QTY: int(position["quantity"]),
            Position.AVG_PRICE: average_price,
            Position.UNREALISED_PNL: position["unrealised"],
            Position.REALISED_PNL: position["realised"],
            Position.BUY_QTY: buy_qty,
            Position.BUY_PRICE: float(position["buy_price"]),
            Position.SELL_QTY: sell_qty,
            Position.SELL_PRICE: float(position["sell_price"]),
            Position.LTP: position["last_price"],
            Order.PRODUCT: self._parse_from_broker(
                "product", position["product"]
            ),
            Position.EXCHANGE: self._parse_from_broker(
                "exchange", position["exchange"]
            ),
            Position.INFO: position,
        }

        return parsed_position

    def _parse_day_position(
        self,
        position: dict,
    ) -> dict[Any, Any]:
        """Convert an Upstox day-position row to a unified position record.

        Args:
            position: Raw position row returned by Upstox.

        Returns:
            Unified Fenix position record.
        """
        if position["buy_price"]:
            buy_qty = position["buy_value"] // position["buy_price"]
        else:
            buy_qty = 0

        if position["sell_price"]:
            sell_qty = position["sell_value"] // position["sell_price"]
        else:
            sell_qty = 0

        average_price = position["average_price"]
        if not average_price:
            average_price = (position["buy_value"] + position["sell_value"]) / (buy_qty + sell_qty)
            average_price = math.trunc(average_price * 100) / 100

        parsed_position = {
            Position.SYMBOL: position["tradingsymbol"],
            Position.TOKEN: position["instrument_token"],
            Position.NET_QTY: int(position["quantity"]),
            Position.AVG_PRICE: average_price,
            Position.UNREALISED_PNL: position["unrealised"],
            Position.REALISED_PNL: position["realised"],
            Position.BUY_QTY: int(position["day_buy_quantity"]),
            Position.BUY_PRICE: float(position["day_buy_price"]),
            Position.SELL_QTY: int(position["day_sell_quantity"]),
            Position.SELL_PRICE: float(position["day_sell_price"]),
            Position.LTP: position["last_price"],
            Order.PRODUCT: self._parse_from_broker(
                "product", position["product"]
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
        """Convert an Upstox profile payload to a unified profile record.

        Args:
            profile: Raw profile payload returned by Upstox.

        Returns:
            Unified Fenix profile record.
        """
        exchanges_enabled = [
            self._parse_from_broker("exchange", i)
            for i in profile.get("exchanges", [])
        ]

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
            Profile.EXCHANGES_ENABLED: exchanges_enabled,
            Profile.ENABLED: profile.get("is_active", False),
            Profile.INFO: profile,
        }

        return parsed_profile

    def _parse_place_order_response(
        self,
        response: Response,
    ) -> dict[Any, Any]:
        """Extract the order id from an Upstox place-order response.

        Args:
            response: HTTP response returned after placing an order.

        Returns:
            Unified order-id record.
        """
        info = self._parse_json_response(response)
        return {Order.ID: info["order_id"]}

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
        """Build the Upstox API payload for a place-order request.

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
            Upstox place-order payload.

        Raises:
            InputError: If a bracket order is requested. Upstox does not
                support BO orders through this endpoint.
        """
        if target:
            raise InputError(f"BO Orders Not Available in {self.id}.")

        order_type = self._resolve_order_type(price, trigger)
        broker_variety = self._format_for_broker("variety", variety)

        payload = {
            "instrument_token": token_dict["Token"],
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "transaction_type": self._format_for_broker("side", side),
            "order_type": self._format_for_broker("order_type", order_type),
            "product": self._format_for_broker("product", product),
            "validity": self._format_for_broker("validity", validity),
            "is_amo": broker_variety == "AMO",
            "tag": unique_id,
            "disclosed_quantity": 0,
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
        """Place an order through Upstox.

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
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )

        return self._parse_place_order_response(response=response)

    # Order Details, OrderBook & TradeBook

    def fetch_raw_orderbook(
        self,
    ) -> list[dict]:
        """Fetch raw Upstox order-book rows.

        Returns:
            Raw broker order-book rows. In paper mode, returns the unified
            paper order records (paper mode has no raw broker payloads to
            surface).
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_orderbook()

        response = self.fetch(
            method="GET",
            url=self.get_url("orderbook"),
            endpoint_group="default",
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return info

    def fetch_raw_order_history(
        self,
        order_id: str,
    ) -> list[dict]:
        """Fetch raw Upstox history rows for an order.

        Args:
            order_id: Broker order id to query.

        Returns:
            Raw broker order-history rows. In paper mode, returns the unified
            paper order record wrapped in a list.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order_history(order_id)

        params = {"order_id": order_id}
        response = self.fetch(
            method="GET",
            url=self.get_url("order_history"),
            endpoint_group="default",
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return info

    def fetch_raw_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Fetch the raw Upstox detail for a single order.

        Args:
            order_id: Broker order id to query.

        Returns:
            Raw broker order-detail payload. In paper mode, returns the
            unified paper order record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        params = {"order_id": order_id}
        response = self.fetch(
            method="GET",
            url=self.get_url("single_order"),
            endpoint_group="default",
            params=params,
            headers=self._headers,
        )
        info = self._parse_json_response(response)
        return info

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
            Unified order records.
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
        for order in info:
            detail = self._parse_orderbook(order)
            orders.append(detail)

        return orders

    def fetch_orders(
        self,
    ) -> list[dict]:
        """Fetch all orders in the unified Fenix format.

        Returns:
            Unified order records.
        """
        return self.fetch_orderbook()

    def fetch_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Fetch one order in the unified Fenix format.

        Args:
            order_id: Broker order id to query.

        Returns:
            Unified Fenix order record.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_order(order_id)

        info = self.fetch_raw_order(order_id=order_id)
        return self._parse_orderbook(info)

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
            history = self._parse_orderbook(order)
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
    ) -> dict[Any, Any]:
        """Modify an open Upstox order.

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
            Unified Fenix order record for the modified order.
        """
        if self.paper_mode and self._paper is not None:
            self._paper.modify_order(
                order_id=order_id,
                price=price,
                trigger=trigger,
                quantity=quantity,
                order_type=order_type,
                validity=validity,
                raw_order_json=raw_order_json,
                extra_params=extra_params,
            )
            return self.fetch_order(order_id=order_id)

        if raw_order_json:
            order_info = raw_order_json
        else:
            order_history = self.fetch_raw_order_history(order_id=order_id)
            order_info = order_history[-1]

        json_data = {
            "order_id": order_info["order_id"],
            "price": price or order_info["price"],
            "trigger_price": trigger or order_info["trigger_price"],
            "quantity": quantity or order_info["quantity"],
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
            "disclosed_quantity": 0,
        }

        if json_data["orderType"] == "LIMIT":
            json_data["trigger_price"] = 0

        elif json_data["orderType"] == "SL-M":
            json_data["price"] = 0

        elif json_data["orderType"] == "MARKET":
            json_data["price"] = 0
            json_data["trigger_price"] = 0

        # if order_type:
        #     if order_type == OrderType.LIMIT:
        #         json_data["price"] = price
        #         json_data["trigger_price"] = 0
        #     elif order_type == OrderType.SL:
        #         json_data["price"] = price
        #         json_data["trigger_price"] = trigger
        #     elif order_type == OrderType.MARKET:
        #         json_data["price"] = 0
        #         json_data["trigger_price"] = 0
        #     elif order_type == OrderType.SLM:
        #         json_data["price"] = 0
        #         json_data["trigger_price"] = trigger

        response = self.fetch(
            method="PUT",
            url=self.get_url("modify_order"),
            endpoint_group="orders",
            json=json_data,
            headers=self._headers,
        )
        self._parse_json_response(response)

        return self.fetch_order(order_id=order_id)

    def cancel_order(
        self,
        order_id: str,
    ) -> dict[Any, Any]:
        """Cancel an open Upstox order.

        Args:
            order_id: Broker order id to cancel.

        Returns:
            Unified Fenix order record for the cancelled order.
        """
        if self.paper_mode and self._paper is not None:
            self._paper.cancel_order(order_id=order_id)
            return self.fetch_order(order_id=order_id)

        params = {"order_id": order_id}
        response = self.fetch(
            method="DELETE",
            url=self.get_url("cancel_order"),
            endpoint_group="orders",
            params=params,
            headers=self._headers,
        )
        self._parse_json_response(response)

        return self.fetch_order(order_id=order_id)

    # Positions, Account Limits & Profile

    def fetch_raw_positions(
        self,
    ) -> list[dict[str, Any]]:
        """Fetch raw account position rows.

        Returns:
            Raw Upstox position rows. In paper mode, returns the unified paper
            position records.
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

        return info

    def fetch_day_positions(
        self,
    ) -> list[dict[str, Any]]:
        """Fetch the day's account positions in the unified Fenix format.

        Returns:
            Unified Fenix day-position records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        info = self.fetch_raw_positions()

        positions = []
        for position in info:
            detail = self._parse_day_position(position)
            positions.append(detail)

        return positions

    def fetch_net_positions(
        self,
    ) -> list[dict[str, Any]]:
        """Fetch net account positions in the unified Fenix format.

        Returns:
            Unified Fenix net-position records.
        """
        if self.paper_mode and self._paper is not None:
            return self._paper.fetch_positions()

        info = self.fetch_raw_positions()

        positions = []
        for position in info:
            detail = self._parse_net_position(position)
            positions.append(detail)

        return info

    def fetch_holdings(
        self,
    ) -> list[dict[str, Any]]:
        """Fetch account holdings.

        Returns:
            Raw Upstox holding rows. In paper mode, returns the unified paper
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
        info = self._parse_json_response(response)
        return info

    def fetch_margin_limits(
        self,
    ) -> dict[Any, Any]:
        """Fetch account funds and margin (RMS) limits.

        Returns:
            Raw Upstox funds-and-margin payload. In paper mode, returns the
            unified paper margin record.
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

        return info

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
        info = self._parse_json_response(response)

        return self._parse_profile(info)
