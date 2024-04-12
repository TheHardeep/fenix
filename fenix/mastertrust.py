from __future__ import annotations
from typing import TYPE_CHECKING
from typing import Any

import re
import io
import zipfile
from requests_oauthlib import OAuth2Session

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

from fenix.base.errors import InputError
from fenix.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response


class mastertrust(Broker):
    """
    MasterTrust fenix Broker Class

    Returns:
        fenix.mastertrust: fenix MasterTrust Broker Object
    """

    # Market Data Dictonaries

    indices = {}
    eq_tokens = {}
    nfo_tokens = {}
    token_params = [
        "user_id",
        "password",
        "totpstr",
        "api_id",
        "api_secret",
    ]
    id = "mastertrust"
    _session = Broker._create_session()

    # Base URLs

    base_urls = {
        "api_doc": "http://139.180.212.2/mastertrust",
        "marketdata_doc": " http://139.180.212.2/ray-websocket",
        "base": "https://masterswift-beta.mastertrust.co.in/api/v1",
        "market_data": "https://masterswift.mastertrust.co.in/api/v2/contracts.json",
        "bfo_data": "https://masterswift-beta.mastertrust.co.in/api/v1/contract/Compact",
    }

    # Access Token Generation URLs

    token_urls = {
        "auth": "https://masterswift-beta.mastertrust.co.in/oauth2/auth",
        "auth_token": "https://masterswift-beta.mastertrust.co.in/oauth2/token",
        "redirect_uri": "http://127.0.0.1/getCode",
    }

    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base']}/orders",
        "modify_order": f"{base_urls['base']}/orders",
        "cancel_order": f"{base_urls['base']}/orders",
        "order_history": f"{base_urls['base']}/order",
        "orderbook": f"{base_urls['base']}/orders",
        "tradebook": f"{base_urls['base']}/trades",
        "positions": f"{base_urls['base']}/positions",
        "holdings": f"{base_urls['base']}/holdings",
        "profile": f"{base_urls['base']}/user/profile",
    }

    # Request Parameters Dictionaries

    req_exchange = {
        ExchangeCode.NSE: "NSE",
        ExchangeCode.NFO: "NFO",
        ExchangeCode.CDS: "CDS",
        ExchangeCode.BSE: "BSE",
        ExchangeCode.BFO: "BSE",
        ExchangeCode.MCX: "MCX",
    }

    req_side = {
        Side.BUY: "BUY",
        Side.SELL: "SELL",
    }

    req_product = {
        Product.NRML: "NRML",
        Product.MIS: "MIS",
        Product.CNC: "CNC",
        Product.CO: "CO",
    }

    req_order_type = {
        OrderType.MARKET: "MARKET",
        OrderType.LIMIT: "LIMIT",
        OrderType.SL: "SL",
        OrderType.SLM: "SLM",
    }

    req_validity = {
        Validity.DAY: "DAY",
        Validity.IOC: "IOC",
    }

    # Response Parameters Dictionaries

    resp_status = {
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
    }

    # NFO Script Fetch

    @classmethod
    def create_eq_tokens(cls) -> dict:
        """
        Downlaods NSE & BSE Equity Info for F&O Segment.
        Stores them in the mastertrust.indices Dictionary.

        Returns:
            dict: Unified fenix indices format.
        """
        params = {"exchanges": ExchangeCode.NSE}
        response = cls.fetch(
            method="GET",
            url=cls.base_urls["market_data"],
            params=params,
        )
        data = cls._json_parser(response)[ExchangeCode.NSE]

        df_nse = cls.data_frame(data)
        df_nse = df_nse[
            [
                "symbol",
                "trading_symbol",
                "code",
                "exchange_code",
                "exchange",
            ]
        ]
        df_nse.rename(
            {
                "symbol": "Index",
                "trading_symbol": "Symbol",
                "exchange_code": "LotSize",
                "code": "Token",
                "exchange": "Exchange",
            },
            axis=1,
            inplace=True,
        )

        df_nse.set_index(df_nse["Index"], inplace=True)
        df_nse.drop(columns="Index", inplace=True)
        df_nse["Token"] = df_nse["Token"].astype(int)

        params = {"exchanges": ExchangeCode.BSE}
        response = cls.fetch(
            method="GET",
            url=cls.base_urls["market_data"],
            params=params,
        )
        data = cls._json_parser(response)[ExchangeCode.BSE]

        df_bse = cls.data_frame(data)
        df_bse = df_bse[
            [
                "trading_symbol",
                "code",
                "lotSize",
                "exchange",
            ]
        ]
        df_bse.rename(
            {
                "trading_symbol": "Symbol",
                "code": "Token",
                "lotSize": "LotSize",
                "exchange": "Exchange",
            },
            axis=1,
            inplace=True,
        )

        df_bse.set_index(df_bse["Symbol"], inplace=True)
        df_bse.drop_duplicates(subset=["Symbol"], keep="first", inplace=True)
        df_bse["Token"] = df_bse["Token"].astype(int)
        df_bse["LotSize"] = df_bse["LotSize"].astype(int)

        cls.eq_tokens[ExchangeCode.NSE] = df_nse.to_dict(orient="index")
        cls.eq_tokens[ExchangeCode.BSE] = df_bse.to_dict(orient="index")

        return cls.eq_tokens

    @classmethod
    def create_indices(cls) -> dict:
        """
        Downloads all the Broker Indices Token data.
        Stores them in the mastertrust.indices Dictionary.

        Returns:
            dict: Unified fenix indices format.
        """
        params = {"exchanges": "NSE"}
        response = cls.fetch(
            method="GET",
            url=cls.base_urls["market_data"],
            params=params,
        )
        data = cls._json_parser(response)["NSE-IND"]

        df_nse = cls.data_frame(data)

        params = {"exchanges": "BSE"}
        response = cls.fetch(
            method="GET",
            url=cls.base_urls["market_data"],
            params=params,
        )
        data = cls._json_parser(response)["BSE-IND"]

        df_bse = cls.data_frame(data)

        df = cls.concat_df([df_nse, df_bse])

        df = df[["trading_symbol", "code", "exchange"]]
        df.rename(
            {
                "trading_symbol": "Symbol",
                "code": "Token",
                "exchange": "Exchange",
            },
            axis=1,
            inplace=True,
        )
        df.index = df["Symbol"]
        df["Token"] = df["Token"].astype(int)

        indices = df.to_dict(orient="index")

        indices[Root.BNF] = indices["Nifty Bank"]
        indices[Root.NF] = indices["Nifty 50"]
        indices[Root.FNF] = indices["Nifty Fin Service"]
        indices[Root.MIDCPNF] = indices["NIFTY MID SELECT"]

        cls.indices = indices

        return indices

    @classmethod
    def create_fno_tokens(cls) -> dict:
        """
        Downloades Token Data for the FNO Segment for the 3 latest Weekly Expiries.
        Stores them in the mastertrust.fno_tokens Dictionary.

        Raises:
            TokenDownloadError: Any Error Occured is raised through this Error Type.
        """
        try:
            params = {"exchanges": "NFO"}
            response = cls.fetch(
                method="GET",
                url=cls.base_urls["market_data"],
                params=params,
            )
            data = cls._json_parser(response)["NSE-OPT"]

            df_nfo = cls.data_frame(data)

            df_nfo = df_nfo[
                df_nfo["symbol"].str.startswith(
                    ("BANKNIFTY", "NIFTY", "FINNIFTY", "MIDCPNIFTY")
                )
            ]

            df_nfo["Root"] = df_nfo["symbol"].str.split(" ", expand=True)[0]

            sp_op = df_nfo["symbol"].str.rsplit(pat=" ", n=3, expand=True)
            df_nfo["StrikePrice"] = sp_op[2]
            df_nfo["Option"] = sp_op[3]
            df_nfo["expiry"] = cls.pd_datetime(
                df_nfo["expiry"], unit="s"
            ).dt.date.astype(str)

            df_nfo.rename(
                {
                    "code": "Token",
                    "expiry": "Expiry",
                    "trading_symbol": "Symbol",
                    "lotSize": "LotSize",
                    "exchange": "Exchange",
                },
                axis=1,
                inplace=True,
            )

            df_nfo = df_nfo[
                [
                    "Token",
                    "Symbol",
                    "Expiry",
                    "Option",
                    "StrikePrice",
                    "LotSize",
                    "Root",
                    "Exchange",
                ]
            ]

            params = {
                "info": "download",
                "exchanges": "BFO",
            }
            response = cls.fetch(
                method="GET",
                url=cls.base_urls["bfo_data"],
                params=params,
            )

            zip_data = zipfile.ZipFile(io.BytesIO(response.content))
            bfo_file = zip_data.namelist()[0]
            with zip_data.open(bfo_file) as data:
                df_bfo = cls.data_reader(data, filetype="csv")

            df_bfo.rename(
                {
                    "exchange_token": "Token",
                    "expiry": "Expiry",
                    "trading_symbol": "Symbol",
                    "lot_size": "LotSize",
                    "exchange": "Exchange",
                    "option_type": "Option",
                    "strike": "StrikePrice",
                    "company_name": "Root",
                },
                axis=1,
                inplace=True,
            )

            df_bfo = df_bfo[
                ((df_bfo["Root"] == Root.SENSEX) | (df_bfo["Root"] == Root.BANKEX))
                & (df_bfo["instrument_name"] == "IO")
            ]

            df_bfo = df_bfo[
                [
                    "Token",
                    "Symbol",
                    "Expiry",
                    "Option",
                    "StrikePrice",
                    "LotSize",
                    "Root",
                    "Exchange",
                ]
            ]

            df_bfo["Expiry"] = cls.pd_datetime(df_bfo["Expiry"]).dt.date.astype(str)

            df = cls.concat_df([df_nfo, df_bfo])

            df["StrikePrice"] = df["StrikePrice"].astype(float).astype(int).astype(str)
            df["Token"] = df["Token"].astype(int)
            df["LotSize"] = df["LotSize"].astype(int)

            expiry_data = cls.jsonify_expiry(data_frame=df)
            cls.nfo_tokens = expiry_data

            return expiry_data

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc

    # Headers & Json Parsers

    @classmethod
    def create_headers(
        cls,
        params: dict,
    ) -> dict[str, str]:
        """
        Generate Headers used to access Endpoints in mastertrust.

        Parameters:
            Params (dict) : A dictionary which should consist the following keys:
                user_id (str): User ID of the Account.
                password (str): Password of the Account.
                totpstr (str): String of characters used to generate TOTP.
                api_id (str): API ID/Key of the Account.
                api_secret (str): API Secret of the Account.

        Returns:
            dict[str, str]: mastertrust Headers.
        """
        for key in cls.token_params:
            if key not in params:
                raise KeyError(f"Please provide {key}")

        oauth = OAuth2Session(
            params["api_id"], redirect_uri=cls.token_urls["redirect_uri"]
        )
        authorization_url, _ = oauth.authorization_url(cls.token_urls["auth"])

        headers = {
            "DNT": "1",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Site": "none",
            "Connection": "keep-alive",
            "Sec-Fetch-Mode": "navigate",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9,hi;q=0.8",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36",
            "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        }

        request01 = cls.fetch(
            method="GET",
            url=authorization_url,
            headers=headers,
        )

        resp01_content = (request01.content).decode("utf-8")
        csrf_token = re.findall(r"value=\"(.*)\" name=\"_csrf_token\"", resp01_content)[
            0
        ]

        data = {
            "login_id": params["user_id"],
            "password": params["password"],
            "_csrf_token": csrf_token,
        }

        request02 = cls.fetch(
            method="POST",
            url=request01.url,
            data=data,
            headers=headers,
        )

        resp02_content = (request02.content).decode("utf-8")
        csrf_token = re.findall(r"value=\"(.*)\" name=\"_csrf_token\"", resp02_content)[
            0
        ]
        question_ids = re.findall(
            r"name=\"question_ids\[\]\" value=\"(.*)\"", resp02_content
        )[0]
        login_challenge = re.findall(
            r"name=\"login_challenge\" value=\"(.*)\"", resp02_content
        )[0]

        totp = cls.totp_creator(params["totpstr"])

        data = {
            "answers[]": totp,
            "_csrf_token": csrf_token,
            "question_ids[]": question_ids,
            "login_challenge": login_challenge,
        }

        try:
            request03 = cls.fetch(
                method="POST",
                url=request02.url,
                data=data,
            )
            code_str = request03.url

        except Exception as e:
            code_str = str(e)

        auth_response = re.findall(r"/getCode\?code=(.*)&scope", code_str)[0]

        data = {
            "grant_type": "authorization_code",
            "code": auth_response,
            "redirect_uri": cls.token_urls["redirect_uri"],
        }

        token_req = cls.fetch(
            method="POST",
            url=cls.token_urls["auth_token"],
            data=data,
            auth=(params["api_id"], params["api_secret"]),
        )

        token_resp = cls._json_parser(token_req)

        headers = {
            "headers": {"Authorization": f"Bearer {token_resp['access_token']}"},
            "user_id": params["user_id"],
        }

        cls._session = cls._create_session()

        return headers

    @classmethod
    def _orderhistory_json_parser(
        cls,
        order: dict,
    ) -> dict[Any, Any]:
        """
        Parses Order History Json Response to a fenix Unified Order Response.

        Parameters:
            order (dict): Order History Json Response from Broker.

        Returns:
            dict: Unified fenix Order Response.
        """
        parsed_order = {
            Order.ID: order["order_id"],
            Order.USERID: order["client_order_id"],
            Order.TIMESTAMP: (
                cls.datetime_strp(order["exchange_time"], "%d-%b-%Y %H:%M:%S")
                if order["exchange_time"] != "--"
                else None
            ),
            Order.SYMBOL: order["symbol"],
            Order.TOKEN: order["token"],
            Order.SIDE: order["order_side"],
            Order.TYPE: cls.req_order_type.get(
                order["order_type"], order["order_type"]
            ),
            Order.AVGPRICE: order["avg_price"],
            Order.PRICE: order["price"],
            Order.TRIGGERPRICE: order["trigger_price"],
            Order.QUANTITY: order["quantity"],
            Order.FILLEDQTY: order["fill_quantity"],
            Order.REMAININGQTY: order["quantity"] - order["fill_quantity"],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: cls.resp_status.get(order["status"], order["status"]),
            Order.REJECTREASON: order["reject_reason"],
            Order.DISCLOSEDQUANTITY: int(order["disclosed_quantity"] or 0),
            Order.PRODUCT: order["product"],
            Order.EXCHANGE: "",
            Order.SEGMENT: order["segment"],
            Order.VALIDITY: order["validity"],
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _orderbook_json_parser(
        cls,
        order: dict,
    ) -> dict[Any, Any]:
        """
        Parse Orderbook Order Json Response.

        Parameters:
            order (dict): Orderbook Order Json Response from Broker.

        Returns:
            dict: Unified fenix Order Response.
        """
        parsed_order = {
            Order.ID: order["oms_order_id"],
            Order.USERID: order["user_order_id"],
            Order.TIMESTAMP: cls.from_timestamp(order["order_entry_time"]),
            Order.SYMBOL: order["trading_symbol"],
            Order.TOKEN: int(order["instrument_token"]),
            Order.SIDE: order["order_side"],
            Order.TYPE: cls.req_order_type.get(
                order["order_type"], order["order_type"]
            ),
            Order.AVGPRICE: float(order["average_price"] or 0.0),
            Order.PRICE: float(order["price"] or 0.0),
            Order.TRIGGERPRICE: float(order["trigger_price"] or 0.0),
            Order.STOPLOSSPRICE: float(order["stop_loss_value"] or 0.0),
            Order.TRAILINGSTOPLOSS: float(order["trailing_stop_loss"] or 0.0),
            Order.QUANTITY: order["quantity"],
            Order.FILLEDQTY: order["filled_quantity"],
            Order.REMAININGQTY: order["remaining_quantity"],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: cls.resp_status.get(
                order["order_status"], order["order_status"]
            ),
            Order.REJECTREASON: order["rejection_reason"],
            Order.DISCLOSEDQUANTITY: order["disclosed_quantity"],
            Order.PRODUCT: order["product"],
            Order.EXCHANGE: order["exchange"],
            Order.SEGMENT: order["segment"],
            Order.VALIDITY: order["validity"],
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _tradebook_json_parser(
        cls,
        trade: dict,
    ) -> dict[Any, Any]:
        """
        Parse Tradebook Order Json Response.

        Parameters:
            order (dict): Tradebook Order Json Response from Broker.

        Returns:
            dict: Unified fenix Order Response.
        """
        parsed_trade = {
            Order.ID: trade["oms_order_id"],
            Order.USERID: "",
            Order.TIMESTAMP: cls.from_timestamp(trade["order_entry_time"]),
            Order.SYMBOL: trade["trading_symbol"],
            Order.TOKEN: int(trade["instrument_token"]),
            Order.SIDE: trade["order_side"],
            Order.TYPE: cls.req_order_type.get(
                trade["order_type"], trade["order_type"]
            ),
            Order.AVGPRICE: float(trade["trade_price"] or 0.0),
            Order.PRICE: float(trade["order_price"] or 0.0),
            Order.TRIGGERPRICE: 0.0,
            Order.STOPLOSSPRICE: 0.0,
            Order.TRAILINGSTOPLOSS: 0.0,
            Order.QUANTITY: trade["trade_quantity"],
            Order.FILLEDQTY: trade["filled_quantity"],
            Order.REMAININGQTY: (
                0 if not trade["remaining_quantity"] else trade["remaining_quantity"]
            ),
            Order.CANCELLEDQTY: 0,
            Order.STATUS: "",
            Order.REJECTREASON: "",
            Order.DISCLOSEDQUANTITY: 0,
            Order.PRODUCT: trade["product"],
            Order.EXCHANGE: trade["exchange"],
            Order.SEGMENT: "",
            Order.VALIDITY: "",
            Order.VARIETY: "",
            Order.INFO: trade,
        }

        return parsed_trade

    @classmethod
    def _position_json_parser(cls, position: dict) -> dict[Any, Any]:
        """
        Parse Acoount Position Json Response.

        Parameters:
            order (dict): Acoount Position Json Response from Broker.

        Returns:
            dict: Unified fenix Position Response.
        """
        parsedPosition = {
            Position.SYMBOL: position["trading_symbol"],
            Position.TOKEN: position["token"],
            Position.PRODUCT: cls.req_product.get(
                position["product"], position["product"]
            ),
            Position.NETQTY: position["net_quantity"],
            Position.AVGPRICE: position["average_price"],
            Position.MTM: position.get("realized_mtm"),
            Position.BUYQTY: position["buy_quantity"],
            Position.BUYPRICE: position["average_buy_price"],
            Position.SELLQTY: position["sell_quantity"],
            Position.SELLPRICE: position["average_sell_price"],
            Position.LTP: position["ltp"],
            Position.INFO: position,
        }

        return parsedPosition

    @classmethod
    def _profile_json_parser(cls, profile: dict) -> dict[Any, Any]:
        """
        Parse User Profile Json Response.

        Parameters:
            profile (dict): User Profile Json Response from Broker.

        Returns:
            dict: Unified fenix Profile Response.
        """
        parsed_profile = {
            Profile.CLIENTID: profile["account_id"],
            Profile.NAME: profile["name"],
            Profile.EMAILID: profile["email_id"],
            Profile.MOBILENO: profile["phone_number"],
            Profile.PAN: profile["pan_number"],
            Profile.ADDRESS: profile["permanent_addr"],
            Profile.BANKNAME: profile["bank_name"],
            Profile.BANKBRANCHNAME: profile["branch"],
            Profile.BANKACCNO: profile["bank_account_number"],
            Profile.EXHCNAGESENABLED: [],
            Profile.ENABLED: profile["status"] == "Activated",
            Profile.INFO: profile,
        }

        return parsed_profile

    @classmethod
    def _create_order_parser(cls, response: Response, headers: dict) -> dict[Any, Any]:
        """
        Parse Json Response Obtained from Broker After Placing Order to get order_id
        and fetching the json repsone for the said order_id.

        Parameters:
            response (Response): Json Repsonse Obtained from broker after Placing an Order.
            headers (dict): headers to send order request with.

        Returns:
            dict: Unified fenix Order Response.
        """
        info = cls._json_parser(response)

        order_id = info["data"]["oms_order_id"]
        order = cls.fetch_order(order_id=order_id, headers=headers)

        return order

    # Order Functions

    @classmethod
    def create_order(
        cls,
        token_dict: dict,
        quantity: int,
        side: str,
        product: str,
        validity: str,
        variety: str,
        unique_id: str,
        headers: dict,
        price: float = 0.0,
        trigger: float = 0.0,
        target: float = 0.0,
        stoploss: float = 0.0,
        trailing_sl: float = 0.0,
    ) -> dict[Any, Any]:
        """
        Place an Order.

        Parameters:
            token_dict (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or fno_tokens.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            product (str, optional): Order product.
            validity (str, optional): Order validity.
            variety (str, optional): Order variety.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            price (float): Order price
            trigger (float): order trigger price
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        if not target:
            params = {
                "instrument_token": token_dict["Token"],
                "exchange": cls._key_mapper(
                    cls.req_exchange, token_dict["Exchange"], "exchange"
                ),
                "price": price,
                "trigger_price": trigger,
                "quantity": quantity,
                "order_side": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[order_type],
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "user_order_id": unique_id,
                "disclosed_quantity": "0",
                "market_protection_percentage": "0",
                "client_id": headers["user_id"],
            }

            final_url = cls.urls["place_order"]

        else:
            params = {
                "instrument_token": token_dict["Token"],
                "exchange": cls._key_mapper(
                    cls.req_exchange, token_dict["Exchange"], "exchange"
                ),
                "price": price,
                "trigger_price": trigger,
                "square_off_value": target,
                "stop_loss_value": stoploss,
                "trailing_stop_loss": trailing_sl,
                "quantity": quantity,
                "order_side": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[order_type],
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "user_order_id": unique_id,
                "disclosed_quantity": "0",
                "is_trailing": True if trailing_sl else False,
                "market_protection_percentage": "0",
                "client_id": headers["user_id"],
            }

            final_url = f"{cls.urls['place_order']}/bracket"

        response = cls.fetch(
            method="POST",
            url=final_url,
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order(
        cls,
        token_dict: dict,
        quantity: int,
        side: str,
        unique_id: str,
        headers: dict,
        target: float = 0.0,
        stoploss: float = 0.0,
        trailing_sl: float = 0.0,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.REGULAR,
    ) -> dict[Any, Any]:
        """
        Place Market Order.

        Parameters:
            token_dict (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or fno_tokens.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not target:
            params = {
                "instrument_token": token_dict["Token"],
                "exchange": cls._key_mapper(
                    cls.req_exchange, token_dict["Exchange"], "exchange"
                ),
                "price": "0",
                "trigger_price": "0",
                "quantity": quantity,
                "order_side": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.MARKET],
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "user_order_id": unique_id,
                "disclosed_quantity": "0",
                "market_protection_percentage": "0",
                "client_id": headers["user_id"],
            }

            final_url = cls.urls["place_order"]

        else:
            params = {
                "instrument_token": token_dict["Token"],
                "exchange": cls._key_mapper(
                    cls.req_exchange, token_dict["Exchange"], "exchange"
                ),
                "price": "0",
                "trigger_price": "0",
                "square_off_value": target,
                "stop_loss_value": stoploss,
                "trailing_stop_loss": trailing_sl,
                "quantity": quantity,
                "order_side": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.MARKET],
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "user_order_id": unique_id,
                "disclosed_quantity": "0",
                "is_trailing": True if trailing_sl else False,
                "market_protection_percentage": "0",
                "client_id": headers["user_id"],
            }

            final_url = f"{cls.urls['place_order']}/bracket"

        response = cls.fetch(
            method="POST",
            url=final_url,
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order(
        cls,
        token_dict: dict,
        price: float,
        quantity: int,
        side: str,
        unique_id: str,
        headers: dict,
        target: float = 0.0,
        stoploss: float = 0.0,
        trailing_sl: float = 0.0,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.REGULAR,
    ) -> dict[Any, Any]:
        """
        Place Limit Order.

        Parameters:
            token_dict (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or fno_tokens.
            price (float): Order price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not target:
            params = {
                "instrument_token": token_dict["Token"],
                "exchange": cls._key_mapper(
                    cls.req_exchange, token_dict["Exchange"], "exchange"
                ),
                "price": price,
                "trigger_price": "0",
                "quantity": quantity,
                "order_side": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.LIMIT],
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "user_order_id": unique_id,
                "disclosed_quantity": "0",
                "market_protection_percentage": "0",
                "client_id": headers["user_id"],
            }

            final_url = cls.urls["place_order"]

        else:
            params = {
                "instrument_token": token_dict["Token"],
                "exchange": cls._key_mapper(
                    cls.req_exchange, token_dict["Exchange"], "exchange"
                ),
                "price": price,
                "trigger_price": "0",
                "square_off_value": target,
                "stop_loss_value": stoploss,
                "trailing_stop_loss": trailing_sl,
                "quantity": quantity,
                "order_side": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.LIMIT],
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "user_order_id": unique_id,
                "disclosed_quantity": "0",
                "is_trailing": True if trailing_sl else False,
                "market_protection_percentage": "0",
                "client_id": headers["user_id"],
            }

            final_url = f"{cls.urls['place_order']}/bracket"

        response = cls.fetch(
            method="POST",
            url=final_url,
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order(
        cls,
        token_dict: dict,
        price: float,
        trigger: float,
        quantity: int,
        side: str,
        unique_id: str,
        headers: dict,
        target: float = 0.0,
        stoploss: float = 0.0,
        trailing_sl: float = 0.0,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.STOPLOSS,
    ) -> dict[Any, Any]:
        """
        Place Stoploss Order.

        Parameters:
            token_dict (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or fno_tokens.
            price (float): Order price.
            trigger (float): order trigger price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not target:
            params = {
                "instrument_token": token_dict["Token"],
                "exchange": cls._key_mapper(
                    cls.req_exchange, token_dict["Exchange"], "exchange"
                ),
                "price": price,
                "trigger_price": trigger,
                "quantity": quantity,
                "order_side": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.SL],
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "user_order_id": unique_id,
                "disclosed_quantity": "0",
                "market_protection_percentage": "0",
                "client_id": headers["user_id"],
            }

            final_url = cls.urls["place_order"]

        else:
            params = {
                "instrument_token": token_dict["Token"],
                "exchange": cls._key_mapper(
                    cls.req_exchange, token_dict["Exchange"], "exchange"
                ),
                "price": price,
                "trigger_price": trigger,
                "square_off_value": target,
                "stop_loss_value": stoploss,
                "trailing_stop_loss": trailing_sl,
                "quantity": quantity,
                "order_side": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.SL],
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "user_order_id": unique_id,
                "disclosed_quantity": "0",
                "is_trailing": True if trailing_sl else False,
                "market_protection_percentage": "0",
                "client_id": headers["user_id"],
            }

            final_url = f"{cls.urls['place_order']}/bracket"

        response = cls.fetch(
            method="POST",
            url=final_url,
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order(
        cls,
        token_dict: dict,
        trigger: float,
        quantity: int,
        side: str,
        unique_id: str,
        headers: dict,
        target: float = 0.0,
        stoploss: float = 0.0,
        trailing_sl: float = 0.0,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.STOPLOSS,
    ) -> dict[Any, Any]:
        """
        Place Stoploss-Market Order.

        Parameters:
            token_dict (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or fno_tokens.
            trigger (float): order trigger price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not target:
            params = {
                "instrument_token": token_dict["Token"],
                "exchange": cls._key_mapper(
                    cls.req_exchange, token_dict["Exchange"], "exchange"
                ),
                "price": "0",
                "trigger_price": trigger,
                "quantity": quantity,
                "order_side": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.SLM],
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "user_order_id": unique_id,
                "disclosed_quantity": "0",
                "market_protection_percentage": "0",
                "client_id": headers["user_id"],
            }

            final_url = cls.urls["place_order"]

        else:
            params = {
                "instrument_token": token_dict["Token"],
                "exchange": cls._key_mapper(
                    cls.req_exchange, token_dict["Exchange"], "exchange"
                ),
                "price": "0",
                "trigger_price": trigger,
                "square_off_value": target,
                "stop_loss_value": stoploss,
                "trailing_stop_loss": trailing_sl,
                "quantity": quantity,
                "order_side": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.SLM],
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "user_order_id": unique_id,
                "disclosed_quantity": "0",
                "is_trailing": True if trailing_sl else False,
                "market_protection_percentage": "0",
                "client_id": headers["user_id"],
            }

            final_url = f"{cls.urls['place_order']}/bracket"

        response = cls.fetch(
            method="POST",
            url=final_url,
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    # Equity Order Functions

    @classmethod
    def create_order_eq(
        cls,
        exchange: str,
        symbol: str,
        quantity: int,
        side: str,
        product: str,
        validity: str,
        variety: str,
        unique_id: str,
        headers: dict,
        price: float = 0.0,
        trigger: float = 0.0,
    ) -> dict[Any, Any]:
        """
        Place an Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            product (str, optional): Order product.
            validity (str, optional): Order validity.
            variety (str, optional): Order variety.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            price (float): Order price
            trigger (float): order trigger price

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, "exchange")
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        params = {
            "exchange": exchange,
            "instrument_token": token,
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[order_type],
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="POST",
            url=cls.urls["place_order"],
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order_eq(
        cls,
        exchange: str,
        symbol: str,
        quantity: int,
        side: str,
        unique_id: str,
        headers: dict,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.REGULAR,
    ) -> dict[Any, Any]:
        """
        Place Market Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, "exchange")
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        params = {
            "exchange": exchange,
            "instrument_token": token,
            "price": "0",
            "trigger_price": "0",
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.MARKET],
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="POST",
            url=cls.urls["place_order"],
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order_eq(
        cls,
        exchange: str,
        symbol: str,
        price: float,
        quantity: int,
        side: str,
        unique_id: str,
        headers: dict,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.REGULAR,
    ) -> dict[Any, Any]:
        """
        Place Limit Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
            price (float): Order price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, "exchange")
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        params = {
            "exchange": exchange,
            "instrument_token": token,
            "price": price,
            "trigger_price": "0",
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.LIMIT],
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="POST",
            url=cls.urls["place_order"],
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order_eq(
        cls,
        exchange: str,
        symbol: str,
        price: float,
        trigger: float,
        quantity: int,
        side: str,
        unique_id: str,
        headers: dict,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.STOPLOSS,
    ) -> dict[Any, Any]:
        """
        Place Stoploss Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
            price (float): Order price.
            trigger (float): order trigger price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, "exchange")
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        params = {
            "exchange": exchange,
            "instrument_token": token,
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.SL],
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="POST",
            url=cls.urls["place_order"],
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order_eq(
        cls,
        exchange: str,
        symbol: str,
        trigger: float,
        quantity: int,
        side: str,
        unique_id: str,
        headers: dict,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.STOPLOSS,
    ) -> dict[Any, Any]:
        """
        Place Stoploss-Market Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
            trigger (float): order trigger price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, "exchange")
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        params = {
            "exchange": exchange,
            "instrument_token": token,
            "price": "0",
            "trigger_price": trigger,
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.SLM],
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="POST",
            url=cls.urls["place_order"],
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    # NFO Order Functions

    @classmethod
    def create_order_fno(
        cls,
        exchange: str,
        root: str,
        expiry: str,
        option: str,
        strike_price: str,
        quantity: int,
        side: str,
        product: str,
        validity: str,
        variety: str,
        unique_id: str,
        headers: dict,
        price: float = 0.0,
        trigger: float = 0.0,
    ) -> dict[Any, Any]:
        """
        Place an Order in F&O Segment.

        Parameters:
            exchange (str):  Exchange to place the order in.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'.
            option (str): Option Type: 'CE', 'PE'.
            strike_price (str): Strike Price of the Option.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            product (str): Order product.
            validity (str): Order validity.
            variety (str): Order variety.
            unique_id (str): Unique user orderid.
            headers (dict): headers to send order request with.
            price (float): price of the order.
            trigger (float): trigger price of the order.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail["Token"]

        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        params = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "instrument_token": token,
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[order_type],
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="POST",
            url=cls.urls["place_order"],
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order_fno(
        cls,
        option: str,
        strike_price: str,
        quantity: int,
        side: str,
        headers: dict,
        root: str = Root.BNF,
        expiry: str = WeeklyExpiry.CURRENT,
        exchange: str = ExchangeCode.NFO,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.REGULAR,
        unique_id: str = UniqueID.MARKETORDER,
    ) -> dict[Any, Any]:
        """
        Place Market Order in F&O Segment.

        Parameters:
            option (str): Option Type: 'CE', 'PE'.
            strike_price (str): Strike Price of the Option.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            exchange (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail["Token"]

        params = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "instrument_token": token,
            "price": "0",
            "trigger_price": "0",
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.MARKET],
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="POST",
            url=cls.urls["place_order"],
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order_fno(
        cls,
        option: str,
        strike_price: str,
        price: float,
        quantity: int,
        side: str,
        headers: dict,
        root: str = Root.BNF,
        expiry: str = WeeklyExpiry.CURRENT,
        exchange: str = ExchangeCode.NFO,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.REGULAR,
        unique_id: str = UniqueID.LIMITORDER,
    ) -> dict[Any, Any]:
        """
        Place Limit Order in F&O Segment.

        Parameters:
            option (str): Option Type: 'CE', 'PE'.
            strike_price (str): Strike Price of the Option.
            price (float): price of the order.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            exchange (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail["Token"]

        params = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "instrument_token": token,
            "price": price,
            "trigger_price": "0",
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.LIMIT],
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="POST",
            url=cls.urls["place_order"],
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order_fno(
        cls,
        option: str,
        strike_price: str,
        price: float,
        trigger: float,
        quantity: int,
        side: str,
        headers: dict,
        root: str = Root.BNF,
        expiry: str = WeeklyExpiry.CURRENT,
        exchange: str = ExchangeCode.NFO,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.STOPLOSS,
        unique_id: str = UniqueID.SLORDER,
    ) -> dict[Any, Any]:
        """
        Place Stoploss Order in F&O Segment.

        Parameters:
            option (str): Option Type: 'CE', 'PE'.
            strike_price (str): Strike Price of the Option.
            price (float): price of the order.
            trigger (float): trigger price of the order.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            exchange (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail["Token"]

        params = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "instrument_token": token,
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.SL],
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="POST",
            url=cls.urls["place_order"],
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order_fno(
        cls,
        option: str,
        strike_price: str,
        trigger: float,
        quantity: int,
        side: str,
        headers: dict,
        root: str = Root.BNF,
        expiry: str = WeeklyExpiry.CURRENT,
        exchange: str = ExchangeCode.NFO,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = Variety.STOPLOSS,
        unique_id: str = UniqueID.SLORDER,
    ) -> dict[Any, Any]:
        """
        Place Stoploss-Market Order in F&O Segment.

        Parameters:
            option (str): Option Type: 'CE', 'PE'.
            strike_price (str): Strike Price of the Option.
            trigger (float): trigger price of the order.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            exchange (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail["Token"]

        params = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "instrument_token": token,
            "price": "0",
            "trigger_price": trigger,
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.SLM],
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="POST",
            url=cls.urls["place_order"],
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response=response, headers=headers)

    # Order Details, OrderBook & TradeBook

    @classmethod
    def fetch_raw_orderbook(cls, headers: dict) -> list[dict]:
        """
        Fetch Raw Orderbook Details, without any Standardaization.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: Raw Broker Orderbook Response.
        """
        params = {
            "type": "completed",
            "client_id": headers["user_id"],
        }
        response01 = cls.fetch(
            method="GET",
            url=cls.urls["orderbook"],
            params=params,
            headers=headers["headers"],
        )

        info01 = cls._json_parser(response01)
        orders = info01["data"]["orders"] if info01["data"]["orders"] else []

        params = {
            "type": "pending",
            "client_id": headers["user_id"],
        }
        response02 = cls.fetch(
            method="GET",
            url=cls.urls["orderbook"],
            params=params,
            headers=headers["headers"],
        )

        info02 = cls._json_parser(response02)
        orders.extend(info02["data"]["orders"] if info02["data"]["orders"] else [])

        return orders

    @classmethod
    def fetch_orderbook(cls, headers: dict) -> list[dict]:
        """
        Fetch Orderbook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using fenix Unified Order Response.
        """
        info = cls.fetch_raw_orderbook(headers=headers)

        orders = []
        for order in info:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_tradebook(cls, headers: dict) -> list[dict]:
        """
        Fetch Tradebook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using fenix Unified Order Response.
        """
        params = {"client_id": headers["user_id"]}

        response = cls.fetch(
            method="GET",
            url=cls.urls["tradebook"],
            params=params,
            headers=headers["headers"],
        )

        info = cls._json_parser(response)

        orders = []

        for order in info["data"]["trades"]:
            detail = cls._tradebook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_orders(cls, headers: dict) -> list[dict]:
        """
        Fetch OrderBook Details which is unified across all brokers.
        Use This if you want Avg price, etc. values which sometimes unavailable
        thorugh fetch_orderbook.

        Paramters:
            order_id (str): id of the order.

        Raises:
            InputError: If order does not exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        return cls.fetch_orderbook(headers=headers)

    @classmethod
    def fetch_order(cls, order_id: str, headers: dict) -> dict[Any, Any]:
        """
        Fetch Order Details.

        Paramters:
            order_id (str): id of the order.

        Raises:
            InputError: If order does not exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        order_id = str(order_id)
        orders = cls.fetch_raw_orderbook(headers=headers)

        for order in orders:
            if order["oms_order_id"] == order_id:
                detail = cls._orderbook_json_parser(order)
                return detail

        raise InputError({"This order_id does not exist."})

    @classmethod
    def fetch_orderhistory(cls, order_id: str, headers: dict) -> list[dict]:
        """
        Fetch History of an order.

        Paramters:
            order_id (str): id of the order.
            headers (dict): headers to send orderhistory request with.

        Returns:
            list: A list of dicitonaries containing order history using fenix Unified Order Response.
        """
        params = {"client_id": headers["user_id"]}
        final_url = f"{cls.urls['order_history']}/{order_id}/history"
        response = cls.fetch(
            method="GET",
            url=final_url,
            params=params,
            headers=headers["headers"],
        )
        info = cls._json_parser(response)

        order_history = []
        for order in info["data"]:
            history = cls._orderhistory_json_parser(order)

            order_history.append(history)

        return order_history

    # Order Modification & Sq Off

    @classmethod
    def modify_order(
        cls,
        order_id: str,
        headers: dict,
        price: float | None = None,
        trigger: float | None = None,
        quantity: int | None = None,
        order_type: str | None = None,
        validity: str | None = None,
    ) -> dict[Any, Any]:
        """
        Modify an open order.

        Parameters:
            order_id (str): id of the order to modify.
            headers (dict): headers to send modify_order request with.
            price (float | None, optional): price of t.he order. Defaults to None.
            trigger (float | None, optional): trigger price of the order. Defaults to None.
            quantity (int | None, optional): order quantity. Defaults to None.
            order_type (str | None, optional): Type of Order. defaults to None
            validity (str | None, optional): Order validity Defaults to None.

        Returns:
            dict: fenix Unified Order Response.
        """
        order_info = cls.fetch_order(order_id=order_id, headers=headers)

        params = {
            "oms_order_id": order_id,
            "instrument_token": order_info[Order.TOKEN],
            "exchange": cls.req_exchange[order_info[Order.EXCHANGE]],
            "price": price or order_info[Order.PRICE],
            "trigger_price": trigger or order_info[Order.TRIGGERPRICE],
            "quantity": quantity or order_info[Order.QUANTITY],
            "order_type": (
                cls._key_mapper(cls.req_order_type, order_type, "order_type")
                if order_type
                else cls.req_order_type[order_info[Order.TYPE]]
            ),
            "validity": (
                cls._key_mapper(cls.req_validity, validity, "validity")
                if validity
                else cls.req[order_info[Order.VALIDITY]]
            ),
            "product": cls.req_product.get(
                order_info[Order.PRODUCT], order_info[Order.PRODUCT]
            ),
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="GET",
            url=cls.urls["place_order"],
            params=params,
            headers=headers["headers"],
        )

        return cls._create_order_parser(response)

    @classmethod
    def cancel_order(cls, order_id: str, headers: dict) -> dict[Any, Any]:
        """
        Cancel an open order.

        Parameters:
            order_id (str): id of the order.
            headers (dict): headers to send cancel_order request with.

        Returns:
            dict: fenix Unified Order Response.
        """
        params = {"client_id": headers["user_id"]}
        final_url = f"{cls.urls['place_order']}/{order_id}"

        response = cls.fetch(
            method="DELETE",
            url=final_url,
            params=params,
            headers=headers["headers"],
        )
        info = cls._json_parser(response)

        return cls._create_order_parser(info)

    # Positions, Account Limits & Profile

    @classmethod
    def fetch_day_positions(
        cls,
        headers: dict,
    ) -> dict[Any, Any]:
        """
        Fetch the Day's Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        params = {
            "type": "live",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="GET",
            url=cls.urls["positions"],
            params=params,
            headers=headers["headers"],
        )
        info = cls._json_parser(response)

        positions = []
        for position in info["data"]:
            detail = cls._position_json_parser(position)
            positions.append(detail)

        return positions

    @classmethod
    def fetch_net_positions(
        cls,
        headers: dict,
    ) -> dict[Any, Any]:
        """
        Fetch Total Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        params = {
            "type": "historical",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(
            method="GET",
            url=cls.urls["positions"],
            params=params,
            headers=headers["headers"],
        )
        info = cls._json_parser(response)

        positions = []
        for position in info["data"]:
            detail = cls._position_json_parser(position)
            positions.append(detail)

        return positions

    @classmethod
    def fetch_positions(cls, headers: dict) -> dict[Any, Any]:
        """
        Fetch Day & Net Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        return cls.fetch_net_positions(headers=headers)

    @classmethod
    def fetch_holdings(
        cls,
        headers: dict,
    ) -> dict[Any, Any]:
        """
        Fetch Account Holdings.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Positions Response.
        """
        params = {"client_id": headers["user_id"]}

        response = cls.fetch(
            method="GET",
            url=cls.urls["holdings"],
            params=params,
            headers=headers["headers"],
        )
        info = cls._json_parser(response)

        holdings = []
        for holding in info["data"]:
            detail = cls._position_json_parser(holding)
            holdings.append(detail)

        return holdings

    @classmethod
    def profile(cls, headers: dict) -> dict[Any, Any]:
        """
        Fetch Profile Limits of the User.

        Parameters:
            headers (dict): headers to send profile request with.

        Returns:
            dict: fenix Unified Profile Response.
        """
        params = {"client_id": headers["user_id"]}

        response = cls.fetch(
            method="GET",
            url=cls.urls["profile"],
            params=params,
            headers=headers["headers"],
        )

        response = cls._json_parser(response)
        profile = cls._profile_json_parser(response["data"])

        return profile
