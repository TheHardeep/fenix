from __future__ import annotations
import hashlib
from urllib.parse import urlparse
from urllib.parse import parse_qs
from typing import TYPE_CHECKING
from typing import Any

from kronos.base.exchange import Exchange

from kronos.base.constants import Side
from kronos.base.constants import OrderType
from kronos.base.constants import ExchangeCode
from kronos.base.constants import Product
from kronos.base.constants import Validity
from kronos.base.constants import Variety
from kronos.base.constants import Status
from kronos.base.constants import Order
from kronos.base.constants import Profile
from kronos.base.constants import Position
from kronos.base.constants import Root
from kronos.base.constants import WeeklyExpiry
from kronos.base.constants import UniqueID


from kronos.base.errors import InputError
from kronos.base.errors import ResponseError
from kronos.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response


class zerodha(Exchange):
    """
    Zerodha kronos Broker Class

    Returns:
        kronos.zerodha: kronos Zerodha Broker Object
    """


    # Market Data Dictonaries

    indices = {}
    nfo_tokens = {}
    id = "zerodha"
    _session = Exchange._create_session()


    # Base URLs

    base_urls = {
        "api_doc": "https://kite.trade/docs/connect/v3",
        "base": "https://api.kite.trade",
        "access_token_base": "https://kite.zerodha.com",
        "market_data": "https://api.kite.trade/instruments",
    }


    # Access Token Generation URLs

    token_urls = {
        "api_session": "https://kite.trade/connect/login?api_key=***&v=3",
        "session": f"{base_urls['access_token_base']}/api/connect/session?",
        "login": f"{base_urls['access_token_base']}/api/login",
        "twofa": f"{base_urls['access_token_base']}/api/twofa",
        "connect": f"{base_urls['access_token_base']}/connect/finish?",
        "token_url": f"{base_urls['base']}/session/token",
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base']}/orders",
        "tradebook": f"{base_urls['base']}/trades",
        "holdings": f"{base_urls['base']}/portfolio/holdings",
        "postions": f"{base_urls['base']}/portfolio/positions",
        "profile": f"{base_urls['base']}/user/profile",
    }


    # Request Parameters Dictionaries

    req_exchange = {
        ExchangeCode.NSE: "NSE",
        ExchangeCode.BSE: "BSE",
        ExchangeCode.NFO: "NFO",
        ExchangeCode.CDS: "CDS",
        ExchangeCode.BCD: "BCD",
        ExchangeCode.MCX: "MCX"
    }

    req_side = {
        Side.BUY: "BUY",
        Side.SELL: "SELL"
    }

    req_product = {
        Product.MIS: "MIS",
        Product.CNC: "CNC",
        Product.NRML: "NRML",

    }

    req_order_type = {
        OrderType.MARKET: "MARKET",
        OrderType.LIMIT: "LIMIT",
        OrderType.SLM: "SL-M",
        OrderType.SL: "SL"
    }

    req_validity = {
        Validity.DAY: "DAY",
        Validity.IOC: "IOC",
        Validity.TTL: "TTL"
    }

    req_variety = {
        Variety.REGULAR: "regular",
        Variety.AMO: "amo",
        Variety.CO: "co",
        Variety.ICEBERG: "iceberg",
        Variety.AUCTION: "auction",
    }


    # Response Parameters Dictionaries

    resp_status = {
        "OPEN": Status.OPEN,
        "COMPLETE": Status.COMPLETE,
        "CANCELLED": Status.CANCELLED,
        "REJECTED": Status.REJECTED,
        "AMO REQ RECEIVED": Status.PENDING,
        "PUT ORDER REQ RECEIVED": Status.PENDING
    }

    resp_variety = {
        "regular": Variety.REGULAR,
        "amo": Variety.AMO,
        "co": Variety.CO,
        "iceberg": Variety.ICEBERG,
        "auction": Variety.AUCTION,

    }


    # NFO Script Fetch


    @classmethod
    def create_indices(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the aliceblue.indices Dictionary.

        Returns:
            dict: Unified kronos indices format.
        """
        df = cls.data_reader(cls.base_urls["market_data"], filetype='csv')

        df = df[(df["segment"] == "INDICES")][["tradingsymbol", "instrument_token"]]
        df.rename({"tradingsymbol": "Symbol", "instrument_token": "Token"}, axis=1, inplace=True)
        df.index = df['Symbol']

        indices = df.to_dict(orient='index')

        indices[Root.BNF] = indices["NIFTY BANK"]
        indices[Root.NF] = indices["NIFTY 50"]
        indices[Root.FNF] = indices["NIFTY FIN SERVICE"]
        indices[Root.MIDCPNF] = indices["NIFTY MID SELECT"]

        cls.indices = indices

        return indices

    @classmethod
    def create_nfo_tokens(cls):
        """
        Creates BANKNIFTY & NIFTY Current, Next and Far Expiries;
        Stores them in the zerodha.nfo_tokens Dictionary.

        Raises:
            TokenDownloadError: Any Error Occured is raised through this Error Type.
        """
        try:

            df = cls.data_reader(cls.base_urls["market_data"], filetype='csv')

            df = df[
                (
                    (df["name"] == "BANKNIFTY") |
                    (df["name"] == "NIFTY") |
                    (df["name"] == "FINNIFTY") |
                    (df["name"] == "MIDCPNIFTY")

                ) &
                (
                    (df["segment"] == "NFO-OPT")
                )]

            df.rename({"instrument_token": "Token", "name": "Root", "expiry": "Expiry", "tradingsymbol": "Symbol",
                       "instrument_type": "Option", "tick_size": "TickSize", "lot_size": "LotSize",
                       "last_price": "LastPrice", "strike": "StrikePrice"
                       },
                      axis=1, inplace=True)

            df = df[["Token", "Symbol", "Expiry", "Option",
                     "StrikePrice", "LotSize",
                     "Root", "LastPrice", "TickSize"
                     ]]

            df["StrikePrice"] = df["StrikePrice"].astype(int)
            df["Expiry"] = cls.pd_datetime(df["Expiry"]).dt.date.astype(str)

            expiry_data = cls.jsonify_expiry(data_frame=df)
            cls.nfo_tokens = expiry_data

            return expiry_data

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc


    # Headers & Json Parsers


    @classmethod
    def create_headers(cls,
                       params: dict,
                       ) -> dict[str, str]:
        """
        Generate Headers used to access Endpoints in Zerodha.

        Args:
            user_id (str): User ID of the Account.
            password (str): Password of the Account.
            totpstr (str): String of characters used to generate TOTP.
            api_key (str): API Key of the Account.
            api_secret (str): API Secret of the Account.

        Returns:
            dict[str, str]: Zerodha Headers.
        """

        for key in ["user_id", "password", "totpstr", "api_key", "api_secret"]:
            if key not in params:
                raise KeyError(f"Please provide {key}")

        api_session_url = cls.token_urls["api_session"].replace("***", params['api_key'])

        req_01 = cls.fetch(method="GET", url=api_session_url, timeout=10)
        sess_id = req_01.url.split("?")[1]

        req_02 = cls.fetch(method="GET", url=f"{cls.token_urls['session']}{sess_id}", timeout=10)  # noqa: F841

        data = {'password': params["password"], 'user_id': params["user_id"]}
        req_03 = cls.fetch(method="POST", url=cls.token_urls["login"], data=data, timeout=10)
        response = cls._json_parser(req_03)

        req_id = response['data']['request_id']
        totp = cls.totp_creator(params["totpstr"])
        data = {"user_id": params["user_id"], "request_id": req_id, "twofa_value": str(totp),
                "twofa_type": "totp", "skip_session": "false"
                }

        req_04 = cls.fetch(method="POST", url=cls.token_urls["twofa"], data=data, timeout=10)  # noqa: F841

        try:
            req_05 = cls.fetch(method="GET", url=f"{cls.token_urls['connect']}{sess_id}")
            req_token_url = req_05.url
        except Exception as e:
            req_token_url = str(e)

        req_token = parse_qs(urlparse(req_token_url).query).get('request_token')[0].split()[0]

        encoded_str = params["api_key"].encode("utf-8") + req_token.encode("utf-8") + params["api_secret"].encode("utf-8")
        hash_obj = hashlib.sha256(encoded_str)
        checksum = hash_obj.hexdigest()

        data = {"api_key": params["api_key"], "request_token": req_token, "checksum": checksum}

        req_06 = cls.fetch(method="POST", url=cls.token_urls["token_url"], data=data, timeout=10)
        response = cls._json_parser(req_06)

        accessToken = response['data']['access_token']

        headers = {
            "headers": {
                "X-Kite-Version": "3",
                "User-Agent": "Kiteconnect-python/4.2.0",
                "Authorization": f'token {params["api_key"]}:{accessToken}',
                "user_id": params["user_id"],
                "api_key": params["api_key"],
                "access_token": accessToken,

            }

        }

        cls._session = cls._create_session()

        return headers

    @classmethod
    def _json_parser(cls,
                     response: Response,
                     ) -> dict[Any, Any] | list[dict[Any, Any]]:
        """
        Parses the Json Repsonse Obtained from Broker.

        Parameters:
            response (Response): Json Response Obtained from Broker.

        Raises:
            ResponseError: Raised if any error received from broker.

        Returns:
            dict: json response obtained from exchange.
        """
        json_response = cls.on_json_response(response)
        print(json_response)
        if json_response['status']:
            return json_response

        else:
            error = json_response.get('message', "No Message")
            raise ResponseError(cls.id + " " + error)

    @classmethod
    def _orderbook_json_parser(cls, order):
        """
        Parse Orderbook Order Json Response.

        Parameters:
            order (dict): Orderbook Order Json Response from Broker.

        Returns:
            dict: Unified kronos Order Response.
        """
        parsedOrder = {
            Order.ID: order["order_id"],
            Order.USERID: order["tag"],
            Order.TIMESTAMP: cls.datetime_strp(order["order_timestamp"], "%Y-%m-%d %H:%M:%S"),
            Order.SYMBOL: order["tradingsymbol"],
            Order.TOKEN: order["instrument_token"],
            Order.SIDE: cls.req_side.get(order["transaction_type"], order["transaction_type"]),
            Order.TYPE: cls.req_order_type.get(order["order_type"], order["order_type"]),
            Order.AVGPRICE: order["average_price"],
            Order.PRICE: order["price"],
            Order.TRIGGERPRICE: order["trigger_price"],
            Order.QUANTITY: int(order["quantity"]),
            Order.FILLEDQTY: int(order["filled_quantity"]),
            Order.REMAININGQTY: int(order["pending_quantity"]),
            Order.CANCELLEDQTY: int(order["cancelled_quantity"]),
            Order.STATUS: cls.resp_status.get(order["status"], order["status"]),
            Order.REJECTREASON: order["status_message"],
            Order.DISCLOSEDQUANTITY: int(order["disclosed_quantity"]),
            Order.PRODUCT: cls.req_product.get(order["product"], order["product"]),
            Order.EXCHANGE: cls.req_exchange.get(order["exchange"], order["exchange"]),
            Order.SEGMENT: cls.req_exchange.get(order["exchange"], order["exchange"]),
            Order.VALIDITY: cls.req_validity.get(order["validity"], order["validity"]),
            Order.VARIETY: cls.resp_variety.get(order["variety"], order["variety"]),
            Order.INFO: order,
        }

        return parsedOrder

    @classmethod
    def _position_json_parser(cls,
                              position: dict[Any, Any],
                              day_or_net: str = "",
                              ):
        """
        Parse Acoount Position Json Response.

        Parameters:
            order (dict): Acoount Position Json Response from Broker.
            day_or_net (str): Takes 2 parameters "day_" and "_". Defaults to "".
                              Required to access keys in broker response.

        Returns:
            dict: Unified Kronos Position Response.
        """
        parsed_position = {
            Position.SYMBOL: position["tradingsymbol"],
            Position.TOKEN: position["instrument_token"],
            Position.NETQTY: position["quantity"],
            Position.AVGPRICE: position["average_price"],
            Position.MTM: position["m2m"],
            Position.PNL: position["pnl"],
            Position.BUYQTY: position[f"{day_or_net}buy_quantity"],
            Position.BUYPRICE: position[f"{day_or_net}buy_price"],
            Position.SELLQTY: position[f"{day_or_net}sell_quantity"],
            Position.SELLPRICE: position[f"{day_or_net}sell_value"],
            Position.LTP: position["last_price"],
            Position.PRODUCT: cls.req_product.get(position["product"], position["product"]),
            Position.EXCHANGE: cls.req_exchange.get(position["exchange"], position["exchange"]),
            Position.INFO: position,
        }

        return parsed_position

    @classmethod
    def _holding_json_parser(cls,
                             holding: dict[Any, Any],
                             ):
        """
        Parse Account Holding Json Response to a kronos Unified Position Response.

        Parameters:
            holding (dict): Account Position Json Response from Broker.

        Returns:
            dict: Unified kronos Position/Holding Response.
        """
        parsed_holding = {
            Position.SYMBOL: holding["tradingsymbol"],
            Position.TOKEN: holding["instrument_token"],
            Position.NETQTY: holding["quantity"],
            Position.AVGPRICE: holding["average_price"],
            Position.MTM: holding["day_change"],
            Position.PNL: holding["pnl"],
            Position.LTP: holding["last_price"],
            Position.PRODUCT: cls.req_product.get(holding["product"], holding["product"]),
            Position.EXCHANGE: cls.req_exchange.get(holding["exchange"], holding["exchange"]),
            Position.INFO: holding,
        }

        return parsed_holding

    @classmethod
    def _profile_json_parser(cls,
                             profile: dict
                             ) -> dict[Any, Any]:
        """
        Parse User Profile Json Response.

        Parameters:
            profile (dict): User Profile Json Response from Broker.

        Returns:
            dict: Unified kronos Profile Response.
        """
        parsed_profile = {
            Profile.CLIENTID: profile["user_id"],
            Profile.NAME: profile["user_name"],
            Profile.EMAILID: profile["email"],
            Profile.MOBILENO: "0000000000",
            Profile.PAN: "",
            Profile.ADDRESS: "",
            Profile.BANKNAME: "",
            Profile.BANKBRANCHNAME: None,
            Profile.BANKACCNO: "",
            Profile.EXHCNAGESENABLED: profile["exchanges"],
            Profile.ENABLED: "Activated",
            Profile.INFO: profile,
        }

        return parsed_profile

    @classmethod
    def _create_order_parser(cls,
                             response: Response,
                             headers: dict
                             ) -> dict[Any, Any]:
        """
        Parse Json Response Obtained from Broker After Placing Order to get order_id
        and fetching the json repsone for the said order_id.

        Parameters:
            response (Response): Json Repsonse Obtained from broker after Placing an Order.
            headers (dict): headers to send order request with.

        Returns:
            dict: Unified kronos Order Response.
        """
        info = cls._json_parser(response)

        order_id = info["data"]["order_id"]
        order = cls.fetch_order(order_id=order_id, headers=headers)

        return order


    # Order Functions


    @classmethod
    def create_order(cls,
                     token: int,
                     exchange: str,
                     symbol: str,
                     quantity: int,
                     side: str,
                     product: str,
                     validity: str,
                     variety: str,
                     unique_id: str,
                     headers: dict,
                     price: float = 0,
                     trigger: float = 0,
                     target: float = 0,
                     stoploss: float = 0,
                     trailing_sl: float = 0,
                     ) -> dict[Any, Any]:

        """
        Place an Order.

        Parameters:
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            product (str, optional): Order product.
            validity (str, optional): Order validity.
            variety (str, optional): Order variety.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            price (float): Order price
            trigger (float): order trigger price
            target (float, optional): Order Target price. Defaulsts to 0.
            stoploss (float, optional): Order Stoploss price. Defaulsts to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaulsts to 0.

        Returns:
            dict: kronos Unified Order Response
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
            data = {
                "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                "tradingsymbol": symbol,
                "price": price,
                "trigger_price": trigger,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[order_type],
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "tag": unique_id,
                "disclosed_quantity": "0",

            }
        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        variety = cls._key_mapper(cls.req_variety, variety, "variety"),
        final_url = f"{cls.urls['place_order'] }/{variety}"

        response = cls.fetch(method="POST", url=final_url,
                             data=data, headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order(cls,
                     token: int,
                     exchange: str,
                     symbol: str,
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
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaulsts to 0.
            stoploss (float, optional): Order Stoploss price. Defaulsts to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaulsts to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
            data = {
                "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                "tradingsymbol": symbol,
                "price": "0",
                "trigger_price": "0",
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.MARKET],
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "tag": unique_id,
                "disclosed_quantity": "0",

            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        variety = cls._key_mapper(cls.req_variety, variety, "variety"),
        final_url = f"{cls.urls['place_order'] }/{variety}"

        response = cls.fetch(method="POST", url=final_url,
                             data=data, headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order(cls,
                    token: int,
                    exchange: str,
                    symbol: str,
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
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            price (float): Order price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaulsts to 0.
            stoploss (float, optional): Order Stoploss price. Defaulsts to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaulsts to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
            data = {
                "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                "tradingsymbol": symbol,
                "price": price,
                "trigger_price": "0",
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.LIMIT],
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "tag": unique_id,
                "disclosed_quantity": "0",

            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        variety = cls._key_mapper(cls.req_variety, variety, "variety"),
        final_url = f"{cls.urls['place_order'] }/{variety}"

        response = cls.fetch(method="POST", url=final_url,
                             data=data, headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order(cls,
                 token: int,
                 exchange: str,
                 symbol: str,
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
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            price (float): Order price.
            trigger (float): order trigger price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaulsts to 0.
            stoploss (float, optional): Order Stoploss price. Defaulsts to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaulsts to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
            data = {
                "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                "tradingsymbol": symbol,
                "price": price,
                "trigger_price": trigger,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.SL],
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "tag": unique_id,
                "disclosed_quantity": "0",

            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        variety = cls._key_mapper(cls.req_variety, variety, "variety"),
        final_url = f"{cls.urls['place_order'] }/{variety}"

        response = cls.fetch(method="POST", url=final_url,
                             data=data, headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order(cls,
                  token: int,
                  exchange: str,
                  symbol: str,
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
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            trigger (float): order trigger price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaulsts to 0.
            stoploss (float, optional): Order Stoploss price. Defaulsts to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaulsts to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
            data = {
                "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                "tradingsymbol": symbol,
                "price": "0",
                "trigger_price": trigger,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, "side"),
                "order_type": cls.req_order_type[OrderType.SLM],
                "product": cls._key_mapper(cls.req_product, product, "product"),
                "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
                "tag": unique_id,
                "disclosed_quantity": "0",

            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        variety = cls._key_mapper(cls.req_variety, variety, "variety"),
        final_url = f"{cls.urls['place_order'] }/{variety}"

        response = cls.fetch(method="POST", url=final_url,
                             data=data, headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)


    # NFO Order Functions


    @classmethod
    def create_order_nfo(cls,
                         exchange: str,
                         root: str,
                         expiry: str,
                         option: str,
                         strike_price: int,
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
            option (str): Option Type: 'CE', 'PE'.
            strike_price (int): Strike Price of the Option.
            price (float): price of the order.
            trigger (float): trigger price of the order.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: Kronos Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']

        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        data = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "tradingsymbol": symbol,
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "transaction_type": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[order_type],
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "tag": unique_id,
            "disclosed_quantity": "0",

        }

        variety = cls._key_mapper(cls.req_variety, variety, "variety"),

        final_url = f"{cls.urls['place_order'] }/{variety}"

        response = cls.fetch(method="POST", url=final_url,
                             data=data, headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order_nfo(cls,
                         option: str,
                         strike_price: int,
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
            strike_price (int): Strike Price of the Option.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: Kronos Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']

        data = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "tradingsymbol": symbol,
            "price": "0",
            "trigger_price": "0",
            "quantity": quantity,
            "transaction_type": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.MARKET],
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "tag": unique_id,
            "disclosed_quantity": "0",

        }

        variety = cls._key_mapper(cls.req_variety, variety, "variety"),

        final_url = f"{cls.urls['place_order'] }/{variety}"

        response = cls.fetch(method="POST", url=final_url,
                             data=data, headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order_nfo(cls,
                        option: str,
                        strike_price: int,
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
            strike_price (int): Strike Price of the Option.
            price (float): price of the order.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: Kronos Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']

        data = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "tradingsymbol": symbol,
            "price": price,
            "trigger_price": "0",
            "quantity": quantity,
            "transaction_type": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.LIMIT],
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "tag": unique_id,
            "disclosed_quantity": "0",

        }

        variety = cls._key_mapper(cls.req_variety, variety, "variety"),

        final_url = f"{cls.urls['place_order'] }/{variety}"

        response = cls.fetch(method="POST", url=final_url,
                             data=data, headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order_nfo(cls,
                     option: str,
                     strike_price: int,
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
            strike_price (int): Strike Price of the Option.
            price (float): price of the order.
            trigger (float): trigger price of the order.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: Kronos Unified Order Response
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']

        data = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "tradingsymbol": symbol,
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "transaction_type": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.SL],
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "tag": unique_id,
            "disclosed_quantity": "0",

        }

        variety = cls._key_mapper(cls.req_variety, variety, "variety"),

        final_url = f"{cls.urls['place_order'] }/{variety}"

        response = cls.fetch(method="POST", url=final_url,
                             data=data, headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order_nfo(cls,
                      option: str,
                      strike_price: int,
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
            strike_price (int): Strike Price of the Option.
            trigger (float): trigger price of the order.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: Kronos Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']

        data = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "tradingsymbol": symbol,
            "price": "0",
            "trigger_price": trigger,
            "quantity": quantity,
            "transaction_type": cls._key_mapper(cls.req_side, side, "side"),
            "order_type": cls.req_order_type[OrderType.SLM],
            "product": cls._key_mapper(cls.req_product, product, "product"),
            "validity": cls._key_mapper(cls.req_validity, validity, "validity"),
            "tag": unique_id,
            "disclosed_quantity": "0",

        }

        variety = cls._key_mapper(cls.req_variety, variety, "variety"),

        final_url = f"{cls.urls['place_order'] }/{variety}"

        response = cls.fetch(method="POST", url=final_url,
                             data=data, headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)


    # BO Order Functions

    # NO BO Orders For IIFL


    # Order Details, OrderBook & TradeBook


    @classmethod
    def fetch_raw_orderhistory(cls,
                               order_id: str,
                               headers: dict
                               ) -> list[dict]:
        """
        Fetch Raw History of an order.

        Paramters:
            order_id (str): id of the order.
            headers (dict): headers to send orderhistory request with.

        Returns:
            list[dict]: Raw Broker Order History Response.
        """
        final_url = f"{cls.urls['place_order'] }/{order_id}"
        response = cls.fetch(method="GET", url=final_url, headers=headers['headers'])
        return cls._json_parser(response)


    @classmethod
    def fetch_orderbook(cls,
                        headers: dict
                        ) -> list[dict]:
        """
        Fetch Orderbook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using kronos Unified Order Response.
        """
        response = cls.fetch(method="GET", url=cls.urls['place_order'], headers=headers['headers'])
        info = cls._json_parser(response)

        orders = []
        for order in info['data']:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_tradebook(cls,
                        headers: dict
                        ) -> list[dict]:
        """
        Fetch Tradebook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using kronos Unified Order Response.
        """
        response = cls.fetch(method="GET", url=cls.urls['tradebook'], headers=headers['headers'])
        info = cls._json_parser(response)

        orders = []
        for order in info['data']:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_orders(cls,
                     headers: dict
                     ) -> list[dict]:
        """
        Fetch OrderBook Details which is unified across all brokers.
        Use This if you want Avg price, etc. values which sometimes unavailable
        thorugh fetch_orderbook.

        Paramters:
            order_id (str): id of the order.

        Raises:
            InputError: If order does not exist.

        Returns:
            dict: kronos Unified Order Response.
        """
        return cls.fetch_orderbook(headers=headers)

    @classmethod
    def fetch_order(cls,
                    order_id: str,
                    headers: dict
                    ) -> dict[Any, Any]:
        """
        Fetch Order Details.

        Paramters:
            order_id (str): id of the order.

        Raises:
            InputError: If order does not exist.

        Returns:
            dict: kronos Unified Order Response.
        """
        info = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)
        order = info['data'][-1]

        return cls._orderbook_json_parser(order)

    @classmethod
    def fetch_orderhistory(cls,
                           order_id: str,
                           headers: dict,
                           ) -> dict[Any, Any]:
        """
        Fetch History of an order.

        Paramters:
            order_id (str): id of the order.
            headers (dict): headers to send orderhistory request with.

        Returns:
            list: A list of dicitonaries containing order history using kronos Unified Order Response.
        """
        info = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)

        order_history = []
        for order in info["data"]:
            history = cls._orderbook_json_parser(order)
            order_history.append(history)

        return order_history


    # Order Modification & Sq Off


    @classmethod
    def modify_order(cls,
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
            order_type (str | None, optional): Type of Order. defaults to None.
            validity (str | None, optional): Order validity Defaults to None.

        Returns:
            dict: kronos Unified Order Response.
        """
        curr_order = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers["headers"])
        variety = curr_order["variety"]
        final_url = f"{cls.urls['place_order'] }/{variety}/{order_id}"

        data = {
            "price": price or curr_order["price"],
            "trigger_price": trigger or curr_order["trigger_price"],
            "quantity": quantity or curr_order["quantity"],
            "order_type": cls._key_mapper(cls.req_order_type, order_type, 'order_type') or curr_order["order_type"],
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity') or curr_order["validity"],
        }

        response = cls.fetch(method="PUT", url=final_url,
                             data=data, headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def cancel_order(cls,
                     order_id: str,
                     headers: dict
                     ) -> dict[Any, Any]:
        """
        Cancel an open order.

        Parameters:
            order_id (str): id of the order.
            headers (dict): headers to send cancel_order request with.

        Returns:
            dict: kronos Unified Order Response.
        """
        order = cls.fetch_order(order_id=order_id, headers=headers["headers"])
        variety = cls.req_variety[order[Order.VARIETY]]

        final_url = f"{cls.urls['place_order'] }/{variety}/{order_id}"

        response = cls.fetch(method="DELETE", url=final_url,
                             headers=headers['headers'])

        return cls._create_order_parser(response=response, headers=headers)


    # Positions, Account Limits & Profile


    @classmethod
    def fetch_raw_positions(cls,
                            headers: dict
                            ) -> list[dict]:
        """
        Fetch Raw Account Positions.

        Paramters:
            headers (dict): headers to send orderhistory request with.

        Returns:
            list[dict]: Raw Account Position Response.
        """
        response = cls.fetch(method="GET", url=cls.urls['postions'], headers=headers['headers'])
        return cls._json_parser(response)

    @classmethod
    def fetch_day_positions(cls,
                            headers: dict
                            ) -> list[dict]:
        """
        Fetch the Day's Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Position Response.
        """
        info = cls.fetch_raw_positions(headers=headers)

        positions = []
        for order in info["data"]["day"]:
            detail = cls._position_json_parser(order, day_or_net="day_")
            positions.append(detail)

        return positions

    @classmethod
    def fetch_net_positions(cls,
                            headers: dict
                            ) -> list[dict]:
        """
        Fetch Total Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Position Response.
        """
        info = cls.fetch_raw_positions(headers=headers)

        positions = []
        for order in info["data"]["net"]:
            detail = cls._position_json_parser(order)
            positions.append(detail)

        return positions

    @classmethod
    def fetch_positions(cls,
                        headers: dict,
                        ) -> dict[Any, Any]:
        """
        Fetch Day & Net Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Position Response.
        """
        info = cls.fetch_raw_positions(headers=headers)

        positions = []
        for order in info["data"]["net"]:
            detail = cls._position_json_parser(order)
            positions.append(detail)

        for order in info["data"]["day"]:
            detail = cls._position_json_parser(order, day_or_net="day_")
            positions.append(detail)

        return positions

    @classmethod
    def fetch_holdings(cls,
                       headers: dict
                       ) -> list[dict]:
        """
        Fetch Account Holdings.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Positions Response.
        """
        response = cls.fetch(method="GET", url=cls.urls['holdings'], headers=headers['headers'])
        info = cls._json_parser(response)

        holdings = []
        for order in info['data']['net']:
            detail = cls._holding_json_parser(order)
            holdings.append(detail)

        return holdings

    @classmethod
    def rms_limits(cls,
                   headers: dict
                   ) -> dict[Any, Any]:
        """
        Fetch Risk Management System Limits.

        Parameters:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict: kronos Unified RMS Limits Response.
        """
        ...

    @classmethod
    def profile(cls,
                headers: dict
                ) -> dict[Any, Any]:

        """
        Fetch Profile Limits of the User.

        Parameters:
            headers (dict): headers to send profile request with.

        Returns:
            dict: kronos Unified Profile Response.
        """
        response = cls.fetch(method="GET", url=cls.urls["profile"], headers=headers["headers"])

        info = cls._json_parser(response)
        profile = cls._profile_json_parser(info['data'])

        return profile
