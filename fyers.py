from __future__ import annotations
import base64
import hashlib
from urllib.parse import parse_qs, urlparse

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
from kronos.base.constants import Position
from kronos.base.constants import Profile
from kronos.base.constants import Root
from kronos.base.constants import WeeklyExpiry
from kronos.base.constants import UniqueID


from kronos.base.errors import InputError
from kronos.base.errors import BrokerError
from kronos.base.errors import ResponseError
from kronos.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response


class fyers(Exchange):
    """
    Fyers kronos Broker Class

    Returns:
        kronos.aliceblue: kronos Fyers Broker Object
    """

    indices = {}
    eq_tokens = {}
    nfo_tokens = {}
    id = 'fyers'
    _session = Exchange._create_session()


    # Base URLs

    base_urls = {
        "api_doc": "https://myapi.fyers.in/docsv3",
        "base01": "https://api-t2.fyers.in",
        "base02": "https://api.fyers.in/api/v2",
        "base03": "https://api-t1.fyers.in/api/v3",
        "market_data": "https://public.fyers.in/sym_details/NSE_FO.csv"
    }


    # Access Token Generation URLs

    token_urls = {
        "login_otp": f"{base_urls['base01']}/vagator/v2/send_login_otp_v2",
        "verify_totp": f"{base_urls['base01']}/vagator/v2/verify_otp",
        "verify_pin": f"{base_urls['base01']}/vagator/v2/verify_pin_v2",
        "token": f"{base_urls['base03']}/token",
        "validate_authcode": f"{base_urls['base03']}/validate-authcode",

    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base03']}/orders/sync",
        "modify_order": f"{base_urls['base03']}/orders",
        "cancel_order": f"{base_urls['base03']}/orders",
        "orderbook": f"{base_urls['base03']}/orders",
        "tradebook": f"{base_urls['base03']}/tradebook",
        "positions": f"{base_urls['base03']}/positions",
        "holdings": f"{base_urls['base03']}/holdings",
        "rms_limits": f"{base_urls['base03']}/funds",
        "profile": f"{base_urls['base03']}/profile",
    }


    # Request Parameters Dictionaries

    req_side = {
        Side.BUY: 1,
        Side.SELL: -1,
    }

    req_product = {
        Product.MIS: "INTRADAY",
        Product.NRML: "CARRYFORWARD",
        Product.CNC: "CNC",
        Product.MARGIN: "MARGIN",
        Product.BO: "BO",
        Product.CO: "CO",
    }

    req_order_type = {
        OrderType.MARKET: 2,
        OrderType.LIMIT: 1,
        OrderType.SL: 4,
        OrderType.SLM: 3
    }

    req_variety = {
        Variety.REGULAR: "NORMAL",
        Variety.STOPLOSS: "STOPLOSS",
        Variety.AMO: "AMO",
        Variety.BO: "ROBO"
    }

    req_validity = {
        Validity.DAY: "DAY",
        Validity.IOC: "IOC"
    }


    # Response Parameters Dictionaries

    resp_exchange = {
        10: ExchangeCode.NSE,
        11: ExchangeCode.MCX,
        12: ExchangeCode.BSE,
    }

    resp_segment = {
        "1010": ExchangeCode.NSE,
        "1011": ExchangeCode.NFO,
        "1210": ExchangeCode.BSE,
        "1211": ExchangeCode.BFO,
        "1120": ExchangeCode.MCX,


    }

    resp_side = {
        1: Side.BUY,
        -1: Side.SELL,
    }

    resp_status = {
        6: Status.PENDING,
        5: Status.REJECTED,
        2: Status.FILLED,
        1: Status.CANCELLED,
        4: Status.OPEN
    }

    resp_order_type = {
        2: OrderType.MARKET,
        1: OrderType.LIMIT,
        4: OrderType.SL,
        3: OrderType.SLM
    }

    resp_product = {
        "INTRADAY": Product.MIS,
        "CARRYFORWARD": Product.NRML,
        "CNC": Product.CNC,
        "MARGIN": Product.MARGIN,
        "BO": Product.BO,
        "CO": Product.CO,
    }


    # NFO Script Fetch


    @classmethod
    def create_eq_tokens(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the aliceblue.indices Dictionary.

        Returns:
            dict: Unified kronos indices format.
        """
        col_names = [
            "Fytoken", "Symbol Details", "Exchange Instrument type", "Minimum lot size",
            "Tick size", "ISIN", "Trading Session", "Last update date", "Expiry date",
            "Symbol ticker", "Exchange", "Segment", "Scrip code", "Underlying scrip code",
            "Option type", "Strike price", "Underlying FyToken", "NA", "NAA"
        ]

        df_bse = cls.data_reader(cls.base_urls["market_data"].replace("NSE_FO", "BSE_CM"), filetype='csv', col_names=col_names)

        df_bse = df_bse[(df_bse['Exchange'] == 12) &
                        (df_bse['Segment'] == 10) &
                        (df_bse['Exchange Instrument type'].isin([0, 50]))
                        ]
        df_bse = df_bse[["Underlying scrip code", "Scrip code", "Symbol ticker", "Minimum lot size", "Tick size"]]

        df_bse.rename({"Scrip code": "Token", "Underlying scrip code": "Index",
                       "Symbol ticker": "Symbol", "Tick size": "TickSize",
                       "Minimum lot size": "LotSize"}, axis=1, inplace=True)

        df_bse.set_index(df_bse['Index'], inplace=True)
        df_bse.drop_duplicates(subset=['Symbol'], keep='first', inplace=True)
        df_bse.drop(columns="Index", inplace=True)


        df_nse = cls.data_reader(cls.base_urls["market_data"].replace("NSE_FO", "NSE_CM"), filetype='csv', col_names=col_names)

        df_nse = df_nse[(df_nse['Exchange'] == 10) &
                        (df_nse['Segment'] == 10) &
                        (df_nse['Symbol ticker'].str.endswith("-EQ"))
                        ]
        df_nse = df_nse[["Underlying scrip code", "Scrip code", "Symbol ticker", "Minimum lot size", "Tick size"]]

        df_nse.rename({"Scrip code": "Token", "Underlying scrip code": "Index",
                       "Symbol ticker": "Symbol", "Tick size": "TickSize",
                       "Minimum lot size": "LotSize"}, axis=1, inplace=True)

        df_nse.set_index(df_nse['Index'], inplace=True)
        df_nse.drop(columns="Index", inplace=True)

        cls.eq_tokens[ExchangeCode.NSE] = df_nse.to_dict(orient='index')
        cls.eq_tokens[ExchangeCode.BSE] = df_bse.to_dict(orient='index')

        return cls.eq_tokens

    @classmethod
    def create_indices(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the aliceblue.indices Dictionary.

        Returns:
            dict: Unified kronos indices format.
        """
        col_names = [
            "Fytoken", "Symbol Details", "Exchange Instrument type", "Minimum lot size",
            "Tick size", "ISIN", "Trading Session", "Last update date", "Expiry date",
            "Symbol ticker", "Exchange", "Segment", "Scrip code", "Underlying scrip code",
            "Option type", "Strike price", "Underlying FyToken", "NA", "NAA"
        ]

        df = cls.data_reader(cls.base_urls["market_data"].replace("NSE_FO", "NSE_CM"), filetype='csv', col_names=col_names)

        df = df[df["Symbol ticker"].str.endswith("INDEX")][["Symbol ticker", "Scrip code"]]
        df.rename({"Symbol ticker": "Symbol", "Scrip code": "Token"}, axis=1, inplace=True)
        df.index = df['Symbol']

        indices = df.to_dict(orient='index')

        indices[Root.BNF] = indices["NSE:NIFTYBANK-INDEX"]
        indices[Root.NF] = indices["NSE:NIFTY50-INDEX"]
        indices[Root.FNF] = indices["NSE:FINNIFTY-INDEX"]
        indices[Root.MIDCPNF] = indices["NSE:MIDCPNIFTY-INDEX"]

        cls.indices = indices

        return indices

    @classmethod
    def create_nfo_tokens(cls):
        """
        Creates BANKNIFTY & NIFTY Current, Next and Far Expiries;
        Stores them in the aliceblue.nfo_tokens Dictionary.

        Raises:
            TokenDownloadError: Any Error Occured is raised through this Error Type.
        """
        try:
            col_names = [
                "Fytoken", "Symbol Details", "Exchange Instrument type", "Minimum lot size",
                "Tick size", "ISIN", "Trading Session", "Last update date", "Expiry date",
                "Symbol ticker", "Exchange", "Segment", "Scrip code", "Underlying scrip code",
                "Option type", "Strike price", "Underlying FyToken", "NA", "NAA"
            ]

            df = cls.data_reader(cls.base_urls["market_data"], filetype='csv', col_names=col_names)

            df = df[
                (
                    (df["Underlying scrip code"] == "BANKNIFTY") |
                    (df["Underlying scrip code"] == "NIFTY") |
                    (df["Underlying scrip code"] == "FINNIFTY") |
                    (df["Underlying scrip code"] == "MIDCPNIFTY")
                ) &
                (
                    (df["Underlying FyToken"] != "XX")
                )]

            df.rename({"Scrip code": "Token", "Underlying scrip code": "Root",
                       "Expiry date": "Expiry", "Symbol ticker": "Symbol", "Underlying FyToken": "Option",
                       "Tick size": "TickSize", "Minimum lot size": "LotSize", "Strike price": "StrikePrice"},
                      axis=1, inplace=True)

            df["Expiry"] = cls.pd_datetime(df["Expiry"], unit="s").dt.date

            df = df[["Token", "Symbol", "Expiry", "Option",
                     "StrikePrice", "LotSize",
                     "Root", "TickSize"
                     ]
                    ]

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
        Generate Headers used to access Endpoints in Fyers.

        Parameters:
            params (dict) : A dictionary which should consist the following keys:
                user_id (str): User ID of the Account.
                pin (str): pin of the Account Holder.
                totpstr (str): String of characters used to generate TOTP.
                api_key (str): API Key from APP in Fyers myapi Dashboard.
                api_secret (str): API Secret from APP in Fyers myapi Dashboard.
                redirect_uri (str): Redirect URL from APP in Fyers myapi Dashboard.


        Returns:
            dict[str, str]: Fyers Headers.
        """
        for key in ["user_id", "pin", "totpstr", "api_key", "api_secret", "redirect_uri"]:
            if key not in params:
                raise KeyError(f"Please provide {key}")

        en_user_id = str(base64.b64encode(params["user_id"].encode()), encoding="utf-8")
        json_data = {"fy_id": en_user_id, "app_id": "2"}


        user_id_req = cls.fetch(method="POST", url=cls.token_urls["login_otp"], json=json_data)
        user_id_resp = cls._json_parser(user_id_req)

        request_key = user_id_resp["request_key"]
        totp = cls.totp_creator(params["totpstr"])
        json_data = {"request_key": request_key, "otp": str(totp)}

        totp_req = cls.fetch(method="POST", url=cls.token_urls["verify_totp"], json=json_data)
        totp_resp = cls._json_parser(totp_req)

        request_key = totp_resp["request_key"]
        en_pin = str(base64.b64encode(params["pin"].encode()), encoding="utf-8")
        json_data = {"request_key": request_key, "identifier": en_pin, "identity_type": "pin"}


        pin_req = cls.fetch(method="POST", url=cls.token_urls["verify_pin"], json=json_data)
        pin_resp = cls._json_parser(pin_req)

        token = pin_resp["data"]["access_token"]
        headers = {'Authorization': f'Bearer {token}'}
        json_data = {
            "fyers_id": params['user_id'],
            "app_id": params['api_key'].split("-")[0],
            "redirect_uri": params["redirect_uri"],
            "appType": params['api_key'].split("-")[-1],
            "code_challenge": "",
            "state": "sample_state",
            "scope": "",
            "nonce": "",
            "response_type": "code",
            "create_cookie": True
        }

        token_req = cls.fetch(method="POST", url=cls.token_urls["token"],
                              json=json_data, headers=headers)
        token_resp = cls._json_parser(token_req)

        parsed = urlparse(token_resp["Url"])
        auth_code = parse_qs(parsed.query)["auth_code"][0]

        api_key_hash = hashlib.sha256(f"{params['api_key']}:{params['api_secret']}".encode()).hexdigest()
        json_data = {
            "grant_type": "authorization_code",
            "appIdHash": api_key_hash,
            "code": auth_code,
        }

        access_token_req = cls.fetch(method="POST", url=cls.token_urls["validate_authcode"], json=json_data)
        access_token_resp = cls._json_parser(access_token_req)

        access_token = access_token_resp["access_token"]

        headers = {
            "headers":
                {
                    "Authorization": f"{params['api_key']}:{access_token}",
                }
        }

        cls._session = cls._create_session()

        return headers

    @classmethod
    def _json_parser(cls,
                     response: Response,
                     ) -> dict[Any, Any] | list[dict[Any, Any]]:
        """
        Json Parser Parse the Json Repsonse Obtained from Broker.

        Parameters:
            response (Response): Json Response Obtained from Broker.

        Raises:
            ResponseError: Raised if any error received from broker.

        Returns:
            dict: json response obtained from exchange.
        """
        json_response = cls.on_json_response(response)
        print(json_response)
        if json_response['s'] == "ok":
            return json_response

        raise ResponseError(cls.id + " " + json_response['message'])

    @classmethod
    def _orderbook_json_parser(cls,
                               order: dict,
                               ) -> dict[Any, Any]:
        """
        Parse Orderbook Order Json Response.

        Parameters:
            order (dict): Orderbook Order Json Response from Broker.

        Returns:
            dict: Unified kronos Order Response.
        """
        parsed_order = {
            Order.ID: order["id"],
            Order.USERID: "",
            Order.TIMESTAMP: cls.datetime_strp(order["orderDateTime"], "%d-%b-%Y %H:%M:%S"),
            Order.SYMBOL: order["symbol"],
            Order.TOKEN: order["fyToken"][10:],
            Order.SIDE: cls.resp_side.get(order["side"], order["side"]),
            Order.TYPE: cls.resp_order_type.get(order["type"], order["type"]),
            Order.AVGPRICE: order["tradedPrice"],
            Order.PRICE: order["limitPrice"],
            Order.TRIGGERPRICE: order["stopPrice"],
            Order.TARGETPRICE: 0.0,
            Order.STOPLOSSPRICE: 0.0,
            Order.TRAILINGSTOPLOSS: 0.0,
            Order.QUANTITY: order["qty"],
            Order.FILLEDQTY: order["filledQty"],
            Order.REMAININGQTY: order["remainingQuantity"],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: cls.resp_status.get(order["status"], order["status"]),
            Order.REJECTREASON: order["message"],
            Order.DISCLOSEDQUANTITY: order["disclosedQty"],
            Order.PRODUCT: cls.resp_product.get(order["productType"], order["productType"]),
            Order.EXCHANGE: cls.resp_exchange.get(order["exchange"], order["exchange"]),
            Order.SEGMENT: cls.resp_segment.get(f"{order['exchange']}{order['segment']}", order["segment"]),
            Order.VALIDITY: cls.req_validity.get(order["orderValidity"], order["orderValidity"]),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _tradebook_json_parser(cls,
                               order: dict,
                               ) -> dict[Any, Any]:
        """
        Parse Tradebook Order Json Response.

        Parameters:
            order (dict): Tradebook Order Json Response from Broker.

        Returns:
            dict: Unified Kronos Order Response.
        """
        parsed_order = {
            Order.ID: order["orderNumber"],
            Order.USERID: "",
            Order.TIMESTAMP: cls.datetime_strp(order["orderDateTime"], "%d-%b-%Y %H:%M:%S"),
            Order.SYMBOL: order["symbol"],
            Order.TOKEN: order["fyToken"][10:],
            Order.SIDE: cls.resp_side.get(order["side"], order["side"]),
            Order.TYPE: "",
            Order.AVGPRICE: 0.0,
            Order.PRICE: 0.0,
            Order.TRIGGERPRICE: 0.0,
            Order.TARGETPRICE: 0.0,
            Order.STOPLOSSPRICE: 0.0,
            Order.TRAILINGSTOPLOSS: 0.0,
            Order.QUANTITY: order["tradedQty"],
            Order.FILLEDQTY: 0,
            Order.REMAININGQTY: 0,
            Order.CANCELLEDQTY: 0,
            Order.STATUS: "",
            Order.REJECTREASON: "",
            Order.DISCLOSEDQUANTITY: "",
            Order.PRODUCT: "",
            Order.EXCHANGE: cls.resp_exchange.get(order["exchange"], order["exchange"]),
            Order.SEGMENT: cls.resp_segment.get(f"{order['exchange']}{order['segment']}", order["segment"]),
            Order.VALIDITY: "",
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _position_json_parser(cls,
                              position: dict,
                              ) -> dict[Any, Any]:
        """
        Parse Acoount Position Json Response.

        Parameters:
            order (dict): Acoount Position Json Response from Broker.

        Returns:
            dict: Unified Kronos Position Response.
        """
        parsed_position = {
            Position.SYMBOL: position["symbol"],
            Position.TOKEN: position["fyToken"][10:],
            Position.NETQTY: position["netQty"],
            Position.AVGPRICE: position["netAvg"],
            Position.MTM: position["realized_profit"],
            Position.PNL: position["pl"],
            Position.BUYQTY: position["buyQty"],
            Position.BUYPRICE: position["buyAvg"],
            Position.SELLQTY: position["sellQty"],
            Position.SELLPRICE: position["sellAvg"],
            Position.LTP: position["ltp"],
            Position.PRODUCT: cls.resp_product.get(position["productType"], position["productType"]),
            Position.EXCHANGE: cls.resp_segment.get(f"{position['exchange']}{position['segment']}", position["segment"]),
            Position.INFO: position,
        }

        return parsed_position

    @classmethod
    def _profile_json_parser(cls,
                             profile: dict
                             ) -> dict[Any, Any]:
        """
        Parse User Profile Json Response.

        Parameters:
            profile (dict): User Profile Json Response from Broker

        Returns:
            dict: Unified Kronos Profile Response
        """
        parsed_profile = {
            Profile.CLIENTID: profile['fy_id'],
            Profile.NAME: profile['name'],
            Profile.EMAILID: profile['email_id'],
            Profile.MOBILENO: profile['mobile_number'],
            Profile.PAN: profile["PAN"],
            Profile.ADDRESS: "",
            Profile.BANKNAME: "",
            Profile.BANKBRANCHNAME: None,
            Profile.BANKACCNO: "",
            Profile.EXHCNAGESENABLED: "",
            Profile.ENABLED: True,
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

        if info['s'] == "ok" or info.get("id"):

            order_id = info["id"]
            order = cls.fetch_order(order_id=order_id, headers=headers)

            return order

        else:
            raise ResponseError(cls.id + " " + info['message'])


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
                     price: float = 0.0,
                     trigger: float = 0.0,
                     target: float = 0.0,
                     stoploss: float = 0.0,
                     trailing_sl: float = 0.0,
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
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.

        Returns:
            dict: kronos Unified Order Response.
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
            json_data = {
                "symboltoken": token,
                "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": trigger,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[order_type],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        else:
            json_data = {
                "symboltoken": token,
                "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": trigger,
                "squareoff": target,
                "stoploss": stoploss,
                "trailingStopLoss": trailing_sl,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[order_type],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }


        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

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
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
            json_data = {
                "symboltoken": token,
                "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "tradingsymbol": symbol,
                "price": "0",
                "triggerprice": "0",
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.MARKET],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        else:
            json_data = {
                "symboltoken": token,
                "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "tradingsymbol": symbol,
                "price": "0",
                "triggerprice": "0",
                "squareoff": target,
                "stoploss": stoploss,
                "trailingStopLoss": trailing_sl,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.MARKET],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

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
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
            json_data = {
                "symboltoken": token,
                "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": "0",
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.LIMIT],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        else:
            json_data = {
                "symboltoken": token,
                "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": "0",
                "squareoff": target,
                "stoploss": stoploss,
                "trailingStopLoss": trailing_sl,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.LIMIT],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

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
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
            json_data = {
                "symboltoken": token,
                "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": trigger,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.SL],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        else:
            json_data = {
                "symboltoken": token,
                "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": trigger,
                "squareoff": target,
                "stoploss": stoploss,
                "trailingStopLoss": trailing_sl,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.SL],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

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
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
            json_data = {
                "symboltoken": token,
                "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "tradingsymbol": symbol,
                "price": "0",
                "triggerprice": trigger,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.SLM],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        else:
            json_data = {
                "symboltoken": token,
                "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "tradingsymbol": symbol,
                "price": "0",
                "triggerprice": trigger,
                "squareoff": target,
                "stoploss": stoploss,
                "trailingStopLoss": trailing_sl,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.SLM],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)


    # Equity Order Functions


    @classmethod
    def create_order_eq(cls,
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
                        target: float = 0.0,
                        stoploss: float = 0.0,
                        trailing_sl: float = 0.0,
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
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]
        symbol = detail["Symbol"]

        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL


        if not target:
            json_data = {
                "symboltoken": token,
                "exchange": exchange,
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": trigger,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[order_type],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        else:
            json_data = {
                "symboltoken": token,
                "exchange": exchange,
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": trigger,
                "squareoff": target,
                "stoploss": stoploss,
                "trailingStopLoss": trailing_sl,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[order_type],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }


        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order_eq(cls,
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
        Place Market Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
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
            dict: kronos Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]
        symbol = detail["Symbol"]

        if not target:
            json_data = {
                "symboltoken": token,
                "exchange": exchange,
                "tradingsymbol": symbol,
                "price": "0",
                "triggerprice": "0",
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.MARKET],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        else:
            json_data = {
                "symboltoken": token,
                "exchange": exchange,
                "tradingsymbol": symbol,
                "price": "0",
                "triggerprice": "0",
                "squareoff": target,
                "stoploss": stoploss,
                "trailingStopLoss": trailing_sl,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.MARKET],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order_eq(cls,
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
        Place Limit Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
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
            dict: kronos Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]
        symbol = detail["Symbol"]

        if not target:
            json_data = {
                "symboltoken": token,
                "exchange": exchange,
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": "0",
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.LIMIT],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        else:
            json_data = {
                "symboltoken": token,
                "exchange": exchange,
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": "0",
                "squareoff": target,
                "stoploss": stoploss,
                "trailingStopLoss": trailing_sl,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.LIMIT],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order_eq(cls,
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
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]
        symbol = detail["Symbol"]

        if not target:
            json_data = {
                "symboltoken": token,
                "exchange": exchange,
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": trigger,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.SL],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        else:
            json_data = {
                "symboltoken": token,
                "exchange": exchange,
                "tradingsymbol": symbol,
                "price": price,
                "triggerprice": trigger,
                "squareoff": target,
                "stoploss": stoploss,
                "trailingStopLoss": trailing_sl,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.SL],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order_eq(cls,
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
        Place Stoploss-Market Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
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
            dict: kronos Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]
        symbol = detail["Symbol"]

        if not target:
            json_data = {
                "symboltoken": token,
                "exchange": exchange,
                "tradingsymbol": symbol,
                "price": "0",
                "triggerprice": trigger,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.SLM],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        else:
            json_data = {
                "symboltoken": token,
                "exchange": exchange,
                "tradingsymbol": symbol,
                "price": "0",
                "triggerprice": trigger,
                "squareoff": target,
                "stoploss": stoploss,
                "trailingStopLoss": trailing_sl,
                "quantity": quantity,
                "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
                "ordertype": cls.req_order_type[OrderType.SLM],
                "producttype": cls._key_mapper(cls.req_product, product, 'product'),
                "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "ordertag": unique_id,
                "disclosedquantity": "0",
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

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

        token = detail['Token']
        symbol = detail['Symbol']

        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        json_data = {
            "symboltoken": token,
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tradingsymbol": symbol,
            "price": price,
            "triggerprice": trigger,
            "quantity": quantity,
            "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
            "ordertype": cls.req_order_type[order_type],
            "producttype": cls._key_mapper(cls.req_product, product, 'product'),
            "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
            "ordertag": unique_id,
            "disclosedquantity": "0",
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

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

        json_data = {
            "symbol": symbol,
            "limitPrice": 0,
            "stopPrice": 0,
            "takeProfit": 0,
            "stopLoss": 0,
            "qty": quantity,
            "side": cls._key_mapper(cls.req_side, side, 'side'),
            "type": cls.req_order_type[OrderType.MARKET],
            "productType": cls._key_mapper(cls.req_product, product, 'product'),
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "offlineOrder": True if variety == Variety.AMO else False,
            "disclosedQty": 0,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

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

        json_data = {
            "symbol": symbol,
            "limitPrice": price,
            "stopPrice": 0,
            "takeProfit": 0,
            "stopLoss": 0,
            "qty": quantity,
            "side": cls._key_mapper(cls.req_side, side, 'side'),
            "type": cls.req_order_type[OrderType.LIMIT],
            "productType": cls._key_mapper(cls.req_product, product, 'product'),
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "offlineOrder": True if variety == Variety.AMO else False,
            "disclosedQty": 0,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

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
        token = detail['Token']


        json_data = {
            "symboltoken": token,
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tradingsymbol": symbol,
            "price": price,
            "triggerprice": trigger,
            "quantity": quantity,
            "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
            "ordertype": cls.req_order_type[OrderType.SL],
            "producttype": cls._key_mapper(cls.req_product, product, 'product'),
            "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
            "ordertag": unique_id,
            "disclosedquantity": "0",
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

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
        token = detail['Token']

        json_data = {
            "symboltoken": token,
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tradingsymbol": symbol,
            "price": "0",
            "triggerprice": trigger,
            "quantity": quantity,
            "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
            "ordertype": cls.req_order_type[OrderType.SLM],
            "producttype": cls._key_mapper(cls.req_product, product, 'product'),
            "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
            "ordertag": unique_id,
            "disclosedquantity": "0",
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)


    # BO Order Functions


    @classmethod
    def create_order_bo(cls,
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
                        product: str = Product.BO,
                        validity: str = Validity.DAY,
                        variety: str = Variety.BO,
                        ) -> dict[Any, Any]:
        """
        Place a BO Order.

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
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        json_data = {
            "symboltoken": token,
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tradingsymbol": symbol,
            "price": price,
            "triggerprice": trigger,
            "squareoff": target,
            "stoploss": stoploss,
            "trailingStopLoss": trailing_sl,
            "quantity": quantity,
            "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
            "ordertype": cls.req_order_type[order_type],
            "producttype": cls._key_mapper(cls.req_product, product, 'product'),
            "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
            "ordertag": unique_id,
            "disclosedquantity": "0",
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order_bo(cls,
                        symbol: str,
                        token: int,
                        side: str,
                        quantity: int,
                        exchange: str,
                        unique_id: str,
                        headers: dict,
                        target: float = 0.0,
                        stoploss: float = 0.0,
                        trailing_sl: float = 0.0,
                        product: str = Product.BO,
                        validity: str = Validity.DAY,
                        variety: str = Variety.BO,
                        ) -> dict[Any, Any]:
        """
        Place BO Market Order.

        Parameters:
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.BO.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.BO.

        Returns:
            dict: kronos Unified Order Response.
        """
        json_data = {
            "symboltoken": token,
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tradingsymbol": symbol,
            "price": "0",
            "triggerprice": "0",
            "squareoff": target,
            "stoploss": stoploss,
            "trailingStopLoss": trailing_sl,
            "quantity": quantity,
            "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
            "ordertype": cls.req_order_type[OrderType.MARKET],
            "producttype": cls._key_mapper(cls.req_product, product, 'product'),
            "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
            "ordertag": unique_id,
            "disclosedquantity": "0",
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order_bo(cls,
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
                       product: str = Product.BO,
                       validity: str = Validity.DAY,
                       variety: str = Variety.BO,
                       ) -> dict[Any, Any]:
        """
        Place BO Limit Order.

        Parameters:
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            price (float): Order price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.BO.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.BO.

        Returns:
            dict: kronos Unified Order Response.
        """
        json_data = {
            "symboltoken": token,
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tradingsymbol": symbol,
            "price": price,
            "triggerprice": "0",
            "squareoff": target,
            "stoploss": stoploss,
            "trailingStopLoss": trailing_sl,
            "quantity": quantity,
            "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
            "ordertype": cls.req_order_type[OrderType.LIMIT],
            "producttype": cls._key_mapper(cls.req_product, product, 'product'),
            "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
            "ordertag": unique_id,
            "disclosedquantity": "0",
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order_bo(cls,
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
                    product: str = Product.BO,
                    validity: str = Validity.DAY,
                    variety: str = Variety.BO,
                    ) -> dict[Any, Any]:
        """
        Place BO Stoploss Order.

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
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.BO.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.BO.

        Returns:
            dict: kronos Unified Order Response.
        """
        json_data = {
            "symboltoken": token,
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tradingsymbol": symbol,
            "price": price,
            "triggerprice": trigger,
            "squareoff": target,
            "stoploss": stoploss,
            "trailingStopLoss": trailing_sl,
            "quantity": quantity,
            "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
            "ordertype": cls.req_order_type[OrderType.SL],
            "producttype": cls._key_mapper(cls.req_product, product, 'product'),
            "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
            "ordertag": unique_id,
            "disclosedquantity": "0",
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order_bo(cls,
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
                     product: str = Product.BO,
                     validity: str = Validity.DAY,
                     variety: str = Variety.BO,
                     ) -> dict[Any, Any]:

        """
        Place BO Stoploss-Market Order.

        Parameters:
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            trigger (float): order trigger price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.BO.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.BO.

        Returns:
            dict: kronos Unified Order Response.
        """
        json_data = {
            "symboltoken": token,
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tradingsymbol": symbol,
            "price": "0",
            "triggerprice": trigger,
            "squareoff": target,
            "stoploss": stoploss,
            "trailingStopLoss": trailing_sl,
            "quantity": quantity,
            "transactiontype": cls._key_mapper(cls.req_side, side, 'side'),
            "ordertype": cls.req_order_type[OrderType.SLM],
            "producttype": cls._key_mapper(cls.req_product, product, 'product'),
            "duration": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "variety": cls._key_mapper(cls.req_variety, variety, 'variety'),
            "ordertag": unique_id,
            "disclosedquantity": "0",
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)


    # Order Details, OrderBook & TradeBook


    @classmethod
    def fetch_raw_orderbook(cls,
                            headers: dict
                            ) -> list[dict]:
        """
        Fetch Raw Orderbook Details, without any Standardaization.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: Raw Broker Orderbook Response.
        """
        response = cls.fetch(method="GET", url=cls.urls['orderbook'], headers=headers["headers"])
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
        info = cls.fetch_raw_orderbook(headers=headers)

        orders = []
        for order in info['orderBook']:
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
        response = cls.fetch(method="GET", url=cls.urls["tradebook"], headers=headers["headers"])
        info = cls._json_parser(response)

        orders = []
        if info['tradeBook']:
            for order in info['tradeBook']:
                detail = cls._tradebook_json_parser(order)
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
        params = {'id': order_id}

        try:
            response = cls.fetch(method="GET", url=cls.urls['orderbook'],
                                 params=params, headers=headers["headers"])
        except BrokerError as exc:
            if "invalid order id" in exc.args[0]:
                raise InputError({"This order_id does not exist."})

        info = cls._json_parser(response)
        order = cls._orderbook_json_parser(info['orderBook'][0])

        return order


    # Order Modification


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
            order_type (str | None, optional): Type of Order. defaults to None
            validity (str | None, optional): Order validity Defaults to None.

        Returns:
            dict: kronos Unified Order Response.
        """
        json_data = {
            "id": order_id,
            "qty": quantity,
            "limitPrice": price,
            "stopPrice": trigger,
            "type": cls.req_order_type.get(order_type, None),
        }

        for key in list(json_data):
            if not json_data[key]:
                del json_data[key]

        response = cls.fetch(method="PATCH", url=cls.urls["orderbook"],
                             json=json_data, headers=headers["headers"])

        _ = cls._json_parser(response)

        return cls.fetch_order(order_id=order_id, headers=headers)

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
        json_data = {"id": order_id}
        response = cls.fetch(method="DELETE", url=cls.urls["cancel_order"],
                             json=json_data, headers=headers["headers"])

        info = cls._json_parser(response)
        return cls.fetch_order(order_id=info["id"], headers=headers)


    # Positions, Account Limits & Profile


    @classmethod
    def fetch_day_positions(cls,
                            headers: dict,
                            ) -> dict[Any, Any]:
        """
        Fetch the Day's Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Position Response.
        """
        response = cls.fetch(method="GET", url=cls.urls['positions'], headers=headers["headers"])
        info = cls._json_parser(response)

        positions = []
        for position in info['netPositions']:
            detail = cls._position_json_parser(position)
            positions.append(detail)

        return positions

    @classmethod
    def fetch_net_positions(cls,
                            headers: dict,
                            ) -> dict[Any, Any]:
        """
        Fetch Total Account Holdings

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Position Response
        """
        return cls.fetch_day_positions(headers=headers)

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
        return cls.fetch_day_positions(headers=headers)

    @classmethod
    def fetch_holdings(cls,
                       headers: dict,
                       ) -> dict[Any, Any]:
        """
        Fetch Account Holdings.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Positions Response.
        """
        response = cls.fetch(method="GET", url=cls.urls['holdings'], headers=headers["headers"])
        return cls._json_parser(response)

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
        response = cls.fetch(method="GET", url=cls.urls["rms_limits"], headers=headers["headers"])
        return cls._json_parser(response)

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
