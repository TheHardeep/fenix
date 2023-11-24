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
from kronos.base.constants import Profile
from kronos.base.constants import Root
from kronos.base.constants import WeeklyExpiry
from kronos.base.constants import UniqueID


from kronos.base.errors import InputError
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


    nfo_tokens = {}
    id = 'fyers'
    _session = Exchange._create_session()


    # Base URLs

    base_urls = {
        "api_documentation_link": "https://myapi.fyers.in/docsv3",
        "base_url_01": "https://api-t1.fyers.in/api/v3",
        "base_url_02": "https://api-t2.fyers.in",
        "base_url_03": "https://api.fyers.in/api/v2",
        "market_data_url": "https://public.fyers.in/sym_details/NSE_FO.csv"
    }


    # Access Token Generation URLs

    token_urls = {
        "login_otp": f"{base_urls['base_url_02']}/vagator/v2/send_login_otp_v2",
        "verify_totp": f"{base_urls['base_url_02']}/vagator/v2/verify_otp",
        "verify_pin": f"{base_urls['base_url_02']}/vagator/v2/verify_pin_v2",
        "token": f"{base_urls['base_url_01']}/token",
        "validate_authcode": f"{base_urls['base_url_01']}/validate-authcode",

    }


# https://api-t1.fyers.in/api/v3/orders

    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base_url_01']}/orders/sync",
        "modify_order": f"{base_urls['base_url_01']}/orders",
        "cancel_order": f"{base_urls['base_url_01']}/orders",
        "orderbook": f"{base_urls['base_url_01']}/orders",
        "tradebook": f"{base_urls['base_url_01']}/tradebook",
        "positions": f"{base_urls['base_url_01']}/positions",
        "holdings": f"{base_urls['base_url_01']}/holdings",
        "profile": f"{base_urls['base_url_01']}/profile",
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

    resp_status = {
        6: Status.PENDING,
        5: Status.REJECTED,
        2: Status.FILLED,
        1: Status.CANCELLED,
        4: Status.OPEN
    }

    resp_order_type = {
        "MARKET": OrderType.MARKET,
        "LIMIT": OrderType.LIMIT,
        "STOPLOSS_LIMIT": OrderType.SL,
        "STOPLOSS_MARKET": OrderType.SLM,
    }

    resp_product = {
        "DELIVERY": Product.CNC,
        "CARRYFORWARD": Product.NRML,
        "MARGIN": Product.MARGIN,
        "INTRADAY": Product.MIS,
        "BO": Product.BO,
    }

    resp_variety = {
        "NORMAL": Variety.REGULAR,
        "STOPLOSS": Variety.STOPLOSS,
        "AMO": Variety.AMO,
        "ROBO": Variety.BO,
    }


    # NFO Script Fetch


    @classmethod
    def nfo_indices(cls) -> dict:
        """
        Gives NFO Indices Info for F&O Segment.

        Returns:
            dict: Unified kronos nfo_dict format
        """

        col_names = [
            "Fytoken", "Symbol Details", "Exchange Instrument type", "Minimum lot size",
            "Tick size", "ISIN", "Trading Session", "Last update date", "Expiry date",
            "Symbol ticker", "Exchange", "Segment", "Scrip code", "Underlying scrip code",
            "Option type", "Strike price", "Underlying FyToken", "NA", "NAA"
        ]

        df = cls.data_reader(cls.base_urls["market_data_url"].replace("NSE_FO", "NSE_CM"), filetype='csv', col_names=col_names)
        df = df[((df['Underlying scrip code'] == 'BANKNIFTY') | (df['Underlying scrip code'] == 'NIFTY') | (df['Underlying scrip code'] == 'FINNIFTY')) ]

        bnf_details = df[df['Underlying scrip code'] == "BANKNIFTY"].iloc[0]
        nf_details = df[df['Underlying scrip code'] == "NIFTY"].iloc[0]
        fnf_details = df[df['Underlying scrip code'] == "BANKNIFTY"].iloc[0]
        indices = {
            "BANKNIFTY": {"Symbol": bnf_details["Underlying scrip code"], "Token": bnf_details["Scrip code"]},
            "NIFTY": {"Symbol": nf_details["Underlying scrip code"], "Token": nf_details["Scrip code"]},
            "FINIFTY": {"Symbol": fnf_details["Underlying scrip code"], "Token": fnf_details["Scrip code"]},
        }

        return indices

    @classmethod
    def nfo_dict(cls):
        try:
            col_names = [
                "Fytoken", "Symbol Details", "Exchange Instrument type", "Minimum lot size",
                "Tick size", "ISIN", "Trading Session", "Last update date", "Expiry date",
                "Symbol ticker", "Exchange", "Segment", "Scrip code", "Underlying scrip code",
                "Option type", "Strike price", "Underlying FyToken", "NA", "NAA"
            ]

            df = cls.data_reader(cls.base_urls["market_data_url"], filetype='csv', col_names=col_names)

            df = df[((df['Underlying scrip code'] == 'BANKNIFTY') | (df['Underlying scrip code'] == 'NIFTY') | (df['Underlying scrip code'] == 'FINNIFTY')) & (df["Underlying FyToken"] != "XX")]

            df.rename({"Scrip code": "Token", "Underlying scrip code": "Root",
                       "Expiry date": "Expiry", "Symbol ticker": "Symbol", "Underlying FyToken": "Option",
                       "Tick size": "TickSize", "Minimum lot size": "LotSize", "Strike price": "StrikePrice"},
                      axis=1, inplace=True)

            df['Expiry'] = cls.pd_datetime(df['Expiry'], unit='s').dt.date

            df = df[['Token', 'Symbol', 'Expiry', 'Option',
                     'StrikePrice', 'LotSize',
                     'Root', 'TickSize'
                    ]]

            df['Expiry'] = cls.pd_datetime(df['Expiry']).dt.date.astype(str)

            expiry_data = cls.jsonify_expiry(data_frame=df)

            cls.nfo_tokens = expiry_data

            return expiry_data

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc

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
                totpbase (str): String of characters used to generate TOTP.
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


    # Headers & Json Parsers


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
        Parse Orderbook Order Json Response to a Kronos Unified Order Response.

        Parameters:
            order (dict): Orderbook Order Json Response from Broker

        Returns:
            dict: Unified Kronos Order Response
        """
        parsed_order = {
            Order.ID: order["orderid"],
            Order.USERID: order["ordertag"],
            Order.TIMESTAMP: cls.datetime_strp(order["updatetime"], "%d-%b-%Y %H:%M:%S"),
            Order.SYMBOL: order["tradingsymbol"],
            Order.TOKEN: order["symboltoken"],
            Order.SIDE: cls.req_side.get(order["transactiontype"], order["transactiontype"]),
            Order.TYPE: cls.resp_order_type.get(order["ordertype"], order["ordertype"]),
            Order.AVGPRICE: order["averageprice"],
            Order.PRICE: order["price"],
            Order.TRIGGERPRICE: order["triggerprice"],
            Order.TARGETPRICE: order['squareoff'],
            Order.STOPLOSSPRICE: order['stoploss'],
            Order.TRAILINGSTOPLOSS: order['trailingstoploss'],
            Order.QUANTITY: int(order["quantity"]),
            Order.FILLEDQTY: int(order["filledshares"]),
            Order.REMAININGQTY: int(order["unfilledshares"]),
            Order.CANCELLEDQTY: int(order["cancelsize"]),
            Order.STATUS: cls.resp_status.get(order["status"], order["status"]),
            Order.REJECTREASON: order["text"],
            Order.DISCLOSEDQUANTITY: int(order["disclosedquantity"]),
            Order.PRODUCT: cls.resp_product.get(order["producttype"], order["producttype"]),
            Order.EXCHANGE: cls.req_exchange.get(order["exchange"], order["exchange"]),
            Order.SEGMENT: cls.req_exchange.get(order["exchange"], order["exchange"]),
            Order.VALIDITY: cls.req_validity.get(order["duration"], order["duration"]),
            Order.VARIETY: cls.resp_variety.get(order["variety"], order["variety"]),
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _tradebook_json_parser(cls,
                               order: dict,
                               ) -> dict[Any, Any]:
        """
        Parse Orderbook Order Json Response to a Kronos Unified Order Response.

        Parameters:
            order (dict): Orderbook Order Json Response from Broker

        Returns:
            dict: Unified Kronos Order Response
        """
        parsed_order = {
            Order.ID: order["orderid"],
            Order.USERID: "",
            Order.TIMESTAMP: cls.datetime_strp(order["updatetime"], "%d-%b-%Y %H:%M:%S"),
            Order.SYMBOL: order["tradingsymbol"],
            Order.TOKEN: order["symboltoken"],
            Order.SIDE: cls.req_side.get(order["transactiontype"], order["transactiontype"]),
            Order.TYPE: cls.resp_order_type.get(order["ordertype"], order["ordertype"]),
            Order.AVGPRICE: order["averageprice"],
            Order.PRICE: order["price"],
            Order.TRIGGERPRICE: order["triggerprice"],
            Order.TARGETPRICE: order['squareoff'],
            Order.STOPLOSSPRICE: order['stoploss'],
            Order.TRAILINGSTOPLOSS: order['trailingstoploss'],
            Order.QUANTITY: int(order["quantity"]),
            Order.FILLEDQTY: int(order["filledshares"]),
            Order.REMAININGQTY: int(order["unfilledshares"]),
            Order.CANCELLEDQTY: int(order["cancelsize"]),
            Order.STATUS: cls.resp_status.get(order["status"], order["status"]),
            Order.REJECTREASON: order["text"],
            Order.DISCLOSEDQUANTITY: int(order["disclosedquantity"]),
            Order.PRODUCT: cls.resp_product.get(order["producttype"], order["producttype"]),
            Order.EXCHANGE: cls.req_exchange.get(order["exchange"], order["exchange"]),
            Order.SEGMENT: cls.req_exchange.get(order["exchange"], order["exchange"]),
            Order.VALIDITY: cls.req_validity.get(order["duration"], order["duration"]),
            Order.VARIETY: cls.resp_variety.get(order["variety"], order["variety"]),
            Order.INFO: order,
        }

        return parsed_order


    @classmethod
    def _profile_json_parser(cls,
                             profile: dict
                             ) -> dict[Any, Any]:
        """
        Parse User Profile Json Response to a Kronos Unified Profile Response.

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

        info = cls._json_parser(response)

        order_id = info["data"]["orderid"]
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
        Place an Order

        Parameters:
            price (float): Order price
            triggerprice (float): order trigger price
            symbol (str): Trading symbol
            token (int): Exchange token
            side (str): Order Side: BUY, SELL
            unique_id (str): Unique user order_id
            quantity (int): Order quantity
            exchange (str): Exchange to place the order in.
            headers (dict): headers to send order request with.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.

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
                     product: str = Product.MIS,
                     validity: str = Validity.DAY,
                     variety: str = Variety.REGULAR,
                     ) -> dict[Any, Any]:

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
                    product: str = Product.MIS,
                    validity: str = Validity.DAY,
                    variety: str = Variety.REGULAR,
                    ) -> dict[Any, Any]:


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
                 product: str = Product.MIS,
                 validity: str = Validity.DAY,
                 variety: str = Variety.STOPLOSS,
                 ) -> dict[Any, Any]:


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

        print(json_data)

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
                  product: str = Product.MIS,
                  validity: str = Validity.DAY,
                  variety: str = Variety.STOPLOSS,
                  ) -> dict[Any, Any]:

        """
        Place Stoploss-Market Order

        Parameters:
            price (float): Order price
            triggerprice (float): order trigger price
            symbol (str): Trading symbol
            token (int): Exchange token
            side (str): Order Side: BUY, SELL
            unique_id (str): Unique user order_id
            quantity (int): Order quantity
            exchange (str): Exchange to place the order in.
            headers (dict): headers to send order request with.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.

        Returns:
            dict: kronos Unified Order Response
        """

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
                         price: float = 0,
                         trigger: float = 0,
                         ) -> dict[Any, Any]:
        """
        Place Stoploss Order in F&O Segment.

        Parameters:
            price (float): price of the order.
            trigger_price (float): trigger price of the order.
            quantity (int): Order quantity.
            option (str): Option Type: 'CE', 'PE'.
            root (str): Derivative: BANKNIFTY, NIFTY.
            strike_price (int): Strike Price of the Option.
            side (str): Order Side: 'BUY', 'SELL'.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional): Exchange to place the order in.. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

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

        print(json_data)

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
            root (str): Derivative: BANKNIFTY, NIFTY.
            strike_price (int): Strike Price of the Option.
            side (str): Order Side: 'BUY', 'SELL'.
            quantity (int): Order quantity.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional): Exchange to place the order in.. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

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

        return cls._json_parser(response)#cls._create_order_parser(response=response, headers=headers)

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
            price (float): price of the order.
            quantity (int): Order quantity.
            option (str): Option Type: 'CE', 'PE'.
            root (str): Derivative: BANKNIFTY, NIFTY.
            strike_price (int): Strike Price of the Option.
            side (str): Order Side: 'BUY', 'SELL'.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional): Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']
        token = detail['Token']


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
            price (float): price of the order.
            trigger_price (float): trigger price of the order.
            quantity (int): Order quantity.
            option (str): Option Type: 'CE', 'PE'.
            root (str): Derivative: BANKNIFTY, NIFTY.
            strike_price (int): Strike Price of the Option.
            side (str): Order Side: 'BUY', 'SELL'.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional): Exchange to place the order in.. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

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
            price (float): price of the order.
            trigger_price (float): trigger price of the order.
            quantity (int): Order quantity.
            option (str): Option Type: 'CE', 'PE'.
            root (str): Derivative: BANKNIFTY, NIFTY.
            strike_price (int): Strike Price of the Option.
            side (str): Order Side: 'BUY', 'SELL'.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional): Exchange to place the order in.. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

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
                        quantity: int,
                        side: str,
                        unique_id: str,
                        headers: dict,
                        price: float = 0,
                        trigger: float = 0,
                        target: float = 0,
                        stoploss: float = 0,
                        trailing_sl: float = 0,
                        product: str = Product.BO,
                        validity: str = Validity.DAY,
                        variety: str = Variety.BO,
                        ) -> dict[Any, Any]:

        """
        Place BO Order

        Parameters:
            price (float): Order price
            triggerprice (float): order trigger price
            symbol (str): Trading symbol
            token (int): Exchange token
            side (str): Order Side: BUY, SELL
            unique_id (str): Unique user order_id
            quantity (int): Order quantity
            exchange (str): Exchange to place the order in.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaulsts to 0.
            stoploss (float, optional): Order Stoploss price. Defaulsts to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaulsts to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

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
                        target: float = 0,
                        stoploss: float = 0,
                        trailing_sl: float = 0,
                        product: str = Product.BO,
                        validity: str = Validity.DAY,
                        variety: str = Variety.BO,
                        ) -> dict[Any, Any]:

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
                       price: float,
                       symbol: str,
                       token: int,
                       side: str,
                       unique_id: str,
                       quantity: int,
                       exchange: str,
                       headers: dict,
                       target: float = 0,
                       stoploss: float = 0,
                       trailing_sl: float = 0,
                       product: str = Product.BO,
                       validity: str = Validity.DAY,
                       variety: str = Variety.BO,
                       ) -> dict[Any, Any]:


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
                    price: float,
                    trigger: float,
                    symbol: str,
                    token: int,
                    side: str,
                    unique_id: str,
                    quantity: int,
                    exchange: str,
                    headers: dict,
                    target: float = 0,
                    stoploss: float = 0,
                    trailing_sl: float = 0,
                    product: str = Product.BO,
                    validity: str = Validity.DAY,
                    variety: str = Variety.BO,
                    ) -> dict[Any, Any]:


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
                     trigger: float,
                     symbol: str,
                     token: int,
                     side: str,
                     unique_id: str,
                     quantity: int,
                     exchange: str,
                     headers: dict,
                     target: float = 0,
                     stoploss: float = 0,
                     trailing_sl: float = 0,
                     product: str = Product.BO,
                     validity: str = Validity.DAY,
                     variety: str = Variety.BO,
                     ) -> dict[Any, Any]:


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
    def fetch_order(cls,
                    order_id: str,
                    headers: dict
                    ) -> dict[Any, Any]:

        order_id = str(order_id)
        response = cls.fetch(method="GET", url=cls.urls['orderbook'], headers=headers["headers"])
        info = cls._json_parser(response)

        if info['data']:
            for order in info['data']:
                if order["orderid"] == order_id:
                    detail = cls._orderbook_json_parser(order)
                    return detail

        raise InputError({"This orderid does not exist."})

    @classmethod
    def fetch_orders(cls,
                     headers: dict
                     ) -> list[dict]:

        response = cls.fetch(method="GET", url=cls.urls['orderbook'], headers=headers["headers"])
        info = cls._json_parser(response)

        orders = info["orderBook"]

        return orders

    @classmethod
    def fetch_orderbook(cls,
                        headers: dict
                        ) -> list[dict]:

        response = cls.fetch(method="GET", url=cls.urls['orderbook'], headers=headers["headers"])
        info = cls._json_parser(response)

        orders = info["orderBook"]

        return orders

    @classmethod
    def fetch_tradebook(cls,
                        headers: dict
                        ) -> list[dict]:

        response = cls.fetch(method="GET", url=cls.urls["tradebook"], headers=headers["headers"])
        info = cls._json_parser(response)

        orders = []
        if info['data']:
            for order in info['data']:
                detail = cls._tradebook_json_parser(order)
                orders.append(detail)

        return orders


    # Order Modification


    @classmethod
    def modify_order(cls,
                     order_id: str,
                     headers: dict,
                     price: float | None = None,
                     trigger_price: float | None = None,
                     quantity: int | None = None,
                     order_type: str | None = None,
                     validity: str | None = None,
                     ) -> dict[Any, Any]:
        """
        Modify an open order

        Parameters:
            order_id (str): id of the order to modify.
            headers (dict): headers to send modify_order request with.
            price (float | None, optional): price of the order. Defaults to None.
            triggerprice (float | None, optional): trigger price of the order. Defaults to None.
            quantity (int | None, optional): order quantity. Defaults to None.

        Returns:
            dict: Kronos Unified Order Response
        """

        response = cls.fetch(method="GET", url=cls.urls['orderbook'], headers=headers["headers"])
        info = cls._json_parser(response)

        order = {}
        if info['data']:
            for order_detail in info['data']:
                if order_detail["orderid"] == order_id:
                    order = order_detail
                    break
        if not order:
            raise InputError({"This orderid does not exist."})


        # json_data = {
        #     "variety": order["variety"],
        #     "orderid": order["orderid"],
        #     "ordertype": order["ordertype"],
        #     "producttype": order["producttype"],
        #     "duration": order["duration"],
        # }

        return cls._json_parser(response)

    @classmethod
    def cancel_order(cls,
                     order_id: str,
                     headers: dict
                     ) -> dict[Any, Any]:

        order = cls.fetch_order(order_id=order_id, headers=headers)

        json_data = {
            "variety": order['variety'],  # cls.req_variety[order['variety']],
            "orderid": order['id'],
        }

        response = cls.fetch(method="POST", url=cls.urls["cancel_order"],
                             json=json_data, headers=headers["headers"])

        info = cls._json_parser(response)

        return cls.fetch_order(order_id=info["data"]["orderid"], headers=headers)


    # Account Limits & Profile


    @classmethod
    def rms_limits(cls,
                   headers: dict
                   ) -> dict[Any, Any]:
        """
        Fetch Risk Management System Limits

        Parameters:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict: Kronos Unified RMS Limits Response
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
            dict: Kronos Unified Profile Response
        """

        response = cls.fetch(method="GET", url=cls.urls["profile"], headers=headers["headers"])

        info = cls._json_parser(response)
        profile = cls._profile_json_parser(info['data'])

        return profile
