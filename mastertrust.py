from __future__ import annotations
from typing import TYPE_CHECKING
from typing import Any

import re
from requests_oauthlib import OAuth2Session

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
from kronos.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response


class mastertrust(Exchange):

    """
    MasterTrust kronos Broker Class

    Returns:
        kronos.mastertrust: kronos MasterTrust Broker Object
    """


    # Market Data Dictonaries

    nfo_tokens = {}
    id = 'mastertrust'
    _session = Exchange._create_session()


    # Base URLs

    base_urls = {
        "market_data_url": "https://masterswift.mastertrust.co.in/api/v2/contracts.json",
        "base_url": "https://masterswift-beta.mastertrust.co.in/api/v1",
    }


    # Access Token Generation URLs

    token_urls = {
        "redirect_uri": "http://127.0.0.1/getCode",
        "auth_url": "https://masterswift-beta.mastertrust.co.in/oauth2/auth",
        "auth_token_url": "https://masterswift-beta.mastertrust.co.in/oauth2/token",
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base_url']}/orders",
        "modify_order": f"{base_urls['base_url']}/orders",
        "cancel_order": f"{base_urls['base_url']}/orders",
        "orderbook": f"{base_urls['base_url']}/orders",
        "tradebook": f"{base_urls['base_url']}/trades",
        "positions": f"{base_urls['base_url']}/positions",
        "holdings": f"{base_urls['base_url']}/holdings",
        "profile": f"{base_urls['base_url']}/user/profile",

    }


    # Request Parameters Dictionaries

    req_exchange = {
        ExchangeCode.NSE: "NSE",
        ExchangeCode.NFO: "NFO",
        ExchangeCode.CDS: "CDS",
        ExchangeCode.BSE: "BSE",
        ExchangeCode.BFO: "BSE",
        ExchangeCode.MCX: "MCX"
    }

    req_side = {
        Side.BUY: "BUY",
        Side.SELL: "SELL"
    }

    req_product = {
        Product.NRML: "NRML",
        Product.MIS: "MIS",
        Product.CNC: "CNC",
        Product.CO: "CO"
    }

    req_order_type = {
        OrderType.MARKET: "MARKET",
        OrderType.LIMIT: "LIMIT",
        OrderType.SL: "SL",
        OrderType.SLM: "SLM"
    }

    req_validity = {
        Validity.DAY: "DAY",
        Validity.IOC: "IOC"
    }


    # Response Parameters Dictionaries

    resp_status = {
        "validation pending": Status.PENDING,
        "put order req received": Status.PENDING,
        "trigger pending": Status.PENDING,
        "open pending": Status.OPEN,
        "open": Status.OPEN,
        "complete": Status.FILLED,
        "rejected": Status.REJECTED,
        "cancelled": Status.CANCELLED
    }



    # NFO Script Fetch


    @classmethod
    def nfo_indices(cls) -> dict:
        """
        Gives NFO Indices Info for F&O Segment.

        Returns:
            dict: Unified kronos nfo_dict format
        """
        params = {"exchanges": "NSE"}
        response = cls.fetch(method="GET", url=cls.base_urls["market_data_url"], params=params)
        data = cls._json_parser(response)['NSE-IND']
        df = cls.data_frame(data)

        bnf_details = df[df['trading_symbol'] == "Nifty Bank"].iloc[0]
        nf_details = df[df['trading_symbol'] == "Nifty 50"].iloc[0]
        fnf_details = df[df['trading_symbol'] == "Nifty Fin Service"].iloc[0]
        indices = {
            "BANKNIFTY": {"Symbol": bnf_details["trading_symbol"], "Token": bnf_details["code"]},
            "NIFTY": {"Symbol": nf_details["trading_symbol"], "Token": nf_details["code"]},
            "FINIFTY": {"Symbol": fnf_details["trading_symbol"], "Token": fnf_details["code"]},
        }

        return indices

    @classmethod
    def nfo_dict(cls) -> dict:
        """
        Creates BANKNIFTY & NIFTY Current, Next and Far Expiries;
        Stores them in the aliceblue.nfo_tokens Dictionary.

        Raises:
            TokenDownloadError: Any Error Occured is raised through this Error Type.
        """

        try:
            params = {"exchanges": "NFO"}
            response = cls.fetch(method="GET", url=cls.base_urls["market_data_url"], params=params)
            data = cls._json_parser(response)['NSE-OPT']
            df = cls.data_frame(data)

            df = df[df['symbol'].str.startswith(("BANKNIFTY", "NIFTY", "FINNIFTY"))]

            df['Root'] = df['symbol'].str.split(" ", expand=True)[0]
            dfx = df['symbol'].str.rsplit(pat=" ", n=3, expand=True)

            df.rename({"code": "Token", "expiry": "Expiry",
                       "trading_symbol": "Symbol", "lotSize": "LotSize"
                       },
                      axis=1, inplace=True)

            df['StrikePrice'] = dfx[2]
            df['Option'] = dfx[3]

            df = df[['Token', 'Symbol', 'Expiry', 'Option',
                     'StrikePrice', 'LotSize', 'Root',
                     ]]

            df['StrikePrice'] = df['StrikePrice'].astype(float).astype(int)
            df['Expiry'] = cls.pd_datetime(df['Expiry'], unit="s").dt.date.astype(str)
            df['Token'] = df['Token'].astype(int)

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
        Generate Headers used to access Endpoints in AliceBlue.

        Parameters:
            Params (dict) : A dictionary which should consist the following keys:
                user_id (str): User ID of the Account.
                password (str): Password of the Account.
                birth_year (str): Birth Year of the Account Holder.
                totpbase (str): String of characters used to generate TOTP.
                api_key (str): API Key of the Account.

        Returns:
            dict[str, str]: AliceBlue Headers.
        """
        for key in ["user_id", "password", "api_id", "totpstr", "api_secret"]:
            if key not in params:
                raise KeyError(f"Please provide {key}")


        oauth = OAuth2Session(params["api_id"], redirect_uri=cls.token_urls["redirect_uri"])
        authorization_url, _ = oauth.authorization_url(cls.token_urls["auth_url"])

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
            "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
        }

        request01 = cls.fetch(method="GET", url=authorization_url, headers=headers)

        resp01_content = (request01.content).decode('utf-8')
        csrf_token = re.findall(r"value=\"(.*)\" name=\"_csrf_token\"" ,resp01_content)[0]

        data = {
            "login_id": params["user_id"],
            "password": params["password"],
            "_csrf_token": csrf_token,
        }

        request02 = cls.fetch(method="POST", url=request01.url,
                              data=data, headers=headers)


        resp02_content = (request02.content).decode('utf-8')
        csrf_token = re.findall(r"value=\"(.*)\" name=\"_csrf_token\"", resp02_content)[0]
        question_ids = re.findall(r"name=\"question_ids\[\]\" value=\"(.*)\"", resp02_content)[0]
        login_challenge = re.findall(r"name=\"login_challenge\" value=\"(.*)\"", resp02_content)[0]

        totp = cls.totp_creator(params["totpstr"])

        data = {
            "answers[]": totp,
            "_csrf_token": csrf_token,
            "question_ids[]": question_ids,
            "login_challenge": login_challenge
        }

        try:
            request03 = cls.fetch(method="POST", url=request02.url, data=data)
            code_str = request03.url

        except Exception as e:
            code_str = str(e)


        auth_response = re.findall(r"/getCode\?code=(.*)&scope", code_str)[0]

        data = {
            "grant_type": "authorization_code",
            "code": auth_response,
            "redirect_uri": cls.token_urls["redirect_uri"]
        }

        token_req = cls.fetch(method="POST", url=cls.token_urls["auth_token_url"],
                              data=data, auth=(params["api_id"], params["api_secret"])
                              )


        token_resp = cls._json_parser(token_req)


        headers = {
            "headers": {
                "Authorization": f"Bearer {token_resp['access_token']}"
            },
            "user_id": params["user_id"],

        }

        cls._session = cls._create_session()

        return headers

    @classmethod
    def _create_order_parser(cls,
                             response: Response,
                             headers: dict
                             ) -> dict[Any, Any]:
        """
        Parse Json Response Obtained from Broker After Placing Order to get Orderid
        and fetching the json repsone for the said order_id

        Parameters:
            response (Response): Json Repsonse Obtained from broker after Placing an Order

        Returns:
            dict: Unified kronos Order Response
        """

        info = cls._json_parser(response)

        order_id = info['data']['oms_order_id']
        order = cls.fetch_order(order_id=order_id, headers=headers)

        return order

    @classmethod
    def _orderbook_json_parser(cls,
                               order: dict
                               ) -> dict[Any, Any]:

        parsed_order = {
            Order.ID: order['oms_order_id'],
            Order.USERID: order['user_order_id'],
            Order.TIMESTAMP: cls.from_timestamp(order['order_entry_time']),
            Order.SYMBOL: order['trading_symbol'],
            Order.TOKEN: int(order['instrument_token']),
            Order.SIDE: order['order_side'],
            Order.TYPE: cls.req_order_type.get(order['order_type'], order['order_type']),
            Order.AVGPRICE: float(order['average_price'] or 0.0),
            Order.PRICE: float(order['price'] or 0.0),
            Order.TRIGGERPRICE: float(order['trigger_price'] or 0.0),
            Order.STOPLOSSPRICE: float(order['stop_loss_value'] or 0.0),
            Order.TRAILINGSTOPLOSS: float(order['trailing_stop_loss'] or 0.0),
            Order.QUANTITY: order['quantity'],
            Order.FILLEDQTY: order['filled_quantity'],
            Order.REMAININGQTY: order['remaining_quantity'],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: cls.resp_status.get(order['order_status'], order['order_status']),
            Order.REJECTREASON: order['rejection_reason'],
            Order.DISCLOSEDQUANTITY: order['disclosed_quantity'],
            Order.PRODUCT: order['product'],
            Order.EXCHANGE: order['exchange'],
            Order.SEGMENT: order['segment'],
            Order.VALIDITY: order['validity'],
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _profile_json_parser(cls,
                             profile: dict
                             ) -> dict[Any, Any]:
        """
        Parse User Profile Json Response to a kronos Unified Profile Response.

        Parameters:
            profile (dict): User Profile Json Response from Broker

        Returns:
            dict: Unified kronos Profile Response
        """

        parsed_profile = {
            Profile.CLIENTID: profile['account_id'],
            Profile.NAME: profile['name'],
            Profile.EMAILID: profile['email_id'],
            Profile.MOBILENO: profile['phone_number'],
            Profile.PAN: profile["pan_number"],
            Profile.ADDRESS: profile["permanent_addr"],
            Profile.BANKNAME: profile["bank_name"],
            Profile.BANKBRANCHNAME: profile["branch"],
            Profile.BANKACCNO: profile["bank_account_number"],
            Profile.EXHCNAGESENABLED: [],
            Profile.ENABLED: profile['status'] == 'Activated',
            Profile.INFO: profile,
        }


        return parsed_profile

    @classmethod
    def _position_json_parser(cls,
                              position: dict
                              ) -> dict[Any, Any]:

        parsedPosition = {
            Position.SYMBOL: position['trading_symbol'],
            Position.TOKEN: position['token'],
            Position.PRODUCT: cls.req_product.get(position['product'], position['product']),
            Position.NETQTY: position['net_quantity'],
            Position.AVGPRICE: position['net_amount'],
            Position.MTM: position['realized_mtm'],
            Position.BUYQTY: position['buy_quantity'],
            Position.BUYPRICE: position['buy_amount'],
            Position.SELLQTY: position['sell_quantity'],
            Position.SELLPRICE: position['sell_amount'],
            Position.LTP: position['ltp'],
            Position.INFO: position,
        }

        return parsedPosition

    @classmethod
    def _orderhistory_json_parser(cls,
                               order: dict,
                               ) -> dict[Any, Any]:

        parsedOrder = {
            Order.ID: order['order_id'],
            Order.USERID: order['client_order_id'],
            Order.TIMESTAMP: cls.from_timestamp(order['created_at']),
            Order.SYMBOL: order['symbol'],
            Order.TOKEN: order['token'],
            Order.SIDE: order['order_side'],
            Order.TYPE: cls.req_order_type.get(order['order_type'], order['order_type']),
            Order.AVGPRICE: order['avg_price'],
            Order.PRICE: order['price'],
            Order.TRIGGERPRICE: order['trigger_price'],
            Order.QUANTITY: order['quantity'],
            Order.FILLEDQTY: order['fill_quantity'],
            Order.REMAININGQTY: order['quantity'] - order['fill_quantity'],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: cls.resp_status.get(order['status'], order['status']),
            Order.REJECTREASON: order['reject_reason'],
            Order.DISCLOSEDQUANTITY: int(order['disclosed_quantity'] or 0),
            Order.PRODUCT: order['product'],
            Order.EXCHANGE: "",
            Order.SEGMENT: order['segment'],
            Order.VALIDITY: order['validity'],
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsedOrder

    @classmethod
    def orderhistory_parser(cls,
                            response: Response,
                            ) -> dict[Any, Any]:

        info = cls._json_parser(response)
        detail = info['data'][0]

        order = cls._orderhistory_json_parser(detail)
        return order




    def market_order(cls, token: int, side: str,  uniqueid: str, quantity: int,
                     exchange=ExchangeCode.NFO, product=Product.MIS, validity=Validity.DAY):

        params = {
            "exchange": cls.key_mapper(cls.req_exchange, exchange, 'exchange'),
            "order_type": cls.req_order_type[OrderType.MARKET],
            "instrument_token": str(token),
            "quantity": str(quantity),
            "disclosed_quantity": "0",
            "price": "0",
            "order_side": cls.key_mapper(cls.req_side, side, 'side'),
            "trigger_price": "0",
            "validity": cls.key_mapper(cls.req_validity, validity, 'validity'),
            "product": cls.key_mapper(cls.req_product, product, 'product'),
            "client_id": headers["user_id"],
            "user_order_id": uniqueid,
            "market_protection_percentage": "0",
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], params=params, headers=cls.headers)

        return cls.create_order_parser(response)

    def limit_order(cls, price: float,
                    token: int, side: str,  uniqueid: str, quantity: int,
                    exchange=ExchangeCode.NFO, product=Product.MIS, validity=Validity.DAY):

        params = {
            "exchange": cls.key_mapper(cls.req_exchange, exchange, 'exchange'),
            "order_type": cls.req_order_type[OrderType.LIMIT],
            "instrument_token": str(token),
            "quantity": str(quantity),
            "disclosed_quantity": "0",
            "price": str(price),
            "order_side": cls.key_mapper(cls.req_side, side, 'side'),
            "trigger_price": "0",
            "validity": cls.key_mapper(cls.req_validity, validity, 'validity'),
            "product": cls.key_mapper(cls.req_product, product, 'product'),
            "client_id": headers["user_id"],
            "user_order_id": uniqueid,
            "market_protection_percentage": "0",
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], params=params, headers=cls.headers)

        return cls.create_order_parser(response)

    def sl_order(cls, price: float, triggerprice: float,
                 token: int, side: str,  uniqueid: str, quantity: int,
                 exchange=ExchangeCode.NFO, product=Product.MIS, validity=Validity.DAY):

        params = {
            "exchange": cls.key_mapper(cls.req_exchange, exchange, 'exchange'),
            "order_type": cls.req_order_type[OrderType.SL],
            "instrument_token": str(token),
            "quantity": str(quantity),
            "disclosed_quantity": "0",
            "price": str(price),
            "order_side": cls.key_mapper(cls.req_side, side, 'side'),
            "trigger_price": str(triggerprice),
            "validity": cls.key_mapper(cls.req_validity, validity, 'validity'),
            "product": cls.key_mapper(cls.req_product, product, 'product'),
            "client_id": headers["user_id"],
            "user_order_id": uniqueid,
            "market_protection_percentage": "0",
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], params=params, headers=cls.headers)

        return cls.create_order_parser(response)


    # NFO Order Functions


    @classmethod
    def create_order_nfo(cls,
                         exchange: str,
                         root: str,
                         expiry: str,
                         option: str,
                         strike_price: int,
                         price: float,
                         trigger: float,
                         quantity: int,
                         side: str,
                         product: str,
                         validity: str,
                         variety: str,
                         unique_id: str,
                         headers: dict,
                         ) -> dict[Any, Any]:
        """
        Place Stoploss Order in F&O Segment.

        Parameters:
            price (float): price of the order.
            trigger (float): trigger price of the order.
            quantity (int): Order quantity.
            option (str): Option Type: 'CE', 'PE'.
            root (str): Derivative: BANKNIFTY, NIFTY.
            strike_price (int): Strike Price of the Option.
            side (str): Order Side: 'BUY', 'SELL'.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional):  Exchange to place the order in.. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: Voluspa Unified Order Response
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

        json_data = [
            {
                "symbol_id": token,
                "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "trading_symbol": symbol,
                "price": price,
                "trigPrice": trigger,
                "qty": quantity,
                "transtype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[order_type],
                "pCode": cls._key_mapper(cls.req_product, product, 'product'),
                "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "complexty": cls._key_mapper(cls.req_variety, variety, 'variety'),
                "orderTag": unique_id,
                "discqty": 0,
            }
        ]

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response,
                                        key_to_check="NOrdNo", headers=headers)

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
            exchange (str, optional):  Exchange to place the order in.. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: Voluspa Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        params = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "instrument_token": token,
            "price": "0",
            "trigger_price": "0",
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, 'side'),
            "order_type": cls.req_order_type[OrderType.MARKET],
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "product": cls._key_mapper(cls.req_product, product, 'product'),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, headers=headers["headers"])

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
            price (float): price of the order.
            quantity (int): Order quantity.
            option (str): Option Type: 'CE', 'PE'.
            root (str): Derivative: BANKNIFTY, NIFTY.
            strike_price (int): Strike Price of the Option.
            side (str): Order Side: 'BUY', 'SELL'.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: Voluspa Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        params = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "instrument_token": token,
            "price": price,
            "trigger_price": "0",
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, 'side'),
            "order_type": cls.req_order_type[OrderType.LIMIT],
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "product": cls._key_mapper(cls.req_product, product, 'product'),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, headers=headers["headers"])

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
            trigger (float): trigger price of the order.
            quantity (int): Order quantity.
            option (str): Option Type: 'CE', 'PE'.
            root (str): Derivative: BANKNIFTY, NIFTY.
            strike_price (int): Strike Price of the Option.
            side (str): Order Side: 'BUY', 'SELL'.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional):  Exchange to place the order in.. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: Voluspa Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        params = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "instrument_token": token,
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, 'side'),
            "order_type": cls.req_order_type[OrderType.SL],
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "product": cls._key_mapper(cls.req_product, product, 'product'),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, headers=headers["headers"])

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
            trigger (float): trigger price of the order.
            quantity (int): Order quantity.
            option (str): Option Type: 'CE', 'PE'.
            root (str): Derivative: BANKNIFTY, NIFTY.
            strike_price (int): Strike Price of the Option.
            side (str): Order Side: 'BUY', 'SELL'.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional):  Exchange to place the order in.. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: Voluspa Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        params = {
            "exchange": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "instrument_token": token,
            "price": "0",
            "trigger_price": trigger,
            "quantity": quantity,
            "order_side": cls._key_mapper(cls.req_side, side, 'side'),
            "order_type": cls.req_order_type[OrderType.SLM],
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "product": cls._key_mapper(cls.req_product, product, 'product'),
            "user_order_id": unique_id,
            "disclosed_quantity": "0",
            "market_protection_percentage": "0",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)


    @classmethod
    def fetch_order(cls,
                    order_id: str,
                    headers: dict
                    ) -> dict[Any, Any]:

        order_id = str(order_id)
        params = {
            "type": "completed",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(method="GET", url=cls.urls["place_order"],
                             params=params, headers=headers["headers"])
        info = cls._json_parser(response)

        for order in info['data']['orders']:
            if order['oms_order_id'] == order_id:
                detail = cls._orderbook_json_parser(order)
                return detail

        raise InputError({"This order_id does not exist."})

    @classmethod
    def fetch_orders(cls,
                     headers: dict
                     ) -> list[dict]:
        """
        Fetch OrderBook Details which is unified across all brokers.
        Use This if you want Avg price, etc. values which sometimes unavailable
        thorugh fetch_orderbook.

        Paramters:
            order_id (str): id of the order

        Raises:
            InputError: If order does not exist.

        Returns:
            dict: kronos Unified Order Response
        """

        params = {
            "type": "completed",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(method="GET", url=cls.urls["place_order"],
                             params=params, headers=headers["headers"])
        info = cls._json_parser(response)

        orders = []

        for order in info['data']['orders']:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)


        params = {
            "type": "pending",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(method="GET", url=cls.urls["place_order"],
                             params=params, headers=headers["headers"])
        info = cls._json_parser(response)

        for order in info['data']['orders']:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    def modify_order(cls, order_id, token, ordertype, price, triggerprice, quantity, exchange="NFO", product="MIS", validity="DAY"):

        params = {

            "exchange": exchange,
            "product": product,
            "validity": validity,

            'oms_order_id': str(order_id),
            'instrument_token': str(token),
            'order_type': ordertype,
            'price': str(price),
            'trigger_price': str(triggerprice),
            'quantity': str(quantity),
            'client_id': headers["user_id"],
        }

        response = cls.fetch(method="GET", url=cls.urls["place_order"], params=params, headers=cls.headers)

        return cls.Parser(response)

    def cancel_order(cls, order_id):

        params = {
            'client_id': headers["user_id"]
            }

        final_url = f"{cls.urls['place_order']}/{order_id}"

        response = cls.fetch(method="DELETE", url=final_url, params=params, headers=cls.headers)
        response = cls._json_parser(response)
        info = response.json()

        order_id = info['data']['oms_order_id']
        order = cls.fetch_order(order_id)

        return order

    @classmethod
    def fetch_position(cls,
                       headers: dict
                       ) -> dict[Any, Any]:

        params = {
            "type": "live",
            "client_id": headers["user_id"],
        }

        response = cls.fetch(method="GET", url=cls.urls["positions"], headers=cls.headers, params=params)
        info = cls._json_parser(response)

        positions = []
        for position in info['data']:
            parsedPosition = cls._position_json_parser(position)
            positions.append(parsedPosition)

        return positions

    @classmethod
    def profile(cls,
                headers: dict
                ) -> dict[Any, Any]:
        """
        Fetch Profile Limits of the User.

        Parameters:
            headers (dict): headers to send profile request with.

        Returns:
            dict: kronos Unified Profile Response
        """

        params = {'client_id': headers["user_id"]}

        response = cls.fetch(method="GET", url=cls.urls["profile"],
                             params=params, headers=headers["headers"])

        response = cls._json_parser(response)

        profile = cls._profile_json_parser(response["data"])
        return profile

