from __future__ import annotations
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


class angelone(Exchange):
    """
    AngelOne kronos Broker Class

    Returns:
        kronos.aliceblue: kronos AngelOne Broker Object
    """


    nfo_tokens = {}
    id = 'angelone'
    _session = Exchange.create_session()


    # Base URLs

    base_urls = {
        "api_documentation_link": "https://smartapi.angelbroking.com/docs",
        "access_token_url": "https://apiconnect.angelbroking.com/rest/auth/angelbroking/user/v1/loginByPassword",
        "base_url": "https://apiconnect.angelbroking.com/rest/secure/angelbroking",
        "market_data_url": "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base_url']}/order/v1/placeOrder",
        "modify_order": f"{base_urls['base_url']}/order/v1/modifyOrder",
        "cancel_order": f"{base_urls['base_url']}/order/v1/cancelOrder",
        "orderbook": f"{base_urls['base_url']}/order/v1/getOrderBook",
        "tradebook": f"{base_urls['base_url']}/order/v1/getTradeBook",
        "positions": f"{base_urls['base_url']}/order/v1/getPosition",
        "holdings": f"{base_urls['base_url']}/portfolio/v1/getHolding",
        "profile": f"{base_urls['base_url']}/user/v1/getProfile",
        "rms_limits": f"{base_urls['base_url']}/user/v1/getRMS",
    }


    # Request Parameters Dictionaries

    req_exchange = {
        ExchangeCode.NSE: "NSE",
        ExchangeCode.BSE: "BSE",
        ExchangeCode.NFO: "NFO",
        ExchangeCode.MCX: "MCX",
    }

    req_side = {
        Side.BUY: "BUY",
        Side.SELL: "SELL",
    }

    req_product = {
        Product.MIS: "INTRADAY",
        Product.NRML: "CARRYFORWARD",
        Product.CNC: "DELIVERY",
        Product.MARGIN: "MARGIN",
        Product.BO: "BO"
    }

    req_order_type = {
        OrderType.MARKET: "MARKET",
        OrderType.LIMIT: "LIMIT",
        OrderType.SL: "STOPLOSS_LIMIT",
        OrderType.SLM: "STOPLOSS_MARKET"
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
        "validation pending": Status.PENDING,
        "rejected": Status.REJECTED,
        "complete": Status.FILLED,
        "cancelled": Status.CANCELLED,
        "open": Status.OPEN
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


    # NFO Script Fetch


    @classmethod
    def nfo_dict(cls):
        try:
            df = cls.data_reader(cls.base_urls["market_data_url"], filetype='json')
            df = df[((df['name'] == 'BANKNIFTY') | (df['name'] == 'NIFTY') | (df['name'] == 'FINNIFTY')) & (df['exch_seg'] == 'NFO') & (df['instrumenttype'] == "OPTIDX")]

            df.rename({"token": "Token", "name": "Root", "expiry": "Expiry", "symbol": "Symbol",
                       "instrument_type": "Option", "tick_size": "TickSize", "lotsize": "LotSize",
                       "strike": "StrikePrice"},
                      axis=1, inplace=True)

            df['Option'] = df['Symbol'].str.extract(r"(CE|PE)")
            df['StrikePrice'] = df['StrikePrice'] // 100
            df['TickSize'] = df['TickSize'] / 100
            df['Token'] = df['Token'].astype(int)

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
        Generate Headers used to access Endpoints in AngelOne.

        Parameters:
            params (dict) : A dictionary which should consist the following keys:
                user_id (str): User ID of the Account.
                pin (str): pin of the Account Holder.
                totpbase (str): String of characters used to generate TOTP.
                api_key (str): API Key of the Account.

        Returns:
            dict[str, str]: AngelOne Headers.
        """

        for key in ["user_id", "pin", "totpstr", "api_key"]:
            if key not in params:
                raise KeyError(f"Please provide {key}")


        totp = cls.totp_creator(params["totpstr"])

        headers = {
            "Content-type": "application/json",
            "X-ClientLocalIP": "127.0.0.1",
            "X-ClientPublicIP": "106.193.147.98",
            "X-MACAddress": "00:00:00:00:00:00",
            "Accept": "application/json",
            "X-PrivateKey": params["api_key"],
            "X-UserType": "USER",
            "X-SourceID": "WEB"
        }

        json_data = {
            "clientcode": params["user_id"],
            "password": params["pin"],
            "totp": totp
        }

        response = cls.fetch(method="POST", url=cls.base_urls["access_token_url"], json=json_data, headers=headers["headers"])
        response = cls._json_parser(response)


        headers = {
            "headers":
                {
                    "Content-type": "application/json",
                    "X-ClientLocalIP": "127.0.0.1",
                    "X-ClientPublicIP": "106.193.147.98",
                    "X-MACAddress": "00:00:00:00:00:00",
                    "Accept": "application/json",
                    "X-PrivateKey": params["api_key"],
                    "X-UserType": "USER",
                    "X-SourceID": "WEB",
                    "Authorization": f"Bearer {response['data']['jwtToken']}",
                    'x-api-key': 'nBmFCnuK',
                    'x-client-code': params["user_id"],
                    'x-feed-token': response["data"]["feedToken"]
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
        # print(json_response)
        if json_response['status']:
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
            Order.VARIETY: cls.req_variety.get(order["variety"], order["variety"]),
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
        print(profile)

        parsed_profile = {
            Profile.CLIENTID: profile['clientcode'],
            Profile.NAME: profile['name'],
            Profile.EMAILID: profile['email'],
            Profile.MOBILENO: profile['mobileno'],
            Profile.PAN: "",
            Profile.ADDRESS: "",
            Profile.BANKNAME: "",
            Profile.BANKBRANCHNAME: None,
            Profile.BANKACCNO: "",
            Profile.EXHCNAGESENABLED: profile['exchanges'],
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
    def market_order(cls,
                     symbol: str,
                     token: int,
                     side: str,
                     unique_id: str,
                     quantity: int,
                     exchange: str,
                     headers: dict,
                     product: str = Product.MIS,
                     validity: str = Validity.DAY,
                     ) -> dict[Any, Any]:

        json_data = {
            "variety": cls.req_variety[Variety.REGULAR],
            "disclosedquantity": "0",
            "exchange": cls.req_exchange[exchange],
            "producttype": cls.req_product[product],
            "ordertype": cls.req_order_type[OrderType.MARKET],
            "price": "0",
            "triggerprice": "0",
            "quantity": quantity,
            "duration": cls.req_validity[validity],
            "symboltoken": token,
            "tradingsymbol": symbol,
            "transactiontype": cls.req_side[side],
            "ordertag": unique_id,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order(cls,
                    price: float,
                    symbol: str,
                    token: int,
                    side: str,
                    unique_id: int,
                    quantity: int,
                    exchange: str,
                    headers: dict,
                    product: str = Product.MIS,
                    validity: str = Validity.DAY
                    ) -> dict[Any, Any]:


        json_data = {
            "variety": cls.req_variety[Variety.REGULAR],
            "disclosedquantity": "0",
            "exchange": cls.req_exchange[exchange],
            "producttype": cls.req_product[product],
            "ordertype": cls.req_order_type[OrderType.LIMIT],
            "price": price,
            "triggerprice": "0",
            "quantity": quantity,
            "duration": cls.req_validity[validity],
            "symboltoken": token,
            "tradingsymbol": symbol,
            "transactiontype": cls.req_side[side],
            "ordertag": unique_id,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order(cls,
                 price: float,
                 trigger_price: float,
                 symbol: str,
                 token: int,
                 side: str,
                 unique_id: int,
                 quantity: int,
                 exchange: str,
                 headers: dict,
                 product: str = Product.MIS,
                 validity: str = Validity.DAY,
                 ) -> dict[Any, Any]:


        json_data = {
            "variety": cls.req_variety[Variety.STOPLOSS],
            "disclosedquantity": "0",
            "exchange": cls.req_exchange[exchange],
            "producttype": cls.req_product[product],
            "ordertype": cls.req_order_type[OrderType.SL],
            "price": price,
            "triggerprice": trigger_price,
            "quantity": quantity,
            "duration": cls.req_validity[validity],
            "symboltoken": token,
            "tradingsymbol": symbol,
            "transactiontype": cls.req_side[side],
            "ordertag": unique_id,
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
                         price: float,
                         trigger_price: float,
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

        if not price and trigger_price:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger_price:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        json_data = [
            {
                "symbol_id": token,
                "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "trading_symbol": symbol,
                "price": price,
                "trigPrice": trigger_price,
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
            exchange (str, optional): Exchange to place the order in.. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist

        Returns:
            dict: Voluspa Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.expiry_markets()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']
        token = detail['Token']

        json_data = [
            {
                "symbol_id": token,
                "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "trading_symbol": symbol,
                "price": 0,
                "trigPrice": 0,
                "qty": quantity,
                "transtype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.MARKET],
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
            dict: Voluspa Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.expiry_markets()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']
        token = detail['Token']

        json_data = [
            {
                "symbol_id": token,
                "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "trading_symbol": symbol,
                "price": price,
                "trigPrice": 0,
                "qty": quantity,
                "transtype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.LIMIT],
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
    def sl_order_nfo(cls,
                     option: str,
                     strike_price: int,
                     price: float,
                     trigger_price: float,
                     quantity: int,
                     side: str,
                     headers: dict,
                     root: str = Root.BNF,
                     expiry: str = WeeklyExpiry.CURRENT,
                     exchange: str = ExchangeCode.NFO,
                     product: str = Product.MIS,
                     validity: str = Validity.DAY,
                     variety: str = Variety.REGULAR,
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
            dict: Voluspa Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']
        token = detail['Token']

        json_data = [
            {
                "symbol_id": token,
                "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "trading_symbol": symbol,
                "price": price,
                "trigPrice": trigger_price,
                "qty": quantity,
                "transtype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.SL],
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
    def slm_order_nfo(cls,
                      option: str,
                      strike_price: int,
                      trigger_price: float,
                      quantity: int,
                      side: str,
                      headers: dict,
                      root: str = Root.BNF,
                      expiry: str = WeeklyExpiry.CURRENT,
                      exchange: str = ExchangeCode.NFO,
                      product: str = Product.MIS,
                      validity: str = Validity.DAY,
                      variety: str = Variety.REGULAR,
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
            dict: Voluspa Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']
        token = detail['Token']

        json_data = [
            {
                "symbol_id": token,
                "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "trading_symbol": symbol,
                "price": 0,
                "trigPrice": trigger_price,
                "qty": quantity,
                "transtype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.SLM],
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



    # BO Order Functions


    @classmethod
    def market_order_bo(cls,
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
                        product: str = Product.MIS,
                        validity: str = Validity.DAY,
                        ) -> dict[Any, Any]:

        json_data = {
            "variety": cls.req_variety[Variety.REGULAR],
            "disclosedquantity": "0",
            "exchange": cls.req_exchange[exchange],
            "producttype": cls.req_product[product],
            "ordertype": cls.req_order_type[OrderType.MARKET],
            "price": "0",
            "triggerprice": "0",
            "squareoff": target,
            "stoploss": stoploss,
            "trailingStopLoss": trailing_sl,
            "quantity": quantity,
            "duration": cls.req_validity[validity],
            "symboltoken": token,
            "tradingsymbol": symbol,
            "transactiontype": cls.req_side[side],
            "ordertag": unique_id,
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
                       unique_id: int,
                       quantity: int,
                       exchange: str,
                       headers: dict,
                       target: float = 0,
                       stoploss: float = 0,
                       trailing_sl: float = 0,
                       product: str = Product.MIS,
                       validity: str = Validity.DAY
                       ) -> dict[Any, Any]:


        json_data = {
            "variety": cls.req_variety[Variety.REGULAR],
            "disclosedquantity": "0",
            "exchange": cls.req_exchange[exchange],
            "producttype": cls.req_product[product],
            "ordertype": cls.req_order_type[OrderType.LIMIT],
            "price": price,
            "triggerprice": "0",
            "squareoff": target,
            "stoploss": stoploss,
            "trailingStopLoss": trailing_sl,
            "quantity": quantity,
            "duration": cls.req_validity[validity],
            "symboltoken": token,
            "tradingsymbol": symbol,
            "transactiontype": cls.req_side[side],
            "ordertag": unique_id,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order_bo(cls,
                    price: float,
                    trigger_price: float,
                    symbol: str,
                    token: int,
                    side: str,
                    unique_id: int,
                    quantity: int,
                    exchange: str,
                    headers: dict,
                    target: float = 0,
                    stoploss: float = 0,
                    trailing_sl: float = 0,
                    product: str = Product.MIS,
                    validity: str = Validity.DAY,
                    ) -> dict[Any, Any]:


        json_data = {
            "variety": cls.req_variety[Variety.STOPLOSS],
            "disclosedquantity": "0",
            "exchange": cls.req_exchange[exchange],
            "producttype": cls.req_product[product],
            "ordertype": cls.req_order_type[OrderType.SL],
            "price": price,
            "triggerprice": trigger_price,
            "squareoff": target,
            "stoploss": stoploss,
            "trailingStopLoss": trailing_sl,
            "quantity": quantity,
            "duration": cls.req_validity[validity],
            "symboltoken": token,
            "tradingsymbol": symbol,
            "transactiontype": cls.req_side[side],
            "ordertag": unique_id,
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

        orders = []
        if info['data']:
            for order in info['data']:
                detail = cls._orderbook_json_parser(order)
                orders.append(detail)

        return orders

    @classmethod
    def fetch_orderbook(cls,
                        headers: dict
                        ) -> list[dict]:

        response = cls.fetch(method="GET", url=cls.urls['orderbook'], headers=headers["headers"])
        info = cls._json_parser(response)

        orders = []
        if info['data']:
            for order in info['data']:
                detail = cls._orderbook_json_parser(order)
                orders.append(detail)

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
                detail = cls._orderbook_json_parser(order)
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
