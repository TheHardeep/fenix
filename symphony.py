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
from kronos.base.constants import Position
from kronos.base.constants import Root
from kronos.base.constants import WeeklyExpiry
from kronos.base.constants import UniqueID


from kronos.base.errors import ResponseError
from kronos.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response


class symphony(Exchange):
    """
    Symphony kronos Broker Class

    Returns:
        kronos.symphony: kronos Symphony Broker Object
    """


    # Market Data Dictonaries

    nfo_tokens = {}
    id = 'symphony'
    _session = Exchange._create_session()


    # Base URLs

    base_urls = {
        "api_documentation_url": "https://developers.symphonyfintech.in/doc/interactive",
        "market_data_documentation_url": "https://developers.symphonyfintech.in/doc/marketdata",
        "market_data_url": "https://developers.symphonyfintech.in/marketdata/instruments/master",
        "base_url": "https://smartweb.jmfinancialservices.in/interactive",
        "access_token": "https://smartweb.jmfinancialservices.in/interactive/user/session"
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base_url']}/orders",
        "modify_order": f"{base_urls['base_url']}/orders",
        "cancel_order": f"{base_urls['base_url']}/orders",
        "order_history": f"{base_urls['base_url']}/orders",
        "orderbook": f"{base_urls['base_url']}/orders",
        "tradebook": f"{base_urls['base_url']}/orders/trades",
        "positions": f"{base_urls['base_url']}/portfolio/positions",
        "holdings": f"{base_urls['base_url']}/portfolio/holdings",
        "profile": f"{base_urls['base_url']}/user/profile",
        "rms_limits": f"{base_urls['base_url']}/user/balance",
    }


    # Request Parameters Dictionaries

    req_exchange = {
        ExchangeCode.NSE: "NSECM",
        ExchangeCode.NFO: "NSEFO",
        ExchangeCode.BSE: "BSECM"
    }

    req_side = {
        Side.BUY: "BUY",
        Side.SELL: "SELL"
    }

    req_product = {
        Product.MIS: "MIS",
        Product.NRML: "NRML",
        Product.CNC: "CNC",
        Product.CO: "CO",
        Product.BO: "MIS",
    }

    req_order_type = {
        OrderType.MARKET: "Market",
        OrderType.LIMIT: "Limit",
        OrderType.SLM: "StopMarket",
        OrderType.SL: "StopLimit",
    }

    req_validity = {
        Validity.DAY: "DAY",
        Validity.IOC: "IOC"
    }


    # Response Parameters Dictionaries

    resp_order_type = {
        "Market": OrderType.MARKET,
        "Limit": OrderType.LIMIT,
        "StopMarket": OrderType.SLM,
        "StopLimit": OrderType.SL,
    }

    resp_status = {
        "New": Status.OPEN,
        "Open": Status.OPEN,
        "PendingNew": Status.PENDING,
        "PendingReplace": Status.PENDING,
        "Replaced": Status.MODIFIED,
        "Filled": Status.FILLED,
        "Cancelled": Status.CANCELLED,
        "Rejected": Status.REJECTED,
        'PartiallyFilled': Status.PARTIALLYFILLED,
    }




    @classmethod
    def nfo_dict(cls):
        try:

            response = cls.fetch(method='POST', url=cls.base_urls["market_data_url"], json={"exchangeSegmentList": ["NSEFO"]})
            data = cls._json_parser(response)['result']
            data = [row.split('|') for row in data.split('\n')]

            df = cls.data_frame(data)

            df = df[(df[5] == 'OPTIDX') & (df[3].str.startswith(("BANKNIFTY", "NIFTY")))]
            df[4] = df[4].str[-2:]
            df[10] = df[10].astype(int) - 1

            df.rename({1: "Token", 3: "Root", 4: "Option", 10: "QtyLimit",
                       11: "TickSize", 12: "LotSize", 16: "Expiry",
                       17: "StrikePrice", 19: "Symbol"
                       },
                      axis=1, inplace=True)

            df = df[['Token', 'Symbol', 'Expiry', 'Option',
                     'StrikePrice', 'LotSize', 'QtyLimit',
                     'Root', 'TickSize'
                     ]]

            df['LotSize'] = df['LotSize'].astype(int)
            df['TickSize'] = df['TickSize'].astype(float)
            df['Token'] = df['Token'].astype(int)
            df['StrikePrice'] = df['StrikePrice'].astype(int)
            df['Expiry'] = cls.pd_datetime(df['Expiry']).dt.date.astype(str)

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
                api_key (str): API Key of the Account.
                api_secret (str): API Secret of the Account.

        Returns:
            dict[str, str]: AliceBlue Headers.
        """
        for key in ["user_id", "api_key", "api_secret"]:
            if key not in params:
                raise KeyError(f"Please provide {key}")

        data = {
            "appKey": params["api_key"],
            "secretKey": params["api_secret"],
            "source": "WEBAPI"
        }

        token_req = cls.fetch(method="POST", url=cls.base_urls["access_token"], data=data)
        token_resp = cls._json_parser(token_req)

        access_token = token_resp["result"]["token"]

        headers = {
            "headers": {
                "Content-Type": "application/json",
                "Authorization": access_token,
            }
        }

        return headers

    @classmethod
    def _json_parser(cls,
                     response: Response
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

        if json_response['type'] == "success":
            return json_response

        raise ResponseError(cls.id + " " + json_response['message'])

    @classmethod
    def _orderbook_json_parser(cls,
                               order: dict,
                               ) -> dict[Any, Any]:
        """
        Parses Order History Json Response to a kronos Unified Order Response.

        Parameters:
            order (dict): Order History Json Response from Broker

        Returns:
            dict: Unified kronos Order Response
        """

        parsed_order = {
            Order.ID: order['AppOrderID'],
            Order.USERID: order['OrderUniqueIdentifier'],
            Order.TIMESTAMP: cls.pd_datetime(order['ExchangeTransactTime']),
            Order.SYMBOL: order['TradingSymbol'],
            Order.TOKEN: order['ExchangeInstrumentID'],
            Order.SIDE: cls.req_side[order['OrderSide']],
            Order.TYPE: cls.resp_order_type.get(order['OrderType'], order['OrderType']),
            Order.AVGPRICE: float(order['OrderAverageTradedPrice'] or 0.0),
            Order.PRICE: order['OrderPrice'],
            Order.TRIGGERPRICE: order['OrderStopPrice'],
            Order.TARGETPRICE: 0.0,
            Order.STOPLOSSPRICE: 0.0,
            Order.TRAILINGSTOPLOSS: 0.0,
            Order.QUANTITY: order['OrderQuantity'],
            Order.FILLEDQTY: order['CumulativeQuantity'],
            Order.REMAININGQTY: order['LeavesQuantity'],
            Order.CANCELLEDQTY: "",
            Order.STATUS: cls.resp_status.get(order['OrderStatus'], order['OrderStatus']),
            Order.REJECTREASON: order.get('CancelRejectReason', ""),
            Order.DISCLOSEDQUANTITY: order['OrderDisclosedQuantity'],
            Order.PRODUCT: order['ProductType'],
            Order.EXCHANGE: "",
            Order.SEGMENT: order['ExchangeSegment'],
            Order.VALIDITY: order['TimeInForce'],
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

        exclist = profile['ClientExchangeDetailsList']
        exchanges_enabled = [i for i in exclist if exclist[i]['Enabled']]

        parsed_profile = {
            Profile.CLIENTID: profile['ClientId'],
            Profile.NAME: profile['ClientName'],
            Profile.EMAILID: profile['EmailId'],
            Profile.MOBILENO: int(profile['MobileNo']),
            Profile.PAN: profile['PAN'],
            Profile.ADDRESS: profile['ResidentialAddress'],
            Profile.BANKNAME: profile['ClientBankInfoList'][0]['BankName'],
            Profile.BANKBRANCHNAME: None,
            Profile.BANKACCNO: int(profile['ClientBankInfoList'][0]['AccountNumber']),
            Profile.EXHCNAGESENABLED: exchanges_enabled,
            Profile.ENABLED: None,
            Profile.INFO: profile,
        }

        return parsed_profile

    @classmethod
    def _position_json_parser(cls,
                              position: dict
                              ) -> dict[Any, Any]:

        parsed_position = {
            Position.SYMBOL: position['TradingSymbol'],
            Position.TOKEN: position['ExchangeInstrumentID'],
            Position.NETQTY: position['Quantity'],
            Position.AVGPRICE: (position["SumOfTradedQuantityAndPriceBuy"] + position["SumOfTradedQuantityAndPriceSell"]) / (position["BuyAmount"] + position["SellAmount"]),
            Position.MTM: position['RealizedMTM'],
            Position.PNL: position['MTM'],
            Position.BUYQTY: position['OpenBuyQuantity'],
            Position.BUYPRICE: position['BuyAveragePrice'],
            Position.SELLQTY: position['OpenSellQuantity'],
            Position.SELLPRICE: position['SellAveragePrice'],
            Position.LTP: 0.0,
            Position.EXCHANGE: cls.resp_exchange.get(position['ExchangeSegment'], position['ExchangeSegment']),
            Position.PRODUCT: cls.req_product.get(position['product'], position['product']),
            Position.INFO: position,
        }

        return parsed_position

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
        order_id = info['result']['AppOrderID']

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
                "exchangeInstrumentID": token,
                "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                "limitPrice": 0.0,
                "stopPrice": 0.0,
                "orderQuantity": quantity,
                "orderSide": cls._key_mapper(cls.req_side, side, "side"),
                "orderType": cls.req_order_type[OrderType.MARKET],
                "productType": cls._key_mapper(cls.req_product, product, "product"),
                "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
                "orderUniqueIdentifier": unique_id,
                "disclosedQuantity": 0,
            }

            final_url = cls.urls["place_order"]

        else:
            json_data = {
                "exchangeInstrumentID": token,
                "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                "limitPrice": price,
                "stopPrice": trigger,
                "squarOff": target,
                "stopLossPrice": stoploss,
                "trailingStoploss": trailing_sl,
                "orderQuantity": quantity,
                "orderSide": cls._key_mapper(cls.req_side, side, "side"),
                "orderType": cls.req_order_type[order_type],
                "productType": cls._key_mapper(cls.req_product, product, "product"),
                "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
                "orderUniqueIdentifier": unique_id,
                "disclosedQuantity": 0,
            }

            final_url = f"{cls.urls['place_order']}/bracket"


        response = cls.fetch(method="POST", url=final_url,
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
        """
        Place Market Order

        Parameters:
            symbol (str): Trading Symbol
            token (int): Exchange Token
            side (str): Order Side: BUY, SELL
            unique_id (str): Unique User Orderid
            quantity (int): Order Quantity
            exchange (str): Exchange to place the order in.
            headers (dict): headers to send order request with.
            product (str, optional): Order Product. Defaults to Product.MIS.
            validity (str, optional): Order Validity. Defaults to Validity.DAY.

        Returns:
            dict: kronos Unified Order Response
        """

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": 0.0,
            "stopPrice": 0.0,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.MARKET],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
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
        """
        Place Limit Order

        Parameters:
            price (float): Order price
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
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": price,
            "stopPrice": 0.0,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.LIMIT],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
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

        """
        Place Stoploss Order

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
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": price,
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.SL],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
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
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": 0.0,
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.SLM],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
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
            dict: Kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": price,
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[order_type],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
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
            dict: Kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": 0.0,
            "stopPrice": 0.0,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.MARKET],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
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
            dict: Kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": price,
            "stopPrice": 0.0,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.LIMIT],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
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
            dict: Kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": price,
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.SL],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
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
            dict: Kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.nfo_dict()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": 0.0,
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.SLM],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
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
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": price,
            "stopPrice": trigger,
            "squarOff": target,
            "stopLossPrice": stoploss,
            "trailingStoploss": trailing_sl,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[order_type],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
        }

        final_url = f"{cls.urls['place_order']}/bracket"

        response = cls.fetch(method="POST", url=final_url,
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
        """
        Place BO Market Order

        Parameters:
            symbol (str): Trading Symbol
            token (int): Exchange Token
            side (str): Order Side: BUY, SELL
            unique_id (str): Unique User Orderid
            quantity (int): Order Quantity
            exchange (str): Exchange to place the order in.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaulsts to 0.
            stoploss (float, optional): Order Stoploss price. Defaulsts to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaulsts to 0.
            product (str, optional): Order Product. Defaults to Product.MIS.
            validity (str, optional): Order Validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Returns:
            dict: kronos Unified Order Response
        """

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": 0.0,
            "stopPrice": 0.0,
            "squarOff": target,
            "stopLossPrice": stoploss,
            "trailingStoploss": trailing_sl,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.MARKET],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
        }

        final_url = f"{cls.urls['place_order']}/bracket"

        response = cls.fetch(method="POST", url=final_url,
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
                       product: str = Product.MIS,
                       validity: str = Validity.DAY,
                       variety: str = Variety.BO,
                       ) -> dict[Any, Any]:
        """
        Place Limit Order

        Parameters:
            price (float): Order price
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
        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": price,
            "stopPrice": 0.0,
            "squarOff": target,
            "stopLossPrice": stoploss,
            "trailingStoploss": trailing_sl,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.LIMIT],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
        }

        final_url = f"{cls.urls['place_order']}/bracket"

        response = cls.fetch(method="POST", url=final_url,
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

        """
        Place Stoploss Order

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
        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": price,
            "stopPrice": trigger,
            "squarOff": target,
            "stopLossPrice": stoploss,
            "trailingStoploss": trailing_sl,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.SL],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
        }

        final_url = f"{cls.urls['place_order']}/bracket"

        response = cls.fetch(method="POST", url=final_url,
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
            target (float, optional): Order Target price. Defaulsts to 0.
            stoploss (float, optional): Order Stoploss price. Defaulsts to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaulsts to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Returns:
            dict: kronos Unified Order Response
        """
        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
            "limitPrice": 0.0,
            "stopPrice": trigger,
            "squarOff": target,
            "stopLossPrice": stoploss,
            "trailingStoploss": trailing_sl,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, "side"),
            "orderType": cls.req_order_type[OrderType.SLM],
            "productType": cls._key_mapper(cls.req_product, product, "product"),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, "validity"),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
        }

        final_url = f"{cls.urls['place_order']}/bracket"

        response = cls.fetch(method="POST", url=final_url,
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)



    # Order Details, OrderBook & TradeBook


    @classmethod
    def fetch_orderhistory(cls,
                           order_id: str,
                           headers: dict
                           ) -> list[dict]:
        """
        Fetch History of an order

        Paramters:
            order_id (str): id of the order
            headers (dict): headers to send orderhistory request with.

        Returns:
            list: A list of dicitonaries containing order history using kronos Unified Order Response
        """
        params = {"appOrderID": order_id}
        response = cls.fetch(method="GET", url=cls.urls['order_history'],
                             params=params, headers=headers["headers"])

        info = cls._json_parser(response)

        order_history = []
        for order in info["result"]:
            history = cls._orderbook_json_parser(order)
            order_history.append(history)

        return order_history

    @classmethod
    def fetch_order(cls,
                    order_id: str,
                    headers: dict
                    ) -> dict[Any, Any]:
        """
        Fetch Order Details.

        Paramters:
            order_id (str): id of the order

        Raises:
            InputError: If order does not exist.

        Returns:
            dict: kronos Unified Order Response
        """
        params = {'appOrderID': order_id}

        response = cls.fetch(method="GET", url=cls.urls["order_history"],
                             params=params, headers=headers["headers"])

        info = cls._json_parser(response)

        detail = info['result'][-1]
        order = cls._orderbook_json_parser(detail)

        return order

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
        response = cls.fetch(method="GET", url=cls.urls["orderbook"], headers=headers["headers"])
        info = cls._json_parser(response)

        orders = []
        for order in info['result']:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_orderbook(cls,
                        headers: dict
                        ) -> list[dict]:
        """
        Fetch Orderbook Details

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using kronos Unified Order Response
        """
        response = cls.fetch(method="GET", url=cls.urls["orderbook"], headers=headers["headers"])
        info = cls._json_parser(response)

        orders = []
        for order in info['result']:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_tradebook(cls,
                        headers: dict
                        ) -> list[dict]:
        """
        Fetch Tradebook Details

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using kronos Unified Order Response
        """
        response = cls.fetch(method="GET", url=cls.urls["tradebook"], headers=headers["headers"])
        info = cls._json_parser(response)

        orders = []
        for order in info['result']:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders


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
        Modify an open order

        Parameters:
            order_id (str): id of the order to modify.
            headers (dict): headers to send modify_order request with.
            price (float | None, optional): price of the order. Defaults to None.
            triggerprice (float | None, optional): trigger price of the order. Defaults to None.
            quantity (int | None, optional): order quantity. Defaults to None.

        Returns:
            dict: kronos Unified Order Response
        """

        curr_order = cls.fetch_order(order_id=order_id, headers=headers)

        json_data = {
            "appOrderID": order_id,
            "modifiedProductType": cls.req_product[Order.PRODUCT],
            "modifiedOrderType": cls._key_mapper(cls.req_order_type, order_type, 'order_type') or cls.req_order_type[curr_order[Order.TYPE]],
            "modifiedOrderQuantity": quantity or curr_order[Order.QUANTITY],
            "modifiedDisclosedQuantity": curr_order[Order.DISCLOSEDQUANTITY],
            "modifiedLimitPrice": price or curr_order[Order.PRICE],
            "modifiedStopPrice": trigger or curr_order[Order.TRIGGERPRICE],
            "modifiedTimeInForce": cls._key_mapper(cls.req_validity, validity, 'validity') or cls.req[curr_order[Order.VALIDITY]],
            "orderUniqueIdentifier": curr_order[Order.Order.USERID]
        }

        params = {"clientID": headers["user_id"]}

        response = cls.fetch(method="PUT", url=cls.urls["modify_order"],
                             params=params, json=json_data,
                             headers=headers["headers"])

        return cls._create_order_parser(response=response)

    @classmethod
    def cancel_order(cls,
                     order_id: str,
                     headers: dict
                     ) -> dict[Any, Any]:
        """
        Cancel an open order.

        Parameters:
            order_id (str): id of the order
            headers (dict): headers to send cancel_order request with.

        Returns:
            dict: kronos Unified Order Response
        """
        params = {"appOrderID": order_id}

        response = cls.fetch(method="DELETE", url=cls.urls["cancel_order"],
                             params=params, headers=headers["headers"])

        return cls._create_order_parser(response=response)


    # Account Limits & Profile


    @classmethod
    def fetch_day_positions(cls,
                            headers: dict,
                            ) -> dict[Any, Any]:
        """
        Fetch the Day's Account Holdings

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Position Response
        """

        params = {'dayOrNet': "DayWise"}
        response = cls.fetch(method="GET", url=cls.urls["positions"],
                             params=params, headers=headers["headers"])

        return cls._json_parser(response)

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

        params = {"dayOrNet": "NetWise"}
        response = cls.fetch(method="GET", url=cls.urls["positions"],
                             params=params, headers=headers["headers"])

        return cls._json_parser(response)

    @classmethod
    def fetch_holdings(cls,
                       headers: dict,
                       ) -> dict[Any, Any]:
        """
        Fetch Account Holdings

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Positions Response
        """
        params = {"clientID": headers["user_id"]}
        response = cls.fetch(method="GET", url=cls.urls["holdings"],
                             params=params, headers=headers["headers"])
        try:
            return cls._json_parser(response)
        except ResponseError as e:
            if "no data" in str(e):
                return []

    @classmethod
    def rms_limits(cls,
                   headers: dict
                   ) -> dict[Any, Any]:
        """
        Fetch Risk Management System Limits

        Parameters:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict: kronos Unified RMS Limits Response
        """
        params = {"clientID": headers["user_id"]}
        response = cls.fetch(method="GET", url=cls.urls["rms_limits"],
                             params=params, headers=headers["headers"])

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
        params = {"clientID": headers["user_id"]}
        response = cls.fetch(method="GET", url=cls.urls["profile"],
                             params=params, headers=headers["headers"])

        info = cls._json_parser(response)
        profile = cls._profile_json_parser(info["result"])

        return profile
