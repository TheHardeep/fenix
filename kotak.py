from __future__ import annotations
from typing import TYPE_CHECKING
from typing import Any

from kronos.base.exchange import Exchange

from kronos.base.constants import Side
from kronos.base.constants import ExchangeCode
from kronos.base.constants import Product
from kronos.base.constants import Validity
from kronos.base.constants import Variety
from kronos.base.constants import Status
from kronos.base.constants import Order
from kronos.base.constants import Root
from kronos.base.constants import WeeklyExpiry
from kronos.base.constants import UniqueID


from kronos.base.errors import InputError
from kronos.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response


class kotak(Exchange):
    """
    AliceBlue kronos Broker Class.

    Returns:
        kronos.kotak: kronos AliceBlue Broker Object.
    """


    # Market Data Dictonaries

    indices = {}
    eq_tokens = {}
    nfo_tokens = {}
    token_params = ["user_id", "password", "consumer_key", "access_token"]
    id = 'kotak'
    _session = Exchange._create_session()


    # Base URLs

    base_urls = {
        "api_doc": "https://ctradeapi.kotaksecurities.com/devportal/apis",
        "git_sdk": "https://github.com/paramatrixtech/ksapi",
        "base": "https://tradeapi.kotaksecurities.com/apim",
        "market_data": "https://preferred.kotaksecurities.com/security/production",
    }

    # Access Token Generation URLs

    token_urls = {
        "login": f"{base_urls['base']}/session/1.0/session/login/userid",
        "session_token": f"{base_urls['base']}/session/1.0/session/2FA/oneTimeToken",
    }


    urls = {
        "place_order": f"{base_urls['base']}/placeOrder/executePlaceOrder",
        "modify_order": f"{base_urls['base']}/placeOrder/modifyOrder",
        "cancel_order": f"{base_urls['base']}/placeOrder/cancelOrder",
        "exit_bracket_order": f"{base_urls['base']}/placeOrder/exitBracketOrder",
        "orderbook": f"{base_urls['base']}/placeOrder/fetchOrderBook",
        "tradebook": f"{base_urls['base']}/placeOrder/fetchTradeBook",
        "order_history": f"{base_urls['base']}/placeOrder/orderHistory",
        "positions": f"{base_urls['base']}/positionAndHoldings/positionBook",
        "holdings": f"{base_urls['base']}/positionAndHoldings/holdings",
        "sqoff_position": f"{base_urls['base']}/positionAndHoldings/sqrOofPosition",
        "rms_limits": f"{base_urls['base']}/limits/getRmsLimits",
        "profile": f"{base_urls['base']}/customer/accountDetails",
    }

    order_cancel_url = f"{base_urls['base']}/orders/1.0/orders"
    fetch_order_url = f"{base_urls['base']}/reports/1.0/orders"
    fetch_trade_book_url = f"{base_urls['base']}/reports/1.0/trades"

    place_order_urls = {
        Product.NRML: f"{base_urls['base']}/orders/1.0/order/normal",
        Product.SM: f"{base_urls['base']}/orders/1.0/order/supermultiple",
        "SOR": f"{base_urls['base']}/orders/1.0/order/sor",
        "MTF": f"{base_urls['base']}/orders/1.0/order/mtf",
        Product.MIS: f"{base_urls['base']}/orders/1.0/order/mis"
    }


    # Request Parameters Dictionaries

    req_side = {
        Side.BUY: "BUY",
        Side.SELL: "SELL"
    }

    req_product = {
        Product.MIS: "MIS",
        Product.NRML: "NORMAL",
        "SUPERMULTIPLE": "SUPERMULTIPLE",
        "SUPERMULTIPLEOPTION": "SUPERMULTIPLEOPTION",
        "MTF": "MTF",
    }

    req_validity = {
        Validity.DAY: "GFD",
        Validity.IOC: "IOC",
    }

    req_variety = {
        Variety.REGULAR: "REGULAR",
        Variety.AMO: "AMO",
        "SQUAREOFF": "SQUAREOFF"
    }


    # Response Parameters Dictionaries

    resp_validity = {
        "Good For Day": "DAY"
    }

    resp_product = {
        "NORMAL": Product.NRML
    }

    resp_status = {
        "OPN": Status.OPEN,
        "Traded": Status.FILLED,
        "NEWF": Status.PENDING,
    }


    # NFO Script Fetch


    @classmethod
    def data_datetime(cls):
        """
        Datetime object converted to a string format to be used in creating a market data URL.

        Returns:
            datetime string (str): Datetime string.
        """
        todaysdate = cls.current_datetime()
        weekday = todaysdate.weekday()
        days = 0
        if weekday >= 5:
            days = 3

        date_obj = cls.time_delta(todaysdate, days, dtformat="%d_%m_%Y")

        return date_obj

    @classmethod
    def create_eq_tokens(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the aliceblue.indices Dictionary.

        Returns:
            dict: Unified kronos indices format.
        """
        date_obj = cls.data_datetime()
        link = f"{cls.base_urls['market_data']}/TradeApiInstruments_Cash_{date_obj}.txt"

        df = cls.data_reader(link, filetype='csv', sep="|")

        df = df[df['instrumentType'] == "EQ"]
        df = df[["exchange", "instrumentName", "instrumentToken", "tickSize", "lotSize"]]


        df.rename({"instrumentToken": "Token", "instrumentName": "Symbol",
                   'tickSize': 'TickSize', "lotSize": "LotSize"
                   }, axis=1, inplace=True)

        df_bse = df[df['exchange'] == "BSE"]
        df_bse.drop_duplicates(subset=['Symbol'], keep='first', inplace=True)
        df_bse.drop(columns="exchange", inplace=True)


        df_nse = df[df['exchange'] == "BSE"]
        df_nse.drop(columns="exchange", inplace=True)

        cls.eq_tokens[ExchangeCode.NSE] = df_nse.to_dict(orient='index')
        cls.eq_tokens[ExchangeCode.BSE] = df_bse.to_dict(orient='index')

        return cls.eq_tokens


    @classmethod
    def create_indices(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the kotak.indices Dictionary.

        Returns:
            dict: Unified kronos indices format.
        """
        date_obj = cls.data_datetime()
        link = f"{cls.base_urls['market_data']}/TradeApiInstruments_Cash_{date_obj}.txt"

        df = cls.data_reader(link, filetype='csv', sep="|")
        df = df[df['instrumentType'] == "IN"][["instrumentName", "instrumentToken"]]

        df.rename({"instrumentName": "Symbol", "instrumentToken": "Token"}, axis=1, inplace=True)
        df.index = df['Symbol']

        indices = df.to_dict(orient='index')

        indices[Root.BNF] = indices["NIFTY BANK"]
        indices[Root.NF] = indices["NIFTY 50"]
        indices[Root.FNF] = indices["FINNIFTY"]
        indices[Root.MIDCPNF] = indices["NIFTY MIDCAP 50"]  # could not find NIFTY MIDCAP SELECT

        cls.indices = indices

        return indices

    @classmethod
    def create_nfo_tokens(cls) -> dict:
        """
        Creates BANKNIFTY & NIFTY Current, Next and Far Expiries;
        Stores them in the zerodha.nfo_tokens Dictionary.

        Raises:
            TokenDownloadError: Any Error Occured is raised through this Error Type.
        """
        try:
            date_obj = cls.data_datetime()
            link = f"{cls.base_urls['market_data']}/TradeApiInstruments_FNO_{date_obj}.txt"

            df = cls.data_reader(link, filetype='csv', sep="|")

            df = df[
                (
                    (df['instrumentName'] == 'BANKNIFTY') |
                    (df['instrumentName'] == 'NIFTY') |
                    (df['instrumentName'] == 'FINNIFTY') |
                    (df['instrumentName'] == 'MIDCPNIFTY')
                ) &
                (
                    (df['optionType'] != "XX")
                )
            ]

            df.rename({"instrumentToken": "Token", "instrumentName": "Root", "expiry": "Expiry",
                       "optionType": "Option", 'tickSize': 'TickSize', "lotSize": "LotSize",
                       "lastPrice": "LastPrice", "strike": "StrikePrice"
                       },
                      axis=1, inplace=True)

            df = df[['Token', 'Expiry', 'Option',
                     'StrikePrice', 'LotSize',
                     'Root', 'LastPrice', 'TickSize'
                     ]]

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
        Generate Headers used to access Endpoints in Kotak.

        Parameters:
            Params (dict) : A dictionary which should consist the following keys:
                user_id (str): User ID of the Account.
                password (str): Password of the Account.
                consumer_key (str): Consumer Key of the Account API.
                access_token (str): Access Token of the Account API.

        Returns:
            dict[str, str]: Kotak Headers.
        """
        for key in cls.token_params:
            if key not in params:
                raise KeyError(f"Please provide {key}")

        headers01 = {
            "consumerKey": params["consumer_key"],
            "ip": "0.0.0.0",
            "appId": "APP1",
            "Content-Type": "application/json",
            "User-Agent": "KSTradeApi-python/1.0.0/python",
            "Authorization": f"Bearer {params['access_token']}"
        }

        json_data01 = {
            "userid": params["user_id"],
            "password": params["password"]
        }

        response01 = cls.fetch(method="POST", url=cls.token_urls["login"],
                               json=json_data01, headers=headers01)

        info01 = cls._json_parser(response01)
        one_time_token = info01['Success']['oneTimeToken']

        headers02 = {
            "oneTimeToken": one_time_token,
            "consumerKey": params["consumer_key"],
            "ip": "0.0.0.0",
            "appId": "APP1",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "KSTradeApi-python/1.0.0/python",
            "Authorization": f"Bearer {params['access_token']}"
        }

        json_data02 = {"userid": params["user_id"]}

        response02 = cls.fetch(method="POST", url=cls.token_urls["session_token"],
                               json=json_data02, headers=headers02)

        info02 = cls._json_parser(response02)

        headers = {
            "headers": {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "KSTradeApi-python/1.0.0/python",
                "consumerKey": params["consumer_key"],
                "sessionToken": info02["success"]["sessionToken"],
                "Authorization": f"Bearer {params['access_token']}"
            }
        }

        cls._session = cls._create_session()

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
        return json_response

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
            Order.ID: order["orderId"],
            Order.USERID: order["tag"],
            Order.TIMESTAMP: cls.datetime_strp(order["orderTimestamp"], "%b %d %Y %I:%M:%S:%f%p"),
            Order.SYMBOL: order["instrumentName"],
            Order.TOKEN: order["instrumentToken"],
            Order.SIDE: cls.req_side.get(order["transactionType"], order["transactionType"]),
            Order.TYPE: "",
            Order.AVGPRICE: order["price"],
            Order.PRICE: order["price"],
            Order.TRIGGERPRICE: order["triggerPrice"],
            Order.QUANTITY: order["orderQuantity"],
            Order.FILLEDQTY: order["filledQuantity"],
            Order.REMAININGQTY: order["pendingQuantity"],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: cls.resp_status.get(order["statusInfo"], order["statusInfo"]),
            Order.REJECTREASON: "",
            Order.DISCLOSEDQUANTITY: order["disclosedQuantity"],
            Order.PRODUCT: cls.resp_product.get(order["product"], order["product"]),
            Order.EXCHANGE: order["exchange"],
            Order.SEGMENT: order["exchange"],
            Order.VALIDITY: "DAY",
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _tradebookhistory_json_parser(cls,
                                      order: dict
                                      ) -> dict[Any, Any]:
        """
        Parse Orderbook Order Json Response.

        Parameters:
            order (dict): Orderbook Order Json Response from Broker.

        Returns:
            dict: Unified kronos Order Response.
        """
        parsed_order = {
            Order.ID: order['exchOrderId'],
            Order.USERID: order['message'],
            Order.TIMESTAMP: cls.datetime_strp(order["activityTimestamp"], '%b %d %Y %I:%M:%S:%f%p'),
            Order.SYMBOL: "",
            Order.TOKEN: 0,
            Order.SIDE: "",
            Order.TYPE: "",
            Order.AVGPRICE: 0.0,
            Order.PRICE: order['price'],
            Order.TRIGGERPRICE: order['triggerPrice'],
            Order.QUANTITY: order['orderQuantity'],
            Order.FILLEDQTY: order['filledQuantity'],
            Order.REMAININGQTY: order['orderQuantity'] - order['filledQuantity'],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: cls.resp_status.get(order['status'], order['status']),
            Order.REJECTREASON: "",
            Order.DISCLOSEDQUANTITY: 0,
            Order.PRODUCT: "",
            Order.SEGMENT: "",
            Order.VALIDITY: cls.resp_validity.get(order['validity'], order['validity']),
            Order.VARIETY: "",
        }

        return parsed_order

    @classmethod
    def _create_order_parser(cls,
                             response: Response,
                             key_to_check: str,
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

        if 'fault' in info:
            detail = info['fault']

            order = {
                detail.ID: "0",
                Order.USERID: "0",
                Order.TIMESTAMP: cls.current_datetime(),
                Order.SYMBOL: "",
                Order.TOKEN: 0,
                Order.SIDE: "",
                Order.TYPE: "",
                Order.AVGPRICE: 0.0,
                Order.PRICE: 0.0,
                Order.TRIGGERPRICE: 0.0,
                Order.QUANTITY: 0,
                Order.FILLEDQTY: 0,
                Order.REMAININGQTY: 0,
                Order.CANCELLEDQTY: 0,
                Order.STATUS: Status.REJECTED,
                Order.REJECTREASON: detail['message'],
                Order.DISCLOSEDQUANTITY: 0,
                Order.PRODUCT: "",
                Order.SEGMENT: "",
                Order.VALIDITY: "",
                Order.VARIETY: ""
            }

            return order

        else:
            order_id = info['Success']['NSE']['orderId']
            data = cls.fetch_order(order_id=order_id, headers=headers)

            return data

            # if  "BSE"  not in info['Success']:

            #     order = info['Success']['NSE']

            #     data = {
            #         "id": order['orderId'],
            #         "userOrderId": order['tag'],
            #         "price": order['orderId'],
            #         "qauntity": order['quantity'],
            #         'message': order['message'],
            #         "info": info
            #             }

            #     return data

            # else:
            #     orderNSE = info['Success']['NSE']
            #     orderBSE = info['Success']['BSE']

            #     data = {
            #         "NSE": {
            #             "id": orderNSE['orderId'],
            #             "userOrderId": orderNSE['tag'],
            #             "price": orderNSE['orderId'],
            #             "qauntity": orderNSE['quantity'],
            #             "message": orderNSE['message']
            #             },
            #         "BSE": {
            #             "id": orderBSE['orderId'],
            #             "userOrderId": orderBSE['tag'],
            #             "price": orderBSE['orderId'],
            #             "qauntity": orderBSE['quantity'],
            #             "message": orderBSE['message']
            #             },
            #         "info": info
            #             }
            #     return data

        #
        # Sample Response
        #
        # {"Success":{
        #     "NSE":{
        #         "message":"Your Order has been Placed and Forwarded to the Exchange: 2230131034372.",
        #         "orderId":2230131034372,
        #         "price":0,
        #         "quantity":1,
        #         "tag":"HD"
        #         }
        #     }
        #  }
        #
        #


    # Order Functions


    def create_order(cls, token: int, side: str, price: float, triggerprice: float, uniqueid: int, quantity: int,
                     variety: str, product: str, validity: str, headers: dict, orderType: str = "", exchange: str = ""):

        """
        create a trade order

        :param int token: token of the script of the market to create an order in
        :param str side: 'BUY' or 'SELL'
        :param float price: price of the order
        :param float triggerprice: 0 for market order, non-zero for limit
        :param str uniqueid: a unique id to denote your order
        :param int quantity: quantity of shares
        :param str ordertype: Not Needed for this Exchange
        :param str exchange: Not Needed for this Exchange
        :param str product: 'NRML', 'SM', 'SOR', 'MTF', 'MIS'
        :param str validity: 'DAY' or 'IOC'
        :param str variety: "REGULAR" or "AMO"
        :returns json: a json response of order
        """

        json_data = {
            'instrumentToken': token,
            'transactionType': side,
            'quantity': quantity,
            'price': price,
            'validity': cls.key_mapper(cls.req_validity, validity, "validity"),
            'variety': cls.key_mapper(cls.req_variety, variety, "variety"),
            'disclosedQuantity': 0,
            'triggerPrice': triggerprice,
            'tag': uniqueid
        }

        url = cls.key_mapper(cls.place_order_urls, product, "product")

        response = cls.fetch(method="POST", url=url, data=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    def market_order(cls, token: int, side: str, uniqueid: int, quantity: int, headers: dict,
                     product: str = Product.MIS, validity: str = Validity.DAY, variety: str = Variety.REGULAR, exchange: str = ""):

        """
        create a market order
        :param int token: token of the script of the market to create an order in
        :param str side: 'BUY' or 'SELL'
        :param str uniqueid: a unique id to denote your order
        :param int quantity: quantity of shares
        :param str exchange: Not Needed for this Exchange
        :param str product: 'NRML', 'SM', 'SOR', 'MTF', 'MIS'
        :param str validity: 'DAY' or 'IOC'
        :param str variety: "REGULAR" or "AMO"
        :returns json: a json response of order
        """

        json_data = {
            'instrumentToken': token,
            'transactionType': side,
            'quantity': quantity,
            'price': 0,
            'validity': cls.key_mapper(cls.req_validity, validity, "validity"),
            'variety': cls.key_mapper(cls.req_variety, variety, "variety"),
            'disclosedQuantity': 0,
            'triggerPrice': 0,
            'tag': uniqueid
        }

        final_url = cls.key_mapper(cls.order_place_urls, product, "product")

        response = cls.fetch(method="POST", url=final_url, json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    def limit_order(cls, price: float, quantity: int,
                    token: int, side: str, uniqueid: int, headers: dict,
                    product: str = Product.MIS, validity: str = Validity.DAY, variety: str = Variety.REGULAR, exchange: str = ""):

        """
        create a market order
        :param int token: token of the script of the market to create an order in
        :param str side: 'BUY' or 'SELL'
        :param str uniqueid: a unique id to denote your order
        :param int quantity: quantity of shares
        :param str exchange: Not Needed for this Exchange
        :param str product: 'NRML', 'SM', 'SOR', 'MTF', 'MIS'
        :param str validity: 'DAY' or 'IOC'
        :param str variety: "REGULAR" or "AMO"
        :returns json: a json response of order
        """

        json_data = {
            'instrumentToken': token,
            'transactionType': side,
            'quantity': quantity,
            'price': price,
            'validity': cls.key_mapper(cls.req_validity, validity, "validity"),
            'variety': cls.key_mapper(cls.req_variety, variety, "variety"),
            'disclosedQuantity': 0,
            'triggerPrice': 0,
            'tag': uniqueid
        }

        final_url = cls.key_mapper(cls.order_place_urls, product, "product")

        response = cls.fetch(method="POST", url=final_url, json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    def sl_order(cls, price: float, triggerprice: float, quantity: int,
                 token: int, side: str, uniqueid: int, headers: dict,
                 product: str = Product.MIS, validity: str = Validity.DAY, variety: str = Variety.REGULAR, exchange: str = ""):

        """
        create a market order
        :param int token: token of the script of the market to create an order in
        :param str side: 'BUY' or 'SELL'
        :param str uniqueid: a unique id to denote your order
        :param int quantity: quantity of shares
        :param str exchange: Not Needed for this Exchange
        :param str product: 'NRML', 'SM', 'SOR', 'MTF', 'MIS'
        :param str validity: 'DAY' or 'IOC'
        :param str variety: "REGULAR" or "AMO"
        :returns json: a json response of order
        """

        json_data = {
            'instrumentToken': token,
            'transactionType': side,
            'quantity': quantity,
            'price': price,
            'validity': cls.key_mapper(cls.req_validity, validity, "validity"),
            'variety': cls.key_mapper(cls.req_variety, variety, "variety"),
            'disclosedQuantity': 0,
            'triggerPrice': triggerprice,
            'tag': uniqueid
        }

        final_url = cls.key_mapper(cls.order_place_urls, product, "product")

        response = cls.fetch(method="POST", url=final_url, json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)


    # NFO Order Functions


    @classmethod
    def market_order_nfo(cls, option: str, strikeprice: int,
                         side: str, quantity: int,
                         headers: dict,
                         root: str = Root.BNF,
                         expiry: str = WeeklyExpiry.CURRENT,
                         uniqueid: str = UniqueID.MARKETORDER,
                         product: str = Product.MIS, variety: str = "REGULAR",
                         validity: str = Validity.DAY):

        """
        create a market order
        :param str option: 'CE' or 'PE'
        :param str root: 'BANKNIFTY' or 'NIFTY'
        :param int strikeprice: Strike Price of the Option
        :param str side: 'BUY' or 'SELL'
        :param str expiry: 'CURRENT', 'NEXT', 'FAR'
        :param str uniqueid: a unique id to denote your order
        :param int quantity: quantity of shares
        :param str product: 'NRML', 'MIS', 'SM' (Super Multiple Order), 'SOR' (Smart Order Routing), 'MTF' (Margin Tading Facility)
        :param str validity: 'DAY' or 'IOC'
        :param str variety: "REGULAR" or "AMO"
        :returns json: a json response of order
        """

        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strikeprice, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strikeprice} Does not Exist")

        token = detail['Token']

        json_data = {
            'instrumentToken': token,
            'transactionType': side,
            'quantity': quantity,
            'price': 10,
            'validity': cls._key_mapper(cls.req_validity, validity, "validity"),
            'variety': cls._key_mapper(cls.req_variety, variety, "variety"),
            'disclosedQuantity': 0,
            'triggerPrice': 0,
            'tag': uniqueid
        }

        final_url = cls._key_mapper(cls.place_order_urls, product, "product")

        response = cls.fetch(method="POST", url=final_url, json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response, headers)

    def limit_order_nfo(cls, price: float, quantity: int,
                        option: str, root: str, strikeprice: int, side: str, headers: dict,
                        expiry: str = WeeklyExpiry.CURRENT, uniqueid: str = UniqueID.LIMITORDER,
                        product: str = Product.MIS, variety: str = "REGULAR", validity: str = Validity.DAY):

        """
        create a market order
        :param str option: 'CE' or 'PE'
        :param str root: 'BANKNIFTY' or 'NIFTY'
        :param int strikeprice: Strike Price of the Option
        :param str side: 'BUY' or 'SELL'
        :param str expiry: 'CURRENT', 'NEXT', 'FAR'
        :param str uniqueid: a unique id to denote your order
        :param int quantity: quantity of shares
        :param str product: 'NRML', 'MIS', 'SM' (Super Multiple Order), 'SOR' (Smart Order Routing), 'MTF' (Margin Tading Facility)
        :param str validity: 'DAY' or 'IOC'
        :param str variety: "REGULAR" or "AMO"
        :returns json: a json response of order
        """

        if not cls.Global:
            cls.expiry_markets()

        detail = cls.Global[expiry][root][option]
        detail = detail.get(strikeprice, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strikeprice} Does not Exist")

        token = detail['Token']

        json_data = {
            'instrumentToken': token,
            'transactionType': side,
            'quantity': quantity,
            'price': price,
            'validity': cls.key_mapper(cls.req_validity, validity, "validity"),
            'variety': cls.key_mapper(cls.req_variety, variety, "variety"),
            'disclosedQuantity': 0,
            'triggerPrice': 0.0,
            'tag': uniqueid
        }

        final_url = cls.key_mapper(cls.place_order_urls, product, "product")

        response = cls.fetch(method="POST", url=final_url, json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    def sl_order_nfo(cls, price: float, triggerprice: float,
                     option: str, root: str, strikeprice: int, side: str, quantity: int, headers: dict,
                     expiry: str = WeeklyExpiry.CURRENT, uniqueid: str = UniqueID.SLORDER,
                     product: str = Product.MIS, variety: str = "REGULAR", validity: str = Validity.DAY):

        """
        create a market order
        :param str option: 'CE' or 'PE'
        :param str root: 'BANKNIFTY' or 'NIFTY'
        :param int strikeprice: Strike Price of the Option
        :param str side: 'BUY' or 'SELL'
        :param str expiry: 'CURRENT', 'NEXT', 'FAR'
        :param str uniqueid: a unique id to denote your order
        :param int quantity: quantity of shares
        :param str product: 'NRML', 'MIS', 'SM' (Super Multiple Order), 'SOR' (Smart Order Routing), 'MTF' (Margin Tading Facility)
        :param str validity: 'DAY' or 'IOC'
        :param str variety: "REGULAR" or "AMO"
        :returns json: a json response of order
        """

        if not cls.Global:
            cls.expiry_markets()

        detail = cls.Global[expiry][root][option]
        detail = detail.get(strikeprice, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strikeprice} Does not Exist")

        token = detail['Token']

        json_data = {
            'instrumentToken': token,
            'transactionType': side,
            'quantity': quantity,
            'price': price,
            'validity': cls.key_mapper(cls.req_validity, validity, "validity"),
            'variety': cls.key_mapper(cls.req_variety, variety, "variety"),
            'disclosedQuantity': 0,
            'triggerPrice': triggerprice,
            'tag': uniqueid
        }

        final_url = cls.key_mapper(cls.place_order_urls, product, "product")

        response = cls.fetch(method="POST", url=final_url, json=json_data, headers=headers["headers"])

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
        response = cls.fetch(method="GET", url=cls.fetch_order_url, headers=headers["headers"])
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
        for order in info['success']:
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
        response = cls.fetch(method="GET", url=cls.fetch_trade_book_url, headers=headers["headers"])
        info = cls._json_parser(response)

        orders = []
        for order in info['success']:
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
        order_id = str(order_id)
        info = cls.fetch_raw_orderbook(headers=headers)

        for order in info['success']:
            if order["orderId"] == order_id:
                detail = cls._orderbook_json_parser(order)
                return detail

        raise InputError({"This orderid does not exist."})

    @classmethod
    def fetch_tradebook_order(cls,
                              order_id: str,
                              headers: dict
                              ) -> dict[Any, Any]:
        """
        Fetch  TradeBook Order Details.

        Paramters:
            order_id (str): id of the order.

        Raises:
            InputError: If order does not exist.

        Returns:
            dict: kronos Unified Order Response.
        """
        final_url = f"{cls.fetch_trade_book_url}/{order_id}"

        response = cls.fetch(method="GET", url=final_url, headers=headers["headers"])
        info = cls._json_parser(response)

        detail = info['success'][-1]
        order = cls._tradebookhistory_json_parser(detail)

        return order


    # Order Modification & Sq Off


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
        final_url = f"{cls.order_cancel_url}/{order_id}"

        response = cls.fetch(method="DELETE", url=final_url, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)
