from __future__ import annotations
from typing import TYPE_CHECKING
from typing import Any

import io

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


class iifl(Exchange):
    """
    IIFL kronos Broker Class

    Returns:
        kronos.iifl: kronos IIFL Broker Object
    """


    nfo_tokens = {}
    id = 'iifl'
    _session = Exchange._create_session()


    # Base URLs

    base_urls = {
        "api_documentation_link": "https://ttblaze.iifl.com/doc/interactive/",
        "api_marketdata_docuemtnation_link": "https://ttblaze.iifl.com/doc/marketdata",
        "base_url": "https://ttblaze.iifl.com/interactive",
        "access_token_url": "https://ttblaze.iifl.com/interactive/user/session",
        "market_data_url": "https://ttblaze.iifl.com/apimarketdata/instruments/master",
        "index_data_url": "https://ttblaze.iifl.com/apimarketdata/instruments/indexlist"
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base_url']}/orders",
        "modify_order": f"{base_urls['base_url']}/orders",
        "cancel_order": f"{base_urls['base_url']}/orders",
        "orderbook": f"{base_urls['base_url']}/orders",
        "tradebook": f"{base_urls['base_url']}/orders/trades",
        "positions": f"{base_urls['base_url']}/portfolio/positions",
        "holdings": f"{base_urls['base_url']}/portfolio/holdings",
        "rms_limits": f"{base_urls['base_url']}/user/balance",
        "profile": f"{base_urls['base_url']}/user/profile",
    }


    # Request Parameters Dictionaries

    req_exchange = {
        ExchangeCode.NSE: "NSECM",
        ExchangeCode.BSE: "BSECM",
        ExchangeCode.NFO: "NSEFO",
        ExchangeCode.BFO: "BSEFO",
        ExchangeCode.MCX: "MSECM",
        ExchangeCode.NCO: "NSECO",
        ExchangeCode.BCO: "BSECO",
    }

    req_side = {
        Side.BUY: "BUY",
        Side.SELL: "SELL",
    }

    req_product = {
        Product.MIS: "MIS",
        Product.NRML: "NRML",
        Product.CNC: "CNC",
        Product.CO: "CO",
    }

    req_order_type = {
        OrderType.MARKET: "Market",
        OrderType.LIMIT: "Limit",
        OrderType.SL: "StopLimit",
        OrderType.SLM: "StopMarket",
    }


    req_validity = {
        Validity.DAY: "DAY",
        Validity.IOC: "IOC"
    }


    # Response Parameters Dictionaries

    resp_status = {
        "PendingNew": Status.PENDING,
        "PendingReplace": Status.PENDING,
        "Rejected": Status.REJECTED,
        "PartiallyFilled": Status.PARTIALLYFILLED,
        "Filled": Status.FILLED,
        "Cancelled": Status.CANCELLED,
        "Open": Status.OPEN,
        "New": Status.OPEN,
        "Replaced": Status.MODIFIED,
    }

    resp_order_type = {
        "Market": OrderType.MARKET,
        "Limit": OrderType.LIMIT,
        "StopLimit": OrderType.SL,
        "StopMarket": OrderType.SLM,
    }

    resp_exchange = {
        "NSECM": ExchangeCode.NSE,
        "BSECM": ExchangeCode.BSE,
        "NSEFO": ExchangeCode.NFO,
        "BSEFO": ExchangeCode.BFO,
        "MSECM": ExchangeCode.MCX,
        "NSECO": ExchangeCode.NCO,
        "BSECO": ExchangeCode.BCO,
    }


    # NFO Script Fetch


    @classmethod
    def create_indices(cls) -> dict:
        """
        Gives NFO Indices Info for F&O Segment.

        Returns:
            dict: Unified kronos create_nfo_tokens format
        """

        params = {"exchangeSegment": 1}
        response = cls.fetch(method="GET", url=cls.base_urls["index_data_url"], params=params)
        df = cls._json_parser(response)['result']['indexList']

        indices = {}

        for i in df:
            symbol, token = i.split("_")
            indices[symbol] = {"Symbol": symbol, "Token": int(token)}

        indices[Root.BNF] = indices["NIFTY BANK"]
        indices[Root.NF] = indices["NIFTY 50"]
        indices[Root.FNF] = indices["NIFTY FIN SERVICE"]
        indices[Root.MIDCPNF] = indices["NIFTY MIDCAP 50"]

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

            json_data = {"exchangeSegmentList": ["NSEFO"]}
            headers = {"Content-Type": "application/json", "Accept": "application/json"}

            req_data = cls.fetch(method="POST", url=cls.base_urls["market_data_url"], json=json_data, headers=headers)
            csv_bytes = cls._json_parser(req_data)['result']
            str_file = io.StringIO(csv_bytes, newline="\n")

            col_names = ["ExchangeSegment", "ExchangeInstrumentID", "InstrumentType", "Name",
                         "Description", "Series", "NameWithSeries", "InstrumentID", "PriceBand.High", "PriceBand.Low",
                         "FreezeQty", "TickSize", "LotSize", "Multiplier", "UnderlyingInstrumentId", "UnderlyingIndexName",
                         "ContractExpiration", "StrikePrice", "OptionType", "AA", "AWS", "AAQ", "Symbol"]
            df = cls.data_reader(link=str_file, filetype="csv",
                                 sep="|", col_names=col_names)

            df = df[((df['Name'] == "BANKNIFTY") | (df['Name'] == "NIFTY") | (df['Name'] == "FINNIFTY")) & ((df['Series'] == "OPTIDX"))]

            df.rename({"ExchangeInstrumentID": "Token", "Name": "Root",
                       "ContractExpiration": "Expiry", "OptionType": "Option"},
                      axis=1, inplace=True)

            df['Option'] = df['Symbol'].str.extract(r"(CE|PE)")
            df['Token'] = df['Token'].astype(int)
            df['StrikePrice'] = df['StrikePrice'].astype(int)
            df['Expiry'] = cls.pd_datetime(df['Expiry']).dt.date.astype(str)

            df = df[['Token', 'Symbol', 'Expiry', 'Option',
                     'StrikePrice', 'LotSize',
                     'Root', 'TickSize'
                     ]]

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
        Generate Headers used to access Endpoints in IIFL.

        Parameters:
            params (dict) : A dictionary which should consist the following keys:
                api_key (str): API Key of the Account.
                api_secret (str): API Secret of the Account.

        Returns:
            dict[str, str]: IIFL Headers.
        """

        for key in ["api_key", "api_secret"]:
            if key not in params:
                raise KeyError(f"Please provide {key}")

        json_data = {
            "secretKey": params["api_secret"],
            "appKey": params["api_key"],
            "source": "WebAPI"
        }

        response = cls.fetch(method="POST", url=cls.base_urls["access_token_url"], json=json_data)
        response = cls._json_parser(response)


        headers = {
            "headers":
                {
                    "Content-type": "application/json",
                    "authorization": response["result"]["token"]
                },
            "user_id": response["result"]["userID"]
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
        # print(json_response)

        if json_response['type'] == "success":
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
        order_status = cls.resp_status.get(order["OrderStatus"], order["OrderStatus"])
        parsed_order = {
            Order.ID: str(order["AppOrderID"]),
            Order.USERID: order["OrderUniqueIdentifier"],
            Order.TIMESTAMP: cls.datetime_strp(order["LastUpdateDateTime"], "%d-%m-%Y %H:%M:%S"),
            Order.SYMBOL: order["TradingSymbol"],
            Order.TOKEN: order["ExchangeInstrumentID"],
            Order.SIDE: cls.req_side.get(order["OrderSide"], order["OrderSide"]),
            Order.TYPE: cls.resp_order_type.get(order["OrderType"], order["OrderType"]),
            Order.AVGPRICE: float(order["OrderAverageTradedPrice"] or 0.0),
            Order.PRICE: order["OrderPrice"],
            Order.TRIGGERPRICE: order["OrderStopPrice"],
            Order.TARGETPRICE: 0.0,
            Order.STOPLOSSPRICE: 0.0,
            Order.TRAILINGSTOPLOSS: 0.0,
            Order.QUANTITY: order["OrderQuantity"],
            Order.FILLEDQTY: order["LeavesQuantity"],
            Order.REMAININGQTY: order["OrderQuantity"] - order["LeavesQuantity"],
            Order.CANCELLEDQTY: order["LeavesQuantity"] if order_status == Status.CANCELLED else 0,
            Order.STATUS: order_status,
            Order.REJECTREASON: order["CancelRejectReason"],
            Order.DISCLOSEDQUANTITY: order["OrderDisclosedQuantity"],
            Order.PRODUCT: cls.req_product.get(order["ProductType"], order["ProductType"]),
            Order.EXCHANGE: cls.req_exchange.get(order["ExchangeSegment"], order["ExchangeSegment"]),
            Order.SEGMENT: cls.req_exchange.get(order["ExchangeSegment"], order["ExchangeSegment"]),
            Order.VALIDITY: cls.req_validity.get(order["TimeInForce"], order["TimeInForce"]),
            Order.VARIETY: "",
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
        order_status = cls.resp_status.get(order["OrderStatus"], order["OrderStatus"])
        parsed_order = {
            Order.ID: str(order["AppOrderID"]),
            Order.USERID: order["OrderUniqueIdentifier"],
            Order.TIMESTAMP: cls.datetime_strp(order["LastUpdateDateTime"], "%d-%m-%Y %H:%M:%S"),
            Order.SYMBOL: order["TradingSymbol"],
            Order.TOKEN: order["ExchangeInstrumentID"],
            Order.SIDE: cls.req_side.get(order["OrderSide"], order["OrderSide"]),
            Order.TYPE: cls.resp_order_type.get(order["OrderType"], order["OrderType"]),
            Order.AVGPRICE: float(order["OrderAverageTradedPrice"] or 0.0),
            Order.PRICE: order["OrderPrice"],
            Order.TRIGGERPRICE: order["OrderStopPrice"],
            Order.TARGETPRICE: 0.0,
            Order.STOPLOSSPRICE: 0.0,
            Order.TRAILINGSTOPLOSS: 0.0,
            Order.QUANTITY: order["OrderQuantity"],
            Order.FILLEDQTY: order["LeavesQuantity"],
            Order.REMAININGQTY: order["OrderQuantity"] - order["LeavesQuantity"],
            Order.CANCELLEDQTY: order["LeavesQuantity"] if order_status == Status.CANCELLED else 0,
            Order.STATUS: order_status,
            Order.REJECTREASON: order["CancelRejectReason"],
            Order.DISCLOSEDQUANTITY: order["OrderDisclosedQuantity"],
            Order.PRODUCT: cls.req_product.get(order["ProductType"], order["ProductType"]),
            Order.EXCHANGE: cls.req_exchange.get(order["ExchangeSegment"], order["ExchangeSegment"]),
            Order.SEGMENT: cls.req_exchange.get(order["ExchangeSegment"], order["ExchangeSegment"]),
            Order.VALIDITY: cls.req_validity.get(order["TimeInForce"], order["TimeInForce"]),
            Order.VARIETY: "",
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
        exchanges = profile['ClientExchangeDetailsList']
        exchanges_enabled = [cls.resp_exchange.get(i, i) for i in exchanges if exchanges[i]['Enabled']]
        parsed_profile = {
            Profile.CLIENTID: profile['ClientId'],
            Profile.NAME: profile['ClientName'],
            Profile.EMAILID: profile['EmailId'],
            Profile.MOBILENO: profile['MobileNo'],
            Profile.PAN: profile["PAN"],
            Profile.ADDRESS: "",
            Profile.BANKNAME: "",
            Profile.BANKBRANCHNAME: None,
            Profile.BANKACCNO: "",
            Profile.EXHCNAGESENABLED: exchanges_enabled,
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
        Parse Json Response Obtained from Broker After Placing Order to get Orderid
        and fetching the json repsone for the said order_id

        Parameters:
            response (Response): Json Repsonse Obtained from broker after Placing an Order

        Returns:
            dict: Unified kronos Order Response
        """

        info = cls._json_parser(response)

        order_id = info["result"]["AppOrderID"]
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
                "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "limitPrice": price,
                "stopPrice": trigger,
                "orderQuantity": quantity,
                "orderSide": cls._key_mapper(cls.req_side, side, 'side'),
                "orderType": cls.req_order_type[order_type],
                "productType": cls._key_mapper(cls.req_product, product, 'product'),
                "timeInForce": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "orderUniqueIdentifier": unique_id,
                "disclosedQuantity": 0,
            }



        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")


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
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "limitPrice": "0",
            "stopPrice": "0",
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, 'side'),
            "orderType": cls.req_order_type[OrderType.MARKET],
            "productType": cls._key_mapper(cls.req_product, product, 'product'),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, 'validity'),
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
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "limitPrice": price,
            "stopPrice": "0",
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, 'side'),
            "orderType": cls.req_order_type[OrderType.LIMIT],
            "productType": cls._key_mapper(cls.req_product, product, 'product'),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, 'validity'),
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
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "limitPrice": price,
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, 'side'),
            "orderType": cls.req_order_type[OrderType.SL],
            "productType": cls._key_mapper(cls.req_product, product, 'product'),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, 'validity'),
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
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "limitPrice": "0",
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, 'side'),
            "orderType": cls.req_order_type[OrderType.SLM],
            "productType": cls._key_mapper(cls.req_product, product, 'product'),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, 'validity'),
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
            dict: Kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

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
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "limitPrice": price,
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, 'side'),
            "orderType": cls.req_order_type[order_type],
            "productType": cls._key_mapper(cls.req_product, product, 'product'),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, 'validity'),
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
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "limitPrice": "0",
            "stopPrice": "0",
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, 'side'),
            "orderType": cls.req_order_type[OrderType.MARKET],
            "productType": cls._key_mapper(cls.req_product, product, 'product'),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, 'validity'),
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
            exchange (str, optional): Exchange to place the order in. Defaults to ExchangeCode.NFO.
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

        token = detail['Token']

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "limitPrice": price,
            "stopPrice": "0",
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, 'side'),
            "orderType": cls.req_order_type[OrderType.LIMIT],
            "productType": cls._key_mapper(cls.req_product, product, 'product'),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, 'validity'),
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
            dict: Kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "limitPrice": price,
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, 'side'),
            "orderType": cls.req_order_type[OrderType.SL],
            "productType": cls._key_mapper(cls.req_product, product, 'product'),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, 'validity'),
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
            dict: Kronos Unified Order Response
        """

        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "limitPrice": "0",
            "stopPrice": trigger,
            "orderQuantity": quantity,
            "orderSide": cls._key_mapper(cls.req_side, side, 'side'),
            "orderType": cls.req_order_type[OrderType.SLM],
            "productType": cls._key_mapper(cls.req_product, product, 'product'),
            "timeInForce": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "orderUniqueIdentifier": unique_id,
            "disclosedQuantity": 0,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)



    # BO Order Functions
    # NO BO Orders For IIFL


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
        response = cls.fetch(method="GET", url=cls.urls['orderbook'],
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
        params = {"appOrderID": order_id}
        response = cls.fetch(method="GET", url=cls.urls['orderbook'],
                             params=params, headers=headers["headers"])

        info = cls._json_parser(response)

        order = info["result"][-1]
        order = cls._orderbook_json_parser(order)
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
        response = cls.fetch(method="GET", url=cls.urls['orderbook'], headers=headers["headers"])
        info = cls._json_parser(response)

        orders = []
        if info["result"]:
            for order in info["result"]:
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
        response = cls.fetch(method="GET", url=cls.urls['orderbook'], headers=headers["headers"])
        info = cls._json_parser(response)

        orders = []
        if info["result"]:
            for order in info["result"]:
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
        if info["result"]:
            for order in info["result"]:
                detail = cls._tradebook_json_parser(order)
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
            "modifiedProductType": cls.req_product[curr_order[Order.PRODUCT]],
            "modifiedOrderType": cls._key_mapper(cls.req_order_type, order_type, 'order_type') or cls.req_order_type[curr_order[Order.TYPE]],
            "modifiedOrderQuantity": quantity or curr_order[Order.QUANTITY],
            "modifiedDisclosedQuantity": curr_order[Order.DISCLOSEDQUANTITY],
            "modifiedLimitPrice": price or curr_order[Order.PRICE],
            "modifiedStopPrice": trigger or curr_order[Order.TRIGGERPRICE],
            "modifiedTimeInForce": cls._key_mapper(cls.req_validity, validity, 'validity') or cls.req[curr_order[Order.VALIDITY]],
            "orderUniqueIdentifier": curr_order[Order.USERID]
        }

        params = {"clientID": headers["user_id"]}

        response = cls.fetch(method="PUT", url=cls.urls["modify_order"],
                             params=params, json=json_data,
                             headers=headers["headers"])

        info = cls._json_parser(response)
        # return cls.fetch_order(order_id=info["result"]["AppOrderID"], headers=headers)

        return info


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

        info = cls._json_parser(response)
        # return cls.fetch_order(order_id=info["result"]["AppOrderID"], headers=headers)

        return info


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
        profile = cls._profile_json_parser(info['result'])

        return profile
