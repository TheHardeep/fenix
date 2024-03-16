from __future__ import annotations
from typing import TYPE_CHECKING
from typing import Any

import io

from fenix.base.exchange import Exchange

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
from fenix.base.errors import ResponseError
from fenix.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response


class iifl(Exchange):
    """
    IIFL fenix Broker Class

    Returns:
        fenix.iifl: fenix IIFL Broker Object
    """


    indices = {}
    nfo_tokens = {}
    eq_tokens = {}
    token_params = ["api_key", "api_secret"]
    id = 'iifl'
    _session = Exchange._create_session()


    # Base URLs

    base_urls = {
        "api_doc": "https://ttblaze.iifl.com/doc/interactive/",
        "marketdata_doc": "https://ttblaze.iifl.com/doc/marketdata",
        "base": "https://ttblaze.iifl.com/interactive",
        "access_token": "https://ttblaze.iifl.com/interactive/user/session",
        "index_data": "https://ttblaze.iifl.com/apimarketdata/instruments/indexlist",
        "market_data": "https://ttblaze.iifl.com/apimarketdata/instruments/master",
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base']}/orders",
        "modify_order": f"{base_urls['base']}/orders",
        "cancel_order": f"{base_urls['base']}/orders",
        "orderbook": f"{base_urls['base']}/orders",
        "tradebook": f"{base_urls['base']}/orders/trades",
        "positions": f"{base_urls['base']}/portfolio/positions",
        "holdings": f"{base_urls['base']}/portfolio/holdings",
        "rms_limits": f"{base_urls['base']}/user/balance",
        "profile": f"{base_urls['base']}/user/profile",
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
    def create_eq_tokens(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the aliceblue.indices Dictionary.

        Returns:
            dict: Unified fenix indices format.
        """
        json_data = {"exchangeSegmentList": ["BSECM", "NSECM"]}
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        req_data = cls.fetch(method="POST", url=cls.base_urls["market_data"], json=json_data, headers=headers)
        csv_bytes = cls._json_parser(req_data)['result']
        str_file = io.StringIO(csv_bytes, newline="\n")

        col_names = ["ExchangeSegment", "ExchangeInstrumentID", "InstrumentType", "Name",
                     "Description", "Series", "NameWithSeries", "InstrumentID", "PriceBand.High", "PriceBand.Low",
                     "FreezeQty", "TickSize", "LotSize", "Multiplier", "UnderlyingInstrumentId", "UnderlyingIndexName",
                     "ContractExpiration", "StrikePrice", "OptionType", "AA", "AWS", "AAQ", "Symbol"]

        df = cls.data_reader(link=str_file, filetype="csv", sep="|", col_names=col_names)

        df.rename({"ExchangeInstrumentID": "Token", "ExchangeSegment": "Exchange",
                   "Name": "Index", "Symbol": "XXZ",
                   "Description": "Symbol"}, axis=1, inplace=True)


        df_bse = df[(df["Exchange"] == "BSECM")]
        df_bse = df_bse[["Token", "Index", "Symbol", "LotSize", "TickSize", "Exchange"]]
        # df_bse["Exchange"] = ExchangeCode.BSE
        df_bse.drop_duplicates(subset=['Symbol'], keep='first', inplace=True)
        df_bse.set_index(df_bse['Index'], inplace=True)
        df_bse.drop(columns="Index", inplace=True)


        df_nse = df[(df["Exchange"] == "NSECM") & (df['Series'] == 'EQ')]
        df_nse = df_nse[["Token", "Index", "Symbol", "LotSize", "TickSize", "Exchange"]]
        # df_nse["Exchange"] = ExchangeCode.NSE
        df_nse.drop_duplicates(subset=['Symbol'], keep='first', inplace=True)
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
            dict: Unified fenix indices format.
        """
        params = {"exchangeSegment": 1}
        response = cls.fetch(method="GET", url=cls.base_urls["index_data"], params=params)
        df = cls._json_parser(response)['result']['indexList']

        indices = {}

        for i in df:
            symbol, token = i.split("_")
            indices[symbol] = {"Symbol": symbol, "Token": int(token)}

        indices[Root.BNF] = indices["NIFTY BANK"]
        indices[Root.NF] = indices["NIFTY 50"]
        indices[Root.FNF] = indices["NIFTY FIN SERVICE"]
        indices[Root.MIDCPNF] = indices["NIFTY MIDCAP SELECT"]

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

            json_data = {"exchangeSegmentList": ["NSEFO"]}
            headers = {"Content-Type": "application/json", "Accept": "application/json"}

            req_data = cls.fetch(method="POST", url=cls.base_urls["market_data"], json=json_data, headers=headers)
            csv_bytes = cls._json_parser(req_data)['result']
            str_file = io.StringIO(csv_bytes, newline="\n")

            col_names = ["ExchangeSegment", "ExchangeInstrumentID", "InstrumentType", "Name",
                         "Description", "Series", "NameWithSeries", "InstrumentID", "PriceBand.High", "PriceBand.Low",
                         "FreezeQty", "TickSize", "LotSize", "Multiplier", "UnderlyingInstrumentId", "UnderlyingIndexName",
                         "ContractExpiration", "StrikePrice", "OptionType", "AA", "AWS", "AAQ", "Symbol"]
            df = cls.data_reader(link=str_file, filetype="csv",
                                 sep="|", col_names=col_names)

            df = df[
                (
                    (df['Name'] == "BANKNIFTY") |
                    (df['Name'] == "NIFTY") |
                    (df['Name'] == "FINNIFTY") |
                    (df['Name'] == "MIDCPNIFTY")
                ) &
                (
                    (df['Series'] == "OPTIDX")
                )]

            df.rename({"ExchangeInstrumentID": "Token", "Name": "Root",
                       "ContractExpiration": "Expiry", "OptionType": "Option",
                       "ExchangeSegment": "Exchange"},
                      axis=1, inplace=True)

            df['Option'] = df['Symbol'].str.extract(r"(CE|PE)")
            df['Token'] = df['Token'].astype(int)
            df['StrikePrice'] = df['StrikePrice'].astype(int)
            df['Expiry'] = cls.pd_datetime(df['Expiry']).dt.date.astype(str)

            df = df[['Token', 'Symbol', 'Expiry', 'Option',
                     'StrikePrice', 'LotSize',
                     'Root', 'TickSize', "Exchange"
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

        for key in cls.token_params:
            if key not in params:
                raise KeyError(f"Please provide {key}")

        json_data = {
            "secretKey": params["api_secret"],
            "appKey": params["api_key"],
            "source": "WebAPI"
        }

        response = cls.fetch(method="POST", url=cls.base_urls["access_token"], json=json_data)
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
        Parse Orderbook Order Json Response.

        Parameters:
            order (dict): Orderbook Order Json Response from Broker.
fenix
        Returns:
            dict: Unified kronos Order Response.
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
        Fetch Tradebook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.
fenix
        Returns:
            list[dict]: List of dicitonaries of orders using kronos Unified Order Response.
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
    def _position_json_parser(cls,
                              position: dict,
                              ) -> dict[Any, Any]:
        """
        Parse Acoount Position Json Response.

        Parameters:
            order (dict): Acoount Position Json Response from Broker.
fenix
        Returns:
            dict: Unified Kronos Position Response.
        """
        avg_price = ((int(position["OpenBuyQuantity"]) * float(position["BuyAveragePrice"])) +
                     (int(position["OpenSellQuantity"]) * float(position["SellAveragePrice"]))
                     ) / (int(position["OpenBuyQuantity"]) + int(position["OpenSellQuantity"]))

        parsed_position = {
            Position.SYMBOL: position["TradingSymbol"],
            Position.TOKEN: position["TokenID"],
            Position.NETQTY: int(position["Quantity"]),
            Position.AVGPRICE: avg_price,
            Position.MTM: float(position["MTM"]),
            Position.PNL: float(position["RealizedMTM"]),
            Position.BUYQTY: int(position["OpenBuyQuantity"]),
            Position.BUYPRICE: float(position["BuyAveragePrice"]),
            Position.SELLQTY: int(position["OpenSellQuantity"]),
            Position.SELLPRICE: float(position["SellAveragePrice"]),
            Position.LTP: None,
            Position.PRODUCT: cls.req_product.get(position["ProductType"], position["ProductType"]),
            Position.EXCHANGE: cls.req_exchange.get(position["ExchangeSegment"], position["ExchangeSegment"]),
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
            profile (dict): User Profile Json Response from Broker.
fenix
        Returns:
            dict: Unified kronos Profile Response.
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
        Parse Json Response Obtained from Broker After Placing Order to get order_id
        and fetching the json repsone for the said order_id.

        Parameters:
            response (Response): Json Repsonse Obtained from broker after Placing an Order.
            headers (dict): headers to send order request with.
fenix
        Returns:
            dict: Unified kronos Order Response.
        """
        info = cls._json_parser(response)

        order_id = info["result"]["AppOrderID"]
        order = cls.fetch_order(order_id=order_id, headers=headers)

        return order


    # Order Functions


    @classmethod
    def create_eq_nfo_order(cls,
                            quantity: int,
                            side: str,
                            headers: dict,
                            token_dict: dict,
                            price: float = 0.0,
                            trigger: float = 0.0,
                            product: str = Product.MIS,
                            validity: str = Validity.DAY,
                            variety: str = Variety.REGULAR,
                            unique_id: str = UniqueID.DEFORDER
                            ) -> dict[Any, Any]:
        """
        Place an Order in F&O and Equity Segment.

        Parameters:
            quantity (int): Order quantity.
            side (str): Order Side: "BUY", "SELL".
            headers (dict): headers to send order request with.
            token_dict (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or nfo_tokens.
            price (float): price of the order. Defaults to 0.0.
            trigger (float): trigger price of the order. Defaults to 0.0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.DEFORDER.

        Returns:
            dict: Kronos Unified Order Response.
        """
        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:fenix
            order_type = OrderType.SL

        token = token_dict["Token"]
        exchange = token_dict["Exchange"]
        symbol = token_dict["Symbol"]

        json_data = {
            "exchangeInstrumentID": token,
            "exchangeSegment":  exchange,
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
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_fenix OrderType.MARKET
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
            varietfenix, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
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

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

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

        Returns:fenix
            dict: kronos Unified Order Response.
        """
        if not target:
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

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

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
            varietfenix, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
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

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

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
        """fenix
        if not target:
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

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

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
                        price: float = 0,
                        trigger: float = 0,
                        target: float = 0,
                        stoploss: float = 0,
                        trailing_sl: float = 0,
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

        if not price and trigger:
            order_fenix OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL


        if not target:
            json_data = {
                "exchangeInstrumentID": token,
                "exchangeSegment": exchange,
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
        if not clsfenixkens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not target:
            json_data = {
                "exchangeInstrumentID": token,
                "exchangeSegment": exchange,
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

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

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
fenix
        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not target:
            json_data = {
                "exchangeInstrumentID": token,
                "exchangeSegment": exchange,
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

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

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
        if not clsfenixkens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not target:
            json_data = {
                "exchangeInstrumentID": token,
                "exchangeSegment": exchange,
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

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

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

        if not target:
            json_data = {
                "efenixeInstrumentID": token,
                "exchangeSegment": exchange,
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

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

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
fenix
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

        detail = cfenix_tokens[expiry][root][option]
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
fenix
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

        detail = cfenix_tokens[expiry][root][option]
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
            "disclosedQuantity": 0,fenix
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)


    # BO Order Functions

    # NO BO Orders For IIFL


    # Order Details, OrderBook & TradeBook


    @classmethod
    def fetch_raw_orderbook(cls,
                            headers: dict
                            ) -> list[dict]:
        """
        Fetch Raw Orderbook Details, without any Standardaization.
fenix
        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: Raw Broker Orderbook Response.
        """
        response = cls.fetch(method="GET", url=cls.urls['orderbook'], headers=headers["headers"])
        return cls._json_parser(response)

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
        params = {"appOrderID": order_id}
        response = cls.fetch(method="GET", url=cls.urls['orderbook'],
                             params=params, headers=headers["headers"])

        return clsfenix_parser(response)

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
        if info["result"]:
            for orfenix info["result"]:
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
fenix
        orders = []
        if info["result"]:
            for order in info["result"]:
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
            order_fenixr): id of the order.

        Raises:
            InputError: If order does not exist.

        Returns:
            dict: kronos Unified Order Response.
        """
        info = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)

        order = info["result"][-1]
        order = cls._orderbook_json_parser(order)
        return order

    @classmethod
    def fetch_orderhistory(cls,
                           order_id: str,
                           headers: dict
                           ) -> list[dict]:
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
        for order in info["result"]:
            history = cls._orderbook_json_parser(order)
            order_history.append(history)

        return order_history

fenix
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
            order_type (str | None, optional): Type of Order. defaults to None
            validity (str | fenixoptional): Order validity Defaults to None.

        Returns:
            dict: kronos Unified Order Response.
        """
        info = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)
        order_info = info["result"][-1]

        json_data = {
            "appOrderID": order_id,
            "modifiedLimitPrice": price or order_info["OrderPrice"],
            "modifiedStopPrice": trigger or order_info["OrderStopPrice"],
            "modifiedOrderQuantity": quantity or order_info["OrderType"],
            "modifiedOrderType": cls._key_mapper(cls.req_order_type, order_type, 'order_type') if order_type else order_info["OrderType"],
            "modifiedProductType": order_info["ProductType"],
            "modifiedTimeInForce": cls.req_validity.get(validity, order_info["TimeInForce"]) if validity else order_info["TimeInForce"],
            "orderUniqueIdentifier": order_info["OrderUniqueIdentifier"],
            "modifiedDisclosedQuantity": order_info["OrderDisclosedQuantity"],
        }

        params = {"clientID": headers["user_id"]}

        response = cls.fetch(method="PUT", url=cls.urls["modify_order"],
                             params=params, json=json_data,
                             headers=headers["headers"])

        return cls._create_ofenixarser(response=response, headers=headers)

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
        params = {"appOrderID": order_id}
        response = cls.fetch(method="DELETE", url=cls.urls["cancel_order"],
                             params=params, headers=headers["headers"])
        info = cls._json_parser(response)

        return cls.fetch_order(order_id=info["result"][0]["AppOrderID"], headers=headers)


    # Account Limits & Profile
fenix

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
        params = {"dayOrNet": "DayWise"}
        response = cls.fetch(method="GET", url=cls.urls['positions'],
                             params=params, headers=headers["headers"])
        info = cls._json_parfenixsponse)

        positions = []
        if info["result"]:
            for position in info["result"]["positionList"]:
                detail = cls._position_json_parser(position)
                positions.append(detail)

        return positions

    @classmethod
    def fetch_net_positions(cls,
                            headers: dict,
                            ) -> dict[Any, Any]:
        """
        Fetch Total Account Positions.

        Args:
            headerfenixt): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Position Response.
        """
        params = {"dayOrNet": "NetWise"}
        response = cls.fetch(method="GET", url=cls.urls['positions'],
                             params=params, headers=headers["headers"])
        info = cls._json_parser(response)

        positions = []
        if info["result"]:
            for position in info["result"]["positionList"]:
                detail = cls._position_json_parser(position)
                positions.append(detail)

        return positions

    @classmethodfenix
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
        day_positions = cls.fetch_day_positions(headers=headers)
        net_positions = cls.fetch_net_positions(headers=headers)

        return day_positions + net_positions

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
        params = {"clientID": headers["user_id"]}
        response = cls.fetch(method="GET", url=cls.urls['holdings'],
                             params=params, headers=headers["headers"])
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
            dict: Kronos Unified Profile Response.
        """
        params = {"clientID": headers["user_id"]}
        response = cls.fetch(method="GET", url=cls.urls["profile"],
                             params=params, headers=headers["headers"])

        info = cls._json_parser(response)
        profile = cls._profile_json_parser(info['result'])

        return profile
