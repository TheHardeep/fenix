from __future__ import annotations
from typing import TYPE_CHECKING
from typing import Any


from fenix.base.broker import Broker

from fenix.base.constants import Side
from fenix.base.constants import OrderType
from fenix.base.constants import ExchangeCode
from fenix.base.constants import Product
from fenix.base.constants import Validity
from fenix.base.constants import Variety
from fenix.base.constants import Status
from fenix.base.constants import Order
from fenix.base.constants import Profile
from fenix.base.constants import Position
from fenix.base.constants import Root
from fenix.base.constants import WeeklyExpiry
from fenix.base.constants import UniqueID


from fenix.base.errors import InputError
from fenix.base.errors import ResponseError
from fenix.base.errors import TokenDownloadError

import time
from datetime import datetime

if TYPE_CHECKING:
    from requests.models import Response



class paper(Broker):
    """
    Paper fenix Broker Class.

    Returns:
        fenix.paper: fenix Paper Broker Object.
    """


    # Market Data Dictonaries

    indices = {}
    eq_tokens = {}
    nfo_tokens = {}
    token_params = ["user_id", "password", "birth_year", "totpstr", "api_key"]
    orderbook = []
    positions = {}
    id = 'paper'
    _session = Broker._create_session()


    # Base URLs

    base_urls = {
        "market_data": "https://v2api.aliceblueonline.com/restpy/contract_master",
    }

    # Request Parameters Dictionaries

    req_exchange = {
        ExchangeCode.NSE: "NSE",
        ExchangeCode.NFO: "NFO",
        ExchangeCode.BSE: "BSE",
        ExchangeCode.BFO: "BFO",
        ExchangeCode.BCD: "BCD",
        ExchangeCode.MCX: "MCX",
        ExchangeCode.CDS: "CDS",
    }

    req_order_type = {
        OrderType.MARKET: "MKT",
        OrderType.LIMIT: "L",
        OrderType.SL: "SL",
        OrderType.SLM: "SL-M"
    }

    req_product = {
        Product.MIS: "MIS",
        Product.NRML: "NRML",
        Product.CNC: "CNC",
        Product.CO: "CO",
        Product.BO: "BO"
    }

    req_side = {
        Side.BUY: "BUY",
        Side.SELL: "SELL",
    }

    req_validity = {
        Validity.DAY: "DAY",
        Validity.IOC: "IOC",
    }

    req_variety = {
        Variety.REGULAR: "REGULAR",
        Variety.STOPLOSS: "REGULAR",
        Variety.BO: "BO",
        Variety.AMO: "AMO",
    }



    # response_dicts

    rms_limits_dict = {
        "symbol": "ALL",
        "cncMarginUsed": "0.00",
        "spanmargin": "0.00",
        "branchAdhoc": "0.000000",
        "adhocMargin": "0.00",
        "payoutamount": "0.00",
        "cdsSpreadBenefit": "0",
        "adhocscripmargin": "0.00",
        "exposuremargin": "0.00",
        "scripbasketmargin": "0.00",
        "credits": "0.00",
        "segment": "ALL",
        "net": "0.00",
        "turnover": "0.00",
        "grossexposurevalue": "0.00",
        "mfssAmountUsed": "0.00",
        "realizedMtomPrsnt": "0.00",
        "product": "ALL",
        "stat": "Ok",
        "cncSellCrditPrsnt": "0",
        "debits": "0.00",
        "varmargin": "0.00",
        "multiplier": "1.00",
        "elm": "0.00",
        "mfamount": "0.00",
        "cashmarginavailable": "0.00",
        "brokeragePrsnt": "0.00",
        "cncRealizedMtomPrsnt": "0",
        "notionalCash": "0.000000",
        "directcollateralvalue": "0.00",
        "cncBrokeragePrsnt": "0.00",
        "valueindelivery": "0",
        "nfoSpreadBenefit": "0",
        "losslimit": "0",
        "subtotal": "0.00",
        "rmsPayInAmnt": "0.00",
        "unrealizedMtomPrsnt": "0.00",
        "coverOrderMarginPrsnt": "0.00",
        "exchange": "ALL",
        "category": "ABFSFREEDOM",
        "collateralvalue": "0.00",
        "rmsIpoAmnt": "0",
        "cncUnrealizedMtomPrsnt": "0.00",
        "premiumPrsnt": "0.00"
    }

    profile_dict = {
        "accountStatus": "Activated",
        "dpType": "NA",
        "accountId": "796894",
        "sBrokerName": "PAPER",
        "product": ["CNC", "NRML", "MIS", "CO", "BO"],
        "accountName": "KRATOS",
        "cellAddr": "8750407885",
        "emailAddr": "GODOFWAR@GMAIL.COM",
        "exchEnabled": "bse_cm|bse_fo|bcs_fo|cde_fo|mcx_fo|nse_cm|nse_fo|"
    }


    # NFO Script Fetch


    @classmethod
    def create_eq_tokens(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the paper.indices Dictionary.

        Returns:
            dict: Unified fenix indices format.
        """
        req_bse = cls.fetch(method="GET", url=cls.base_urls["market_data"], params={'exch': ExchangeCode.BSE})
        resp_bse = cls._json_parser(req_bse)

        df_bse = cls.data_frame(resp_bse[ExchangeCode.BSE])

        df_bse = df_bse[(df_bse['instrument_type'] == "E")]
        df_bse = df_bse[["trading_symbol", 'token', "tick_size", "lot_size", "exch"]]
        df_bse['token'] = df_bse['token'].astype(int)
        df_bse.rename({"token": "Token", "trading_symbol": "Symbol",
                       "tick_size": 'TickSize', "lot_size": "LotSize", "exch": "Exchange"}, axis=1, inplace=True)

        df_bse.set_index(df_bse['Symbol'], inplace=True)

        df_bse['Token'] = df_bse['Token']  # .astype(int)
        df_bse['TickSize'] = df_bse['TickSize'].astype(float)
        df_bse['LotSize'] = df_bse['LotSize'].astype(int)


        req_nse = cls.fetch(method="GET", url=cls.base_urls["market_data"], params={'exch': ExchangeCode.NSE})
        resp_nse = cls._json_parser(req_nse)

        df_nse = cls.data_frame(resp_nse[ExchangeCode.NSE])

        df_nse = df_nse[(df_nse['group_name'] == "EQ")]
        df_nse = df_nse[["symbol", "trading_symbol", 'token', "lot_size", "tick_size", "exch"]]
        df_nse.rename({"symbol": "Index", "token": "Token", "trading_symbol": "Symbol",
                       "tick_size": 'TickSize', "lot_size": "LotSize", "exch": "Exchange"}, axis=1, inplace=True)

        df_nse.set_index(df_nse['Index'], inplace=True)
        df_nse.drop(columns="Index", inplace=True)


        df_nse['Token'] = df_nse['Token'].astype(int)
        df_nse['TickSize'] = df_nse['TickSize'].astype(float)
        df_nse['LotSize'] = df_nse['LotSize'].astype(int)



        cls.eq_tokens[ExchangeCode.NSE] = df_nse.to_dict(orient='index')
        cls.eq_tokens[ExchangeCode.BSE] = df_bse.to_dict(orient='index')

        return cls.eq_tokens

    @classmethod
    def create_indices(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the paper.indices Dictionary.

        Returns:
            dict: Unified fenix indices format.
        """
        req = cls.fetch(method="GET", url=cls.base_urls["market_data"], params={'exch': ExchangeCode.NSE})
        resp = cls._json_parser(req)

        df = cls.data_frame(resp[ExchangeCode.NSE])

        df = df[df["exchange_segment"] == "nse_idx"][["symbol", "token"]]

        df.rename({"symbol": "Symbol", "token": "Token"}, axis=1, inplace=True)
        df.index = df['Symbol']

        indices = df.to_dict(orient='index')

        indices[Root.BNF] = indices["NIFTY BANK"]
        indices[Root.NF] = indices["NIFTY 50"]
        indices[Root.FNF] = indices["NIFTY FIN SERVICE"]
        indices[Root.MIDCPNF] = indices["NIFTY MIDCAP SELECT"]

        cls.indices = indices

        return indices

    @classmethod
    def create_nfo_tokens(cls) -> dict:
        """
        Creates BANKNIFTY & NIFTY Current, Next and Far Expiries;
        Stores them in the paper.nfo_tokens Dictionary.

        Raises:
            TokenDownloadError: Any Error Occured is raised through this Error Type.
        """
        try:
            req = cls.fetch(method="GET", url=cls.base_urls["market_data"], params={'exch': ExchangeCode.NFO})
            resp = cls._json_parser(req)

            df = cls.data_frame(resp[ExchangeCode.NFO])

            df = df[
                (
                    (df['symbol'] == 'BANKNIFTY') |
                    (df['symbol'] == 'NIFTY') |
                    (df['symbol'] == 'FINNIFTY') |
                    (df['symbol'] == 'MIDCPNIFTY')
                ) &
                (
                    (df['instrument_type'] == 'OPTIDX')
                )
            ]

            df.rename({"option_type": "Option", "token": "Token", "symbol": "Root", "exch": "Exchange",
                       "expiry_date": "Expiry", "trading_symbol": "Symbol",
                       "tick_size": 'TickSize', "lot_size": "LotSize", "strike_price": "StrikePrice"
                       }, axis=1, inplace=True)
            df = df[['Token', 'Symbol', 'Expiry', 'Option', 'StrikePrice',
                     'LotSize', 'Root', 'TickSize', "Exchange"
                     ]]

            df['StrikePrice'] = df['StrikePrice'].astype(int)
            df['Expiry'] = cls.pd_datetime(df['Expiry'], unit='ms').dt.date.astype(str)
            df["Token"] = df["Token"].astype(int)
            df["TickSize"] = df["TickSize"].astype(float)
            df["LotSize"] = df["LotSize"].astype(float)

            expiry_data = cls.jsonify_expiry(data_frame=df)
            cls.nfo_tokens = expiry_data

            return expiry_data

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc


    # Headers & Json Parsers


    @classmethod
    def create_headers(cls,
                       params: dict = {},
                       ) -> dict[str, str]:
        """
        Generate Headers used to access Endpoints in Paper.

        Parameters:
            Params (dict) : A placeholder dictionary for header creation.

        Returns:
            dict[str, str]: Paper Headers.
        """

        headers = {
            "headers":
                {
                    "ID": "user_id",
                    "AccessToken": "access_token",
                    "Authorization": "Bearer user_id access_token",
                    "X-SAS-Version": "2.0",
                    "User-Agent": "fenix_Paper",
                    "Content-Type": "application/json",
                    "susertoken": "susertoken"
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
        if isinstance(json_response, dict):
            stat = json_response.get('stat', None)

            if stat == 'Ok' or not stat:
                return json_response

            error = json_response.get('emsg', None)
            error = error if error else json_response.get('Emsg', None)
            raise ResponseError(cls.id + " " + error)

        if isinstance(json_response, list):
            stat = json_response[0].get('stat', )

            if stat == 'Ok' or not stat:
                return json_response

            error = json_response[0].get('emsg', None)
            error = error if error else json_response[0].get('Emsg', str(json_response))
            raise ResponseError(cls.id + " " + error)

    @classmethod
    def _order_data_creator(cls,
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
            Order.ID: str(time.time_ns()),
            Order.USERID: order[Order.USERID],
            Order.TIMESTAMP: datetime.now().replace(microsecond=0),
            Order.SYMBOL: order[Order.SYMBOL],
            Order.TOKEN: order[Order.TOKEN],
            Order.SIDE: order[Order.SIDE],
            Order.TYPE: order[Order.TYPE],
            Order.AVGPRICE: order[Order.PRICE],
            Order.PRICE: order[Order.PRICE],
            Order.TRIGGERPRICE: order[Order.TRIGGERPRICE],
            Order.TARGETPRICE: 0.0,
            Order.STOPLOSSPRICE: 0.0,
            Order.TRAILINGSTOPLOSS: 0.0,
            Order.QUANTITY: order[Order.QUANTITY],
            Order.FILLEDQTY: order[Order.QUANTITY],
            Order.REMAININGQTY: 0,
            Order.CANCELLEDQTY: 0,
            Order.STATUS: Status.PENDING,
            Order.REJECTREASON: "",
            Order.DISCLOSEDQUANTITY: 0,
            Order.PRODUCT: order[Order.PRODUCT],
            Order.EXCHANGE: order[Order.EXCHANGE],
            Order.SEGMENT: order[Order.EXCHANGE],
            Order.VALIDITY: order[Order.VALIDITY],
            Order.VARIETY: "",
            Order.INFO: {},
        }

        cls.orderbook.append(parsed_order)
        return parsed_order

    @classmethod
    def _profile_paper(cls):
        """
        Parse User Profile Json Response.

        Parameters:
            profile (dict): User Profile Json Response from Broker.

        Returns:
            dict: Unified fenix Profile Response.
        """
        exchanges_enabled = [ExchangeCode.NSE, ExchangeCode.BSE, ExchangeCode.NFO,
                             ExchangeCode.BFO, ExchangeCode.MCX, ExchangeCode.CDS,
                             ExchangeCode.BFO, ExchangeCode.BCD, ExchangeCode.NCO,
                             ExchangeCode.BCO
                             ]

        parsed_profile = {
            Profile.CLIENTID: "796894",
            Profile.NAME: "KRATOS",
            Profile.EMAILID: "GODOFWAR@GMAIL.COM",
            Profile.MOBILENO: "7054251468",
            Profile.PAN: "KRATOSPANNO",
            Profile.ADDRESS: "GREEK MYTHOS",
            Profile.BANKNAME: "OMEGA BANK",
            Profile.BANKBRANCHNAME: "NO BRANCH",
            Profile.BANKACCNO: "5354983205",
            Profile.EXHCNAGESENABLED: exchanges_enabled,
            Profile.ENABLED: True,
            Profile.INFO: cls.profile_dict
        }

        return parsed_profile


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

        token = token_dict["Token"]
        exchange = token_dict["Exchange"]
        symbol = token_dict["Symbol"]

        order = {
            Order.USERID: unique_id,
            Order.SYMBOL: symbol,
            Order.TOKEN: token,
            Order.SIDE: cls._key_mapper(cls.req_side, side, "side"),
            Order.TYPE: order_type,
            Order.PRICE: price,
            Order.TRIGGERPRICE: 0,
            Order.QUANTITY: quantity,
            Order.PRODUCT: cls._key_mapper(cls.req_product, product, "product"),
            Order.EXCHANGE: exchange,
            Order.SEGMENT: exchange,
            Order.VALIDITY: cls._key_mapper(cls.req_validity, validity, "validity"),
            Order.VARIETY: "",
            Order.INFO: {},
        }

        order = cls._order_data_creator(order)
        return order


    # Order Details, OrderBook & TradeBook


    @classmethod
    def fetch_orderbook(cls,
                        headers: dict
                        ) -> list[dict]:
        """
        Fetch Orderbook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using fenix Unified Order Response.
        """
        return cls.orderbook

    @classmethod
    def fetch_tradebook(cls,
                        headers: dict
                        ) -> list[dict]:
        """
        Fetch Tradebook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using fenix Unified Order Response.
        """
        return cls.orderbook

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
            dict: fenix Unified Order Response.
        """
        return cls.orderbook

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
            dict: fenix Unified Order Response.
        """
        order_id = str(order_id)

        for order in cls.orderbook:
            if order[Order.ID] == order_id:
                return order

        raise InputError({"This order_id does not exist."})

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
            list: A list of dicitonaries containing order history using fenix Unified Order Response.
        """
        return [cls.fetch_order(order_id, headers)]


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
            dict: fenix Unified Order Response.
        """
        order_id = str(order_id)

        for index in range(len(cls.orderbook)):
            if cls.orderbook[index][Order.ID] == order_id:
                order = cls.orderbook[index]
                if order[Order.STATUS] == Status.PENDING:
                    order[Order.PRICE] = price or order[Order.PRICE]
                    order[Order.TRIGGERPRICE] = trigger or order[Order.TRIGGERPRICE]
                    order[Order.QUANTITY] = quantity or order[Order.QUANTITY]
                    order[Order.VALIDITY] = cls._key_mapper(cls.req_validity, validity, 'validity')
                    order[Order.TYPE] = cls._key_mapper(cls.req_order_type, order_type, 'order_type') or order[Order.TYPE]

                return order

        raise InputError({"This order_id does not exist."})

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
            dict: fenix Unified Order Response.
        """
        order_id = str(order_id)

        for index in range(len(cls.orderbook)):
            if cls.orderbook[index][Order.ID] == order_id:
                order = cls.orderbook[index]
                if order[Order.STATUS] == Status.PENDING:
                    order[Order.STATUS] = Status.CANCELLED

                return order


        raise InputError({"This order_id does not exist."})


    # Positions, Account Limits & Profile


    @classmethod
    def _position_calc(cls,
                       position,
                       order,
                       key
                       ):

        qkey = f"{key}qty"
        pkey = f"{key}price"

        position[Position.INFO][qkey].append(order[Order.QUANTITY])
        position[Position.INFO][pkey].append(order[Order.AVGPRICE])

        qty = sum(position[Position.INFO][qkey])
        price = 0

        for order_qty, order_price in zip(position[Position.INFO][qkey], position[Position.INFO][pkey]):
            price += (order_qty * order_price)

        avgprice = price / qty

        return qty, avgprice, price

    @classmethod
    def fetch_day_positions(cls,
                            headers: dict,
                            ) -> dict[Any, Any]:
        """
        Fetch the Day's Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        return cls.fetch_positions(headers)

    @classmethod
    def fetch_net_positions(cls,
                            headers: dict,
                            ) -> dict[Any, Any]:
        """
        Fetch Total Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        return cls.fetch_positions(headers)

    @classmethod
    def fetch_positions(cls,
                        headers: dict,
                        ) -> dict[Any, Any]:
        """
        Fetch Day & Net Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        for order in cls.orderbook:

            if order[Order.STATUS] == Status.FILLED:
                if order[Order.SYMBOL] in cls.positions:
                    position = cls.positions[order[Order.SYMBOL]]

                    if order[Order.SIDE] == Side.BUY:
                        position[Position.BUYQTY], position[Position.BUYPRICE], position[Position.INFO]["b_avgprice"] = cls._position_calc(position, order, "b")
                    else:
                        position[Position.SELLQTY], position[Position.SELLPRICE], position[Position.INFO]["s_avgprice"] = cls._position_calc(position, order, "s")

                    tprice = position[Position.INFO]["b_avgprice"] + position[Position.INFO]["s_avgprice"]
                    tqty = position[Position.BUYQTY] + position[Position.SELLQTY]

                    position[Position.NETQTY] = abs(position[Position.BUYQTY] - position[Position.SELLQTY])
                    position[Order.AVGPRICE] = tprice / tqty

                else:
                    position = {
                        Position.SYMBOL: order[Order.SYMBOL],
                        Position.TOKEN: order[Order.TOKEN],
                        Position.NETQTY: order[Order.QUANTITY],
                        Position.AVGPRICE: order[Order.AVGPRICE],
                        Position.MTM: None,
                        Position.PNL: None,
                        Position.BUYQTY: 0,
                        Position.BUYPRICE: 0.0,
                        Position.SELLQTY: 0,
                        Position.SELLPRICE: 0.0,
                        Position.LTP: None,
                        Position.PRODUCT: order[Order.PRODUCT],
                        Position.EXCHANGE: order[Order.EXCHANGE],
                        Position.INFO: {"bqty": [], "bprice": [], "b_avgprice": 0,
                                        "sqty": [], "sprice": [], "s_avgprice": 0}
                    }


                    if order[Order.SIDE] == Side.BUY:
                        position[Position.BUYQTY] = order[Order.QUANTITY]
                        position[Position.BUYPRICE] = order[Order.AVGPRICE]
                        position[Position.INFO]["bqty"].append(order[Order.QUANTITY])
                        position[Position.INFO]["bprice"].append(order[Order.AVGPRICE])
                    else:
                        position[Position.SELLQTY] = order[Order.QUANTITY]
                        position[Position.SELLPRICE] = order[Order.AVGPRICE]
                        position[Position.INFO]["sqty"].append(order[Order.QUANTITY])
                        position[Position.INFO]["sprice"].append(order[Order.AVGPRICE])


                    cls.positions[order[Order.SYMBOL]] = position


        return list(cls.positions.values())


    @classmethod
    def fetch_holdings(cls,
                       headers: dict,
                       ) -> dict[Any, Any]:
        """
        Fetch Account Holdings.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Positions Response.
        """
        return cls.fetch_positions(headers)

    @classmethod
    def rms_limits(cls,
                   headers: dict
                   ) -> dict[Any, Any]:
        """
        Fetch Risk Management System Limits.

        Parameters:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict: fenix Unified RMS Limits Response.
        """
        return cls.rms_limits_dict

    @classmethod
    def profile(cls,
                headers: dict
                ) -> dict[Any, Any]:
        """
        Fetch Profile Limits of the User.

        Parameters:
            headers (dict): headers to send profile request with.

        Returns:
            dict: fenix Unified Profile Response.
        """
        return cls._profile_paper()
