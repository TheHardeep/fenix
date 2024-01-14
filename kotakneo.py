from __future__ import annotations
from typing import TYPE_CHECKING
from typing import Any

import jwt
import base64

from kronos.base.exchange import Exchange

from kronos.base.constants import Side
from kronos.base.constants import OrderType
from kronos.base.constants import ExchangeCode
from kronos.base.constants import Product
from kronos.base.constants import Validity
from kronos.base.constants import Variety
from kronos.base.constants import Status
from kronos.base.constants import Order
from kronos.base.constants import Root
from kronos.base.constants import WeeklyExpiry


from kronos.base.errors import BrokerError
from kronos.base.errors import InputError
from kronos.base.errors import ResponseError
from kronos.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response



class kotakneo(Exchange):
    """
    Kotak Neo kronos Broker Class.

    Returns:
        kronos.kotakneo: kronos Kotak Neo Broker Object.
    """


    # Market Data Dictonaries

    indices = {}
    eq_tokens = {}
    nfo_tokens = {}
    token_params = ["user_id", "client_id", "password", "mobile_no",
                    "pin", "consumer_key", "consumer_secret", "trade_password"
                    ]
    id = 'kotakneo'
    _session = Exchange._create_session()


    # Base URLs

    base_urls = {
        "api_doc": "https://documenter.getpostman.com/view/21534797/UzBnqmpD",
        "base": "https://gw-napi.kotaksecurities.com",
        "market_data": "https://lapi.kotaksecurities.com/wso2-scripmaster/v1/prod/<date>/transformed/<exchange>.csv",
    }


    # Access Token Generation URLs

    token_urls = {
        "token": "https://napi.kotaksecurities.com/oauth2/token",
        "validate": f"{base_urls['base']}/login/1.0/login/v2/validate",
        "otp_generate": f"{base_urls['base']}/login/1.0/login/otp/generate",
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base']}/Orders/2.0/quick/order/rule/ms/place",
        "modify_order": f"{base_urls['base']}/Orders/2.0/quick/order/vr/modify",
        "cancel_order": f"{base_urls['base']}/Orders/2.0/quick/order/cancel",
        "orderbook": f"{base_urls['base']}/Orders/2.0/quick/user/orders",
        "tradebook": f"{base_urls['base']}/Orders/2.0/quick/user/trades",
        "order_history": f"{base_urls['base']}/Orders/2.0/quick/order/history",
        "positions": f"{base_urls['base']}/Orders/2.0/quick/user/positions",
        "holdings": f"{base_urls['base']}/Portfolio/1.0/portfolio/v1/holdings",
        "rms_limits": f"{base_urls['base']}/Orders/2.0/quick/user/limits",
    }


    # Request Parameters Dictionaries

    req_exchange = {
        ExchangeCode.NSE: "nse_cm",
        ExchangeCode.NFO: "nse_fo",
        ExchangeCode.BSE: "bse_cm",
        ExchangeCode.BFO: "bse_fo",
        ExchangeCode.BCD: "bcs_fo",
        ExchangeCode.MCX: "mcx",
        ExchangeCode.CDS: "cde_fo",
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
        Product.BO: "Bracket Order",
        Product.CO: "CO",
    }

    req_side = {
        Side.BUY: "B",
        Side.SELL: "S",
    }

    req_validity = {
        Validity.DAY: "DAY",
        Validity.IOC: "IOC",
        Validity.GTC: "GTC",
    }


    # Response Parameters Dictionaries

    resp_exchange = {
        "nse_cm": ExchangeCode.NSE,
        "nse_fo": ExchangeCode.NFO,
        "bse_cm": ExchangeCode.BSE,
        "bse_fo": ExchangeCode.BFO,
        "bcs_fo": ExchangeCode.BCD,
        "mcx": ExchangeCode.MCX,
        "cde_fo": ExchangeCode.CDS,
    }

    resp_order_type = {
        "MKT": OrderType.MARKET,
        "L": OrderType.LIMIT,
        "SL": OrderType.SL,
        "SL-M": OrderType.SLM,
    }

    resp_product = {
        "MIS": Product.MIS,
        "NRML": Product.NRML,
        "CNC": Product.CNC,
        "Bracket Order": Product.BO,
        "CO": Product.CO,
    }

    resp_side = {
        "B": Side.BUY,
        "S": Side.SELL
    }


    resp_status = {
        "open pending": Status.PENDING,
        "not modified": Status.PENDING,
        "not cancelled": Status.PENDING,
        "modify pending": Status.PENDING,
        "trigger pending": Status.PENDING,
        "cancel pending": Status.PENDING,
        "validation pending": Status.PENDING,
        "put order req received": Status.PENDING,
        "modify validation pending": Status.PENDING,
        "after market order req received": Status.PENDING,
        "modify after market order req received": Status.PENDING,
        "cancelled": Status.CANCELLED,
        "cancelled after market order": Status.CANCELLED,
        "open": Status.OPEN,
        "complete": Status.FILLED,
        "rejected": Status.REJECTED,
        "modified": Status.MODIFIED,
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
        final_url = cls.base_urls["market_data"].replace("<date>", str(cls.current_datetime().date())
                                                         ).replace("<exchange>", cls.req_exchange[ExchangeCode.BSE])
        df_bse = cls.data_reader(final_url, filetype='csv')

        df_bse = df_bse[df_bse["dTickSize "] != -1]
        df_bse = df_bse[['pTrdSymbol', "pSymbol", "lLotSize", "dTickSize ", "pExchSeg"]]
        df_bse.rename({"pSymbol": "Token", "pTrdSymbol": "Symbol",
                       "dTickSize ": 'TickSize', "lLotSize": "LotSize", "pExchSeg": "Exchange"}, axis=1, inplace=True)

        df_bse["TickSize"] = df_bse["TickSize"] / 100
        df_bse.set_index(df_bse['Symbol'], inplace=True)
        df_bse.drop_duplicates(subset=['Symbol'], keep='first', inplace=True)


        final_url = cls.base_urls["market_data"].replace("<date>", str(cls.current_datetime().date())
                                                         ).replace("<exchange>", cls.req_exchange[ExchangeCode.NSE])
        df_nse = cls.data_reader(final_url, filetype='csv')

        df_nse = df_nse[df_nse['pGroup'] == "EQ"]
        df_nse = df_nse[["pSymbolName", 'pTrdSymbol', "pSymbol", "lLotSize", "dTickSize ", "pExchSeg"]]
        df_nse.rename({"pSymbolName": "Index", "pSymbol": "Token", "pTrdSymbol": "Symbol",
                       "dTickSize ": 'TickSize', "lLotSize": "LotSize", "pExchSeg": "Exchange"}, axis=1, inplace=True)

        df_nse["TickSize"] = df_nse["TickSize"] / 100
        df_nse.set_index(df_nse['Index'], inplace=True)
        df_nse.drop(columns="Index", inplace=True)
        df_nse.drop_duplicates(subset=['Symbol'], keep='first', inplace=True)


        cls.eq_tokens[ExchangeCode.NSE] = df_nse.to_dict(orient='index')
        cls.eq_tokens[ExchangeCode.BSE] = df_bse.to_dict(orient='index')

        return cls.eq_tokens

    @classmethod
    def create_indices(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the kotakneo.indices Dictionary.

        Returns:
            dict: Unified kronos indices format.
        """
        final_url = cls.base_urls["market_data"].replace("<date>", str(cls.current_datetime().date())
                                                         ).replace("<exchange>", cls.req_exchange[ExchangeCode.NSE])
        df = cls.data_reader(final_url, filetype='csv')

        df = df[df['pGroup'].isna()][["pTrdSymbol", "pSymbol", "pSymbolName"]]

        df.rename({"pTrdSymbol": "Symbol", "pSymbol": "Token"}, axis=1, inplace=True)
        df.index = df['pSymbolName']
        del df["pSymbolName"]

        indices = df.to_dict(orient='index')

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
            final_url = cls.base_urls["market_data"].replace("<date>", str(cls.current_datetime().date())
                                                             ).replace("<exchange>", cls.req_exchange[ExchangeCode.NFO])
            df = cls.data_reader(final_url, filetype='csv')

            df = df[df["pInstType"] == "OPTIDX"]


            df.rename({"pOptionType": "Option", "pSymbol": "Token", "pSymbolName": "Root",
                       "lExpiryDate ": "Expiry", "pTrdSymbol": "Symbol", "pExchSeg": "Exchange",
                       "dTickSize ": 'TickSize', "lLotSize": "LotSize", "dStrikePrice;": "StrikePrice"
                       }, axis=1, inplace=True)

            df = df[['Token', 'Symbol', 'Expiry', 'Option', 'StrikePrice',
                     'LotSize', 'Root', 'TickSize', "Exchange"
                     ]]

            df["TickSize"] = df["TickSize"] / 100
            df["StrikePrice"] = (df["StrikePrice"] / 100).astype(int)
            df["Expiry"] = (cls.pd_datetime(df["Expiry"], unit="s") + cls.pd_dateoffset(years=10)).dt.date.astype(str)


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
        Generate Headers used to access Endpoints in Kotak Neo.

        Parameters:
            Params (dict) : A dictionary which should consist the following keys:
                user_id (str): User ID of the Account.
                client_id (str): Client ID of the Account, created during Creation of API.
                password (str): Password of the Account.
                mobile_no (str): Mobile Number of the Account Holder (Should include country code Example: +91708745XXXX).
                pin (str): PIN of the Account.
                consumer_key (str): Consumer Key of the Account, created during Creation of API.
                consumer_secret (str): Consumer Secret of the Account, created during Creation of API.
                trade_password (str): Trade Password of the Account.

        Returns:
            dict[str, str]: Kotak Neo Headers.
        """
        for key in cls.token_params:
            if key not in params:
                raise KeyError(f"Please provide {key}")

            base64_code = base64.b64encode(f"{params['consumer_key']}:{params['consumer_secret']}".encode()).decode()
            headers = {
                "Authorization": f"Basic {base64_code}",
                "Content-Type": "application/x-www-form-urlencoded",
            }

            data = {
                "grant_type": "password",
                "username": params["client_id"],
                "password": params["password"],
            }

            response01 = cls.fetch(method="POST", url=cls.token_urls["token"],
                                   data=data, headers=headers)

            info01 = cls._json_parser(response01)
            access_token = info01['access_token']

            json_data = {
                "mobileNumber": params['mobile_no'],
                "password": params["trade_password"],
            }

            headers = {
                'accept': '*/*',
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {access_token}'
            }

            response02 = cls.fetch(method="POST", url=cls.token_urls["validate"],
                                   json=json_data, headers=headers, )

            info02 = cls._json_parser(response02)
            token = info02['data']['token']
            session_id = info02['data']['sid']
            token_decode = jwt.decode(token, algorithms=['RS256'], options={'verify_signature': False})
            user_id = token_decode["sub"]

            json_data = {
                "userId": user_id,
                "sendEmail": True,
                "isWhitelisted": True
            }

            headers = {
                'accept': '*/*',
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {access_token}'
            }

            response03 = cls.fetch(method="POST", url=cls.token_urls["otp_generate"],
                                   json=json_data, headers=headers)
            _ = cls._json_parser(response03)


            json_data = {
                "userId": user_id,
                "mpin": params['pin']
            }

            headers = {
                'accept': '*/*',
                'sid': session_id,
                'Auth': token,
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {access_token}'
            }

            response04 = cls.fetch(method="POST", url=cls.token_urls["validate"],
                                   json=json_data, headers=headers)

            info04 = cls._json_parser(response04)
            session_id_headers = info04['data']['sid']
            token_headers = info04['data']['token']
            hid = info04['data']['hsServerId']

            headers = {
                "headers": {
                    "Sid": session_id_headers,
                    "Auth": token_headers,
                    "neo-fin-key": "neotradeapi",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Bearer {access_token}",
                    "accept": "application/json",
                },
                "sId": hid,
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

        stat = json_response.get('stat', None)
        if stat == 'Ok' or not stat:
            return json_response

        error = json_response.get('errMsg', None)
        raise ResponseError(cls.id + " " + error)

    @classmethod
    def _orderhistory_json_parser(cls,
                                  order: dict,
                                  ) -> dict[Any, Any]:
        """
        Parses Order History Json Response to a kronos Unified Order Response.

        Parameters:
            order (dict): Order History Json Response from Broker.

        Returns:
            dict: Unified kronos Order Response.
        """
        parsed_order = {
            Order.ID: order["nOrdNo"],
            Order.USERID: order["GuiOrdId"],
            Order.TIMESTAMP: cls.datetime_strp(order["flDtTm"], "%d-%b-%Y %H:%M:%S"),
            Order.SYMBOL: order["trdSym"],
            Order.TOKEN: order["tok"],
            Order.SIDE: cls.resp_side.get(order["trnsTp"], order["trnsTp"]),
            Order.TYPE: cls.resp_order_type.get(order["prcTp"], order["prcTp"]),
            Order.AVGPRICE: float(order["avgPrc"]),
            Order.PRICE: float(order["prc"]),
            Order.TRIGGERPRICE: float(order["trgPrc"]),
            Order.TARGETPRICE: 0.0,
            Order.STOPLOSSPRICE: 0.0,
            Order.TRAILINGSTOPLOSS: 0.0,
            Order.QUANTITY: order["qty"],
            Order.FILLEDQTY: order["fldQty"],
            Order.REMAININGQTY: order["qty"] - order["fldQty"],
            Order.CANCELLEDQTY: order.get("cnlQty", 0),
            Order.STATUS: cls.resp_status.get(order["ordSt"], order["ordSt"]),
            Order.REJECTREASON: order["rejRsn"],
            Order.DISCLOSEDQUANTITY: int(order["dclQty"]),
            Order.PRODUCT: cls.resp_product.get(order["prod"], order["prod"]),
            Order.EXCHANGE: cls.resp_exchange.get(order["exSeg"], order["exSeg"]),
            Order.SEGMENT: cls.resp_exchange.get(order["exSeg"], order["exSeg"]),
            Order.VALIDITY: cls.req_validity.get(order["ordDur"], order["ordDur"]),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

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
            Order.ID: order["nOrdNo"],
            Order.USERID: order["GuiOrdId"],
            Order.TIMESTAMP: cls.datetime_strp(order["hsUpTm"], "%Y/%m/%d %H:%M:%S"),
            Order.SYMBOL: order["trdSym"],
            Order.TOKEN: order["tok"],
            Order.SIDE: cls.resp_side.get(order["trnsTp"], order["trnsTp"]),
            Order.TYPE: cls.resp_order_type.get(order["prcTp"], order["prcTp"]),
            Order.AVGPRICE: float(order["avgPrc"]),
            Order.PRICE: float(order["prc"]),
            Order.TRIGGERPRICE: float(order["trgPrc"]),
            Order.TARGETPRICE: 0.0,
            Order.STOPLOSSPRICE: 0.0,
            Order.TRAILINGSTOPLOSS: 0.0,
            Order.QUANTITY: order["qty"],
            Order.FILLEDQTY: order["fldQty"],
            Order.REMAININGQTY: order["qty"] - order["fldQty"],
            Order.CANCELLEDQTY: order["cnlQty"],
            Order.STATUS: cls.resp_status.get(order["ordSt"], order["ordSt"]),
            Order.REJECTREASON: order["rejRsn"],
            Order.DISCLOSEDQUANTITY: order["dscQty"],
            Order.PRODUCT: cls.resp_product.get(order["prod"], order["prod"]),
            Order.EXCHANGE: cls.resp_exchange.get(order["exSeg"], order["exSeg"]),
            Order.SEGMENT: cls.resp_exchange.get(order["exSeg"], order["exSeg"]),
            Order.VALIDITY: cls.req_validity.get(order["vldt"], order["vldt"]),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

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

        order_id = info["nOrdNo"]
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
                     headers: dict,
                     price: float = 0.0,
                     trigger: float = 0.0,
                     target: float = 0.0,
                     stoploss: float = 0.0,
                     trailing_sl: float = 0.0,
                     unique_id: str | None = None,
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
            order_data = {
                "es": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "ts": symbol,
                "pr": price,
                "tp": trigger,
                "qt": quantity,
                "tt": cls._key_mapper(cls.req_side, side, 'side'),
                "pt": cls.req_order_type[order_type],
                "pc": cls._key_mapper(cls.req_product, product, 'product'),
                "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "am": "YES" if variety == Variety.AMO else "NO",
                "ig": unique_id,
                "dq": "0",
                "mp": "0",
                "pf": "N",
                "os": "API"
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order(cls,
                     token: int,
                     exchange: str,
                     symbol: str,
                     quantity: int,
                     side: str,
                     headers: dict,
                     target: float = 0.0,
                     stoploss: float = 0.0,
                     trailing_sl: float = 0.0,
                     product: str = Product.MIS,
                     validity: str = Validity.DAY,
                     variety: str = Variety.REGULAR,
                     unique_id: str | None = None,
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
            order_data = {
                "es": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "ts": symbol,
                "pr": "0",
                "tp": "0",
                "qt": quantity,
                "tt": cls._key_mapper(cls.req_side, side, 'side'),
                "pt": cls.req_order_type[OrderType.MARKET],
                "pc": cls._key_mapper(cls.req_product, product, 'product'),
                "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "am": "YES" if variety == Variety.AMO else "NO",
                "ig": unique_id,
                "dq": "0",
                "mp": "0",
                "pf": "N",
                "os": "API"
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order(cls,
                    token: int,
                    exchange: str,
                    symbol: str,
                    price: float,
                    quantity: int,
                    side: str,
                    headers: dict,
                    target: float = 0.0,
                    stoploss: float = 0.0,
                    trailing_sl: float = 0.0,
                    product: str = Product.MIS,
                    validity: str = Validity.DAY,
                    variety: str = Variety.REGULAR,
                    unique_id: str | None = None,
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
            order_data = {
                "es": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "ts": symbol,
                "pr": price,
                "tp": "0",
                "qt": quantity,
                "tt": cls._key_mapper(cls.req_side, side, 'side'),
                "pt": cls.req_order_type[OrderType.LIMIT],
                "pc": cls._key_mapper(cls.req_product, product, 'product'),
                "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "am": "YES" if variety == Variety.AMO else "NO",
                "ig": unique_id,
                "dq": "0",
                "mp": "0",
                "pf": "N",
                "os": "API"
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

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
                 headers: dict,
                 target: float = 0.0,
                 stoploss: float = 0.0,
                 trailing_sl: float = 0.0,
                 product: str = Product.MIS,
                 validity: str = Validity.DAY,
                 variety: str = Variety.STOPLOSS,
                 unique_id: str | None = None,
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
            order_data = {
                "es": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "ts": symbol,
                "pr": price,
                "tp": trigger,
                "qt": quantity,
                "tt": cls._key_mapper(cls.req_side, side, 'side'),
                "pt": cls.req_order_type[OrderType.SL],
                "pc": cls._key_mapper(cls.req_product, product, 'product'),
                "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "am": "YES" if variety == Variety.AMO else "NO",
                "ig": unique_id,
                "dq": "0",
                "mp": "0",
                "pf": "N",
                "os": "API"
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order(cls,
                  token: int,
                  exchange: str,
                  symbol: str,
                  trigger: float,
                  quantity: int,
                  side: str,
                  headers: dict,
                  target: float = 0.0,
                  stoploss: float = 0.0,
                  trailing_sl: float = 0.0,
                  product: str = Product.MIS,
                  validity: str = Validity.DAY,
                  variety: str = Variety.STOPLOSS,
                  unique_id: str | None = None,
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
            order_data = {
                "es": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "ts": symbol,
                "pr": "0",
                "tp": trigger,
                "qt": quantity,
                "tt": cls._key_mapper(cls.req_side, side, 'side'),
                "pt": cls.req_order_type[OrderType.SLM],
                "pc": cls._key_mapper(cls.req_product, product, 'product'),
                "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "am": "YES" if variety == Variety.AMO else "NO",
                "ig": unique_id,
                "dq": "0",
                "mp": "0",
                "pf": "N",
                "os": "API"
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

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
                        headers: dict,
                        price: float = 0.0,
                        trigger: float = 0.0,
                        target: float = 0.0,
                        stoploss: float = 0.0,
                        trailing_sl: float = 0.0,
                        unique_id: str | None = None,
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
            order_data = {
                "es": exchange,
                "ts": symbol,
                "pr": price,
                "tp": trigger,
                "qt": quantity,
                "tt": cls._key_mapper(cls.req_side, side, 'side'),
                "pt": cls.req_order_type[order_type],
                "pc": cls._key_mapper(cls.req_product, product, 'product'),
                "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "am": "YES" if variety == Variety.AMO else "NO",
                "ig": unique_id,
                "dq": "0",
                "mp": "0",
                "pf": "N",
                "os": "API"
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order_eq(cls,
                        exchange: str,
                        symbol: str,
                        quantity: int,
                        side: str,
                        headers: dict,
                        target: float = 0.0,
                        stoploss: float = 0.0,
                        trailing_sl: float = 0.0,
                        product: str = Product.MIS,
                        validity: str = Validity.DAY,
                        variety: str = Variety.REGULAR,
                        unique_id: str | None = None,
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
        symbol = detail["Symbol"]

        if not target:
            order_data = {
                "es": exchange,
                "ts": symbol,
                "pr": "0",
                "tp": "0",
                "qt": quantity,
                "tt": cls._key_mapper(cls.req_side, side, 'side'),
                "pt": cls.req_order_type[OrderType.MARKET],
                "pc": cls._key_mapper(cls.req_product, product, 'product'),
                "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "am": "YES" if variety == Variety.AMO else "NO",
                "ig": unique_id,
                "dq": "0",
                "mp": "0",
                "pf": "N",
                "os": "API"
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order_eq(cls,
                       exchange: str,
                       symbol: str,
                       price: float,
                       quantity: int,
                       side: str,
                       headers: dict,
                       target: float = 0.0,
                       stoploss: float = 0.0,
                       trailing_sl: float = 0.0,
                       product: str = Product.MIS,
                       validity: str = Validity.DAY,
                       variety: str = Variety.REGULAR,
                       unique_id: str | None = None,
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
        symbol = detail["Symbol"]

        if not target:
            order_data = {
                "es": exchange,
                "ts": symbol,
                "pr": price,
                "tp": "0",
                "qt": quantity,
                "tt": cls._key_mapper(cls.req_side, side, 'side'),
                "pt": cls.req_order_type[OrderType.LIMIT],
                "pc": cls._key_mapper(cls.req_product, product, 'product'),
                "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "am": "YES" if variety == Variety.AMO else "NO",
                "ig": unique_id,
                "dq": "0",
                "mp": "0",
                "pf": "N",
                "os": "API"
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order_eq(cls,
                    exchange: str,
                    symbol: str,
                    price: float,
                    trigger: float,
                    quantity: int,
                    side: str,
                    headers: dict,
                    target: float = 0.0,
                    stoploss: float = 0.0,
                    trailing_sl: float = 0.0,
                    product: str = Product.MIS,
                    validity: str = Validity.DAY,
                    variety: str = Variety.STOPLOSS,
                    unique_id: str | None = None,
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
        symbol = detail["Symbol"]

        if not target:
            order_data = {
                "es": exchange,
                "ts": symbol,
                "pr": price,
                "tp": trigger,
                "qt": quantity,
                "tt": cls._key_mapper(cls.req_side, side, 'side'),
                "pt": cls.req_order_type[OrderType.SL],
                "pc": cls._key_mapper(cls.req_product, product, 'product'),
                "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "am": "YES" if variety == Variety.AMO else "NO",
                "ig": unique_id,
                "dq": "0",
                "mp": "0",
                "pf": "N",
                "os": "API"
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order_eq(cls,
                     exchange: str,
                     symbol: str,
                     trigger: float,
                     quantity: int,
                     side: str,
                     headers: dict,
                     target: float = 0.0,
                     stoploss: float = 0.0,
                     trailing_sl: float = 0.0,
                     product: str = Product.MIS,
                     validity: str = Validity.DAY,
                     variety: str = Variety.STOPLOSS,
                     unique_id: str | None = None,
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
        if not target:
            order_data = {
                "es": exchange,
                "ts": symbol,
                "pr": "0",
                "tp": trigger,
                "qt": quantity,
                "tt": cls._key_mapper(cls.req_side, side, 'side'),
                "pt": cls.req_order_type[OrderType.SLM],
                "pc": cls._key_mapper(cls.req_product, product, 'product'),
                "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "am": "YES" if variety == Variety.AMO else "NO",
                "ig": unique_id,
                "dq": "0",
                "mp": "0",
                "pf": "N",
                "os": "API"
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

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
                         headers: dict,
                         price: float = 0.0,
                         trigger: float = 0.0,
                         unique_id: str | None = None,
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

        symbol = detail['Symbol']

        order_data = {
            "es": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "ts": symbol,
            "pr": price,
            "tp": trigger,
            "qt": quantity,
            "tt": cls._key_mapper(cls.req_side, side, 'side'),
            "pt": cls.req_order_type[order_type],
            "pc": cls._key_mapper(cls.req_product, product, 'product'),
            "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "am": "YES" if variety == Variety.AMO else "NO",
            "ig": unique_id,
            "dq": "0",
            "mp": "0",
            "pf": "N",
            "os": "API"
        }

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

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
                         unique_id: str | None = None,
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

        order_data = {
            "es": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "ts": symbol,
            "pr": "0",
            "tp": "0",
            "qt": quantity,
            "tt": cls._key_mapper(cls.req_side, side, 'side'),
            "pt": cls.req_order_type[OrderType.MARKET],
            "pc": cls._key_mapper(cls.req_product, product, 'product'),
            "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "am": "YES" if variety == Variety.AMO else "NO",
            "ig": unique_id,
            "dq": "0",
            "mp": "0",
            "pf": "N",
            "os": "API"
        }

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

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
                        unique_id: str | None = None,
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

        order_data = {
            "es": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "ts": symbol,
            "pr": price,
            "tp": "0",
            "qt": quantity,
            "tt": cls._key_mapper(cls.req_side, side, 'side'),
            "pt": cls.req_order_type[OrderType.LIMIT],
            "pc": cls._key_mapper(cls.req_product, product, 'product'),
            "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "am": "YES" if variety == Variety.AMO else "NO",
            "ig": unique_id,
            "dq": "0",
            "mp": "0",
            "pf": "N",
            "os": "API"
        }

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

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
                     unique_id: str | None = None,
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

        order_data = {
            "es": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "ts": symbol,
            "pr": price,
            "tp": trigger,
            "qt": quantity,
            "tt": cls._key_mapper(cls.req_side, side, 'side'),
            "pt": cls.req_order_type[OrderType.SL],
            "pc": cls._key_mapper(cls.req_product, product, 'product'),
            "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "am": "YES" if variety == Variety.AMO else "NO",
            "ig": unique_id,
            "dq": "0",
            "mp": "0",
            "pf": "N",
            "os": "API"
        }

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

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
                      unique_id: str | None = None,
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

        order_data = {
            "es": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "ts": symbol,
            "pr": "0",
            "tp": trigger,
            "qt": quantity,
            "tt": cls._key_mapper(cls.req_side, side, 'side'),
            "pt": cls.req_order_type[OrderType.SLM],
            "pc": cls._key_mapper(cls.req_product, product, 'product'),
            "rt": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "am": "YES" if variety == Variety.AMO else "NO",
            "ig": unique_id,
            "dq": "0",
            "mp": "0",
            "pf": "N",
            "os": "API"
        }

        params = {'sId': headers["sId"]}
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             params=params, data=data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)


    # BO Order Functions

    # NO BO Orders For Upstox


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
        params = {"sId": headers["sId"]}
        response = cls.fetch(method="GET", url=cls.urls["orderbook"],
                             params=params, headers=headers["headers"])
        try:
            return cls._json_parser(response)

        except ResponseError:
            return []

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
        params = {"sId": headers["sId"]}
        order_data = {'nOrdNo': str(order_id)}
        data = {"jData": cls.json_dumps(order_data)}

        try:
            response = cls.fetch(method="POST", url=cls.urls["order_history"],
                                 params=params, data=data, headers=headers["headers"])
        except BrokerError as exc:
            if 'Cancel, Modify and OrderHistory will only' in str(exc):
                raise InputError({"This order_id does not exist."}) from exc
            else:
                raise exc

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
        for order in info["data"]:
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
        params = {"sId": headers["sId"]}
        response = cls.fetch(method="GET", url=cls.urls["tradebook"],
                             params=params, headers=headers["headers"])

        info = cls._json_parser(response)
        return info

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
        order = info["data"][0]
        return cls._orderhistory_json_parser(order)

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
        for order in info["data"]:
            history = cls._orderhistory_json_parser(order)
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
        order_history = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)
        order_info = order_history["data"][0]

        params = {"sId": headers["sId"]}
        order_data = {
            "no": order_info["nOrdNo"],
            "tk": order_info['tok'],
            "es": order_info["exSeg"],
            "ts": order_info["trdSym"],
            "pr": str(price or order_info["prc"]),
            "tp": str(trigger or order_info["trgPrc"]),
            "qt": str(quantity or order_info["qty"]),
            "fq": str(order_info["fldQty"]),
            "tt": order_info["trnsTp"],
            "pt": cls._key_mapper(cls.req_order_type, order_type, 'order_type') if order_type else order_info["prcTp"],
            "pc": order_info["prod"],
            "am": "YES" if order_info["ordGenTp"] == Variety.AMO else "NO",
            "vd": cls._key_mapper(cls.req_validity, validity, 'validity') if validity else order_info['ordDur'],
            "dq": "0",
            "mp": "0",
            "dd": "NA",
        }
        print(order_data)
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["modify_order"],
                             params=params, data=data, headers=headers["headers"])

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
        info = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)

        order = info["data"][0]
        params = {"sId": headers["sId"]}
        order_data = {
            "on": str(order_id),
            "am": "YES" if order["ordGenTp"] == Variety.AMO else "NO",
            "ts": order["trdSym"]
        }
        data = {'jData': cls.json_dumps(order_data)}

        response = cls.fetch(method="POST", url=cls.urls["cancel_order"],
                             params=params, data=data, headers=headers["headers"])

        info = cls._json_parser(response)

        order_id = info["result"]
        order = cls.fetch_order(order_id=order_id, headers=headers)

        return order


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
        params = {"sId": headers["sId"]}
        response = cls.fetch(method="GET", url=cls.urls["positions"],
                             params=params, headers=headers["headers"])

        try:
            return cls._json_parser(response)
        except ResponseError as e:
            if "No Data" in str(e):
                return []

    @classmethod
    def fetch_net_positions(cls,
                            headers: dict,
                            ) -> dict[Any, Any]:
        """
        Fetch Total Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Position Response.
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
        params = {'alt': 'false'}
        response = cls.fetch(method="GET", url=cls.urls['holdings'],
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
        Fetch Risk Management System Limits.

        Parameters:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict: kronos Unified RMS Limits Response.
        """
        params = {"sId": headers["sId"]}
        data = {"jData": "{'seg':'CASH','exch':'NSE','prod':'ALL'}"}

        response = cls.fetch(method="POST", url=cls.urls["rms_limits"],
                             params=params, data=data, headers=headers["headers"])
        return cls._json_parser(response)
