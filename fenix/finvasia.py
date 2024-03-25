from __future__ import annotations
import hashlib
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

if TYPE_CHECKING:
    from requests.models import Response


class finvasia(Broker):
    """
    Finvasia fenix Broker Class

    Returns:
        fenix.finvasia: fenix Finvasia Broker Object
    """


    # Market Data Dictonaries

    indices = {}
    eq_tokens = {}
    nfo_tokens = {}
    token_params = ['user_id', "password", "api_key", "vendor_code", "totpstr"]
    id = 'finvasia'
    _session = Broker._create_session()


    # Base URLs & Access Token Generation URLs

    base_urls = {
        "api_doc": "https://www.shoonya.com/api-documentation",
        "access_token": "https://api.shoonya.com/NorenWClientTP/QuickAuth",
        "base": "https://api.shoonya.com/NorenWClientTP",
        "market_data": f"https://api.shoonya.com/{ExchangeCode.NFO}_symbols.txt.zip",
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base']}/PlaceOrder",
        "modify_order": f"{base_urls['base']}/ModifyOrder",
        "cancel_order": f"{base_urls['base']}/CancelOrder",
        "order_history": f"{base_urls['base']}/SingleOrdHist",
        "orderbook": f"{base_urls['base']}/OrderBook",
        "tradebook": f"{base_urls['base']}/TradeBook",
        "positions": f"{base_urls['base']}/PositionBook",
        "holdings": f"{base_urls['base']}/Holdings",
        "profile": f"{base_urls['base']}/ClientDetails",
        "rms_limits": f"{base_urls['base']}/Limits"


    }


    # Request Parameters Dictionaries

    req_exchange = {
        ExchangeCode.NSE: "NSE",
        ExchangeCode.NFO: "NFO",
        ExchangeCode.CDS: "CDS",
        ExchangeCode.MCX: "MCX",
        ExchangeCode.BSE: "BSE"
    }

    req_order_type = {
        OrderType.MARKET: "MKT",
        OrderType.LIMIT: "LMT",
        OrderType.SL: "SL-LMT",
        OrderType.SLM: "SL-MKT"
    }

    req_product = {
        Product.MIS: "I",
        Product.NRML: "M",
        Product.CNC: "C",
        Product.CO: "H",
        Product.BO: "B"
    }

    req_side = {
        Side.BUY: "B",
        Side.SELL: "S",
    }

    req_validity = {
        Validity.DAY: "DAY",
        Validity.IOC: "IOC",
        "EOS": "EOS",
    }


    # Response Parameters Dictionaries

    resp_order_type = {
        "LMT": OrderType.LIMIT,
        "MKT": OrderType.MARKET
    }

    resp_product = {
        "I": Product.MIS,
        "M": Product.NRML,
        "C": Product.CNC,
        "H": Product.CO,
        "B": Product.BO,
    }

    resp_side = {
        "B": Side.BUY,
        "S": Side.SELL,
    }

    resp_validity = {
        "DAY": Validity.DAY,
        "IOC": Validity.IOC,
        "EOS": "EOS"
    }

    resp_status = {
        "PENDING": Status.PENDING,
        "OPEN": Status.OPEN,
        "COMPLETE": Status.FILLED,
        "CANCELED": Status.CANCELLED,
        "REJECT": Status.REJECTED,
        "Replaced": Status.MODIFIED,
        "New": Status.OPEN,
    }


    # NFO Script Fetch


    @classmethod
    def create_eq_tokens(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the finvasia.indices Dictionary.

        Returns:
            dict: Unified fenix indices format.
        """
        df_bse = cls.data_reader(cls.base_urls["market_data"].replace(ExchangeCode.NFO, ExchangeCode.BSE), filetype='csv')
        df_bse = df_bse[['Symbol', 'Token', 'LotSize', 'TickSize', "Exchange"]]

        df_bse.drop_duplicates(subset=['Symbol'], keep='first', inplace=True)
        df_bse.set_index(df_bse['Symbol'], inplace=True)

        df_nse = cls.data_reader(cls.base_urls["market_data"].replace(ExchangeCode.NFO, ExchangeCode.NSE), filetype='csv')
        df_nse = df_nse[df_nse['Instrument'] == 'EQ'][['Symbol', 'TradingSymbol', 'TickSize', 'Token', 'LotSize', "Exchange"]]
        df_nse.rename({"Symbol": "Index", "TradingSymbol": "Symbol", "token": "Token"}, axis=1, inplace=True)

        df_nse.set_index(df_nse['Index'], inplace=True)
        df_nse.drop(columns="Index", inplace=True)

        cls.eq_tokens[ExchangeCode.NSE] = df_nse.to_dict(orient='index')
        cls.eq_tokens[ExchangeCode.BSE] = df_bse.to_dict(orient='index')

        return cls.eq_tokens

    @classmethod
    def create_indices(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the finvasia.indices Dictionary.

        Returns:
            dict: Unified fenix indices format.
        """
        df = cls.data_reader(cls.base_urls["market_data"].replace("NFO", "NSE"), filetype='csv')

        df = df[df["Instrument"] == "INDEX"][["TradingSymbol", "Token"]]
        df.rename({"TradingSymbol": "Symbol"}, axis=1, inplace=True)
        df.index = df['Symbol']

        indices = df.to_dict(orient='index')

        indices[Root.BNF] = indices["NIFTY BANK"]
        indices[Root.NF] = indices["NIFTY INDEX"]
        indices[Root.FNF] = indices["FINNIFTY"]
        indices[Root.MIDCPNF] = indices["MIDCPNIFTY"]

        cls.indices = indices

        return indices

    @classmethod
    def create_fno_tokens(cls):
        """
        Creates BANKNIFTY & NIFTY Current, Next and Far Expiries;
        Stores them in the finvasia.nfo_tokens Dictionary.

        Raises:
            TokenDownloadError: Any Error Occured is raised through this Error Type.
        """
        try:
            df_nfo = cls.data_reader(cls.base_urls["market_data"], filetype='csv')
            df_nfo = df_nfo[
                (
                    (df_nfo['Symbol'] == 'BANKNIFTY') |
                    (df_nfo['Symbol'] == 'NIFTY') |
                    (df_nfo['Symbol'] == 'FINNIFTY') |
                    (df_nfo['Symbol'] == 'MIDCPNIFTY')
                ) &
                (
                    (df_nfo['Instrument'] == "OPTIDX")
                )]

            bfo_url = cls.base_urls["market_data"].replace(ExchangeCode.NFO, ExchangeCode.BFO)
            df_bfo = cls.data_reader(bfo_url, filetype='csv')
            df_bfo = df_bfo[
                (
                    (df_bfo['Symbol'] == 'BSXOPT') |
                    (df_bfo['Symbol'] == 'BKXOPT')

                ) &
                (
                    (df_bfo['Instrument'] == "OPTIDX")
                )]

            df_bfo['Symbol'] = df_bfo['Symbol'].replace({"BKXOPT": "BANKEX", "BSXOPT": "SENSEX"})

            df = cls.concat_df([df_nfo, df_bfo])
            df = df[['Token', 'TradingSymbol', 'Expiry', 'OptionType',
                     'StrikePrice', 'LotSize', 'Symbol', 'TickSize', 'Exchange',
                     ]]

            df.rename({"OptionType": "Option", "Symbol": "Root", "TradingSymbol": "Symbol"},
                      axis=1, inplace=True)

            df['Expiry'] = cls.pd_datetime(df['Expiry']).dt.date.astype(str)
            df['StrikePrice'] = df['StrikePrice'].astype(int).astype(str)


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
        Generate Headers used to access Endpoints in Finvasia.

        Parameters:
            Params (dict) : A dictionary which should consist the following keys:
                user_id (str): User ID of the Account.
                password (str): Password of the Account.
                api_key (str): API Key of the Account.
                vendor_code (str): Vendor code of the Account.
                totpstr (str): String of characters used to generate TOTP.


        Returns:
            dict[str, str]: Finvasia Headers.
        """
        for key in cls.token_params:
            if key not in params:
                raise KeyError(f"Please provide {key}")


        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        sha256_password = hashlib.sha256(params["password"].encode('utf-8')).hexdigest()
        app_key_format = f'{params["user_id"]}|{params["api_key"]}'
        sha256api_key = hashlib.sha256(app_key_format.encode('utf-8')).hexdigest()

        jdata = {
            "source": "API",
            "apkversion": "1.0.0",
            "uid": params["user_id"],
            "pwd": sha256_password,
            "factor2": cls.totp_creator(params["totpstr"]),
            "vc": params["vendor_code"],
            "appkey": sha256api_key,
            "imei": "abc1234"
        }

        data = "jData=" + cls.json_dumps(jdata)

        response = cls.fetch(method="POST", url=cls.base_urls["access_token"],
                             data=data, headers=headers)

        response = cls._json_parser(response)
        access_token = response['susertoken']

        headers = {
            "uid": params["user_id"],
            "jKey": f"&jKey={access_token}",
            "payload": f"jData=<data>&jKey={access_token}",
            "access_token": access_token,
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
        # print(json_response)

        if isinstance(json_response, dict):
            stat = json_response.get('stat', None)

            if stat == 'Ok':
                return json_response

        if isinstance(json_response, list):
            return json_response

        error = json_response.get('emsg', None)
        raise ResponseError(cls.id + " " + error)

    @classmethod
    def _orderbook_json_parser(cls,
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
            Order.ID: order["norenordno"],
            Order.USERID: order.get("remarks", ""),
            Order.TIMESTAMP: cls.datetime_strp(order["norentm"], "%H:%M:%S %d-%m-%Y"),
            Order.SYMBOL: order["tsym"],
            Order.TOKEN: int(order["token"]),
            Order.SIDE: cls.resp_side[order["trantype"]],
            Order.TYPE: cls.resp_order_type.get(order["prctyp"], order["prctyp"]),
            Order.AVGPRICE: float(order.get("avgprc", 0.0)),
            Order.PRICE: float(order["prc"]),
            Order.TRIGGERPRICE: float(order.get("trgprc", 0.0)),
            Order.TARGETPRICE: float(order.get("bpprc", 0.0)),
            Order.STOPLOSSPRICE: float(order.get("blprc", 0.0)),
            Order.TRAILINGSTOPLOSS: float(order.get("trailprc", 0.0)),
            Order.QUANTITY: int(order["qty"]),
            Order.FILLEDQTY: int(order.get("fillshares", 0)),
            Order.REMAININGQTY: int(order["qty"]) - int(order.get("fillshares", 0)),
            Order.CANCELLEDQTY: int(order.get("cancelqty", 0.0)),
            Order.STATUS: cls.resp_status.get(order["status"], order["status"]),
            Order.REJECTREASON: order.get("rejreason", ""),
            Order.DISCLOSEDQUANTITY: 0,  # int(order["dscqty"]),
            Order.PRODUCT: cls.resp_product.get(order["prd"], order["prd"]),
            Order.EXCHANGE: cls.req_exchange.get(order["exch"], order["exch"]),
            Order.SEGMENT: "",
            Order.VALIDITY: cls.req_validity.get(order["ret"], order["ret"]),
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
            dict: Unified fenix Order Response.
        """
        parsed_order = {
            Order.ID: order["norenordno"],
            Order.USERID: order.get("remarks", ""),
            Order.TIMESTAMP: cls.datetime_strp(order["norentm"], "%H:%M:%S %d-%m-%Y"),
            Order.SYMBOL: order["tsym"],
            Order.TOKEN: int(order["token"]),
            Order.SIDE: cls.resp_side[order["trantype"]],
            Order.TYPE: cls.resp_order_type.get(order["prctyp"], order["prctyp"]),
            Order.AVGPRICE: float(order.get("flprc", 0.0)),
            Order.PRICE: float(order["prc"]),
            Order.TRIGGERPRICE: float(order.get("trgprc", 0.0)),
            Order.TARGETPRICE: float(order.get("bpprc", 0.0)),
            Order.STOPLOSSPRICE: float(order.get("blprc", 0.0)),
            Order.TRAILINGSTOPLOSS: float(order.get("trailprc", 0.0)),
            Order.QUANTITY: int(order["qty"]),
            Order.FILLEDQTY: int(order.get("fillshares", 0)),
            Order.REMAININGQTY: int(order["qty"]) - int(order.get("fillshares", 0)),
            Order.CANCELLEDQTY: int(order.get("cancelqty", 0.0)),
            Order.STATUS: "",
            Order.REJECTREASON: "",
            Order.DISCLOSEDQUANTITY: 0,
            Order.PRODUCT: cls.resp_product.get(order["prd"], order["prd"]),
            Order.EXCHANGE: cls.req_exchange.get(order["exch"], order["exch"]),
            Order.SEGMENT: "",
            Order.VALIDITY: cls.req_validity.get(order["ret"], order["ret"]),
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
            dict: Unified fenix Position Response.
        """
        parsed_position = {
            Position.SYMBOL: position["tsym"],
            Position.TOKEN: int(position["token"]),
            Position.NETQTY: int(position["netqty"]),
            Position.AVGPRICE: float(position["netavgprc"]),
            Position.MTM: float(position["urmtom"]),
            Position.PNL: float(position["rpnl"]),
            Position.BUYQTY: int(position["daybuyqty"]),
            Position.BUYPRICE: float(position["daybuyavgprc"]),
            Position.SELLQTY: int(position["daysellqty"]),
            Position.SELLPRICE: float(position["daysellavgprc"]),
            Position.LTP: float(position["lp"]),
            Position.PRODUCT: cls.resp_product.get(position["prd"], position["prd"]),
            Position.EXCHANGE: cls.req_exchange.get(position["exch"], position["exch"]),
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

        Returns:
            dict: Unified fenix Profile Response.
        """
        parsed_profile = {
            Profile.CLIENTID: profile['actid'],
            Profile.NAME: profile['cliname'],
            Profile.EMAILID: profile['email'],
            Profile.MOBILENO: profile['m_num'],
            Profile.PAN: profile['pan'],
            Profile.ADDRESS: "",
            Profile.BANKNAME: profile['bankdetails'][0]['bankn'],
            Profile.BANKBRANCHNAME: None,
            Profile.BANKACCNO: profile['bankdetails'][0]['acctnum'],
            Profile.EXHCNAGESENABLED: profile['exarr'],
            Profile.ENABLED: profile['act_sts'] == 'Activated',
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
            dict: Unified fenix Order Response.
        """
        info = cls._json_parser(response)
        order_id = info['norenordno']

        order = cls.fetch_order(order_id=order_id, headers=headers)

        return order


    # Order Functions


    @classmethod
    def create_order(cls,
                     token_dict: dict,
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

        if not target:
            jdata = {
                "exch": token_dict["Exchange"],
                "tsym": token_dict["Symbol"],
                "prc": str(price),
                "trgprc": str(trigger),
                "bpprc": str(target),
                "blprc": str(stoploss),
                "trailprc": str(trailing_sl),
                "qty": str(quantity),
                "trantype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[order_type],
                "prd": cls._key_mapper(cls.req_product, product, 'product'),
                "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "remarks": unique_id,
                "dscqty": "0",
                "uid": headers['uid'],
                "actid": headers['uid'],
                "ordersource": "API",
            }

        else:
            jdata = {
                "exch": token_dict["Exchange"],
                "tsym": token_dict["Symbol"],
                "prc": str(price),
                "trgprc": str(trigger),
                "bpprc": str(target),
                "blprc": str(stoploss),
                "trailprc": str(trailing_sl),
                "qty": str(quantity),
                "trantype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[order_type],
                "prd": cls._key_mapper(cls.req_product, product, 'product'),
                "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "remarks": unique_id,
                "dscqty": "0",
                "uid": headers['uid'],
                "actid": headers['uid'],
                "ordersource": "API",
            }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order(cls,
                     token_dict: dict,
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
            dict: fenix Unified Order Response.
        """
        if not target:
            jdata = {
                "exch": token_dict["Exchange"],
                "tsym": token_dict["Symbol"],
                "prc": "0",
                "trgprc": "0",
                "qty": str(quantity),
                "trantype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.MARKET],
                "prd": cls._key_mapper(cls.req_product, product, 'product'),
                "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "remarks": unique_id,
                "dscqty": "0",
                "uid": headers['uid'],
                "actid": headers['uid'],
                "ordersource": "API",
            }

        else:
            jdata = {
                "exch": token_dict["Exchange"],
                "tsym": token_dict["Symbol"],
                "prc": "0",
                "trgprc": "0",
                "bpprc": str(target),
                "blprc": str(stoploss),
                "trailprc": str(trailing_sl),
                "qty": str(quantity),
                "trantype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.MARKET],
                "prd": cls._key_mapper(cls.req_product, product, 'product'),
                "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "remarks": unique_id,
                "dscqty": "0",
                "uid": headers['uid'],
                "actid": headers['uid'],
                "ordersource": "API",
            }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order(cls,
                    token_dict: dict,
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
            dict: fenix Unified Order Response.
        """
        if not target:
            jdata = {
                "exch": token_dict["Exchange"],
                "tsym": token_dict["Symbol"],
                "prc": str(price),
                "trgprc": "0",
                "qty": str(quantity),
                "trantype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.LIMIT],
                "prd": cls._key_mapper(cls.req_product, product, 'product'),
                "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "remarks": unique_id,
                "dscqty": "0",
                "uid": headers['uid'],
                "actid": headers['uid'],
                "ordersource": "API",
            }

        else:
            jdata = {
                "exch": token_dict["Exchange"],
                "tsym": token_dict["Symbol"],
                "prc": str(price),
                "trgprc": "0",
                "bpprc": str(target),
                "blprc": str(stoploss),
                "trailprc": str(trailing_sl),
                "qty": str(quantity),
                "trantype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.LIMIT],
                "prd": cls._key_mapper(cls.req_product, product, 'product'),
                "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "remarks": unique_id,
                "dscqty": "0",
                "uid": headers['uid'],
                "actid": headers['uid'],
                "ordersource": "API",
            }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order(cls,
                 token_dict: dict,
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
            dict: fenix Unified Order Response.
        """
        if not target:
            jdata = {
                "exch": token_dict["Exchange"],
                "tsym": token_dict["Symbol"],
                "prc": str(price),
                "trgprc": str(trigger),
                "qty": str(quantity),
                "trantype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.SL],
                "prd": cls._key_mapper(cls.req_product, product, 'product'),
                "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "remarks": unique_id,
                "dscqty": "0",
                "uid": headers['uid'],
                "actid": headers['uid'],
                "ordersource": "API",
            }

        else:
            jdata = {
                "exch": token_dict["Exchange"],
                "tsym": token_dict["Symbol"],
                "prc": str(price),
                "trgprc": str(trigger),
                "bpprc": str(target),
                "blprc": str(stoploss),
                "trailprc": str(trailing_sl),
                "qty": str(quantity),
                "trantype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.SL],
                "prd": cls._key_mapper(cls.req_product, product, 'product'),
                "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "remarks": unique_id,
                "dscqty": "0",
                "uid": headers['uid'],
                "actid": headers['uid'],
                "ordersource": "API",
            }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order(cls,
                  token_dict: dict,
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
            dict: fenix Unified Order Response.
        """
        if not target:
            jdata = {
                "exch": token_dict["Exchange"],
                "tsym": token_dict["Symbol"],
                "prc": "0",
                "trgprc": str(trigger),
                "qty": str(quantity),
                "trantype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.SLM],
                "prd": cls._key_mapper(cls.req_product, product, 'product'),
                "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "remarks": unique_id,
                "dscqty": "0",
                "uid": headers['uid'],
                "actid": headers['uid'],
                "ordersource": "API",
            }

        else:
            jdata = {
                "exch": token_dict["Exchange"],
                "tsym": token_dict["Symbol"],
                "prc": "0",
                "trgprc": str(trigger),
                "bpprc": str(target),
                "blprc": str(stoploss),
                "trailprc": str(trailing_sl),
                "qty": str(quantity),
                "trantype": cls._key_mapper(cls.req_side, side, 'side'),
                "prctyp": cls.req_order_type[OrderType.SLM],
                "prd": cls._key_mapper(cls.req_product, product, 'product'),
                "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "remarks": unique_id,
                "dscqty": "0",
                "uid": headers['uid'],
                "actid": headers['uid'],
                "ordersource": "API",
            }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

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
            dict: fenix Unified Order Response.
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

        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
            "prc": str(price),
            "trgprc": str(trigger),
            "qty": str(quantity),
            "trantype": cls._key_mapper(cls.req_side, side, 'side'),
            "prctyp": cls.req_order_type[order_type],
            "prd": cls._key_mapper(cls.req_product, product, 'product'),
            "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "remarks": unique_id,
            "dscqty": "0",
            "uid": headers['uid'],
            "actid": headers['uid'],
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order_eq(cls,
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
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        symbol = detail["Symbol"]

        jdata = {
            "exch": exchange,
            "tsym": symbol,
            "prc": "0",
            "trgprc": "0",
            "qty": str(quantity),
            "trantype": cls._key_mapper(cls.req_side, side, 'side'),
            "prctyp": cls.req_order_type[OrderType.MARKET],
            "prd": cls._key_mapper(cls.req_product, product, 'product'),
            "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "remarks": unique_id,
            "dscqty": "0",
            "uid": headers['uid'],
            "actid": headers['uid'],
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

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
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        symbol = detail["Symbol"]

        jdata = {
            "exch": exchange,
            "tsym": symbol,
            "prc": str(price),
            "trgprc": "0",
            "qty": str(quantity),
            "trantype": cls._key_mapper(cls.req_side, side, 'side'),
            "prctyp": cls.req_order_type[OrderType.LIMIT],
            "prd": cls._key_mapper(cls.req_product, product, 'product'),
            "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "remarks": unique_id,
            "dscqty": "0",
            "uid": headers['uid'],
            "actid": headers['uid'],
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

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
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        symbol = detail["Symbol"]

        jdata = {
            "exch": exchange,
            "tsym": symbol,
            "prc": str(price),
            "trgprc": str(trigger),
            "qty": str(quantity),
            "trantype": cls._key_mapper(cls.req_side, side, 'side'),
            "prctyp": cls.req_order_type[OrderType.SL],
            "prd": cls._key_mapper(cls.req_product, product, 'product'),
            "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "remarks": unique_id,
            "dscqty": "0",
            "uid": headers['uid'],
            "actid": headers['uid'],
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

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
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        symbol = detail["Symbol"]

        jdata = {
            "exch": exchange,
            "tsym": symbol,
            "prc": "0",
            "trgprc": str(trigger),
            "qty": str(quantity),
            "trantype": cls._key_mapper(cls.req_side, side, 'side'),
            "prctyp": cls.req_order_type[OrderType.SLM],
            "prd": cls._key_mapper(cls.req_product, product, 'product'),
            "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "remarks": unique_id,
            "dscqty": "0",
            "uid": headers['uid'],
            "actid": headers['uid'],
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

        return cls._create_order_parser(response=response, headers=headers)


    # NFO Order Functions


    @classmethod
    def create_order_fno(cls,
                         exchange: str,
                         root: str,
                         expiry: str,
                         option: str,
                         strike_price: str,
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
            dict: fenix Unified Order Response.
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

        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
            "prc": str(price),
            "trgprc": str(trigger),
            "qty": str(quantity),
            "trantype": cls._key_mapper(cls.req_side, side, 'side'),
            "prctyp": cls.req_order_type[order_type],
            "prd": cls._key_mapper(cls.req_product, product, 'product'),
            "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "remarks": unique_id,
            "dscqty": "0",
            "uid": headers['uid'],
            "actid": headers['uid'],
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order_fno(cls,
                         option: str,
                         strike_price: str,
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
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']

        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
            "prc": "0",
            "trgprc": "0",
            "qty": str(quantity),
            "trantype": cls._key_mapper(cls.req_side, side, 'side'),
            "prctyp": cls.req_order_type[OrderType.MARKET],
            "prd": cls._key_mapper(cls.req_product, product, 'product'),
            "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "remarks": unique_id,
            "dscqty": "0",
            "uid": headers['uid'],
            "actid": headers['uid'],
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order_fno(cls,
                        option: str,
                        strike_price: str,
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
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']

        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
            "prc": str(price),
            "trgprc": "0",
            "qty": str(quantity),
            "trantype": cls._key_mapper(cls.req_side, side, 'side'),
            "prctyp": cls.req_order_type[OrderType.LIMIT],
            "prd": cls._key_mapper(cls.req_product, product, 'product'),
            "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "remarks": unique_id,
            "dscqty": "0",
            "uid": headers['uid'],
            "actid": headers['uid'],
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order_fno(cls,
                     option: str,
                     strike_price: str,
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
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']

        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
            "prc": str(price),
            "trgprc": str(trigger),
            "qty": str(quantity),
            "trantype": cls._key_mapper(cls.req_side, side, 'side'),
            "prctyp": cls.req_order_type[OrderType.SL],
            "prd": cls._key_mapper(cls.req_product, product, 'product'),
            "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "remarks": unique_id,
            "dscqty": "0",
            "uid": headers['uid'],
            "actid": headers['uid'],
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order_fno(cls,
                      option: str,
                      strike_price: str,
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
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        symbol = detail['Symbol']

        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
            "prc": "0",
            "trgprc": str(trigger),
            "qty": str(quantity),
            "trantype": cls._key_mapper(cls.req_side, side, 'side'),
            "prctyp": cls.req_order_type[OrderType.SLM],
            "prd": cls._key_mapper(cls.req_product, product, 'product'),
            "ret": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "remarks": unique_id,
            "dscqty": "0",
            "uid": headers['uid'],
            "actid": headers['uid'],
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["place_order"], data=data)

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
        jdata = {
            "uid": headers['uid'],
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["orderbook"], data=data)

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
        jdata = {
            "uid": headers['uid'],
            "norenordno": str(order_id),
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))
        response = cls.fetch(method="POST", url=cls.urls["order_history"], data=data)

        try:
            return cls._json_parser(response)
        except ResponseError as exc:
            raise InputError({"This order_id does not exist."}) from exc

    @classmethod
    def fetch_orderbook(cls,
                        headers: dict,
                        ) -> list[dict]:
        """
        Fetch Orderbook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using fenix Unified Order Response.
        """
        info = cls.fetch_raw_orderbook(headers=headers)

        orders = []
        for order in info:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_tradebook(cls,
                        headers: dict,
                        ) -> list[dict]:
        """
        Fetch Tradebook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using fenix Unified Order Response.
        """
        jdata = {
            "uid": headers['uid'],
            "actid": headers['uid'],
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["tradebook"], data=data)

        orders = []
        try:
            info = cls._json_parser(response)
        except ResponseError:
            return orders

        for order in info:
            detail = cls._tradebook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_orders(cls,
                     headers: dict,
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
            dict: fenix Unified Order Response.
        """
        info = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)
        order = info[0]
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
            list: A list of dicitonaries containing order history using fenix Unified Order Response.
        """
        info = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)

        order_history = []
        for order in info:
            history = cls._orderbook_json_parser(order)
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
                     ):
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
            dict: fenix Unified Order Response.
        """
        info = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)
        order_info = info[0]

        jdata = {
            "norenordno": order_info["norenordno"],
            "exch": order_info['exch'],
            "tsym": order_info['tsym'],
            "prc": price or order_info["prc"],
            "trgprc": trigger or order_info["trgprc"],
            "qty": quantity or order_info["qty"],
            "prctyp": cls._key_mapper(cls.req_order_type, order_type, 'order_type') if order_type else order_info["prctyp"],
            "ret": cls.req_validity.get(validity, order_info["ret"]) if validity else order_info["ret"],
            "uid": headers['uid'],
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["modify_order"], data=data)
        info = cls._json_parser(response)
        order_id = info["result"]

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
            dict: fenix Unified Order Response.
        """
        jdata = {
            "uid": headers['uid'],
            "norenordno": order_id,
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["cancel_order"], data=data)
        info = cls._json_parser(response)
        order_id = info["result"]


        return cls.fetch_order(order_id=order_id, headers=headers)


    # Positions, Account Limits & Profile


    @classmethod
    def fetch_positions(cls,
                        headers: dict
                        ) -> dict[Any, Any]:
        """
        Fetch Day & Net Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        jdata = {
            "uid": headers['uid'],
            "actid": headers['uid'],
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))
        response = cls.fetch(method="POST", url=cls.urls["positions"], data=data)

        positions = []
        try:
            info = cls._json_parser(response)
        except ResponseError:
            return positions

        for position in info:
            detail = cls._position_json_parser(position)
            positions.append(detail)

        return positions

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
        holdings = []

        for product in cls.resp_product:
            jdata = {
                "uid": headers['uid'],
                "actid": headers['uid'],
                "prd": product
            }

            data = headers['payload'].replace("<data>", cls.json_dumps(jdata))
            response = cls.fetch(method="POST", url=cls.urls["positions"], data=data)

            try:
                info = cls._json_parser(response)
            except ResponseError:
                continue

            holdings.append(info)
            # for holding in info:
            #     detail = cls._json_parser(holding)
            #     holdings.append(detail)

        return holdings

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
        jdata = {
            "uid": headers['uid'],
            "actid": headers['uid'],
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))
        response = cls.fetch(method="POST", url=cls.urls["rms_limits"], data=data)

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
            dict: fenix Unified Profile Response.
        """
        jdata = {
            "uid": headers['uid'],
            "actid": headers['uid'],
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))
        response = cls.fetch(method="POST", url=cls.urls["profile"], data=data)
        response = cls._json_parser(response)
        profile = cls._profile_json_parser(response)

        return profile
