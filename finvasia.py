from __future__ import annotations
import hashlib
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


from kronos.base.errors import InputError
from kronos.base.errors import ResponseError
from kronos.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response


class finvasia(Exchange):
    """
    Finvasia kronos Broker Class

    Returns:
        kronos.finvasia: kronos Finvasia Broker Object
    """


    # Market Data Dictonaries

    nfo_tokens = {}
    id = 'finvasia'
    _session = Exchange._create_session()


    # Base URLs & Access Token Generation URLs

    base_urls = {
        "api_documentation_link": "https://www.shoonya.com/api-documentation",
        "market_data_url": "https://api.shoonya.com/NFO_symbols.txt.zip",
        "base_url": "https://api.shoonya.com/NorenWClientTP",
        "access_token_url": "https://api.shoonya.com/NorenWClientTP/QuickAuth",
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base_url']}/PlaceOrder",
        "modify_order": f"{base_urls['base_url']}/ModifyOrder",
        "cancel_order": f"{base_urls['base_url']}/CancelOrder",
        "order_history": f"{base_urls['base_url']}/SingleOrdHist",
        "orderbook": f"{base_urls['base_url']}/OrderBook",
        "tradebook": f"{base_urls['base_url']}/TradeBook",
        "positions": f"{base_urls['base_url']}/PositionBook",
        "profile": f"{base_urls['base_url']}/ClientDetails",
        "rms_limits": f"{base_urls['base_url']}/Limits"


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
    }


    # NFO Script Fetch


    @classmethod
    def create_indices(cls) -> dict:
        """
        Gives NFO Indices Info for F&O Segment.

        Returns:
            dict: Unified kronos create_nfo_tokens format
        """

        df = cls.data_reader(cls.base_urls["market_data_url"].replace("NFO", "NSE"), filetype='csv')

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
    def create_nfo_tokens(cls):
        try:
            df = cls.data_reader(cls.base_urls["market_data_url"], filetype='csv')

            df = df[((df['Symbol'] == 'BANKNIFTY') | (df['Symbol'] == 'NIFTY') | (df['Symbol'] == 'FINNIFTY')) & (df['Instrument'] == "OPTIDX")]

            df = df[['Token', 'TradingSymbol', 'Expiry', 'OptionType',
                     'StrikePrice', 'LotSize', 'Symbol', 'TickSize', 'Exchange',
                     ]]

            df.rename({"OptionType": "Option", "Symbol": "Root", "TradingSymbol": "Symbol"},
                      axis=1, inplace=True)

            df['Expiry'] = cls.pd_datetime(df['Expiry']).dt.date.astype(str)
            df['StrikePrice'] = df['StrikePrice'].astype(int)

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


        for key in ['user_id', "password", "api_key", "vendor_code", "totpstr"]:
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

        response = cls.fetch(method="POST", url=cls.base_urls["access_token_url"], headers=headers, data=data)
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

        json_response = cls.on_json_response(response)
        print(json_response)

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

        parsed_order = {
            Order.ID: order["norenordno"],
            Order.USERID: order.get("remarks", ""),
            Order.TIMESTAMP: cls.datetime_strp(order["norentm"], "%H:%M:%S %d-%m-%Y"),
            Order.SYMBOL: order["tsym"],
            Order.TOKEN: order["token"],
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

        parsed_order = {
            Order.ID: order["norenordno"],
            Order.USERID: order.get("remarks", ""),
            Order.TIMESTAMP: cls.datetime_strp(order["norentm"], "%H:%M:%S %d-%m-%Y"),
            Order.SYMBOL: order["tsym"],
            Order.TOKEN: order["token"],
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
    def _profile_json_parser(cls,
                             profile: dict
                             ) -> dict[Any, Any]:

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
    def _position_json_parser(cls,
                              position: dict,
                              ) -> dict[Any, Any]:

        parsed_position = {
            Position.SYMBOL: position["tsym"],
            Position.TOKEN: position["token"],
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
    def _create_order_parser(cls,
                             response: Response,
                             headers: dict
                             ) -> dict[Any, Any]:

        info = cls._json_parser(response)
        order_id = info['norenordno']

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

        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
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
                     symbol: str,
                     side: str,
                     unique_id: str,
                     quantity: int,
                     exchange: str,
                     headers: dict,
                     token: int | None = None,
                     product: str = Product.MIS,
                     validity: str = Validity.DAY,
                     ) -> dict[Any, Any]:

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
    def limit_order(cls,
                    price: float,
                    symbol: str,
                    token: int,
                    side: str,
                    unique_id: str,
                    quantity: int,
                    exchange: str,
                    headers: dict,
                    product: str = Product.MIS,
                    validity: str = Validity.DAY
                    ) -> dict[Any, Any]:

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
            trigger (float): trigger price of the order.
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

        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
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

        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
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

        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
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
        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
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

        jdata = {
            "exch": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "tsym": symbol,
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


    # Order Details, OrderBook & TradeBook


    @classmethod
    def fetch_orderhistory(cls,
                           order_id: str,
                           headers: dict
                           ) -> list[dict]:

        jdata = {
            "uid": headers['uid'],
            "norenordno": order_id,
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["order_history"], data=data)
        try:
            info = cls._json_parser(response)
        except ResponseError as exc:
            raise InputError({"This order_id does not exist."}) from exc

        order_history = []
        for order in info:
            history = cls._orderbook_json_parser(order)

            order_history.append(history)

        return order_history

    @classmethod
    def fetch_order(cls,
                    order_id: str,
                    headers: dict
                    ) -> dict[Any, Any]:



        jdata = {
            "uid": headers['uid'],
            "norenordno": order_id,
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["order_history"], data=data)
        try:
            info = cls._json_parser(response)
        except ResponseError as exc:
            raise InputError({"This order_id does not exist."}) from exc

        order = info[0]
        order = cls._orderbook_json_parser(order)
        return order

    @classmethod
    def fetch_orders(cls,
                     headers: dict,
                     ) -> list[dict]:

        jdata = {
            "uid": headers['uid'],
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["orderbook"], data=data)

        orders = []
        try:
            info = cls._json_parser(response)
        except ResponseError:
            return orders

        for order in info:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_orderbook(cls,
                        headers: dict,
                        ) -> list[dict]:

        jdata = {
            "uid": headers['uid'],
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["orderbook"], data=data)

        orders = []
        try:
            info = cls._json_parser(response)
        except ResponseError:
            return orders

        for order in info:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_tradebook(cls,
                        headers: dict,
                        ) -> list[dict]:

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

        jdata = {
            "uid": headers['uid'],
            "norenordno": order_id,
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["order_history"], data=data)
        try:
            info = cls._json_parser(response)
        except ResponseError as exc:
            raise InputError({"This order_id does not exist."}) from exc

        order = info[0]

        jdata = {
            "uid": headers['uid'],
            "exch": order['exch'],
            "tsym": order['tsym'],
            "norenordno": order["norenordno"],
            "qty": quantity or order["qty"],
            "prc": price or order["prc"],
            "trgprc": trigger or order["trgprc"],
            "prctyp": cls.req_order_type.get(order_type, order['prctyp']),
            "ret": cls.req_validity.get(validity, order["ret"]),
            "ordersource": "API",
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["modify_order"], data=data)

        info = cls._json_parser(response)
        order_id = info["result"]

        order = cls.fetch_order(order_id=order_id, headers=headers)
        return order

    @classmethod
    def cancel_order(cls,
                     order_id: str,
                     headers: dict
                     ) -> dict[Any, Any]:


        jdata = {
            "uid": headers['uid'],
            "norenordno": order_id,
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["cancel_order"], data=data)

        info = cls._json_parser(response)
        order_id = info["result"]

        order = cls.fetch_order(order_id=order_id, headers=headers)
        return order


    # Positions, Account Limits & Profile


    @classmethod
    def positions(cls,
                  headers: dict
                  ) -> dict[Any, Any]:

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

        jdata = {
            "uid": headers['uid'],
            "actid": headers['uid'],
        }

        data = headers['payload'].replace("<data>", cls.json_dumps(jdata))

        response = cls.fetch(method="POST", url=cls.urls["profile"], data=data)
        response = cls._json_parser(response)

        profile = cls._profile_json_parser(response)
        return profile
