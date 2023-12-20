from __future__ import annotations
import base64
from typing import TYPE_CHECKING
from typing import Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


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
from kronos.base.errors import TokenDownloadError
from kronos.base.errors import ResponseError


if TYPE_CHECKING:
    from requests.models import Response


class EncryptionClient:

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.mode = AES.MODE_CBC
        self.ciphertext = None

    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        text = pad(text, 16)
        self.ciphertext = cryptor.encrypt(text)

        return base64.b64encode(self.ciphertext).decode()


class choice(Exchange):

    """ Class for Choice """


    # Market Data Dictonaries

    indices = {}
    eq_tokens = {}
    nfo_tokens = {}
    id = 'choice'
    _session = Exchange._create_session()


    # Base URLs

    base_urls = {
        "api_doc": "https://uat.jiffy.in/api/OpenAPI/Info",
        "base_url": "https://finx.choiceindia.com/api/OpenAPI",
        "market_data": "https://scripmaster.choiceindia.com/scripmaster",
    }


    # Access Token Generation URLs

    token_urls = {
        "login": f"{base_urls['base_url']}/LoginTOTP",
        "totp": f"{base_urls['base_url']}/GetClientLoginTOTP",
        "validate_totp": f"{base_urls['base_url']}/ValidateTOTP",
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base_url']}/NewOrder",
        "modify_order": f"{base_urls['base_url']}/ModifyOrder",
        "cancel_order": f"{base_urls['base_url']}/CancelOrder",
        "order_history": f"{base_urls['base_url']}/OrderBookByOrderNo",
        "orderbook": f"{base_urls['base_url']}/OrderBook",
        "tradebook": f"{base_urls['base_url']}/TradeBook",
        "positions": f"{base_urls['base_url']}/NetPosition",
        "holdings": f"{base_urls['base_url']}/Holdings",
        "funds": f"{base_urls['base_url']}/FundsView",
        "profile": f"{base_urls['base_url']}/UserProfile",
    }


    # Request Parameters Dictionaries

    req_exchange = {
        ExchangeCode.NSE: 1,
        ExchangeCode.NFO: 2,
        ExchangeCode.BSE: 3,
        "MCX-D": 5,
        "MCX-S": 6,
        "NCDEX-D": 7,
        "NCDEX-S": 8,
        "NCDS-D": 13,
        "NCDS-S": 14
    }

    req_order_type = {
        OrderType.MARKET: "RL_MKT",
        OrderType.LIMIT: "RL_LIMIT",
        OrderType.SL: "SL_LIMIT",
        OrderType.SLM: "SL_MKT"
    }

    req_product = {
        Product.MIS: "M",
        Product.NRML: "D"
    }

    req_side = {
        Side.BUY: 1,
        Side.SELL: 2
    }

    req_validity = {
        Validity.DAY: 1,
        Validity.IOC: 4,
        Validity.GTD: 11,
        Validity.GTC: 11
    }


    # Response Parameters Dictionaries

    resp_exchange = {
        1: ExchangeCode.NSE,
        2: ExchangeCode.NFO,
        3: ExchangeCode.BSE,
        5: "MCX-D",
        6: "MCX-S",
        7: "NCDEX-D",
        8: "NCDEX-S",
        13: "NCDS-D",
        14: "NCDS-S",
    }

    resp_order_type = {
        '2': OrderType.MARKET,
    }

    resp_product = {
        "M": Product.MIS,
        "D": Product.NRML
    }

    resp_side = {
        '1': Side.BUY,
        '2': Side.SELL
    }

    resp_status = {
        "CLIENT XMITTED": Status.PENDING,
        "GATEWAY XMITTED": Status.PENDING,
        "OMS XMITTED": Status.PENDING,
        "EXCHANGE XMITTED": Status.PENDING,
        "PENDING": Status.PENDING,
        "CANCELLED": Status.CANCELLED,
        "AMO CANCELLED": Status.CANCELLED,
        "GATEWAY REJECT": Status.REJECTED,
        "OMS REJECT": Status.REJECTED,
        "ORDER ERROR": Status.REJECTED,
        "FROZEN": Status.REJECTED,
        "AMO SUBMITTED": Status.OPEN,
        "EXECUTED": Status.FILLED,
    }

    resp_validity = {
        1: Validity.DAY,
        4: Validity.IOC,
        11: f"{Validity.GTD}/{Validity.GTC}",
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
        todaysdate = cls.current_datetime().date().strftime("%d%b%Y")
        link = f"{cls.base_urls['market_data']}/SCRIP_MASTER_{todaysdate}.csv"
        df = cls.data_reader(link, filetype='csv', dtype={"ISIN": str, "SecName": str, 'Instrument': str, "PriceUnit": str, "QtyUnit": str, "DeliveryUnit": str})

        df["PriceTick"] = df["PriceTick"] / df["PriceDivisor"]
        df.rename({"Symbol": "Index", "SecDesc": "Symbol", "PriceTick": "TickSize",
                   "MarketLot": "LotSize"}, axis=1, inplace=True)


        df_bse = df[df['Exchange'] == "BSE"]
        df_bse = df_bse[["Index", "Symbol", "Token", "TickSize", "LotSize"]]
        df_bse.drop_duplicates(subset=['Index'], keep='first', inplace=True)
        df_bse.set_index(df_bse['Index'], inplace=True)
        df_bse.drop(columns="Index", inplace=True)


        df_nse = df[(df['Exchange'] == "NSE") & (df['Series'] == "EQ")]
        df_nse = df_nse[["Index", "Symbol", "Token", "TickSize", "LotSize"]]
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
            dict: Unified kronos indices format.
        """
        try:
            todaysdate = cls.current_datetime().date().strftime("%d%b%Y")
            link = f"{cls.base_urls['market_data']}/SCRIP_MASTER_{todaysdate}.csv"
            df = cls.data_reader(link, filetype='csv', dtype={"ISIN": str, "SecName": str, 'Instrument': str, "PriceUnit": str, "QtyUnit": str, "DeliveryUnit": str})

            df = df[
                (
                    (df["Segment"] == 1) &
                    (df["PriceTick"] == 0)
                )][["Symbol", "Token"]]
            df.index = df['Symbol']

            indices = df.to_dict(orient='index')

            indices[Root.BNF] = indices["BANKNIFTY"]
            indices[Root.NF] = indices["NIFTY"]
            indices[Root.FNF] = indices["FINNIFTY"]
            indices[Root.MIDCPNF] = indices["MIDCPNIFTY"]


            cls.indices = indices

            return indices

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc

    @classmethod
    def create_nfo_tokens(cls) -> dict:
        """
        Creates BANKNIFTY & NIFTY Current, Next and Far Expiries;
        Stores them in the aliceblue.nfo_tokens Dictionary.

        Raises:
            TokenDownloadError: Any Error Occured is raised through this Error Type.
        """

        try:
            todaysdate = cls.current_datetime().date().strftime("%d%b%Y")
            link = f"{cls.base_urls['market_data']}/SCRIP_MASTER_{todaysdate}.csv"
            df = cls.data_reader(link, filetype='csv', dtype={"ISIN": str, "SecName": str, 'Instrument': str, "PriceUnit": str, "QtyUnit": str, "DeliveryUnit": str})

            df = df[
                (
                    (df["Symbol"] == "BANKNIFTY") |
                    (df["Symbol"] == "NIFTY") |
                    (df["Symbol"] == "FINNIFTY") |
                    (df["Symbol"] == "MIDCPNIFTY")
                ) &
                (
                    (df["Instrument"] == "OPTIDX")
                )]

            df = df[["Token", "SecDesc", "Expiry", "OptionType", "StrikePrice", "MarketLot",
                     "MaxOrderLots", "PriceDivisor", "Symbol", "PriceTick"
                     ]]

            df.rename({"Symbol": "Root", "SecDesc": "Symbol", "OptionType": "Option",
                       "PriceTick": "TickSize", "MarketLot": "LotSize",
                       "lastPrice": "LastPrice", "MaxOrderLots": "QtyLimit"},
                      axis=1, inplace=True)

            df["Expiry"] = cls.pd_datetime(df["Expiry"]).dt.date.astype(str)
            df["StrikePrice"] = (df["StrikePrice"] / df["PriceDivisor"]).astype(int)
            df["TickSize"] = df["TickSize"] / df["PriceDivisor"]

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
                user_name (str): UserName of the Account.
                password (str): Password of the Account.
                vendor_id (str): Vendor ID of the Account Holder.
                vendor_key (str): Vendor Key of the Account Holder.
                encryption_key (str): Encryption Key of the Account Holder.
                encryption_iv (str): Encryption IV of the Account Holder.

        Returns:
            dict[str, str]: Choice Headers.
        """
        for key in ["user_name", "password", "vendor_id", "vendor_key", "encryption_key", "encryption_iv"]:
            if key not in params:
                raise KeyError(f"Please provide {key}")


        encryption_client = EncryptionClient(params["encryption_key"].encode(), params["encryption_iv"].encode())
        encrypt_username = encryption_client.encrypt(params["user_name"].encode())
        encrypt_password = encryption_client.encrypt(params["password"].encode())

        headers = {'VendorId': params["vendor_id"], 'VendorKey': params["vendor_key"], 'Content-Type': 'application/json'}
        json_data = {"UserId": params["user_name"], "Pwd": encrypt_password}
        response = cls.fetch(method="POST", url=cls.token_urls["login"],
                             json=json_data, headers=headers)

        _ = cls._json_parser(response)

        json_data = {"UserId": encrypt_username}
        response = cls.fetch(method="POST", url=cls.token_urls["totp_url"],
                             json=json_data, headers=headers)

        response = cls._json_parser(response)
        totp = response["Response"]

        json_data = {"UserId": params["user_name"], "Otp": totp}
        response = cls.fetch(method="POST", url=cls.token_urls["validate_totp"],
                             json=json_data, headers=headers)
        response = cls._json_parser(response)

        session_id = response["Response"]["SessionId"]

        headers = {
            "headers": {
                "VendorId": params["vendor_id"],
                "VendorKey": params["vendor_key"],
                "Authorization": f"SessionId {session_id}",
                "Content-Type": "application/json"
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
        if json_response['Status'] == 'Success':
            return json_response['Response']
        else:
            error = json_response['Reason']
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
            dict: Unified kronos Order Response.
        """
        parsed_order = {
            Order.ID: order['ClientOrderNo'],
            Order.USERID: '',
            Order.TIMESTAMP: cls.datetime_strp(order["Time"], '%Y-%m-%d %H:%M:%S'),
            Order.SYMBOL: order['Symbol'],
            Order.TOKEN: order['Token'],
            Order.SIDE: cls.resp_side[order['BS']],
            Order.TYPE: cls.resp_order_type.get(order['OrderType'], order['OrderType']),
            Order.AVGPRICE: 0.0,
            Order.PRICE: order['Price'],
            Order.TRIGGERPRICE: order['TriggerPrice'],
            Order.TARGETPRICE: order["ProfitOrderPrice"],
            Order.STOPLOSSPRICE: order["SLOrderPrice"],
            Order.TRAILINGSTOPLOSS: order["SLJumpprice"],
            Order.QUANTITY: order['Qty'],
            Order.FILLEDQTY: order['TradedQty'],
            Order.REMAININGQTY: order['TotalQtyRemaining'],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: cls.resp_status.get(order['OrderStatus'], order['OrderStatus']),
            Order.REJECTREASON: order['ErrorString'],
            Order.DISCLOSEDQUANTITY: order['DisclosedQty'],
            Order.PRODUCT: cls.resp_product.get(order['ProductType'], order['ProductType']),
            Order.EXCHANGE: cls.resp_exchange.get(order['SegmentId'], order['SegmentId']),
            Order.SEGMENT: "",
            Order.VALIDITY: cls.resp_validity.get(order['Validity'], order['Validity']),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _profile_json_parser(cls,
                             profile: dict
                             ) -> dict[Any, Any]:
        """
        Parse User Profile Json Response.

        Parameters:
            profile (dict): User Profile Json Response from Broker.

        Returns:
            dict: Unified kronos Profile Response.
        """
        parsed_profile = {
            Profile.CLIENTID: profile['ClientId'],
            Profile.NAME: profile['Name'],
            Profile.EMAILID: profile['EmailID'],
            Profile.MOBILENO: profile['MobileNo'],
            Profile.PAN: "",
            Profile.ADDRESS: "",
            Profile.BANKNAME: "",
            Profile.BANKBRANCHNAME: None,
            Profile.BANKACCNO: "",
            Profile.EXHCNAGESENABLED: [],
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

        Returns:
            dict: Unified kronos Order Response.
        """
        info = cls._json_parser(response)

        if 'fault' in info:
            order_id = info['fault']['orderId']
            order = cls.fetch_order(order_id=order_id, headers=headers)
            return order

        if "BSE" not in info['Success']:
            order_id = info['Success']['NSE']['orderId']
            order = cls.fetch_order(order_id=order_id, headers=headers)
            return order

        order_nse = info['Success']['NSE']
        order_bse = info['Success']['BSE']
        data = {
            "NSE": {
                "id": order_nse['orderId'],
                "userOrderId": order_nse['tag'],
                "price": order_nse['orderId'],
                "qauntity": order_nse['quantity'],
                "message": order_nse['message']
            },

            "BSE": {
                "id": order_bse['orderId'],
                "userOrderId": order_bse['tag'],
                "price": order_bse['orderId'],
                "qauntity": order_bse['quantity'],
                "message": order_bse['message']
            },

            "info": info
        }

        return data


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
                "Token": token,
                "SegmentId": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "Price": price,
                "TriggerPrice": trigger,
                "Qty": quantity,
                "BS": cls._key_mapper(cls.req_side, side, 'side'),
                "OrderType": cls.req_order_type[order_type],
                "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
                "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "DisclosedQty": 0,
                "IsEdisReq": False,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")


        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
            json_data = {
                "Token": token,
                "SegmentId": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "Price": 0,
                "TriggerPrice": 0,
                "Qty": quantity,
                "BS": cls._key_mapper(cls.req_side, side, 'side'),
                "OrderType": cls.req_order_type[OrderType.MARKET],
                "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
                "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "DisclosedQty": 0,
                "IsEdisReq": False,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
            json_data = {
                "Token": token,
                "SegmentId": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "Price": price,
                "TriggerPrice": 0,
                "Qty": quantity,
                "BS": cls._key_mapper(cls.req_side, side, 'side'),
                "OrderType": cls.req_order_type[OrderType.LIMIT],
                "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
                "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "DisclosedQty": 0,
                "IsEdisReq": False,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: kronos Unified Order Response.
        """
        if not target:
            json_data = {
                "Token": token,
                "SegmentId": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "Price": price,
                "TriggerPrice": trigger,
                "Qty": quantity,
                "BS": cls._key_mapper(cls.req_side, side, 'side'),
                "OrderType": cls.req_order_type[OrderType.SL],
                "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
                "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "DisclosedQty": 0,
                "IsEdisReq": False,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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
        """
        if not target:
            json_data = {
                "Token": token,
                "SegmentId": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
                "Price": 0,
                "TriggerPrice": trigger,
                "Qty": quantity,
                "BS": cls._key_mapper(cls.req_side, side, 'side'),
                "OrderType": cls.req_order_type[OrderType.SLM],
                "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
                "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "DisclosedQty": 0,
                "IsEdisReq": False,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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
            dict: kronos Unified Order Response
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

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
                "Token": token,
                "SegmentId": exchange,
                "Price": price,
                "TriggerPrice": trigger,
                "Qty": quantity,
                "BS": cls._key_mapper(cls.req_side, side, 'side'),
                "OrderType": cls.req_order_type[order_type],
                "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
                "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "DisclosedQty": 0,
                "IsEdisReq": False,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")


        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = exchange
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not target:
            json_data = {
                "Token": token,
                "SegmentId": exchange,
                "Price": 0,
                "TriggerPrice": 0,
                "Qty": quantity,
                "BS": cls._key_mapper(cls.req_side, side, 'side'),
                "OrderType": cls.req_order_type[OrderType.MARKET],
                "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
                "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "DisclosedQty": 0,
                "IsEdisReq": False,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not target:
            json_data = {
                "Token": token,
                "SegmentId": exchange,
                "Price": price,
                "TriggerPrice": 0,
                "Qty": quantity,
                "BS": cls._key_mapper(cls.req_side, side, 'side'),
                "OrderType": cls.req_order_type[OrderType.LIMIT],
                "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
                "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "DisclosedQty": 0,
                "IsEdisReq": False,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not target:
            json_data = {
                "Token": token,
                "SegmentId": exchange,
                "Price": price,
                "TriggerPrice": trigger,
                "Qty": quantity,
                "BS": cls._key_mapper(cls.req_side, side, 'side'),
                "OrderType": cls.req_order_type[OrderType.SL],
                "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
                "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "DisclosedQty": 0,
                "IsEdisReq": False,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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
                "Token": token,
                "SegmentId": exchange,
                "Price": 0,
                "TriggerPrice": trigger,
                "Qty": quantity,
                "BS": cls._key_mapper(cls.req_side, side, 'side'),
                "OrderType": cls.req_order_type[OrderType.SLM],
                "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
                "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "DisclosedQty": 0,
                "IsEdisReq": False,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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

        token = detail['Token']

        json_data = {
            "Token": token,
            "SegmentId": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "Price": 0,
            "TriggerPrice": 0,
            "Qty": quantity,
            "BS": cls._key_mapper(cls.req_side, side, 'side'),
            "OrderType": cls.req_order_type[OrderType.MARKET],
            "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
            "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "DisclosedQty": 0,
            "IsEdisReq": False,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "Token": token,
            "SegmentId": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "Price": price,
            "TriggerPrice": 0,
            "Qty": quantity,
            "BS": cls._key_mapper(cls.req_side, side, 'side'),
            "OrderType": cls.req_order_type[OrderType.LIMIT],
            "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
            "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "DisclosedQty": 0,
            "IsEdisReq": False,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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
            "Token": token,
            "SegmentId": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "Price": price,
            "TriggerPrice": trigger,
            "Qty": quantity,
            "BS": cls._key_mapper(cls.req_side, side, 'side'),
            "OrderType": cls.req_order_type[OrderType.SL],
            "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
            "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "DisclosedQty": 0,
            "IsEdisReq": False,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

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
            "Token": token,
            "SegmentId": cls._key_mapper(cls.req_exchange, exchange, 'exchange'),
            "Price": 0,
            "TriggerPrice": trigger,
            "Qty": quantity,
            "BS": cls._key_mapper(cls.req_side, side, 'side'),
            "OrderType": cls.req_order_type[OrderType.SLM],
            "ProductType": cls._key_mapper(cls.req_product, product, 'product'),
            "Validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "DisclosedQty": 0,
            "IsEdisReq": False,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers)

        return cls._create_order_parser(response=response, headers=headers)


    # BO Order Functions

    # NO BO Orders For Choice


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
        response = cls.fetch(method="GET", url=cls.urls["orderbook"], headers=headers)
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
        final_url = f'{cls.urls["order_history"]}/{order_id}'
        response = cls.fetch(method="GET", url=final_url, headers=headers)

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
        for order in info['Orders']:
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
        response = cls.fetch(method="GET", url=cls.urls["tradebook"], headers=headers)
        info = cls._json_parser(response)

        orders = []
        for order in info['Trades']:
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
        info = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)

        detail = info[0]
        order = cls._orderbook_json_parser(detail)

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
        for order in info:
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
            order_type (str | None, optional): Type of Order. defaults to None
            validity (str | None, optional): Order validity Defaults to None.

        Returns:
            dict: kronos Unified Order Response.
        """
        info = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)
        order_info = info[0]

        json_data = {
            "ClientOrderNo": order_info["ClientOrderNo"],
            "GatewayOrderNo": order_info["GatewayOrderNo"],
            "ExchangeOrderNo": order_info["ExchangeOrderNo"],
            "Token": order_info["Token"],
            "Price": price or order_info["Price"],
            "TriggerPrice": trigger or order_info["TriggerPrice"],
            "Qty": quantity or order_info["Qty"],
            "BS": order_info["BS"],
            "OrderType": cls._key_mapper(cls.req_order_type, order_type, "OrderType") if order_type else order_info["OrderType"],
            "ProductType": order_info["ProductType"],
            "SegmentId": order_info["SegmentId"],
            "Validity": cls.req_validity.get(validity, order_info["Validity"]) if validity else order_info["Validity"],
            "DisclosedQty": order_info["DisclosedQty"],
        }

        response = cls.fetch("POST", cls.urls["modify_order"], headers=headers, json=json_data)

        # return cls._create_order_parser(response=response, headers=headers)
        return cls._json_parser(response)

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
        order_info = info[0]

        json_data = {
            "ClientOrderNo": order_info["ClientOrderNo"],
            "GatewayOrderNo": order_info["GatewayOrderNo"],
            "ExchangeOrderNo": order_info["ExchangeOrderNo"],
            "Token": order_info["Token"],
            "Price": order_info["Price"],
            "TriggerPrice": order_info["TriggerPrice"],
            "BS": order_info["BS"],
            "Qty": order_info["Qty"],
            "OrderType": order_info["OrderType"],
            "ProductType": order_info["ProductType"],
            "SegmentId": order_info["SegmentId"],
            "Validity": order_info["Validity"],
            "DisclosedQty": order_info["DisclosedQty"],
            "ExchangeOrderTime": order_info["ExchangeOrderTime"],
        }

        response = cls.fetch("POST", cls.urls["cancel_order"], headers=headers, json=json_data)

        # return cls._create_order_parser(response=response, headers=headers)
        return cls._json_parser(response)


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
        response = cls.fetch(method="GET", url=cls.urls["positions"], headers=headers)
        return cls._json_parser(response)

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
                       ) -> list[dict]:
        """
        Fetch Account Holdings.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: kronos Unified Positions Response.
        """
        response = cls.fetch(method="GET", url=cls.urls["holdings"], headers=headers)
        return cls._json_parser(response)

    @classmethod
    def fetch_funds(cls,
                    headers: dict,
                    ) -> list[dict]:
        """
        Fetch Available Fund in the Account.

        Parameters:
            headers (dict): headers to send fund request with.

        Returns:
            dict: Kronos Unified Funds Response.
        """
        response = cls.fetch(method="GET", url=cls.urls["funds"], headers=headers)
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
        response = cls.fetch(method="GET", url=cls.urls["profile"], headers=headers)
        info = cls._json_parser(response)
        return cls._profile_json_parser(info)
