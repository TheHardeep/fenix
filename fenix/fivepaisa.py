from __future__ import annotations
from typing import TYPE_CHECKING
from typing import Any
import base64
from re import split as ReSplit
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

from fenix.base.broker import Broker

from fenix.base.constants import Side
from fenix.base.constants import OrderType
from fenix.base.constants import ExchangeCode
from fenix.base.constants import Product
from fenix.base.constants import Validity
from fenix.base.constants import Variety
from fenix.base.constants import Status
from fenix.base.constants import Order
from fenix.base.constants import Position
from fenix.base.constants import Root
from fenix.base.constants import WeeklyExpiry
from fenix.base.constants import UniqueID


from fenix.base.errors import InputError
from fenix.base.errors import ResponseError
from fenix.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response


class EncryptionClient:

    def __init__(self, encryption_key):

        self.iv = bytes([83, 71, 26, 58, 54, 35, 22, 11,
                        83, 71, 26, 58, 54, 35, 22, 11])
        self.enc_key = encryption_key

    def _pad_and_convert_to_bytes(self, text):
        return bytes(text + chr(16 - len(text) % 16) * (16 - len(text) % 16), encoding="utf-8")

    def encrypt(self, text):
        padded_text = self._pad_and_convert_to_bytes(text)
        cd = PBKDF2(password=self.enc_key, salt=self.iv, dkLen=48)
        aesiv = cd[:16]
        aeskey = cd[16:]

        cipher = AES.new(aeskey, AES.MODE_CBC, aesiv)

        return str(base64.b64encode(cipher.encrypt(padded_text)), encoding="utf-8")


class fivepaisa(Broker):
    """
    FivePaisa fenix Broker Class.

    Returns:
        fenix.fivepaisa: fenix FivePaisa Broker Object.
    """


    # Market Data Dictonaries

    indices = {}
    eq_tokens = {}
    nfo_tokens = {}
    token_params = ["user_id", "password", "email", "web_login_password",
                    "dob", "app_name", "user_key", "encryption_key"
                    ]
    id = "fivepaisa"
    _session = Broker._create_session()


    # Base URLs

    base_urls = {
        "api_doc": "https://www.5paisa.com/developerapi/overview",
        "access_token": "https://Openapi.5paisa.com/VendorsAPI/Service1.svc/V4/LoginRequestMobileNewbyEmail",
        "base": "https://Openapi.5paisa.com/VendorsAPI/Service1.svc",
        "market_data": "https://images.5paisa.com/website/scripmaster-csv-format.csv",
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base']}/V1/PlaceOrderRequest",
        "bo_order": f"{base_urls['base']}/BracketOrderRequest",
        "modify_order": f"{base_urls['base']}/V1/ModifyOrderRequest",
        "cancel_order": f"{base_urls['base']}/V1/CancelOrderRequest",
        "orderbook": f"{base_urls['base']}/V2/OrderBook",
        "tradebook": f"{base_urls['base']}/V1/TradeBook",
        "positions": f"{base_urls['base']}/V4/NetPosition",
        "holdings": f"{base_urls['base']}/V3/Holding",
    }


    # Request Parameters Dictionaries

    req_exchange = {
        ExchangeCode.NSE: "N",
        ExchangeCode.NFO: "N",
        ExchangeCode.BSE: "B",
        ExchangeCode.BFO: "B"
    }

    req_exchange_type = {
        ExchangeCode.NSE: "C",
        ExchangeCode.NFO: "D",
        ExchangeCode.BSE: "C",
        ExchangeCode.BFO: "D"
    }

    req_product = {
        Product.MIS: True,
        Product.NRML: False,
        Variety.BO: True
    }

    req_side = {
        Side.BUY: "Buy",
        Side.SELL: "Sell"
    }

    req_validity = {
        Validity.DAY: False,
        Validity.IOC: True
    }


    # Response Parameters Dictionaries

    resp_exchange = {
        "N": ExchangeCode.NSE,
        "B": ExchangeCode.BSE,
        "M": ExchangeCode.MCX
    }

    resp_order_type = {
        "N": OrderType.LIMIT,
        "Y": OrderType.MARKET,
    }

    resp_product = {
        "I": Validity.DAY,
        "D": Product.NRML
    }

    resp_side = {
        "B": Side.BUY,
        "S": Side.SELL
    }

    resp_segment = {
        "NC": ExchangeCode.NSE,
        "ND": ExchangeCode.NFO,
        "NU": "NU",
        "BC": ExchangeCode.BSE,
        "BD": ExchangeCode.BFO,
        "BU": "BU",
        "MC": "MSE",
        "MD": "MFO",
        "MU": "MU"
    }

    resp_validity = {
        0: Validity.DAY,
        1: Validity.GTD,
        2: Validity.GTC,
        3: Validity.IOC,
        4: "EOS",
        5: "VTD",
        6: Validity.FOK,
    }

    resp_status = {
        "Fully Executed": Status.FILLED,
        "Rejected By 5P": Status.REJECTED,
        'Pending': Status.PENDING,
        "Cancelled": Status.CANCELLED,
        "modified": Status.MODIFIED,
    }


    # NFO Script Fetch


    @classmethod
    def create_eq_tokens(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the fivepaise.indices Dictionary.

        Returns:
            dict: Unified fenix indices format.
        """
        df = cls.data_reader(cls.base_urls["market_data"], filetype='csv')
        df.rename({"Scripcode": "Token", "Name": "Symbol",
                   "Exch": "Exchange", "ExchType": "ExchangeType"}, axis=1, inplace=True)

        df_bse = df[(df['CpType'] == "XX") &
                    (df['Exchange'] == "B") &
                    (df['ExchangeType'] == "C") &
                    (df['Series'] == "EQ")
                    ]

        df_bse = df_bse[["Symbol", "Token", "TickSize", "LotSize", "Exchange", "ExchangeType"]]
        df_bse.drop_duplicates(subset=['Symbol'], keep='first', inplace=True)
        df_bse.set_index(df_bse['Symbol'], inplace=True)



        df_nse = df[(df['CpType'] == "XX") &
                    (df['Exchange'] == "N") &
                    (df['ExchangeType'] == "C") &
                    (df['Series'] == "EQ")
                    ]

        df_nse = df_nse[["Symbol", "Token", "TickSize", "LotSize", "Exchange", "ExchangeType"]]
        df_nse["Exchange"] = ExchangeCode.NSE
        df_nse.set_index(df_nse['Symbol'], inplace=True)

        cls.eq_tokens[ExchangeCode.NSE] = df_nse.to_dict(orient='index')
        cls.eq_tokens[ExchangeCode.BSE] = df_bse.to_dict(orient='index')

        return cls.eq_tokens


    @classmethod
    def create_indices(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the fivepaise.indices Dictionary.

        Returns:
            dict: Unified fenix indices format.
        """
        df = cls.data_reader(cls.base_urls["market_data"], filetype='csv')
        df = df[(df['CpType'] == "EQ") | (df['Name'] == "SENSEX")][["Name", "Scripcode"]]
        df.rename({"Name": "Symbol", "Scripcode": "Token"}, axis=1, inplace=True)
        df.index = df['Symbol']

        indices = df.to_dict(orient='index')

        indices[Root.BNF] = indices["BANKNIFTY"]
        indices[Root.NF] = indices["NIFTY"]
        indices[Root.FNF] = indices["FINNIFTY"]
        indices[Root.MIDCPNF] = indices["MIDCPNifty"]

        cls.indices = indices

        return indices

    @classmethod
    def create_fno_tokens(cls):
        """
        Creates BANKNIFTY & NIFTY Current, Next and Far Expiries;
        Stores them in the fivepaisa.nfo_tokens Dictionary.

        Raises:
            TokenDownloadError: Any Error Occured is raised through this Error Type.
        """
        try:
            df = cls.data_reader(cls.base_urls["market_data"], filetype='csv')

            df = df[['Exch', 'ExchType', 'Scripcode', 'Name', 'CpType',
                     'StrikeRate', 'LotSize', 'QtyLimit', 'Underlyer', 'Root', 'TickSize'
                     ]]

            df = df[
                (
                    (df['Root'] == 'NIFTY') |
                    (df['Root'] == 'BANKNIFTY') |
                    (df['Root'] == "FINNIFTY") |
                    (df['Root'] == "MIDCPNIFTY") |
                    (df['Root'] == "SENSEX") |
                    (df['Root'] == "BANKEX")
                ) &
                (
                    (df['CpType'].str.endswith("E"))
                )]


            df.rename({"StrikeRate": "StrikePrice", "Scripcode": "Token",
                       "Name": "Symbol", "CpType": "Option", "Underlyer": "Expiry",
                       "Exch": "Exchange", "ExchType": "ExchangeType"},
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
        """"
        Generate Headers used to access Endpoints in FivePaisa.

        Parameters:
            Params (dict) : A dictionary which should consist the following keys:
                user_id (str): User ID of the Account.
                password (str): Password of the Account.
                email (str): Email-ID of the Account.
                web_login_password (str): Password used to login to Trading Account.
                dob (str): date of Brth of the Account Holder in the format: "YYYYMMDD".
                app_name (str): App Name of the Account.
                user_key (str): User Key of the Account.
                encryption_key (str): Encryption Key of the Account Holder.

        Returns:
            dict[str, str]: FivePaisa Headers.
        """
        for key in cls.token_params:
            if key not in params:
                raise KeyError(f"Please provide {key}")

        encryption_client = EncryptionClient(params["encryption_key"])

        login_payload = {
            "head": {
                "appName": params["app_name"],
                "appVer": "1.0",
                "key": params["user_key"],
                "osName": "WEB",
                "requestCode": "5PLoginV4",
                "userId": params["user_id"],
                "password": params["password"],
            },
            "body": {
                "Email_id": encryption_client.encrypt(params["email"]),
                "Password": encryption_client.encrypt(params["web_login_password"]),
                "LocalIP": "0.0.0.0",
                "PublicIP": "0.0.0.0",
                "HDSerailNumber": "",
                "MACAddress": "",
                "MachineID": "000000",
                "VersionNo": "1.7",
                "RequestNo": "1",
                "My2PIN": encryption_client.encrypt(params["dob"]),
                "ConnectionType": "1"
            }
        }

        response = cls.fetch(method="POST", url=cls.base_urls["access_token"], json=login_payload)
        response = cls._json_parser(response)

        client_code = response['body']["ClientCode"]
        jwt_token = response['body']['JWTToken']
        req_headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {jwt_token}"
        }
        json_data = {
            "head": {
                "key": params["user_key"],
            },
            "body": {
                "ClientCode": client_code,
            }
        }

        headers = {
            "headers": req_headers,
            "user_key": params["user_key"],
            "client_code": client_code,
            "json_data": json_data,
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

        return json_response

    @classmethod
    def _datetime_converter(cls,
                            dt_str: str
                            ):
        """
        Convert FivePaisa's datetime string to datetime object.

        Parameters:
            dt_str (str): Datetime string.

        Returns:
            datetime: String converted to a datetime object.
        """
        dt_str = int(ReSplit(r'\(|\+', dt_str)[1])
        return cls.from_timestamp(dt_str / 1000)

    @classmethod
    def _orderbook_json_parser(cls,
                               order: dict
                               ) -> dict[Any, Any]:
        """
        Parse Orderbook Order Json Response.

        Parameters:
            order (dict): Orderbook Order Json Response from Broker.

        Returns:
            dict: Unified fenix Order Response.
        """
        parsed_order = {
            Order.ID: order['ExchOrderID'],
            Order.USERID: order['RemoteOrderID'],
            Order.TIMESTAMP: cls._datetime_converter(order['BrokerOrderTime']),
            Order.SYMBOL: order['ScripName'],
            Order.TOKEN: order['ScripCode'],
            Order.SIDE: cls.resp_side[order['BuySell']],
            Order.TYPE: cls.resp_order_type[order['AtMarket']] if order['WithSL'] == "N" else OrderType.SL if order["Rate"] else OrderType.SLM,
            Order.AVGPRICE: order['Rate'],  # float(order['Rate'] or 0.0),
            Order.PRICE: order['Rate'],  # float(order['Rate'] or 0.0),
            Order.TRIGGERPRICE: order['SLTriggerRate'],  # float(order['SLTriggerRate'] or 0.0),
            Order.QUANTITY: order['Qty'],
            Order.FILLEDQTY: order['TradedQty'],
            Order.REMAININGQTY: order['PendingQty'],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: cls.resp_status.get(order['OrderStatus'], order['OrderStatus']),
            Order.REJECTREASON: order['Reason'],
            Order.DISCLOSEDQUANTITY: order['DisClosedQty'],
            Order.PRODUCT: cls.resp_product[order['DelvIntra']],
            Order.EXCHANGE: cls.resp_exchange[order['Exch']],
            Order.SEGMENT: cls.resp_segment[order['Exch'] + order['ExchType']],
            Order.VALIDITY: cls.resp_validity[order['OrderValidity']],
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _tradebook_json_parser(cls,
                               order: dict
                               ) -> dict[Any, Any]:
        """
        Parse Tradebook Order Json Response.

        Parameters:
            order (dict): Tradebook Order Json Response from Broker.

        Returns:
            dict: Unified fenix Order Response.
        """
        parsed_order = {
            Order.ID: order['ExchOrderID'],
            Order.USERID: "",
            Order.TIMESTAMP: cls._datetime_converter(order['ExchangeTradeTime']),
            Order.SYMBOL: order['ScripName'],
            Order.TOKEN: order['ScripCode'],
            Order.SIDE: cls.resp_side[order['BuySell']],
            Order.TYPE: "",
            Order.AVGPRICE: float(order['Rate'] or 0.0),
            Order.PRICE: 0.0,
            Order.TRIGGERPRICE: 0.0,
            Order.QUANTITY: order['Qty'],
            Order.FILLEDQTY: order['Qty'] - order['PendingQty'],
            Order.REMAININGQTY: order['PendingQty'],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: "",
            Order.REJECTREASON: "",
            Order.DISCLOSEDQUANTITY: 0,
            Order.PRODUCT: cls.resp_product[order['DelvIntra']],
            Order.EXCHANGE: cls.resp_exchange[order['Exch']],
            Order.SEGMENT: cls.resp_segment[order['Exch'] + order['ExchType']],
            Order.VALIDITY: "",
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
            Position.SYMBOL: position["ScripName"],
            Position.TOKEN: position["ScripCode"],
            Position.NETQTY: position["NetQty"],
            Position.AVGPRICE: (position["BuyValue"] + position["SellValue"]) / (position["BuyQty"] + position["SellQty"]),
            Position.MTM: position["MTOM"],
            Position.PNL: position["BookedPL"],
            Position.BUYQTY: position["BuyQty"],
            Position.BUYPRICE: position["BuyAvgRate"],
            Position.SELLQTY: position["SellQty"],
            Position.SELLPRICE: position["SellAvgRate"],
            Position.LTP: position["LTP"],
            Position.PRODUCT: cls.resp_product.get(position["OrderFor"], position["OrderFor"]),
            Position.EXCHANGE: cls.resp_segment[position['Exch'] + position['ExchType']],
            Position.INFO: position,
        }

        return parsed_position

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

        broker_id = info["body"]["BrokerOrderID"]

        if broker_id == 0:
            raise ResponseError(cls.id + " " + info["body"]["Message"])
        order = cls.fetch_order(order_id=broker_id, headers=headers, key_to_check="BrokerOrderId")

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
            token_dict (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or nfo_tokens.
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
        is_sl = False
        at_market = False
        if not price and trigger: # OrderType.SLM
            is_sl = True
        elif not price: # OrderType.MARKET
            at_market = True
        elif not trigger: # OrderType.LIMIT
            pass
        else: # OrderType.SL
            is_sl = True

        if not target:
            json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token_dict["Token"],
                    "Exchange": token_dict["Exchange"],
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, token_dict["Exchange"], "exchange"),
                    "Price": price,
                    "StopLossPrice": trigger,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": is_sl,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

            response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

        else:
            json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token_dict["Token"],
                    "Exch": token_dict["Exchange"],
                    "ExchType": cls._key_mapper(cls.req_exchange_type, token_dict["Exchange"], "exchange"),
                    "LimitPriceInitialOrder": price,
                    "TriggerPriceInitialOrder": trigger,
                    "LimitPriceProfitOrder": target,
                    "LimitPriceForSL": stoploss,
                    "TrailingSL": trailing_sl,
                    "Qty": quantity,
                    "BuySell": cls._key_mapper(cls.req_side, side, "side"),
                    "IsStopLossOrder": is_sl,
                    "AtMarket": at_market,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product, "product"),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity, "validity"),
                    "ClientCode": headers["client_code"],
                    "UniqueOrderIDNormal": unique_id,
                    "DisQty": 0,
                }
            }

            response = cls.fetch(method="POST", url=cls.urls["bo_order"], json=json_data, headers=headers["headers"])

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
            json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token_dict["Token"],
                    "Exchange": token_dict["Exchange"],
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, token_dict["Exchange"], "exchange"),
                    "Price": 0,
                    "StopLossPrice": 0,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": False,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

            response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

        else:
            json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token_dict["Token"],
                    "Exch": token_dict["Exchange"],
                    "ExchType": cls._key_mapper(cls.req_exchange_type, token_dict["Exchange"], "exchange"),
                    "LimitPriceInitialOrder": 0,
                    "TriggerPriceInitialOrder": 0,
                    "LimitPriceProfitOrder": target,
                    "LimitPriceForSL": stoploss,
                    "TrailingSL": trailing_sl,
                    "Qty": quantity,
                    "BuySell": cls._key_mapper(cls.req_side, side, "side"),
                    "IsStopLossOrder": False,
                    "AtMarket": True,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product, "product"),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity, "validity"),
                    "ClientCode": headers["client_code"],
                    "UniqueOrderIDNormal": unique_id,
                    "DisQty": 0,
                }
            }

            response = cls.fetch(method="POST", url=cls.urls["bo_order"], json=json_data, headers=headers["headers"])

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
            json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token_dict["Token"],
                    "Exchange": token_dict["Exchange"],
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, token_dict["Exchange"], "exchange"),
                    "Price": price,
                    "StopLossPrice": 0,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": False,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

            response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

        else:
            json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token_dict["Token"],
                    "Exch": token_dict["Exchange"],
                    "ExchType": cls._key_mapper(cls.req_exchange_type, token_dict["Exchange"], "exchange"),
                    "LimitPriceInitialOrder": price,
                    "TriggerPriceInitialOrder": 0,
                    "LimitPriceProfitOrder": target,
                    "LimitPriceForSL": stoploss,
                    "TrailingSL": trailing_sl,
                    "Qty": quantity,
                    "BuySell": cls._key_mapper(cls.req_side, side, "side"),
                    "IsStopLossOrder": False,
                    "AtMarket": False,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product, "product"),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity, "validity"),
                    "ClientCode": headers["client_code"],
                    "UniqueOrderIDNormal": unique_id,
                    "DisQty": 0,
                }
            }

            response = cls.fetch(method="POST", url=cls.urls["bo_order"], json=json_data, headers=headers["headers"])

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
            json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token_dict["Token"],
                    "Exchange": token_dict["Exchange"],
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, token_dict["Exchange"], "exchange"),
                    "Price": price,
                    "StopLossPrice": trigger,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": True,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

            response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

        else:
            json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token_dict["Token"],
                    "Exch": token_dict["Exchange"],
                    "ExchType": cls._key_mapper(cls.req_exchange_type, token_dict["Exchange"], "exchange"),
                    "LimitPriceInitialOrder": price,
                    "TriggerPriceInitialOrder": trigger,
                    "LimitPriceProfitOrder": target,
                    "LimitPriceForSL": stoploss,
                    "TrailingSL": trailing_sl,
                    "Qty": quantity,
                    "BuySell": cls._key_mapper(cls.req_side, side, "side"),
                    "IsStopLossOrder": True,
                    "AtMarket": False,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product, "product"),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity, "validity"),
                    "ClientCode": headers["client_code"],
                    "UniqueOrderIDNormal": unique_id,
                    "DisQty": 0,
                }
            }

            response = cls.fetch(method="POST", url=cls.urls["bo_order"], json=json_data, headers=headers["headers"])

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
            json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token_dict["Token"],
                    "Exchange": token_dict["Exchange"],
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, token_dict["Exchange"], "exchange"),
                    "Price": 0,
                    "StopLossPrice": trigger,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": True,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

            response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

        else:
            json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token_dict["Token"],
                    "Exch": token_dict["Exchange"],
                    "ExchType": cls._key_mapper(cls.req_exchange_type, token_dict["Exchange"], "exchange"),
                    "LimitPriceInitialOrder": 0,
                    "TriggerPriceInitialOrder": trigger,
                    "LimitPriceProfitOrder": target,
                    "LimitPriceForSL": stoploss,
                    "TrailingSL": trailing_sl,
                    "Qty": quantity,
                    "BuySell": cls._key_mapper(cls.req_side, side, "side"),
                    "IsStopLossOrder": True,
                    "AtMarket": False,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product, "product"),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity, "validity"),
                    "ClientCode": headers["client_code"],
                    "UniqueOrderIDNormal": unique_id,
                    "DisQty": 0,
                }
            }

            response = cls.fetch(method="POST", url=cls.urls["bo_order"], json=json_data, headers=headers["headers"])

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
        token = detail["Token"]

        is_sl = False
        if not price and trigger: # OrderType.SLM
            is_sl = True
        elif not price: # OrderType.MARKET
            pass
        elif not trigger: # OrderType.LIMIT
            pass
        else: # OrderType.SL
            is_sl = True

        json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token,
                    "Exchange": exchange,
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, exchange, "exchange"),
                    "Price": price,
                    "StopLossPrice": trigger,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": is_sl,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

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
        token = detail["Token"]

        json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token,
                    "Exchange": exchange,
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, exchange, "exchange"),
                    "Price": 0,
                    "StopLossPrice": 0,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": False,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

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
        token = detail["Token"]

        json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token,
                    "Exchange": exchange,
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, exchange, "exchange"),
                    "Price": price,
                    "StopLossPrice": 0,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": False,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

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
        token = detail["Token"]

        json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token,
                    "Exchange": exchange,
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, exchange, "exchange"),
                    "Price": price,
                    "StopLossPrice": trigger,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": True,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

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
        token = detail["Token"]

        json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token,
                    "Exchange": exchange,
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, exchange, "exchange"),
                    "Price": 0,
                    "StopLossPrice": trigger,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": True,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

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

        token = detail['Token']

        is_sl = False
        if not price and trigger: # OrderType.SLM
            is_sl = True
        elif not price: # OrderType.MARKET
            pass
        elif not trigger: # OrderType.LIMIT
            pass
        else: # OrderType.SL
            is_sl = True

        json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token,
                    "Exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, exchange, "exchange"),
                    "Price": price,
                    "StopLossPrice": trigger,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": is_sl,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

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

        token = detail['Token']

        json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token,
                    "Exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, exchange, "exchange"),
                    "Price": 0,
                    "StopLossPrice": 0,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": False,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

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

        token = detail['Token']

        json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token,
                    "Exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, exchange, "exchange"),
                    "Price": price,
                    "StopLossPrice": 0,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": False,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

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

        token = detail['Token']

        json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token,
                    "Exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, exchange, "exchange"),
                    "Price": price,
                    "StopLossPrice": trigger,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": True,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

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

        token = detail['Token']

        json_data = {
                "head": {
                    "key": headers["user_key"],
                },
                "body": {
                    "ScripCode": token,
                    "Exchange": cls._key_mapper(cls.req_exchange, exchange, "exchange"),
                    "ExchangeType": cls._key_mapper(cls.req_exchange_type, exchange, "exchange"),
                    "Price": 0,
                    "StopLossPrice": trigger,
                    "Qty": quantity,
                    "OrderType": cls._key_mapper(cls.req_side, side),
                    "IsStopLossOrder": True,
                    "IsAHOrder": "N",
                    "IsIntraday": cls._key_mapper(cls.req_product, product),
                    "IsIOCOrder": cls._key_mapper(cls.req_validity, validity),
                    "ClientCode": headers["client_code"],
                    "RemoteOrderID": unique_id,
                    "DisQty": 0,

                }
            }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

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
        response = cls.fetch(method="POST", url=cls.urls["orderbook"], json=headers["json_data"], headers=headers['headers'])
        return cls._json_parser(response)

    @classmethod
    def fetch_raw_tradebook(cls,
                            headers: dict
                            ) -> list[dict]:
        """
        Fetch Raw Tradebook Details, without any Standardaization.

        Parameters:
            headers (dict): headers to send fetch_raw_tradebook request with.

        Returns:
            list[dict]: Raw Broker Tradebook Response.
        """
        response = cls.fetch(method="POST", url=cls.urls["tradebook"], json=headers["json_data"], headers=headers["headers"])
        return cls._json_parser(response)

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
        for order in info['body']['OrderBookDetail']:
            detail = cls.orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_tradebook(cls,
                        headers: dict,
                        default: bool = True,
                        ) -> list[dict] | dict[Any, Any]:
        """
        Fetch Tradebook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using fenix Unified Order Response.
        """
        info = cls.fetch_raw_tradebook(headers=headers)

        if default:
            orders = []
            for order in info['body']['TradeBookDetail']:
                detail = cls._tradebook_json_parser(order)
                orders.append(detail)
            return orders

        orders = {}
        for order in info['body']['TradeBookDetail']:
            detail = cls._tradebook_json_parser(order)
            orders[detail['id']] = detail

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
            dict: fenix Unified Order Response.
        """
        info = cls.fetch_raw_orderbook(headers=headers)
        tradebook_orders = cls.fetch_tradebook(headers=headers, default=False)

        orders = []
        for order in info['body']['OrderBookDetail']:
            detail = cls._orderbook_json_parser(order)

            avgprice = tradebook_orders[detail['id']]['avgPrice'] if tradebook_orders.get(detail['id']) else 0.0
            detail['avgPrice'] = avgprice

            orders.append(detail)

        return orders

    @classmethod
    def fetch_order(cls,
                    order_id: str,
                    headers: dict,
                    key_to_check: str = "ExchOrderID",
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
        orderid = str(order_id) if key_to_check == "ExchOrderID" else int(order_id)
        info = cls.fetch_raw_orderbook(headers=headers)

        for order in info['body']['OrderBookDetail']:
            if order[key_to_check] == orderid:
                detail = cls._orderbook_json_parser(order)
                detail['avgPrice'] = cls.fetch_tradebook_order(order_id=detail['id'], headers=headers, default=False)  # Five Paisa API is Fuddu i.e. commented.
                return detail

        raise InputError({"This orderid does not exist."})

    @classmethod
    def fetch_tradebook_order(cls,
                              order_id: str,
                              headers: dict,
                              default: bool = True,
                              ):
        info = cls.fetch_raw_tradebook(headers=headers)

        orders = []
        for order in info['body']['TradeBookDetail']:
            if order["ExchOrderID"] == order_id:
                if default:
                    detail = cls._tradebook_json_parser(order)
                    return detail

                return order['Rate']

        if default:
            return orders

        return 0.0


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
        info = cls.fetch_raw_orderbook(headers=headers)

        order = {}
        for order_det in info['body']['OrderBookDetail']:
            if order_det["ExchOrderID"] == order_id:
                order = order_det
                break

        if not order:
            raise InputError({"This orderid does not exist."})

        json_data = {
            'head': {
                'key': headers['user_key'],
            },
            'body': {
                "Price": price or order['Rate'],
                "Qty": quantity or order['Qty'],
                "ExchOrderID": order['ExchOrderID'],
                "DisQty": order['DisClosedQty'],
                "Stoplossprice": trigger or order['SLTriggerRate'],
                "RemoteOrderID": order['RemoteOrderID'],
            }
        }

        response = cls.fetch(method="POST", url=cls.urls["modify_order"], json=json_data, headers=headers["headers"])
        response = cls._json_parser(response)

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
        json_data = {
            'head': {
                'key': headers['user_key'],
            },
            'body': {
                'ExchOrderID': order_id,
            }
        }

        response = cls.fetch(method="POST", url=cls.order_cancel_url, headers=headers["headers"], json=json_data)
        info = cls._json_parser(response)

        order_id = info['body']['ExchOrderID']
        order = cls.fetch_order(order_id=order_id, headers=headers)

        return order

    @classmethod
    def fetch_positions(cls,
                        headers: dict,
                        ) -> list[dict]:
        """
        Fetch Day & Net Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        response = cls.fetch(method="POST", url=cls.urls["positions"], json=headers["json_data"], headers=headers["headers"])
        info = cls._json_parser(response)

        positions = []
        for position in info['head']['NetPositionDetail']:
            detail = cls._position_json_parser(position)
            positions.append(detail)

        return positions

    @classmethod
    def fetch_holdings(cls,
                       headers: dict,
                       ) -> list[dict]:
        """
        Fetch Account Holdings.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Positions Response.
        """
        response = cls.fetch(method="POST", url=cls.urls["holdings"],
                             json=headers["json_data"], headers=headers["headers"])
        info = cls._json_parser(response)

        return info

        # {'body': {'CacheTime': 300,
        #     'Data': [{'AvgRate': 2059.8125,
        #         'BseCode': 543396,
        #         'CurrentPrice': 624.05,
        #         'DPQty': 80,
        #         'Exch': '\x00',
        #         'ExchType': 'C',
        #         'FullName': 'ONE 97 COMMUNICATIONS LTD',
        #         'NseCode': 6705,
        #         'POASigned': 'N',
        #         'PoolQty': 0,
        #         'Quantity': 80,
        #         'ScripMultiplier': 1,
        #         'Symbol': 'PAYTM'},
        #     {'AvgRate': 22.63,
        #         'BseCode': 540787,
        #         'CurrentPrice': 58.73,
        #         'DPQty': 1,
        #         'Exch': '\x00',
        #         'ExchType': 'C',
        #         'FullName': 'ICICIPRAMC - BHARATIWIN',
        #         'NseCode': 522,
        #         'POASigned': 'N',
        #         'PoolQty': 0,
        #         'Quantity': 1,
        #         'ScripMultiplier': 1,
        #         'Symbol': 'ICICIB22'}],
        #     'Message': 'Success',
        #     'Status': 0},
        #     'head': {'responseCode': '5PHoldingV3',
        #     'status': '0',
        #     'statusDescription': 'Success'}}
